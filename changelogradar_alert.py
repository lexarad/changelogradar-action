"""ChangelogRadar alerts: verified AI changelog changes for your stack, posted to Slack, Discord,
Microsoft Teams or your own webhook. Stdlib only, Python 3.9+.

Two users share this file:
- the GitHub Action (action.yml next to it): anyone runs it on a schedule in their own repo, with their
  own webhook secrets; it remembers what it already sent in a small state file (Actions cache);
- the hosted Pro run (.github/workflows/pro-alerts.yml in the ChangelogRadar repo): every merge that
  adds reviewed changes alerts each paying subscriber, and a weekly digest follows on Mondays.

Usage:
  changelogradar_alert.py instant --source URL|FILE (--state FILE | --previous FILE) [who] [--dry-run]
  changelogradar_alert.py digest  --source URL|FILE [--days 7] [--until YYYY-MM-DD] [who] [--dry-run]
  changelogradar_alert.py test    [who] [--dry-run]      # one "connected" message per channel
  changelogradar_alert.py check   [who]                  # validate the subscribers, send nothing
  who = --subscribers-env VAR or --subscribers-file FILE (a JSON list) or, for one subscriber,
        --products a,b --types breaking,deprecated plus the channel URLs in the environment:
        SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, TEAMS_WEBHOOK_URL, WEBHOOK_URL (+ WEBHOOK_SECRET).
Exit codes: 0 ok · 1 bad input · 2 a delivery failed (the others were still sent) · 3 refused (too many
new changes at once; nothing was sent).
Webhook URLs are secrets: this script never prints them, only their host.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import date, timedelta

SITE = "https://changelogradar.vercel.app/"
DEFAULT_SOURCE = SITE + "data/changes.json"
USER_AGENT = "ChangelogRadar-alert/1.0 (+https://changelogradar.vercel.app/pages/integrations.html)"
TYPES = ("breaking", "deprecated", "pricing", "new-capability")  # most urgent first
ACT_NOW = ("breaking", "deprecated")
LABEL = {"breaking": "Breaking", "deprecated": "Deprecated", "pricing": "Pricing", "new-capability": "New capability"}
KINDS = ("slack", "discord", "teams", "webhook")
ENV_CHANNELS = (("slack", "SLACK_WEBHOOK_URL"), ("discord", "DISCORD_WEBHOOK_URL"),
                ("teams", "TEAMS_WEBHOOK_URL"), ("webhook", "WEBHOOK_URL"))
# changes per message (Discord allows 10 embeds)
PER_MESSAGE = {"slack": 10, "discord": 10, "teams": 10}
DISCORD_EMBED_CHARS = 5500  # Discord refuses a message whose embeds pass 6000 characters in all
MAX_PER_RUN = 30        # changes per channel per run; the rest is one "and N more" line
MAX_SOURCE_BYTES = 5_000_000
SEEN_KEEP = 3000
RUN_BUDGET_SECONDS = 240  # a slow endpoint must not hold every later subscriber
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TEAMS_HOSTS = (".logic.azure.com", ".powerplatform.com")
REQUIRED = ("date", "product", "product_slug", "type", "title", "summary", "source_url")
MIN_SECRET = 16  # shorter HMAC secrets are guessable
RECENT_DAYS = 14  # instant alerts only consider changes listed this close to the newest one
# product slugs of data/sources.json (a test keeps them equal)
KNOWN_SLUGS = ("claude-platform", "claude-code", "openai-api", "cursor", "github-copilot", "gemini-api",
               "mistral-ai", "devin-desktop", "vs-code", "cohere")


class ConfigError(Exception):
    pass


def uid(c):
    """Same id as the Atom feeds of ChangelogRadar (build.py feed_entry_id): stable across builds."""
    key = f'{c["date"]}|{c["product_slug"]}|{c["title"]}'
    return "urn:changelogradar:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


# --- Reading the changes -------------------------------------------------------------------------

def _no_redirects():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # a webhook or source that redirects is refused, not followed
            return None
    return urllib.request.build_opener(NoRedirect)


def read_source(source):
    if source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with _no_redirects().open(req, timeout=30) as r:
            raw = r.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ConfigError("source is larger than 5 MB")
        text = raw.decode("utf-8")
    elif "://" in source:
        raise ConfigError("source must be an https:// URL or a local file")
    else:
        with open(source, encoding="utf-8") as f:
            text = f.read()
    return parse_changes(json.loads(text))


def parse_changes(data):
    if not isinstance(data, list):
        raise ConfigError("changes must be a JSON list")
    out = []
    for c in data:
        if not (isinstance(c, dict) and all(isinstance(c.get(k), str) and c.get(k) for k in REQUIRED) and c["type"] in TYPES):
            continue
        if not DAY.match(c["date"]) or ("listed" in c and not (isinstance(c["listed"], str) and DAY.match(c["listed"]))):
            continue  # a date is printed in messages: only plain YYYY-MM-DD gets that far
        out.append(c)
    return out


# --- Who gets what --------------------------------------------------------------------------------

def _plain(value, what):
    """No spaces, control characters or non-ASCII: they would break log masking or leak in error messages."""
    if any(ord(ch) <= 0x20 or ord(ch) >= 0x7f for ch in value):
        raise ConfigError(f"{what}: contains spaces, control or non-ASCII characters")
    return value


def _public_https(url, what):
    _plain(url, what)
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        raise ConfigError(f"{what}: not a URL")
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ConfigError(f"{what}: must be an https:// URL without credentials")
    host = u.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ConfigError(f"{what}: local hosts are not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return u
    if not ip.is_global:
        raise ConfigError(f"{what}: private or reserved addresses are not allowed")
    return u


def validate_url(kind, url):
    """Refuse anything that is not the expected kind of webhook, so a typo cannot post elsewhere."""
    u = _public_https(url, kind)
    host, path = u.hostname.lower(), u.path
    if kind == "slack" and not (host == "hooks.slack.com" and path.startswith(("/services/", "/triggers/"))):
        raise ConfigError("slack: expected https://hooks.slack.com/services/...")
    if kind == "discord" and not (host in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")
                                  and path.startswith("/api/webhooks/")):
        raise ConfigError("discord: expected https://discord.com/api/webhooks/...")
    if kind == "teams" and not host.endswith(TEAMS_HOSTS):
        raise ConfigError("teams: expected a Workflows webhook URL (*.logic.azure.com or *.powerplatform.com)")
    if kind == "webhook" and u.port not in (None, 443):
        raise ConfigError("webhook: only the standard https port (443) is allowed")
    return url


def resolves_public(url):
    """Every address the host resolves to must be public (catches 127.1, 2130706433, DNS names that
    point inside). Checked right before each post.
    Known limit: urllib resolves the name again when it connects, so a host that changes its DNS answer
    in between (DNS rebinding) could still reach an internal address. The risk is bounded: the request
    is a POST of public data on port 443 with TLS, redirects are refused and the response is never read
    or printed."""
    u = urllib.parse.urlsplit(url)
    infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    addrs = {info[4][0] for info in infos}
    if not addrs or not all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs):
        raise ValueError("webhook host resolves to a private or reserved address")


def host_of(url):
    return urllib.parse.urlsplit(url).hostname or "?"


def _csv(value):
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(x).strip() for x in value or [] if str(x).strip()]


def normalise_subscriber(s, where):
    if not isinstance(s, dict):
        raise ConfigError(f"{where}: must be an object")
    sid = str(s.get("id") or where)
    products = _csv(s.get("products") if "products" in s else "*")
    types = _csv(s.get("types") or ",".join(TYPES))
    instant = _csv(s.get("instant_types") or ",".join(ACT_NOW))
    if not products:
        raise ConfigError(f"{sid}: no product (use * for all of them)")
    for prod in products:
        if prod != "*" and prod not in KNOWN_SLUGS:
            raise ConfigError(f"{sid}: unknown product '{prod}' (valid: *, {', '.join(KNOWN_SLUGS)})")
    for t in types + instant:
        if t not in TYPES:
            raise ConfigError(f"{sid}: unknown type '{t}' (valid: {', '.join(TYPES)})")
    if not set(instant) & set(types):
        raise ConfigError(f"{sid}: instant_types must share at least one type with types")
    channels = []
    for i, ch in enumerate(s.get("channels") or []):
        if not isinstance(ch, dict) or ch.get("kind") not in KINDS or not isinstance(ch.get("url"), str):
            raise ConfigError(f"{sid}: channel {i + 1} needs kind ({'/'.join(KINDS)}) and url")
        secret = _plain(str(ch.get("secret") or ""), f"{sid}: secret")
        if secret and ch["kind"] != "webhook":
            raise ConfigError(f"{sid}: only a webhook channel takes a secret")
        if secret and len(secret) < MIN_SECRET:
            raise ConfigError(f"{sid}: the webhook secret needs at least {MIN_SECRET} characters")
        channels.append({"kind": ch["kind"], "url": validate_url(ch["kind"], ch["url"]), "secret": str(secret)})
    if not channels:
        raise ConfigError(f"{sid}: no channel")
    return {"id": sid, "products": set(products), "types": set(types), "instant_types": set(instant) & set(types),
            "channels": channels}


def subscribers_from_args(args):
    if args.subscribers_env or args.subscribers_file:
        where = args.subscribers_env or args.subscribers_file
        if args.subscribers_file:
            with open(args.subscribers_file, encoding="utf-8") as f:
                raw = f.read().strip()
        else:
            raw = os.environ.get(args.subscribers_env, "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ConfigError(f"{where} is not valid JSON")
        if not isinstance(data, list):
            raise ConfigError(f"{where} must be a JSON list")
        subs = [normalise_subscriber(s, f"subscriber {i + 1}") for i, s in enumerate(data)]
        if len({s["id"] for s in subs}) != len(subs):
            raise ConfigError("two subscribers share an id")
        return subs
    channels = []
    for kind, var in ENV_CHANNELS:
        url = os.environ.get(var, "").strip()
        if url:
            ch = {"kind": kind, "url": url}
            if kind == "webhook" and os.environ.get("WEBHOOK_SECRET"):
                ch["secret"] = os.environ["WEBHOOK_SECRET"]
            channels.append(ch)
    if not channels:
        raise ConfigError("no channel: set SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, TEAMS_WEBHOOK_URL or WEBHOOK_URL")
    types = args.types or "breaking,deprecated"
    return [normalise_subscriber({"id": "you", "products": args.products or "*", "types": types,
                                  "instant_types": types, "channels": channels}, "you")]


def wants(sub, c, types):
    return ("*" in sub["products"] or c["product_slug"] in sub["products"]) and c["type"] in types


def urgent_first(rows):
    rows = sorted(rows, key=lambda c: c["date"], reverse=True)
    return sorted(rows, key=lambda c: TYPES.index(c["type"]))


# --- Messages -------------------------------------------------------------------------------------

def _slack_escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _safe_link(url):
    """Vendor URLs go into link markup: keep only plain https URLs without markup characters."""
    return url if url.startswith("https://") and not any(ch in url for ch in "<>|() \n\"") else SITE


def _md_escape(text):
    """Discord renders Markdown: vendor text must not become a disguised link or formatting."""
    return re.sub(r"([\\`*_~\[\]()<>|#])", r"\\\1", text)


def _teams_text(text):
    """Teams TextBlocks render a small Markdown subset and show backslash escapes literally: break only
    the link syntax, so vendor text cannot hide a link."""
    return text.replace("](", "] (")


def _cut(text, n):
    return text if len(text) <= n else text[: n - 1] + "…"


def heading(kind_of_run, n):
    if kind_of_run == "digest":
        return f"ChangelogRadar weekly digest: {n} change{'s' if n != 1 else ''} for your stack"
    if kind_of_run == "test":
        return "ChangelogRadar is connected. Verified changes for your stack will arrive here."
    return f"ChangelogRadar: {n} new change{'s' if n != 1 else ''} for your stack"


def slack_payload(title, rows, more):
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{_slack_escape(title)}*", "verbatim": True}}]
    for c in rows:
        line = (f"*[{LABEL[c['type']]}] {_slack_escape(c['product'])}: {_slack_escape(_cut(c['title'], 200))}*\n"
                f"{_slack_escape(_cut(c['summary'], 600))}\n{c['date']} · <{_safe_link(c['source_url'])}|Official source>")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": line, "verbatim": True}})
    if more:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": more, "verbatim": True}]})
    return {"text": title, "blocks": blocks}


def discord_payload(title, rows, more):
    colours = {"breaking": 0xE5484D, "deprecated": 0xF5A524, "pricing": 0x3E9BFF, "new-capability": 0x30A46C}
    embeds = [{"title": _cut(f"[{LABEL[c['type']]}] {c['product']}: {c['title']}", 256),  # embed titles are plain text
               "description": _md_escape(_cut(c["summary"], 600)), "url": _safe_link(c["source_url"]),
               "color": colours[c["type"]], "footer": {"text": c["date"]}} for c in rows]
    content = _cut(title + (f"\n{more}" if more else ""), 2000)
    return {"content": content, "embeds": embeds, "allowed_mentions": {"parse": []}}  # no @everyone from vendor text


def teams_payload(title, rows, more):
    body = [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True}]
    for c in rows:
        body += [{"type": "TextBlock", "text": _teams_text(f"{LABEL[c['type']]} · {c['product']}: {_cut(c['title'], 200)}"),
                  "weight": "Bolder", "wrap": True, "spacing": "Medium"},
                 {"type": "TextBlock", "text": _teams_text(_cut(c["summary"], 600)), "wrap": True},
                 {"type": "TextBlock", "text": f"{c['date']} · [Official source]({_safe_link(c['source_url'])})",
                  "isSubtle": True, "wrap": True}]
    if more:
        body.append({"type": "TextBlock", "text": more, "isSubtle": True, "wrap": True})
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.2", "body": body}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                "contentUrl": None, "content": card}]}


def webhook_payload(kind_of_run, rows, more_count):
    keep = ("date", "product", "product_slug", "vendor", "type", "title", "summary", "source_url")
    return {"source": "changelogradar", "event": kind_of_run, "delivery": uuid.uuid4().hex, "more": more_count,
            "changes": [dict({k: c[k] for k in keep if k in c}, id=uid(c)) for c in rows]}


def _embed_size(c):
    e = discord_payload("", [c], "")["embeds"][0]
    return len(e["title"]) + len(e["description"]) + len(e["footer"]["text"])


def _chunks(kind, rows):
    """Groups of PER_MESSAGE changes; for Discord also at most DISCORD_EMBED_CHARS characters of embeds."""
    out, cur, used = [], [], 0
    for c in rows:
        size = _embed_size(c) if kind == "discord" else 0
        if cur and (len(cur) == PER_MESSAGE[kind] or used + size > DISCORD_EMBED_CHARS):
            out.append(cur)
            cur, used = [], 0
        cur.append(c)
        used += size
    return out + [cur] if cur else out


def messages(kind, kind_of_run, rows):
    """The payloads for one channel: changes split in messages (Discord's 6000-character embed total allows
    5 per message), capped at MAX_PER_RUN with an "and N more" line."""
    shown, extra = rows[:MAX_PER_RUN], len(rows) - min(len(rows), MAX_PER_RUN)
    more = f"And {extra} more on {SITE}" if extra else ""
    if kind == "webhook":
        return [webhook_payload(kind_of_run, shown, extra)]
    chunks = _chunks(kind, shown) or [[]]
    build = {"slack": slack_payload, "discord": discord_payload, "teams": teams_payload}[kind]
    out = []
    for i, chunk in enumerate(chunks):
        title = heading(kind_of_run, len(rows)) if i == 0 else f"ChangelogRadar (continued {i + 1}/{len(chunks)})"
        out.append(build(title, chunk, more if i == len(chunks) - 1 else ""))
    return out


# --- Delivery -------------------------------------------------------------------------------------

def post(channel, payload, opener=None):
    if opener is None:
        resolves_public(channel["url"])
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": USER_AGENT}
    if channel["kind"] == "webhook" and channel.get("secret"):
        ts = str(int(time.time()))
        sig = hmac.new(channel["secret"].encode("utf-8"), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers["X-ChangelogRadar-Timestamp"] = ts
        headers["X-ChangelogRadar-Signature"] = "sha256=" + sig
    req = urllib.request.Request(channel["url"], data=body, headers=headers, method="POST")
    with (opener or _no_redirects()).open(req, timeout=10) as r:
        if not 200 <= r.status < 300:
            raise urllib.error.HTTPError(channel["url"], r.status, "unexpected status", r.headers, None)


def transient(exc):
    """Worth another try: rate limits, server errors, timeouts and dropped connections."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError))


def channel_key(ch):
    """Names a channel in the state file without storing its URL."""
    return hashlib.sha256(f'{ch["kind"]}|{ch["url"]}'.encode("utf-8")).hexdigest()[:16]


def deliver(subs, rows_for, kind_of_run, dry_run, send=post, out=print, pause=time.sleep):
    """Send each channel of each subscriber its rows (rows_for(sub, channel)).
    Returns (sent, failed, ok: {channel key: True when every message of that channel went through})."""
    sent = failed = 0
    ok = {}
    started = time.monotonic()
    for sub in subs:
        total = 0
        for ch in sub["channels"]:
            key = channel_key(ch)
            rows = rows_for(sub, ch)
            ok[key] = True
            if not rows and kind_of_run != "test":
                continue
            total = max(total, len(rows))
            for n, payload in enumerate(messages(ch["kind"], kind_of_run, rows)):
                if dry_run:
                    out(f"--- {sub['id']} -> {ch['kind']} ({host_of(ch['url'])})")
                    out(json.dumps(payload, ensure_ascii=False, indent=1))
                    sent += 1
                    continue
                if time.monotonic() - started > RUN_BUDGET_SECONDS:
                    reason = "run out of time"
                else:
                    if n:
                        pause(1)  # several messages to one channel: stay under its rate limit
                    reason = None
                    for attempt in range(3):
                        try:
                            send(ch, payload)
                            reason = None
                            break
                        except Exception as exc:  # noqa: BLE001 - one bad endpoint must never stop the others
                            code = getattr(exc, "code", None)
                            reason = code if isinstance(code, int) else type(exc).__name__  # never the message: it can hold the URL
                            if not transient(exc) or attempt == 2:
                                break
                            pause(2 * (attempt + 1))
                if reason is None:
                    sent += 1
                    continue
                failed += 1
                ok[key] = False
                out(f"{sub['id']}: {ch['kind']} ({host_of(ch['url'])}) failed: {reason}")
                break  # the rest of this channel's messages would fail the same way
        out(f"{sub['id']}: {total} change(s) {'shown' if dry_run else 'sent'}, {len(sub['channels'])} channel(s)"
            if total or kind_of_run == "test" else f"{sub['id']}: nothing new")
    return sent, failed, ok


# --- State (GitHub Action): what each channel already got ------------------------------------------

def load_state(path):
    """{channel key: set of change ids}; {} when there is no usable state yet."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    channels = data.get("channels") if isinstance(data, dict) else None
    if not isinstance(channels, dict):
        return {}
    return {k: set(v) for k, v in channels.items() if isinstance(k, str) and isinstance(v, list)}


def save_state(path, state, current_order):
    keep = {k: [i for i in current_order if i in seen][:SEEN_KEEP] for k, seen in state.items()}
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"channels": keep, "saved": date.today().isoformat()}, f)
    os.replace(tmp, path)


# --- Commands -------------------------------------------------------------------------------------

def mask_for_actions(subs, out=print):
    """In GitHub Actions, mask every channel URL and secret, then stop workflow commands for the rest
    of the output (vendor text must never act as one). Returns the token that resumes them."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    for sub in subs:
        for ch in sub["channels"]:
            out(f"::add-mask::{ch['url']}")
            if ch.get("secret"):
                out(f"::add-mask::{ch['secret']}")
    token = uuid.uuid4().hex
    out(f"::stop-commands::{token}")
    return token


def run(argv, out=print, send=post, pause=time.sleep):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=("instant", "digest", "test", "check"))
    ap.add_argument("--source", default=DEFAULT_SOURCE)
    ap.add_argument("--state", help="instant: file that remembers what each channel already got (GitHub Action)")
    ap.add_argument("--previous", help="instant: the changes.json before this update (hosted run)")
    ap.add_argument("--first-run", choices=("latest", "quiet"), default="latest",
                    help="instant with --state, for a channel seen for the first time: send its 3 latest matching "
                         "changes, or nothing")
    ap.add_argument("--max-new", type=int, default=100,
                    help="instant: more new changes than this at once is treated as a fault (see the docstring)")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--until", help="digest: last day included, default yesterday (only completed days, so "
                    "consecutive weekly runs neither skip nor repeat a day)")
    ap.add_argument("--subscribers-env")
    ap.add_argument("--subscribers-file")
    ap.add_argument("--only", help="only the subscriber with this id (test a new customer without pinging the others)")
    ap.add_argument("--products")
    ap.add_argument("--types")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    try:
        subs = subscribers_from_args(args)
        if args.only:
            subs = [s for s in subs if s["id"] == args.only]
            if not subs:
                raise ConfigError(f"no subscriber with id '{args.only}'")
    except OSError as exc:
        out(f"error: could not read the subscribers ({type(exc).__name__})")
        return 1
    except ConfigError as exc:
        out(f"error: {exc}")
        return 1
    if not subs:
        out("No subscribers: nothing to do.")
        return 0
    token = mask_for_actions(subs, out)
    try:
        return _run(args, subs, out, send, pause)
    except ConfigError as exc:
        out(f"error: {exc}")
        return 1
    finally:
        if token:
            out(f"::{token}::")


def recent(changes):
    """Changes listed in the last RECENT_DAYS before the newest one. A typo fix in an old change gives it a
    new id, but its listed day stays old, so it is not alerted again."""
    newest = max(str(c.get("listed") or c["date"]) for c in changes)
    cutoff = (date.fromisoformat(newest) - timedelta(days=RECENT_DAYS)).isoformat()
    return [c for c in changes if str(c.get("listed") or c["date"]) >= cutoff]


def newest_first(rows):
    return sorted(rows, key=lambda c: (str(c.get("listed") or c["date"]), c["date"]), reverse=True)


def _run(args, subs, out, send, pause):
    if args.command == "check":
        for s in subs:
            out(f"{s['id']}: ok, {len(s['channels'])} channel(s): "
                + ", ".join(f"{c['kind']} ({host_of(c['url'])})" for c in s["channels"])
                + f"; products: {', '.join(sorted(s['products']))}")
        return 0
    if args.command == "test":
        _, failed, _ = deliver(subs, lambda s, ch: [], "test", args.dry_run, send, out, pause)
        return 2 if failed else 0

    try:
        changes = read_source(args.source)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise ConfigError(f"could not read the changes ({type(exc).__name__})")
    if not changes:
        raise ConfigError("the source has no changes: refusing to continue")

    if args.command == "digest":
        until = date.fromisoformat(args.until) if args.until else date.today() - timedelta(days=1)
        since = (until - timedelta(days=max(args.days, 1) - 1)).isoformat()
        # "listed" = the day the change appeared on ChangelogRadar, which can be days after the vendor's date
        window = [c for c in changes if since <= str(c.get("listed") or c["date"]) <= until.isoformat()]
        _, failed, _ = deliver(subs, lambda s, ch: urgent_first([c for c in window if wants(s, c, s["types"])]),
                               "digest", args.dry_run, send, out, pause)
        return 2 if failed else 0

    # instant
    if bool(args.state) == bool(args.previous):
        raise ConfigError("instant needs exactly one of --state or --previous")
    ids = [uid(c) for c in changes]
    candidates = recent(changes)

    if args.previous:
        try:
            before = {uid(c) for c in read_source(args.previous)}
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise ConfigError(f"could not read the previous changes ({type(exc).__name__})")
        if not before:
            raise ConfigError("the previous changes are empty: refusing to treat everything as new")
        new = [c for c in candidates if uid(c) not in before]
        if len(new) > args.max_new:
            out(f"refused: {len(new)} recent changes look new at once (limit {args.max_new}). Nothing was sent. "
                "Check the source; to send anyway, raise --max-new.")
            return 3
        _, failed, _ = deliver(subs, lambda s, ch: urgent_first([c for c in new if wants(s, c, s["instant_types"])]),
                               "instant", args.dry_run, send, out, pause)
        return 2 if failed else 0

    # --state: each channel keeps its own memory, so a dead channel never makes the healthy ones repeat
    state = load_state(args.state)

    def rows_for(s, ch):
        key = channel_key(ch)
        matching = [c for c in changes if wants(s, c, s["instant_types"])]
        if key not in state:
            out(f"{s['id']}: {ch['kind']} ({host_of(ch['url'])}) is new here: "
                + ("sending its 3 latest matching changes as a check." if args.first_run == "latest" else "sending nothing."))
            return urgent_first(newest_first(matching)[:3]) if args.first_run == "latest" else []
        rows = [c for c in candidates if uid(c) not in state[key] and wants(s, c, s["instant_types"])]
        if len(rows) > args.max_new:
            out(f"{s['id']}: {ch['kind']} ({host_of(ch['url'])}): {len(rows)} changes look new at once "
                f"(limit {args.max_new}); not sent, marked as seen. See {SITE}")
            return []
        return urgent_first(rows)

    _, failed, ok = deliver(subs, rows_for, "instant", args.dry_run, send, out, pause)
    if not args.dry_run:
        live = {channel_key(ch) for s in subs for ch in s["channels"]}
        updated = {k: v for k, v in state.items() if k in live}
        for key, delivered in ok.items():
            if delivered:
                updated[key] = set(ids)
        save_state(args.state, updated, ids)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
