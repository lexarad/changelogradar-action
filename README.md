# ChangelogRadar alerts — GitHub Action

Verified breaking changes, deprecations and pricing changes from the official changelogs of Claude, OpenAI, Cursor, GitHub Copilot, Gemini, Mistral, Devin, VS Code and Cohere, posted to **Slack, Discord, Microsoft Teams or your own webhook**. Every change was read by a person at [ChangelogRadar](https://changelogradar.vercel.app/) and links to the vendor's official source.

Free. It runs in your repository with your own secrets; ChangelogRadar never sees your webhook.

## Use it

1. Create a webhook for your channel:
   - Slack: an [incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks) (`https://hooks.slack.com/services/...`).
   - Discord: channel settings → Integrations → Webhooks (`https://discord.com/api/webhooks/...`).
   - Microsoft Teams: the channel's **Workflows** → template **Send webhook alerts to a channel**, then copy the link ([Microsoft guide](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)).
2. Save it as a repository secret, for example `SLACK_WEBHOOK_URL`.
3. Add `.github/workflows/changelogradar.yml`:

```yaml
name: changelogradar
on:
  schedule:
    - cron: "23 7 * * *"   # once a day is enough: changes are published after review
  workflow_dispatch:
jobs:
  alerts:
    runs-on: ubuntu-latest
    steps:
      - uses: lexarad/changelogradar-action@v1
        with:
          products: claude-code,claude-platform,cursor
          types: breaking,deprecated
          slack-webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
```

The first run sends the 3 latest matching changes so you can see it works (`first-run: quiet` sends nothing). After that, only changes it has not sent before, listed in the last 14 days. Each channel keeps its own memory: if one fails, the next run tries it again and the others do not repeat. Rate limits and server errors are retried twice. Use the action once per job (the memory is keyed by workflow and job).

## Inputs

| Input | Default | What it does |
|---|---|---|
| `products` | `*` (all) | Product slugs (an unknown slug stops the run): `claude-code`, `claude-platform`, `openai-api`, `cursor`, `github-copilot`, `gemini-api`, `mistral-ai`, `devin-desktop`, `vs-code`, `cohere` |
| `types` | `breaking,deprecated` | Also `pricing`, `new-capability` |
| `slack-webhook` · `discord-webhook` · `teams-webhook` | | One or more channels |
| `webhook-url` · `webhook-secret` | | Your endpoint gets `{"source":"changelogradar","event":"instant","delivery":"<id>","changes":[...]}`; with a secret (16 characters or more), `X-ChangelogRadar-Signature: sha256=HMAC(secret, timestamp + "." + body)` and `X-ChangelogRadar-Timestamp`. Compare in constant time, reject timestamps older than 5 minutes and ignore a `delivery` you have already seen |
| `first-run` | `latest` | `quiet` to send nothing the first time |
| `max-new` | `100` | More new changes than this in one run is treated as a fault: they are marked as seen and not sent |
| `dry-run` | `false` | `true` prints the messages instead |

Webhook URLs must be `https` on the standard port. Slack, Discord and Teams URLs must be on their official hosts, and any other host must resolve to a public address. Redirects are refused, and URLs are masked in the logs.

## Want it without maintaining a workflow?

[ChangelogRadar Pro](https://changelogradar.vercel.app/pages/pricing.html) sends the same alerts within minutes of a change being verified, plus a weekly digest of your stack, for one person or a whole team.

ChangelogRadar is independent and not affiliated with any vendor it covers.
