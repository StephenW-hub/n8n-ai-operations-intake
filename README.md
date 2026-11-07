# n8n AI Operations Intake

An AI-powered operations intake automation built on [n8n](https://n8n.io).

> **Status:** in development. A live demo link and workflow exports will be added here.

## Try it

- **Live demo:** _coming soon_ (a public form/chat link — no n8n login needed)
- **Run it yourself:** import the workflow JSON from [`workflows/`](workflows/) into your own n8n instance
  (n8n → Workflows → Import from File), then connect your own credentials.

## How it's built

- **n8n Cloud** for hosting and execution
- **Claude Code** with the [n8n-mcp](https://github.com/czlonkowski/n8n-mcp) server for node lookup and validation
- **[n8n-skills](https://github.com/czlonkowski/n8n-skills)** (MIT) in `.claude/skills/`, which encode n8n best practices

Every workflow is validated before it's deployed.

## Security

- No credentials or API keys are stored in this repository. Exported workflows reference credentials by name only.
- The public demo uses limited-scope demo credentials with spending caps.
- Report a security issue by opening a GitHub issue (without sensitive details) or contacting the author.

## Author

Stephen Waiganjo — [GitHub](https://github.com/StephenW-hub)
