# n8n AI Operations Intake

This project builds n8n workflows with Claude Code.

## Tooling in this project

- **n8n-mcp MCP server** (configured in `.mcp.json`; needs a one-time `npm install -g n8n-mcp`): node docs, templates, and validation.
  It runs from the global install because `npx` startup is too slow for Claude Code's 30-second MCP timeout.
  It has 7 tools by default (`search_nodes`, `get_node`, `validate_node`, `validate_workflow`, `search_templates`, `get_template`, `tools_documentation`).
  The `n8n_*` management tools (create/update/test workflows on a live instance) turn on when you set the
  `N8N_API_URL` and `N8N_API_KEY` environment variables before you start Claude.
- **n8n-skills** (`.claude/skills/`, from github.com/czlonkowski/n8n-skills): 15 skills, with `using-n8n-mcp-skills` as the entry point.
- **Hooks** (`.claude/settings.json` → `.claude/hooks/`): load the entry-point skill at session start and add reminders before
  `get_node`, create/update/validate/test workflow calls. They need `jq` on PATH.

## How to build workflows

1. Follow the `using-n8n-mcp-skills` skill. It routes to the right specialist skill.
2. Look up nodes with `search_nodes` / `get_node` before you configure them. Don't guess parameters or typeVersions.
3. Validate each node (`validate_node`) and then the whole workflow (`validate_workflow`) before you deploy. Fix every error.
4. Prefer native nodes over Code nodes. Use correct `{{ $json... }}` expression syntax (see `n8n-expression-syntax`).

## Updating

- Skills: re-clone the n8n-skills repo and copy `skills/*` into `.claude/skills/` and `hooks/*` into `.claude/hooks/`.
- MCP server: `npm install -g n8n-mcp@latest`, then restart Claude Code.
