#!/usr/bin/env bash
# Portions of this file are adapted from the n8n-io/skills plugin
# (https://github.com/n8n-io/skills), licensed under Apache License 2.0.
# Adapted for the community n8n-mcp MCP server. See /NOTICES.
#
# Fires before n8n_test_workflow. test_workflow runs real nodes (Code, HTTP, DB
# writes, Slack/email sends, sub-workflow calls), so it is also the closest
# "about to run it for real" signal we have. This server has no execute_workflow
# tool, so the error-handling reminder is surfaced here too.
exec "$(dirname "$0")/_emit.sh" "testing" \
"Before testing: invoke n8n-validation-expert (interpret what the run surfaces) and n8n-error-handling (are error branches wired? caller faults 4xx, your faults 5xx) via the Skill tool. n8n_test_workflow executes real nodes, Code, HTTP Request, database writes, Slack/email sends, and sub-workflow calls all fire for real. Ask the user before running if any node has user-visible side effects, and tell them which nodes ran live afterward."
