---
description: Audit the permissions you've already granted — in Claude Code's settings.json files and in ~/.claudeperms/ — for avenues a rogue or prompt-injected agent could exploit to escalate. The counterpart to /fewer-permission-prompts: that command opens the allowlist up to reduce prompts, this one finds the openings that went too far. Reports findings by severity and proposes tightenings; never edits config itself.
model: sonnet
effort: medium
---

**Starting assumption:** claude-perms is the gate. Its purpose is to remove friction by handling permission checks itself, not by forcing everything through native prompts. Avoid findings that would re-enable native prompts on tooling that claude-perms explicitly allows — that defeats its purpose. The hook runs after native prompts would fire, so `skipAutoPermissionPrompt`/`skipDangerousModePermissionPrompt`/`autoAllowBashIfSandboxed: true` are intentional, not security issues.

Read `~/.claudeperms/permissions.mjs` (or `hooks/permissions.mjs` in the claude-perms repo) first to understand how the gates interact — otherwise you'll false-positive on things already mitigated.

Then read these files if they exist (skip silently if not):

- `~/.claude/settings.json`, `~/.claude/settings.local.json`, `./.claude/settings.json`, `./.claude/settings.local.json`
- `~/.claudeperms/` config: `config.json`, `approved-domains.json`, `ask-before-read`, `ask-before-write`, `read-permitted-prefixes`, `write-permitted-prefixes`, `permitted-paths`, `read-only-commands`, `jq-pipeline-helpers`, `inline-exec-patterns`

Flag findings across five avenues, but **exclude** anything that would re-layer native prompts on claude-perms-allowed tooling:

1. **Arbitrary execution** — `permissions.allow` Bash rules that grant a shell or run code (interpreters, wrappers, lifecycle/build tools, broad VCS/container), `enableAllProjectMcpServers`, broad `WebFetch`/`WebSearch`
2. **Guardrails disabled** — `defaultMode: bypassPermissions`/`acceptEdits`, PreToolUse hook not wired to claude-perms, empty `inline-exec-patterns`, trash disabled. **Do not flag `skipAutoPermissionPrompt`/`skipDangerousModePermissionPrompt`/`autoAllowBashIfSandboxed`** — those bypass native prompts so claude-perms can be the gate.
3. **Self-modification** — write rules over `.claude/`/`.claudeperms`/`CLAUDE.md`, broad `additionalDirectories`, `ask-before-write` missing or negated
4. **Secret exfiltration** — read rules over credentials/shell histories, empty `ask-before-read`, `approved-domains.json` with pastebins or overly broad multi-tenant hosts
5. **Sandbox / path-gate escape** — exec-capable commands mislabelled in `read-only-commands`/`jq-pipeline-helpers`, over-broad `write-permitted-prefixes`/`permitted-paths`

Group by severity, state where/issue/fix, and ask which tightenings the user wants before changing anything. **Do not edit config.** This is a heuristic scan, not a proof of safety.
