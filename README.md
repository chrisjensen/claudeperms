# claude-perms

A `PreToolUse` hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that adds defense-in-depth checks on top of the built-in allow/deny lists. Every allowlist is a plain text or JSON file under `~/.claudeperms/` — the defaults ship in `defaults/` and you copy them into place during install.

`~/.claudeperms/` is intentionally separate from `~/.claude/` so Claude Code's own writes can't clobber your hook config.

## What it does

For each tool call, the hook emits `allow`, `ask`, or `deny`:

- **Bash**
  - Denies `rm`, `shred`, `unlink`, `truncate`, `cat /dev/null >`, and redirects that would truncate an existing file. Use `mv <file> .trash/` instead.
  - Asks before referencing sensitive files (`.env`, `id_rsa`, `~/.ssh/`, `~/.aws/credentials`, shell histories, etc.).
  - Asks before inline code execution (`node -e`, `python -c`, `ruby -e`, …) so reviewable script files are preferred.
  - Asks before `dd`, raw disk devices (`/dev/sd*`, `/dev/nvme*`), or `/proc/` reads.
  - Asks before writing to absolute paths outside `cwd`, `~/.claudeperms/permitted-paths`, or `~/.claudeperms/write-permitted-prefixes` (default: `/tmp/` and `~/src/`). Writing to `/usr/bin/ls` is gated.
  - Asks before reading absolute paths outside `cwd`, `permitted-paths`, or `~/.claudeperms/read-permitted-prefixes` (broad system roots like `/usr/`, `/etc/`).
  - Carve-outs: a long allowlist of read-only commands (`ls`, `git log`, `gh pr view`, `npm ls`, …) and pure `jq` pipelines bypass the path checks.
- **WebFetch** — asks unless the URL's host or prefix is in your approved list.
- **Read / Write / Edit / Glob / Grep** — sensitive-file ask using the same patterns as Bash, plus the read/write permitted-prefix split for absolute paths.

Unknown tools are not gated. Regex safety gates (`rm`, truncation, `dd`, `/proc`) are hardcoded in JS and not configurable.

## Install

1. Clone the repo:

   ```sh
   git clone <repo> ~/src/claude-perms
   ```

2. Deploy the hook + defaults into `~/.claudeperms/`:

   ```sh
   cd ~/src/claude-perms && npm run setup
   ```

   Always overwrites `~/.claudeperms/permissions.mjs` and `~/.claudeperms/check-malicious.mjs` (the code). Copies any missing config files from `defaults/`, but won't overwrite ones you've edited. Also runs `npm install` inside `~/.claudeperms/` to install the runtime dependency `anti-trojan-source` used by `check-malicious`.

3. **Merge** this partial into `~/.claude/settings.json` — do not replace the file, or you'll lose any other hooks/settings you have. `matcher: "*"` covers all tools; unknown tools short-circuit to `allow`.

   ```json
   {
     "hooks": {
       "PreToolUse": [{
         "matcher": "*",
         "hooks": [{
           "type": "command",
           "command": "node ~/.claudeperms/permissions.mjs"
         }]
       }]
     }
   }
   ```

4. Verify both an allow and a deny path:

   ```sh
   echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"'$(pwd)'"}' \
     | node ~/.claudeperms/permissions.mjs
   # expect: "permissionDecision":"allow"

   echo '{"tool_name":"Bash","tool_input":{"command":"rm foo"},"cwd":"/tmp"}' \
     | node ~/.claudeperms/permissions.mjs
   # expect: "permissionDecision":"deny"
   ```

## Customise

All config lives under `~/.claudeperms/`. Each file is one entry per line (`#` for comments, `~/` expands to `$HOME`); `approved-domains.json` is JSON. **If a file is missing the list is empty** — see the per-file effect below.

| File | Purpose | Empty / missing |
|---|---|---|
| `approved-domains.json` | WebFetch allowlist. `domains` matches host + subdomains; `urlPrefixes` matches URL prefix. | All WebFetch calls ask. |
| `ask-before-read` | Patterns whose Read triggers an ask. Shapes: bare basename (`.env`), glob (`*.pem`), dir prefix (`~/.ssh/`), absolute prefix (`/etc/secret/`), or relative path (`.claude/settings.json`). Takes precedence over `read-permitted-prefixes`. | Sensitive-read gate disabled; reads pass through path checks only. |
| `ask-before-write` | Same shape; gates Write/Edit tools and Bash write-targets. Takes precedence over `write-permitted-prefixes`. | Sensitive-write gate disabled. |
| `read-permitted-prefixes` | Absolute path prefixes permitted for **reads** in addition to `cwd` and `permitted-paths`. Default covers `/usr/`, `/bin/`, `/etc/`, `~/src/`, etc. | Reads outside cwd/permitted-paths ask. |
| `write-permitted-prefixes` | Absolute path prefixes permitted for **writes** in addition to `cwd` and `permitted-paths`. Intentionally narrow (default: `/tmp/`, `~/src/`). | Writes to any absolute path outside cwd/permitted-paths ask. |
| `read-only-commands` | Bash command prefixes carved out from the path gate when `dangerouslyDisableSandbox: true`. | Read-only carve-out disabled — sandbox-disabled commands still go through path checks. |
| `jq-pipeline-helpers` | Commands allowed inside a jq pipeline (the carve-out requires every segment to be in this list and at least one to be `jq`). | jq carve-out disabled. |
| `inline-exec-patterns` | Lines `<cmd> <flag1> [<flag2> ...]` that trigger the inline-exec ask. | **Inline-exec check disabled — `node -e`, `python -c`, etc. pass without asking.** Copy the default unless you've intentionally disabled this. |
| `permitted-paths` | Absolute paths the assistant may touch outside `cwd` (read + write). Not in defaults — user-specific. | No paths outside `cwd` or the permitted-prefixes are permitted. |

Notes:

- **Precedence.** `ask-before-*` is checked before the permitted-prefix gate. A file matching both lists always asks.
- **Sandbox toggle.** If `~/.claude/settings.json` has `"sandbox": {"enabled": true}`, the inline-exec ask is skipped (the sandbox confines blast radius). User-level Claude Code settings only — project/local overrides are intentionally ignored. This is the one path under `~/.claude/` the hook still reads.
- **Uninstall.** Remove the `PreToolUse` entry from `~/.claude/settings.json`. The clone itself does nothing without the hook wiring.
- **Debug.** Run Claude Code with `--debug` to see each decision's `permissionDecisionReason`.

## `check-malicious` — isolated injection-resistant code review

`npm run setup` also installs `~/.claudeperms/check-malicious.mjs`, a standalone CLI that asks Claude to review code/diffs for malicious content **without** the review itself becoming an injection vector.

```sh
git diff main...HEAD | ~/.claudeperms/check-malicious.mjs
# stdout: PASS                                          (exit 0) — safe
# stdout: FAIL\nReviewer output: /tmp/.../….log         (exit 1) — concerns
```

How it isolates:

- **Deterministic pre-check.** Before the LLM ever runs, input is scanned with [`anti-trojan-source`](https://github.com/lirantal/anti-trojan-source) for bidi overrides, zero-width characters, tag chars, and other confusables. Any hit short-circuits with `FAIL\nBidi characters present` (exit 1) — no LLM round-trip, and no way for a prompt-injected diff to talk the reviewer out of failing.
- Invokes `claude --bare --disable-slash-commands --setting-sources '' --strict-mcp-config --mcp-config '{}' --tools ''` so CLAUDE.md, settings, hooks, MCP servers, skills, and tools cannot influence the reviewer.
- The "safe" signal is a per-invocation random nonce (`SAFE-<32hex>`) embedded only in the system prompt. Diff content can't see it, so an injected diff can't forge the safe signal.
- Output is checked via exact-match on `trim()`: only a response that is *just* the nonce counts as safe. Anything else fails.
- Reviewer natural-language output is written to a log file under `$TMPDIR/claudeperms-checks/` — it never reaches stdout, so a successful content-channel injection can't cascade into the caller.

Exit codes: `0` safe · `1` concerns · `2` empty input · `3` reviewer invocation failed.

## Test

```sh
npm install
npm test
```

Runs the suite via `node --test test/*.test.mjs`. Each test spawns the hook with a fresh temp `HOME` and seeds it with `defaults/*`, so the real `~/.claudeperms/` is never read.

## License

See [LICENSE](./LICENSE).
