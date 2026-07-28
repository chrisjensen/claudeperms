# claude-perms Operating Model

How permission decisions actually flow in Claude Code, what claude-perms can and
cannot control, and the config decisions that make it work as intended.

## TL;DR

claude-perms is **one of four AND-ed gates**. A tool call runs only if all four
agree. claude-perms (the PreToolUse hook) can **hard-deny** and **force a prompt**,
but its **allow is not final** — the harness re-checks writes and the sandbox can
still block. So eliminating prompt-flood is mostly a **sandbox config** job, not a
hook-logic job.

## The four gates (all must pass)

1. **Sandbox decision** (`Sv`) — is this bash command run sandboxed? Sandboxed bash
   is silently auto-allowed (`autoAllowBashIfSandboxed`). `dangerouslyDisableSandbox`
   drops this auto-allow and falls back to plain permission rules.
2. **Permission rules + mode** — allow/deny/ask rules, filtered by the active mode.
   Auto mode strips "dangerous" allow rules (see below).
3. **PreToolUse hook = claude-perms** — returns allow / ask / deny.
4. **Auto-mode server classifier** — only in auto mode; judges escalations.
   **Cannot approve `dangerouslyDisableSandbox`** (non-classifier-approvable).

## What claude-perms CAN do

- **Hard deny** — a hook `deny` is final. Nothing overrides it.
- **Force a prompt** — a hook `ask` is final (except sandboxed-bash auto-allow).
- **Allow (soft)** — defers to the harness's own write-safety re-check.

## What claude-perms CANNOT do

- **Make an out-of-sandbox write succeed by saying `allow`.** For Edit/Write, the
  harness runs its own write check (`Gj

) and a hook `allow` does NOT lift it. The
  write is permitted only if the path is in the **sandbox write allowlist**
  (`wX6` → `allowWrite`) or in the working dir under acceptEdits.
- **Grant sandbox filesystem or network access.** Those are sandbox config, not
  hook output. The hook can't reach past `--unshare-net` or the FS allowlist.

## The real levers (config, not hook logic)

| Lever | Effect | Where |
|---|---|---|
| `sandbox.filesystem.allowWrite` | **Primary.** Hard-allows Edit/Write to listed paths, mode-independent. Also enables sandboxed-bash writes there. | `settings.json` |
| `additionalDirectories` | Secondary. Adds to working dir. Hard-allows writes only in acceptEdits; otherwise leans on the classifier (weaker than allowWrite). | settings / `/add-dir` |
| `worktree.symlinkDirectories` | Symlinks deps into worktrees so agents don't write outside the sandbox. Needs the **subdir** path (e.g. `api/node_modules`), not repo root. | settings |
| Network (`--unshare-net`) | Host localhost (e.g. DB on 5432) is unreachable from sandboxed bash. Route DB work through a command head that's allowed, or accept the escalation. | sandbox |

## Two-harness adapter model (Claude Code + Kimi Code CLI)

The hook runs under both Claude Code and Kimi Code CLI (`kimicode`) from one
codebase. `detectHarness()` picks an adapter (`CLAUDE_PERMS_HARNESS` env var
first, else input-shape inference); `normalizeInput()` remaps Kimi tool names to
the internal vocabulary; `render()` emits the decision in the target dialect. The
four gates and all `check*` logic are shared and unaware of the harness.

Key semantic gap: **Kimi has no interactive `ask`.** A Kimi `PreToolUse` hook can
only allow or block. So under Kimi the three-way decision collapses to two —
every internal `ask` becomes a `deny` (fail-safe). Under Claude Code the same
case prompts. Kimi is also fail-*open* on hook error/timeout (Claude Code is
fail-safe → ask); that is Kimi's design and not overridable from the hook. See
README "Kimi Code CLI" for the tool-name map and install wiring.

## Why auto mode does not fix the flood

The dominant toil = `dangerouslyDisableSandbox` escalations (writes to sibling
worktrees + host-localhost DB). The classifier **cannot** approve those. So auto's
classifier never clears them — they prompt every time. Measured history confirmed
this (thousands of escalations, the classifier was not the relief valve).

**Mode is near-irrelevant once `allowWrite` is set.** allowWrite is hard-allow and
mode-independent. Pick mode for other reasons; it won't change the write outcome.

## Auto mode hard-denies settings.json self-modification

Editing `~/.claude/settings.json` (e.g. via the `/update-config` skill) does **not**
work in auto mode. claude-perms correctly returns `ask` on the write, but auto mode
never surfaces that as a prompt — it routes the `ask` to the server classifier, which
**hard-denies** it:

> Reason: Editing ~/.claude/settings.json is Self-Modification of agent startup
> config, which cannot be cleared by user intent.

`hard_deny` is not clearable by user intent, so `skipAutoPermissionPrompt` makes no
difference — there is no prompt to show. Verified end-to-end:

| Mode | `ask` path | Outcome on settings.json edit |
|---|---|---|
| `default` / `acceptEdits` | hook `ask` → **interactive prompt** | you approve → write succeeds |
| `auto` | hook `ask` → classifier → **hard_deny** | denied, no prompt |

(A benign non-config `.claude/*.md` write under auto mode is *allowed* by the
classifier — only agent-startup-config self-modification is hard-denied.)

### Operating guidance

- **Config edits** (anything touching `settings.json` / agent startup config): use
  the `/update-config` skill in **default** or **acceptEdits** mode (Shift+Tab). Auto
  mode will hard-deny it.
- **All other work**: stay in **auto** mode — the classifier finds a way to continue
  for normal repo writes, and only escalates/denies the genuinely sensitive cases.

## Decisions to make

1. **Worktree location — has a conflict, must resolve.** The native default is
   `<repo>/.claude/worktrees/`. That path is under the repo (so allowWrite covers
   it via the repo entry) **but** claude-perms' own `ask-before-write` blanket-gates
   **all** of `.claude/` (only `~/.claude/plans/` is carved out). So native
   worktree writes would be `ask`'d on every edit — re-creating the flood for
   subagents. Pick one:
   - **(a)** Add a `!.claude/worktrees/` carve-out to `ask-before-write` (worktrees
     hold working copies of repo code, not behavior-modifying config — reasonable to
     exempt), **and** ensure the repo allowWrite entry covers it. Or
   - **(b)** Point worktrees at a non-`.claude` dir that's in allowWrite (e.g.
     `<repo>/.worktrees/`), sidestepping the gate entirely.
2. **allowWrite list** — add the worktree root and any dep/cache dirs agents touch
   (e.g. `~/.cache/prisma` for prisma engines; client output goes to
   `node_modules/.prisma`). Verify which paths actually get written before adding.
3. **DB / network** — host localhost is blocked under sandbox. Route DB commands
   through an allowed wrapper, or accept those specific escalations.
4. **Keep the dangerous gate in claude-perms** — claude-perms should still `ask`
   on genuinely dangerous actions (destructive git, `.env`, secrets). allowWrite
   handling the routine writes is what removes the noise; the deny/ask logic stays.

## Verified

- **The hook fires for subagent tool calls.** Every tool call (main or subagent)
  routes through one permission pipeline: hooks run first, then canUseTool. Subagent
  spawn passes `canUseTool` + `toolUseContext` (which carries the hook config) into
  that same pipeline. Confirmed empirically too — the subagent edits *did* prompt,
  which only happens if claude-perms runs for them. (The classifier, by contrast,
  does NOT run for subagents — but allowWrite is what matters, not the classifier.)

## Open items to verify before trusting fully

- Exact prisma write paths (`~/.cache/prisma` engines vs `node_modules/.prisma`
  client) on this machine — confirm before adding to allowWrite.
- (The `.claude/worktrees/` vs `ask-before-write` conflict is resolved in
  Decision 1 above.)
