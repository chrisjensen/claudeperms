// claude-perms bridge for opencode.
//
// opencode has no external command-hook mechanism (unlike Claude Code / Kimi),
// so this in-process plugin bridges tool calls to a SINGLE enforcement entry:
//   - ~/.claudeperms/permissions.mjs   (core allow/deny; digests any configured
//     chainedHooks — rewriters like rtk + gates like source-commit-enforce —
//     itself, so the bridge only spawns this one script)
// It is spawned with CLAUDE_PERMS_HARNESS=opencode so permissions.mjs selects
// its opencode adapter: it normalizes opencode's lowercase tool names + camelCase
// arg fields, collapses `ask` -> `deny` (opencode can only proceed or throw), and
// still emits `updatedInput` on allow so a chained rewrite (e.g. rtk) is applied.
//
// It also registers ONE session.idle handler that (a) rings CHIME — mirroring
// Claude Code's Notification/Stop `echo CHIME | nc localhost 9999` bell — and
// (b) injects a follow-up prompt so the agent auto-runs /plan-review (plan
// agent) or /quality-all (build agent).
//
// NOTE: opencode is not installed in this environment, so the SDK response shapes
// (client.session.get -> {agent, model}; event.properties) are handled defensively
// and must be confirmed on first real run — see the loop-guard caveat below.

import { execFile } from "node:child_process";

const HOME = process.env.HOME;
const PERMS = `${HOME}/.claudeperms/permissions.mjs`;

// Spawn a claude-perms script, feeding Claude/opencode-shaped JSON on stdin.
// Resolves { code, stdout, stderr }. Never rejects — a crashed hook must not
// crash the tool call; permissions.mjs itself fails safe (emits ask/deny).
function runHook(command, args, payload, cwd) {
  return new Promise((resolve) => {
    const child = execFile(
      command,
      args,
      {
        cwd,
        env: { ...process.env, CLAUDE_PERMS_HARNESS: "opencode" },
        timeout: 30_000,
        maxBuffer: 8 * 1024 * 1024,
      },
      (err, stdout, stderr) =>
        resolve({ code: err?.code ?? 0, stdout: stdout ?? "", stderr: stderr ?? "" }),
    );
    child.stdin.end(JSON.stringify(payload));
  });
}

// Ring the local sound daemon — mirrors Claude Code's Notification/Stop hook
// `echo CHIME | nc localhost 9999`. Fire-and-forget: never awaited, never
// throws, `-w1` so a dead listener can't hang the event loop.
function chime() {
  try {
    execFile("sh", ["-c", "echo CHIME | nc -w1 localhost 9999"], () => {});
  } catch {
    /* no listener / no nc — bell is best-effort */
  }
}

export const ClaudePerms = async ({ client, directory, worktree, $ }) => {
  const cwd = worktree || directory || process.cwd();
  // Sessions already auto-actioned this work cycle; cleared by a real user turn.
  const acted = new Set();
  // Per-session snapshot of `git status --porcelain` at the first genuine user
  // turn. The /quality-all nag fires only when the current changed-file list
  // differs from this baseline (i.e. THIS session actually touched the tree).
  const baselines = new Map();

  async function gitPorcelain() {
    try {
      return (await $`git -C ${cwd} status --porcelain`.quiet().nothrow().text()).trim();
    } catch {
      return "";
    }
  }

  return {
    "tool.execute.before": async (input, output) => {
      const payload = {
        tool_name: input.tool,
        tool_input: output.args ?? {},
        cwd,
      };

      // Core enforcement. permissions.mjs digests any configured chainedHooks
      // (rewriters + gates) itself, so this single spawn yields the final
      // verdict and any accumulated command rewrite.
      const perms = await runHook("node", [PERMS], payload, cwd);
      let decision;
      try {
        decision = JSON.parse(perms.stdout).hookSpecificOutput ?? {};
      } catch {
        throw new Error("claude-perms: unparseable hook output — blocking to fail safe.");
      }
      if (decision.permissionDecision !== "allow") {
        throw new Error(decision.permissionDecisionReason || "Blocked by claude-perms.");
      }
      // Apply a chained command rewrite (e.g. rtk), when present.
      const rewritten = decision.updatedInput?.command;
      if (rewritten && output.args) output.args.command = rewritten;
    },

    event: async ({ event }) => {
      // Re-arm the reminder when a genuine user turn starts (not our injection).
      // NOTE: the field distinguishing a user message from our synthetic inject
      // ('synthetic' below) is unverified against the opencode SDK — if wrong,
      // the loop guard fails open into a prompt loop. Confirm before relying on it.
      if (event.type === "message.updated") {
        const info = event.properties?.info;
        if (info?.role === "user" && !info?.synthetic) {
          acted.delete(info.sessionID);
          // Snapshot the tree once per session, at the first genuine user turn.
          if (!baselines.has(info.sessionID)) {
            baselines.set(info.sessionID, await gitPorcelain());
          }
        }
        return;
      }

      if (event.type !== "session.idle") return;
      chime(); // ring on every turn-end (mirrors Claude's Stop), before inject guard
      const id = event.properties?.sessionID;
      if (!id || acted.has(id)) return;

      let session;
      try {
        const res = await client.session.get({ path: { id } });
        session = res?.data ?? res;
      } catch {
        return;
      }
      const agent = session?.agent;
      const model = session?.model;
      if (!model?.id || !model?.providerID) return;
      const base = { providerID: model.providerID, modelID: model.id };

      let text;
      if (agent === "plan") {
        text =
          "Before finishing: run /plan-review on the plan you just produced and address any findings.";
      } else {
        const dirty = await gitPorcelain();
        if (!dirty) return; // clean tree -> no nag
        if (!baselines.has(id)) {
          // No baseline (plugin loaded mid-session): record now, err toward silence.
          baselines.set(id, dirty);
          return;
        }
        // No new changes this session vs. the first-user-turn snapshot -> no nag.
        if (dirty === baselines.get(id)) return;
        text =
          "If the implementation is complete, run /quality-all and fix anything it reports before stopping.";
      }

      acted.add(id); // set BEFORE inject so the resulting idle doesn't re-trigger
      try {
        await client.session.prompt({ path: { id }, body: { ...base, parts: [{ type: "text", text }] } });
      } catch {
        acted.delete(id); // inject failed — allow a later retry
      }
    },
  };
};
