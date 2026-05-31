// Test helper: spawn the hook as a subprocess with a temp HOME, seed config
// files into <HOME>/.claudeperms/, write a JSON tool-call input to stdin,
// return the parsed decision from stdout.
//
// Each test gets its own HOME so the real ~/.claudeperms/ never leaks in. By
// default the helper copies <repo>/defaults/* into <HOME>/.claudeperms/ so the
// hook sees the same allowlists every user gets after `npm run setup`. Tests
// that want to assert the empty-defaults behaviour pass `seedDefaults: false`.
//
// `files` entries named "settings.json" go to <HOME>/.claude/ (Claude Code's
// own settings file — that's what isSandboxEnabled reads). Everything else
// goes to <HOME>/.claudeperms/.

import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, copyFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HOOK_PATH = join(REPO_ROOT, 'hooks', 'permissions.mjs');
const DEFAULTS_DIR = join(REPO_ROOT, 'defaults');

// Run the hook with a fresh temp HOME.
//
//   input         tool-call object sent to stdin
//   rawInput      verbatim string sent instead of stringifying input
//   files         { '<name>': '<contents>' } files seeded into the temp HOME.
//                 "settings.json" → <HOME>/.claude/; everything else → <HOME>/.claudeperms/.
//                 Overrides any defaults-seeded file of the same name.
//   seedDefaults  copy <repo>/defaults/* into <HOME>/.claudeperms/ first (default true)
//   env           extra env vars merged into the spawned hook's process.env
//                 (CLAUDE_PERMS_MODE is stripped from the default env so a host
//                 shell that sets it can't leak into default-mode tests).
//
// Returns { decision, reason, raw, home }.
export async function runHook({ input, rawInput, files = {}, seedDefaults = true, env = {} } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'claude-perms-test-'));
  try {
    const claudePermsDir = join(home, '.claudeperms');
    const claudeDir = join(home, '.claude');
    mkdirSync(claudePermsDir, { recursive: true });
    mkdirSync(claudeDir, { recursive: true });

    if (seedDefaults) {
      for (const name of readdirSync(DEFAULTS_DIR)) {
        const src = join(DEFAULTS_DIR, name);
        if (!statSync(src).isFile()) continue;
        copyFileSync(src, join(claudePermsDir, name));
      }
    }

    for (const [name, contents] of Object.entries(files)) {
      const targetDir = name === 'settings.json' ? claudeDir : claudePermsDir;
      writeFileSync(join(targetDir, name), contents);
    }

    const spawnEnv = { ...process.env, HOME: home };
    delete spawnEnv.CLAUDE_PERMS_MODE;
    Object.assign(spawnEnv, env);

    const child = spawn(process.execPath, [HOOK_PATH], {
      env: spawnEnv,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.on('data', (c) => stdoutChunks.push(c));
    child.stderr.on('data', (c) => stderrChunks.push(c));

    const payload = rawInput ?? JSON.stringify(input);
    child.stdin.end(payload);

    const exitCode = await new Promise((resolveExit, rejectExit) => {
      child.on('error', rejectExit);
      child.on('close', resolveExit);
    });

    const stdout = Buffer.concat(stdoutChunks).toString('utf8');
    const stderr = Buffer.concat(stderrChunks).toString('utf8');

    if (exitCode !== 0) {
      throw new Error(
        `Hook exited ${exitCode}.\nstdout: ${stdout}\nstderr: ${stderr}`
      );
    }

    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new Error(`Hook stdout was not valid JSON: ${stdout}`);
    }

    const hookOut = parsed.hookSpecificOutput ?? {};
    return {
      decision: hookOut.permissionDecision,
      reason: hookOut.permissionDecisionReason,
      raw: parsed,
      home,
    };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}
