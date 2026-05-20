import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT_PATH = join(REPO_ROOT, 'hooks', 'check-malicious.mjs');

// Stub that replaces `claude`. Parses --system-prompt to extract the nonce,
// then behaves per STUB_BEHAVIOR env var:
//   emit-nonce         → outputs just the nonce  (PASS case)
//   emit-nonce-in-text → nonce embedded in prose (exact-match rejection)
//   emit-issues        → concern description, no nonce (FAIL case)
//   exit-nonzero       → exits 1 (invocation-error case)
const STUB_SCRIPT = `#!/usr/bin/env node
const args = process.argv.slice(2);
const spIdx = args.indexOf('--system-prompt');
const prompt = spIdx >= 0 ? args[spIdx + 1] : '';
const m = /SAFE-[0-9a-f]{32}/.exec(prompt);
const nonce = m ? m[0] : 'NO-NONCE-FOUND';
switch (process.env.STUB_BEHAVIOR ?? 'emit-nonce') {
  case 'emit-nonce':
    process.stdout.write(nonce + '\\n');
    break;
  case 'emit-nonce-in-text':
    process.stdout.write('Analysis complete. Safe signal: ' + nonce + '. Done.\\n');
    break;
  case 'emit-issues':
    process.stdout.write('Issues found: suspicious base64 blob may exfiltrate credentials.\\n');
    break;
  case 'exit-nonzero':
    process.stderr.write('claude: internal error\\n');
    process.exit(1);
}
`;

// Spawn check-malicious.mjs with a controlled stub binary.
// Returns { exitCode, stdout, stderr }.
async function runCheck(input, stubBehavior, extraEnv = {}) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'check-mal-test-'));
  try {
    // Write stub as a directly-executable file (shebang + 0o755).
    const stubPath = join(tmpDir, 'fake-claude');
    writeFileSync(stubPath, STUB_SCRIPT, { mode: 0o755 });

    const child = spawn(process.execPath, [SCRIPT_PATH], {
      env: {
        ...process.env,
        CHECK_MALICIOUS_CLAUDE_BIN: stubPath,
        STUB_BEHAVIOR: stubBehavior,
        ...extraEnv,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
    child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
    child.stdin.end(input ?? '');

    const exitCode = await new Promise((res, rej) => {
      child.on('error', rej);
      child.on('close', res);
    });

    return { exitCode, stdout, stderr };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

describe('check-malicious', () => {
  test('PASS when reviewer emits exactly the nonce', async () => {
    const { exitCode, stdout } = await runCheck('benign diff content', 'emit-nonce');
    assert.equal(exitCode, 0);
    assert.equal(stdout.trim(), 'PASS');
  });

  test('FAIL when reviewer embeds nonce in prose (exact-match required)', async () => {
    const { exitCode, stdout } = await runCheck('some diff', 'emit-nonce-in-text');
    assert.equal(exitCode, 1);
    assert.match(stdout, /^FAIL/);
  });

  test('FAIL when reviewer reports concerns without nonce', async () => {
    const { exitCode, stdout } = await runCheck('suspicious diff', 'emit-issues');
    assert.equal(exitCode, 1);
    assert.match(stdout, /^FAIL/);
    // Reviewer's concern text must not appear on stdout — only log path may.
    assert.doesNotMatch(stdout, /suspicious base64/);
  });

  test('FAIL writes reviewer output to log file', async () => {
    const { stdout } = await runCheck('suspicious diff', 'emit-issues');
    const logMatch = /Reviewer output: (.+)/.exec(stdout);
    assert.ok(logMatch, 'stdout should include log path');
    const logPath = logMatch[1].trim();
    assert.ok(existsSync(logPath), 'log file should exist');
    const logContent = readFileSync(logPath, 'utf8');
    assert.match(logContent, /suspicious base64/);
    rmSync(logPath, { force: true });
  });

  test('exit 2 on empty stdin', async () => {
    const { exitCode, stderr } = await runCheck('', 'emit-nonce');
    assert.equal(exitCode, 2);
    assert.match(stderr, /no input/i);
  });

  test('exit 3 when reviewer binary fails', async () => {
    const { exitCode, stderr } = await runCheck('some diff', 'exit-nonzero');
    assert.equal(exitCode, 3);
    assert.match(stderr, /reviewer invocation failed/i);
  });

  test('reviewer output never leaks to stdout on failure', async () => {
    const { stdout } = await runCheck('some diff', 'emit-issues');
    // stdout must only contain the FAIL line and log path — not reviewer prose
    const lines = stdout.trim().split('\n');
    assert.equal(lines.length, 2);
    assert.match(lines[0], /^FAIL$/);
    assert.match(lines[1], /^Reviewer output: /);
  });
});
