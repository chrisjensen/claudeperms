import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHook } from './_helpers.mjs';

describe('Dispatcher', () => {
  test('unknown tool returns allow', async () => {
    const r = await runHook({ input: { tool_name: 'SomeMcpTool', tool_input: {} } });
    assert.equal(r.decision, 'allow');
  });

  test('malformed stdin JSON fails safe with ask', async () => {
    const r = await runHook({ rawInput: 'not valid json' });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /failed to parse/i);
  });
});

describe('Bash: denials', () => {
  test('rm foo denies (deletion)', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'rm foo' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'deny');
    assert.match(r.reason, /Deletion is not allowed/);
  });

  test('truncating redirect on existing file denies', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cp-trunc-'));
    const target = join(dir, 'marker');
    writeFileSync(target, '');
    try {
      const r = await runHook({
        input: { tool_name: 'Bash', tool_input: { command: `: > ${target}` }, cwd: dir },
      });
      assert.equal(r.decision, 'deny');
      assert.match(r.reason, /truncate/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('truncating redirect on nonexistent file does not deny', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: ': > /tmp/cp-no-such-file-xyz-12345' },
        cwd: '/tmp',
      },
    });
    assert.notEqual(r.decision, 'deny');
  });
});

describe('Bash: sensitive references', () => {
  test('reading .env asks (read intent)', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat .env' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /sensitive file/);
    assert.match(r.reason, /read/);
  });

  test('writing > .env asks (write intent)', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'echo x > .env' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /write/);
  });
});

describe('Bash: inline-exec', () => {
  test('node -e asks without sandbox', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'node -e "1+1"' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /inline code execution/i);
  });

  test('sandbox.enabled bypasses the inline-exec ask', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'node -e "1+1"' }, cwd: '/tmp' },
      files: { 'settings.json': JSON.stringify({ sandbox: { enabled: true } }) },
    });
    assert.equal(r.decision, 'allow');
  });
});

describe('Bash: disk and kernel', () => {
  test('dd asks', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'dd if=/dev/zero of=/tmp/x' },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /disk access/i);
  });

  test('reading /proc asks', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat /proc/cpuinfo' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /\/proc/);
  });
});

describe('Bash: path checks', () => {
  test('../../ escape to non-system area asks', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'cat ../../home/other/secret' },
        cwd: '/tmp/foo',
      },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /escapes permitted areas|outside permitted/i);
  });

  test('absolute path outside permitted asks', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat /home/other/file' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /outside permitted/i);
  });

  test('absolute path inside ~/.claudeperms/permitted-paths allows', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat /home/other/file' }, cwd: '/tmp' },
      files: { 'permitted-paths': '/home/other\n' },
    });
    assert.equal(r.decision, 'allow');
  });
});

describe('Bash: allow and carve-outs', () => {
  test('ls allows', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'allow');
  });

  test('jq pipeline allows (carve-out)', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'cat data.json | jq .' },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'allow');
    assert.match(r.reason, /jq/);
  });

  test('git log allows under read-only carve-out (sandbox disabled)', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'git log --oneline', dangerouslyDisableSandbox: true },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'allow');
    assert.match(r.reason, /Read-only command/);
  });

  test('gh api (GET) gets the read-only carve-out via its own predicate', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'gh api repos/owner/repo', dangerouslyDisableSandbox: true },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'allow');
    assert.match(r.reason, /Read-only command/);
  });

  test('gh api -X POST does not get the read-only carve-out', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: {
          command: 'gh api -X POST repos/owner/repo',
          dangerouslyDisableSandbox: true,
        },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'allow');
    assert.doesNotMatch(r.reason, /Read-only command/);
  });
});

describe('WebFetch', () => {
  test('default-approved domain allows (no user file)', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://docs.anthropic.com/x' } },
    });
    assert.equal(r.decision, 'allow');
  });

  test('default-approved URL prefix allows (no user file)', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://github.com/anthropics/foo' } },
    });
    assert.equal(r.decision, 'allow');
  });

  test('unknown URL asks', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://example.invalid/x' } },
    });
    assert.equal(r.decision, 'ask');
  });

  test('user file with only `domains` replaces defaults entirely (no per-key merge)', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://github.com/anthropics/foo' } },
      files: { 'approved-domains.json': JSON.stringify({ domains: ['nodejs.org'] }) },
    });
    // urlPrefixes from the bundled default are NOT merged in. The user file is the source of truth.
    assert.equal(r.decision, 'ask');
  });

  test('malformed approved-domains.json yields empty lists (asks even for a default host)', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://docs.anthropic.com/x' } },
      files: { 'approved-domains.json': '{not json' },
    });
    assert.equal(r.decision, 'ask');
  });
});

describe('File tools', () => {
  test('Read .env (relative) asks', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '.env' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
  });

  test('Read of an unrelated file allows', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: 'normal.txt' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'allow');
  });

  test('Read absolute path outside cwd and permitted asks', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '/home/other/file' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
  });

  test('Read absolute path inside permitted-paths allows', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '/home/other/file' }, cwd: '/tmp' },
      files: { 'permitted-paths': '/home/other\n' },
    });
    assert.equal(r.decision, 'allow');
  });
});

describe('Glob / Grep', () => {
  test('Grep with a sensitive basename in pattern asks', async () => {
    const r = await runHook({
      input: { tool_name: 'Grep', tool_input: { pattern: '.env' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
  });

  test('Glob inside cwd allows', async () => {
    const r = await runHook({
      input: { tool_name: 'Glob', tool_input: { glob: '*.txt' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'allow');
  });
});

describe('Pattern matcher shapes', () => {
  test('bare basename matches with suffix (.env → .env.local)', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat .env.local' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
  });

  test('glob (*.pem) matches', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'cat foo.pem' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
  });

  test('directory prefix (~/.ssh/) matches files inside', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '~/.ssh/id_rsa' } },
    });
    assert.equal(r.decision, 'ask');
  });

  test('relative path-with-segments (.claude/settings.json) matches by suffix', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Write',
        tool_input: { file_path: '/tmp/foo/.claude/settings.json' },
        cwd: '/tmp/foo',
      },
    });
    assert.equal(r.decision, 'ask');
  });
});

describe('System-binary write gap (write-permitted-prefixes is /tmp/ only)', () => {
  test('Write tool to /usr/bin/ls asks (not in write-permitted-prefixes)', async () => {
    const r = await runHook({
      input: { tool_name: 'Write', tool_input: { file_path: '/usr/bin/ls' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /outside permitted paths/i);
  });

  test('Bash redirect to /usr/bin/ls asks', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'echo x > /usr/bin/ls' },
        cwd: '/tmp',
      },
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /outside permitted paths/i);
  });

  test('Read tool from /usr/bin/ls allows (read-permitted-prefixes covers /usr/)', async () => {
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '/usr/bin/ls' }, cwd: '/tmp' },
    });
    assert.equal(r.decision, 'allow');
  });
});

describe('Empty defaults (seedDefaults: false)', () => {
  test('WebFetch to docs.anthropic.com asks (no approved-domains.json)', async () => {
    const r = await runHook({
      input: { tool_name: 'WebFetch', tool_input: { url: 'https://docs.anthropic.com/x' } },
      seedDefaults: false,
    });
    assert.equal(r.decision, 'ask');
  });

  test('node -e allows when inline-exec-patterns is missing (documented trade-off)', async () => {
    const r = await runHook({
      input: { tool_name: 'Bash', tool_input: { command: 'node -e "1+1"' }, cwd: '/tmp' },
      seedDefaults: false,
    });
    assert.equal(r.decision, 'allow');
  });

  test('Read /etc/hosts asks when read-permitted-prefixes is missing', async () => {
    // Bash absolute-path check only asks for /Users/ or /home/ paths, so /etc/hosts
    // via Bash would allow regardless. File-tool path-area gate is the meaningful
    // test for the permitted-prefix list.
    const r = await runHook({
      input: { tool_name: 'Read', tool_input: { file_path: '/etc/hosts' }, cwd: '/tmp' },
      seedDefaults: false,
    });
    assert.equal(r.decision, 'ask');
    assert.match(r.reason, /outside permitted paths/i);
  });

  test('git log is NOT carved out as read-only when read-only-commands is missing', async () => {
    const r = await runHook({
      input: {
        tool_name: 'Bash',
        tool_input: { command: 'git log --oneline', dangerouslyDisableSandbox: true },
        cwd: '/tmp',
      },
      seedDefaults: false,
    });
    // Still allows (no path concerns) but the reason should NOT be the carve-out.
    assert.equal(r.decision, 'allow');
    assert.doesNotMatch(r.reason, /Read-only command/);
  });
});
