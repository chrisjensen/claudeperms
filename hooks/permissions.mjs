// Claude Code PreToolUse permission hook.
//
// Reads {tool_name, tool_input, cwd} as JSON on stdin, writes a single
// {hookSpecificOutput: {permissionDecision: allow|ask|deny, ...}} on stdout.
//
// All allowlists/configs live under ~/.claudeperms/ — a separate dotdir so
// Claude Code's own writes to ~/.claude/ can't clobber them. If a list file
// is missing the list is empty (no in-JS fallbacks). Defaults ship in
// <repo>/defaults/ — the install step copies them to ~/.claudeperms/.
// Exception: ~/.claude/settings.json is Claude Code's file; isSandboxEnabled
// reads sandbox.enabled from it.
//
// Layout (top-down):
//   1. Imports + constants
//   2. main() and the per-tool dispatcher
//   3. Research mode: env-var-gated tighter posture for web crawling
//   4. Bash: checkBashCommand + all of its helpers
//   5. WebFetch: checkWebFetch + approved-domains loader
//   6. File tools: checkFileToolAccess, checkGlobOrGrep
//   7. Shared utilities: decisions, path/sensitive-file matching, config loaders

import { readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { homedir, tmpdir } from 'os';
import { execFileSync } from 'child_process';

// === Constants ========================================================
//
// Regex-based safety gates only. Allowlists are loaded from ~/.claudeperms/ at
// invocation time — see Shared utilities for the loaders.

const DELETION_PATTERNS = [
  /\brm\b/,
  /\bshred\b/,
  /\bunlink\b/,
  /cat\s+\/dev\/null\s*>/,
  /\btruncate\b/,
];

const TRUNCATION_REDIRECT_PATTERNS = [
  /(?:^|;|\||\|\||\&\&)\s*(?::|true|printf\s+''?)\s*>\s*(\S+)/,
  /(?:^|[;&|])\s*>(?!>)\s*(\S+)/,
];

const DD_PATTERNS = [/\bdd\b/];
const RAW_DISK_PATTERNS = [/\/dev\/(?:sd|hd|nvme|disk)/];
const PROC_PATTERNS = [/\/proc\//];

// === main() and tool dispatcher =======================================

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    emit(ask('Hook error: failed to parse input JSON. Failing safe.'), detectHarness(null));
    return;
  }

  const harness = detectHarness(input);
  let result;
  try {
    const normalized = normalizeInput(input, harness);
    result = dispatch(normalized);
    result = maybeAttachRtkRewrite(result, normalized, harness);
  } catch (err) {
    result = ask(`Hook error: ${err.message}. Failing safe.`);
  }

  emit(result, harness);
}

// Internal watchdog budget. Sits just under Kimi's hook timeout (default 30s)
// so we self-terminate with a well-formed deny/ask BEFORE Kimi's fail-OPEN
// fires — while leaving enough headroom below 30s to render and flush. Set high
// (not aggressively low) on purpose: compute is sub-second, so the only thing
// this catches is a stuck stdin, and a tight budget would risk a false deny on
// a merely-slow payload. 25s = 5s margin under Kimi's 30s. Well under Claude
// Code's 60s default too (and Claude fails safe regardless).
const WATCHDOG_MS = Number(process.env.CLAUDE_PERMS_WATCHDOG_MS) || 25000;

// Guards against a double-emit when the watchdog or a crash handler races the
// normal path. First writer wins; process.exit() below makes it terminal.
let settled = false;

function emit(result, harness) {
  if (settled) return;
  settled = true;
  const { stdout, stderr, exitCode } = render(result, harness);
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  process.exit(exitCode);
}

// Fail safe on any crash/timeout: emit a well-formed decision instead of
// letting Node exit non-zero (which Kimi treats as ALLOW) or hang (Kimi
// fail-open at timeout). Uses ask(): the adapter renders this as a hard deny
// under Kimi and an interactive prompt under Claude Code — both fail-safe.
function failSafe(reason) {
  emit(ask(`Hook error: ${reason}. Failing safe.`), detectHarness(null));
}

// === Harness adapters =================================================
//
// The decision core (dispatch + all check* functions) speaks Claude Code's
// vocabulary: tool_name in {Bash, WebFetch, Read, Write, Edit, Glob, Grep} and
// a three-way decision {allow, ask, deny} encoded in stdout with exit 0.
//
// Kimi Code CLI (kimicode) differs on both ends:
//   - Input tool names: Shell, ReadFile/ReadMediaFile, WriteFile,
//     StrReplaceFile, FetchURL, SearchWeb (tool_input field names — command,
//     file_path, url — already match Claude's).
//   - Output: a PreToolUse hook can only allow (exit 0) or block; there is no
//     interactive `ask`. A structured deny is `hookSpecificOutput
//     .permissionDecision:"deny"` on exit 0, with the reason fed to the model.
//
// We therefore select an adapter at runtime, remap the input tool name to the
// internal vocabulary, run the unchanged core, then render the decision in the
// target harness's dialect. Per project decision, kimi collapses `ask` -> deny
// (fail-safe) since it cannot prompt.

const HARNESS = { claude: 'claude', kimi: 'kimi' };

const KIMI_TOOL_NAMES = new Map([
  ['Shell', 'Bash'],
  ['ReadFile', 'Read'],
  ['ReadMediaFile', 'Read'],
  ['WriteFile', 'Write'],
  ['StrReplaceFile', 'Edit'],
  ['FetchURL', 'WebFetch'],
]);

function detectHarness(input) {
  const env = process.env.CLAUDE_PERMS_HARNESS;
  if (env === 'kimi' || env === 'kimicode') return HARNESS.kimi;
  if (env === 'claude' || env === 'claude-code') return HARNESS.claude;
  if (input && typeof input === 'object') {
    if ('transcript_path' in input) return HARNESS.claude;
    if ('tool_call_id' in input) return HARNESS.kimi;
  }
  return HARNESS.claude;
}

function normalizeInput(input, harness) {
  if (harness !== HARNESS.kimi) return input;
  const mapped = KIMI_TOOL_NAMES.get(input?.tool_name);
  if (!mapped) return input; // unknown kimi tool -> dispatch's allow() default
  return { ...input, tool_name: mapped };
}

function render(result, harness) {
  const out = result.hookSpecificOutput ?? {};
  const dec = out.permissionDecision;
  const reason = out.permissionDecisionReason ?? '';

  if (harness !== HARNESS.kimi) {
    // Claude Code: decision lives entirely in stdout JSON; always exit 0.
    return { stdout: JSON.stringify(result) + '\n', stderr: '', exitCode: 0 };
  }

  if (dec === 'allow') {
    return { stdout: '', stderr: '', exitCode: 0 };
  }
  const kimiReason = dec === 'ask'
    ? `[approval required] ${reason} — this harness cannot prompt interactively; blocking. Ask the user, then retry.`
    : reason;
  const body = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: kimiReason,
    },
  };
  return { stdout: JSON.stringify(body) + '\n', stderr: '', exitCode: 0 };
}

function dispatch(input) {
  if (isResearchMode()) return dispatchResearchMode(input);

  const { tool_name, tool_input, cwd } = input;

  if (tool_name === 'Bash') {
    const command = tool_input?.command ?? '';
    const sandboxDisabled = tool_input?.dangerouslyDisableSandbox === true;
    return checkBashCommand(command, cwd, { sandboxDisabled });
  }
  if (tool_name === 'WebFetch') {
    return checkWebFetch(tool_input?.url ?? '');
  }
  if (tool_name === 'Read' || tool_name === 'Write' || tool_name === 'Edit') {
    return checkFileToolAccess(tool_name, tool_input, cwd);
  }
  if (tool_name === 'Glob' || tool_name === 'Grep') {
    return checkGlobOrGrep(tool_name, tool_input, cwd);
  }
  return allow(`Tool ${tool_name} is not subject to permission checks.`);
}

// === Research mode ====================================================
//
// Activated by CLAUDE_PERMS_MODE=research in the shell that launches `claude`.
// The PreToolUse hook process inherits that env var. A hook `deny` overrides
// any `settings.json` `allow` rule (including bypassPermissions), so this
// short-circuit is sufficient — no settings.json coordination needed.
//
// Threat model: prompt injection in fetched pages talking the assistant into
// running a shell command or calling a mutating MCP tool. Mitigations:
//   - Hard-deny Bash except a narrow set of read-only filesystem commands
//     (ls, find without -exec/-execdir/-delete, grep, rg). Pipes are allowed
//     only if every segment is also from that safe set or a read-only
//     transformer (sort, uniq, wc, head, tail, cut). Command substitution
//     and redirects are always denied.
//   - Hard-deny every mcp__* tool.
//   - Agent is allowed: subagent tool calls still go through this hook, so
//     Bash/MCP remain blocked inside subagents. Agent itself executes no code.
//   - Restrict writes to cwd or $TMPDIR/`/tmp/` only — ignore the
//     permitted-paths and write-permitted-prefixes lists (so injected content
//     can't reach ~/src/ or other normally-writable areas).
//   - Allow WebFetch unconditionally (the whole point of research mode is
//     wide crawling; per-domain asks defeat that).
//   - Keep the existing read gate as-is (ask-before-read still applies).
//
// Every decision reason is prefixed `[research mode] ` so it's visible in
// `claude --debug` and in interactive prompts.

const RESEARCH_REASON_PREFIX = '[research mode] ';

function isResearchMode() {
  return process.env.CLAUDE_PERMS_MODE === 'research';
}

// Commands allowed as the root of a research-mode Bash call.
const RESEARCH_ROOT_COMMANDS = new Set(['ls', 'find', 'grep', 'egrep', 'fgrep', 'rg', 'head', 'tail']);
// Commands allowed anywhere in a pipeline (root commands + read-only transformers).
const RESEARCH_PIPELINE_COMMANDS = new Set([
  ...RESEARCH_ROOT_COMMANDS,
  'sort', 'uniq', 'wc', 'head', 'tail', 'cut',
]);

// Returns true iff the command is safe to run in research mode:
//   - No command substitution ($(...) or backticks)
//   - No redirects (> or <)
//   - Root command is in RESEARCH_ROOT_COMMANDS
//   - find may not use -exec, -execdir, or -delete
//   - Every pipe segment's leading command is in RESEARCH_PIPELINE_COMMANDS
function isResearchSafeBashCommand(command) {
  if (!command) return false;
  if (/\$\(|`/.test(command)) return false;       // command substitution
  if (/[<>]/.test(command)) return false;          // redirects

  const segments = command.split('|');
  const rootCmd = stripRtkWrapper(segments[0].trim()).split(/\s+/)[0];

  if (!RESEARCH_ROOT_COMMANDS.has(rootCmd)) return false;

  if (rootCmd === 'find' && /-(exec|execdir|delete)\b/.test(segments[0])) return false;

  for (let i = 1; i < segments.length; i++) {
    const segCmd = stripRtkWrapper(segments[i].trim()).split(/\s+/)[0];
    if (!RESEARCH_PIPELINE_COMMANDS.has(segCmd)) return false;
  }

  return true;
}

function dispatchResearchMode(input) {
  const { tool_name, tool_input, cwd } = input;

  if (tool_name === 'Bash') {
    const cmd = stripRtkWrapper(tool_input?.command ?? '');
    if (isResearchSafeBashCommand(cmd)) {
      return researchAllow(`read-only filesystem command allowed in research mode: ${cmd.split(/\s+/)[0]}`);
    }
    return researchDeny(
      'Bash is restricted in research mode. Only ls, find (no -exec/-execdir/-delete), ' +
      'grep, rg, and pipelines between those commands (plus sort/uniq/wc/head/tail/cut) are allowed. ' +
      'No command substitution or redirects.'
    );
  }

  if (tool_name.startsWith('mcp__')) {
    return researchDeny(
      `Execution-class tool (${tool_name}) is disabled in research mode. ` +
        'Restart without CLAUDE_PERMS_MODE=research to use it.'
    );
  }

  if (tool_name === 'WebFetch') {
    return researchAllow('WebFetch is unconditional in research mode (domain allowlist skipped).');
  }

  if (tool_name === 'Write' || tool_name === 'Edit' || tool_name === 'NotebookEdit') {
    return checkResearchWrite(tool_name, tool_input, cwd);
  }

  if (tool_name === 'Read' || tool_name === 'Glob' || tool_name === 'Grep') {
    const inner = tool_name === 'Read'
      ? checkFileToolAccess(tool_name, tool_input, cwd)
      : checkGlobOrGrep(tool_name, tool_input, cwd);
    return prefixResearchReason(inner);
  }

  return researchAllow(`Tool ${tool_name} permitted in research mode (local state only).`);
}

// Research-mode write gate: target must resolve under cwd or $TMPDIR/`/tmp/`.
// Sensitive-write list still applies (it returns ask, not allow, so it
// tightens — never loosens — the research posture).
function checkResearchWrite(toolName, toolInput, cwd) {
  const filePath = toolInput?.file_path ?? '';
  if (!filePath) {
    return researchDeny(`${toolName} called without a file_path in research mode.`);
  }
  const absPath = toAbs(filePath, cwd);

  if (isSensitiveFile(absPath, 'write')) {
    return researchAsk(
      `${toolName} targets a sensitive file: ${absPath}. Approve only if intentional.`
    );
  }

  if (!isResearchWritableTarget(absPath, cwd)) {
    return researchDeny(
      `${toolName} target outside research-mode write scope (cwd or $TMPDIR): ${absPath}.`
    );
  }

  return researchAllow(`${toolName} target is inside research-mode write scope.`);
}

function isResearchWritableTarget(absPath, cwd) {
  if (cwd && (absPath === cwd || absPath.startsWith(cwd + '/'))) return true;
  const tmp = tmpdir().replace(/\/+$/, '');
  if (absPath === tmp || absPath.startsWith(tmp + '/')) return true;
  // Cover /tmp/ explicitly in case $TMPDIR points elsewhere (macOS, sandboxes).
  if (absPath === '/tmp' || absPath.startsWith('/tmp/')) return true;
  return false;
}

function researchAllow(reason) { return decision('allow', RESEARCH_REASON_PREFIX + reason); }
function researchDeny(reason)  { return decision('deny',  RESEARCH_REASON_PREFIX + reason); }
function researchAsk(reason)   { return decision('ask',   RESEARCH_REASON_PREFIX + reason); }

// Re-wrap a decision produced by the shared (non-research) checkers so its
// reason carries the research prefix, without re-deriving the verdict.
function prefixResearchReason(d) {
  const inner = d?.hookSpecificOutput ?? {};
  return decision(
    inner.permissionDecision,
    RESEARCH_REASON_PREFIX + (inner.permissionDecisionReason ?? '')
  );
}

// === Bash =============================================================

function checkBashCommand(command, cwd, opts = {}) {
  // 1. Deletion commands — gated by trash config.
  const delResult = checkDeletion(command, cwd);
  if (delResult) return delResult;

  // 2. Truncation redirects — deny only if target file exists
  const truncResult = checkTruncationRedirects(command, cwd);
  if (truncResult) return truncResult;

  // 3. Sensitive file references (read/write split based on inferred intent)
  const sensitiveHit = commandTouchesSensitive(command, cwd);
  if (sensitiveHit) {
    return ask(
      `Command would ${sensitiveHit.intent} a sensitive file: ${sensitiveHit.path}. ` +
        `Approve only if intentional.`
    );
  }

  // 4. Inline arbitrary-code execution — require script file instead.
  // Skipped when the user-level sandbox is enabled: the sandbox confines
  // network/filesystem access, so reviewability becomes a soft concern.
  // Also skipped if ~/.claudeperms/inline-exec-patterns is missing/empty — see README.
  if (!isSandboxEnabled()) {
    for (const { re, name } of loadInlineExecPatterns()) {
      if (re.test(command)) {
        return ask(
          `Inline code execution detected (${name}). ` +
            `Write the code to a script file and run that instead — script files are reviewable on disk. ` +
            `Approve only if a one-off inline invocation is genuinely necessary.`
        );
      }
    }
  }

  // 5. dd or raw disk access
  if (DD_PATTERNS.some((p) => p.test(command)) || RAW_DISK_PATTERNS.some((p) => p.test(command))) {
    return ask(
      'Direct disk access detected (`dd` or raw device). This can cause data loss — approve only if intentional.'
    );
  }

  // 6. /proc access
  if (PROC_PATTERNS.some((p) => p.test(command))) {
    return ask(
      'Access to `/proc/` detected. This exposes kernel internals — approve only if intentional.'
    );
  }

  // 7. Sandbox-disabled but purely read-only: skip path-area gates.
  // Earlier guards (deletion, truncation, sensitive files, inline exec, dd,
  // /proc) have already cleared. Read-only commands have minimal blast radius
  // even unsandboxed.
  if (opts.sandboxDisabled && isPureReadOnlyCommand(command)) {
    return allow(
      'Read-only command (sandbox disabled). Deletion, sensitive-file, and ' +
        'inline-exec guards already cleared.'
    );
  }

  // 8. Read-only jq pipelines: jq + helpers from jq-pipeline-helpers, with any
  // write redirects targeting permitted paths or write-exempt prefixes. jq
  // doesn't mutate files and its file args are reads.
  if (isJqReadPipeline(command) && allWriteTargetsPermitted(command, cwd)) {
    return allow('jq read pipeline; write targets (if any) are in permitted paths.');
  }

  // 9. Path traversal via ../ — resolve and check against permitted paths.
  // Read tokens use read-exempt-prefixes; write targets use write-exempt-prefixes.
  const writeTargets = new Set(extractWriteTargets(command, cwd));
  const readExempt = loadPrefixList('read-permitted-prefixes');
  const writeExempt = loadPrefixList('write-permitted-prefixes');

  if (command.includes('../')) {
    const tokenRe = /(?:^|[\s'"`])((?:[^\s'"`]*\.\.\/[^\s'"`]*))/g;
    let m;
    while ((m = tokenRe.exec(command)) !== null) {
      const token = m[1];
      const absPath = toAbs(token, cwd);
      if (isPathPermitted(absPath, cwd)) continue;
      const exempt = writeTargets.has(absPath) ? writeExempt : readExempt;
      if (exempt.some((prefix) => absPath.startsWith(prefix))) continue;
      return ask(
        `Relative path escapes permitted areas: ${token} → ${absPath}`
      );
    }
  }

  // 10. Absolute paths outside permitted areas.
  const absolutePathPattern = /(?:^|[\s'"`])(\/.+?)(?:[\s'"`]|$)/g;
  let match;
  while ((match = absolutePathPattern.exec(command)) !== null) {
    const absPath = match[1];
    if (absPath === '/dev/null') continue;
    if (isPathPermitted(absPath, cwd)) continue;
    const exempt = writeTargets.has(absPath) ? writeExempt : readExempt;
    if (exempt.some((prefix) => absPath.startsWith(prefix))) continue;

    if (absPath.startsWith('/Users/') || absPath.startsWith('/home/') ||
        writeTargets.has(absPath)) {
      const kind = writeTargets.has(absPath) ? 'write' : 'read';
      return ask(
        `Access outside permitted paths (${kind}). Path: ${absPath}`
      );
    }
  }

  return allow('Command passes all security checks.');
}

// --- Bash: deletion ---

// Decision matrix:
//   trash disabled                                  → ask
//   trash enabled, every target inside trash dir   → ask  (emptying trash)
//   trash enabled, mixed/outside/unparseable        → deny (use mv <f> <trash>)
function checkDeletion(command, cwd) {
  const matchesDeletion = DELETION_PATTERNS.some((p) => p.test(command));
  if (!matchesDeletion) return null;

  const { trashEnabled, trashLocation } = loadTrashConfig();

  if (!trashEnabled) {
    return ask(
      'Deletion command detected and trash is disabled in ~/.claudeperms/config.json. ' +
        'Approve only if intentional.'
    );
  }

  const trashAbs = toAbs(trashLocation, cwd);
  const targets = extractFileArgs(command, cwd);

  if (targets.length === 0) return deny(denyDeletionMessage(trashLocation));

  if (targets.every((t) => isInsideTrash(t, trashAbs))) {
    return ask(
      `Deletion targets are inside the trash directory (${trashLocation}). ` +
        'Approve only if you intend to empty the trash.'
    );
  }

  return deny(denyDeletionMessage(trashLocation));
}

function denyDeletionMessage(trashLocation) {
  return (
    `Deletion is not allowed. To remove files, use: \`mkdir -p ${trashLocation} && mv <file> ${trashLocation}\``
  );
}

// --- Bash: truncation ---

function checkTruncationRedirects(command, cwd) {
  for (const pattern of TRUNCATION_REDIRECT_PATTERNS) {
    const match = pattern.exec(command);
    if (!match) continue;

    const targetFile = match[1];
    if (!targetFile) {
      return ask(
        'Redirect detected but could not determine target file. Approve only if intentional.'
      );
    }

    const cleanTarget = targetFile.replace(/^['"]|['"]$/g, '');
    const absoluteTarget = cleanTarget.startsWith('/')
      ? cleanTarget
      : resolve(cwd || '.', cleanTarget);

    if (!existsSync(absoluteTarget)) continue;

    const { trashEnabled, trashLocation } = loadTrashConfig();

    if (!trashEnabled) {
      return ask(
        `Redirect would truncate existing file: ${absoluteTarget}. ` +
          'Trash is disabled in ~/.claudeperms/config.json — approve only if intentional.'
      );
    }

    const trashAbs = toAbs(trashLocation, cwd);
    if (isInsideTrash(absoluteTarget, trashAbs)) {
      return ask(
        `Redirect would truncate a file inside the trash directory (${trashLocation}): ${absoluteTarget}. ` +
          'Approve only if you intend to empty the trash.'
      );
    }

    return deny(
      `Redirect would truncate existing file: ${absoluteTarget}. ` +
        `To remove files, use: \`mv <file> ${trashLocation}\``
    );
  }
  return null;
}

// --- Bash: sensitive-file references ---

function commandTouchesSensitive(command, cwd) {
  const writeTargets = extractWriteTargets(command, cwd);
  for (const target of writeTargets) {
    if (isSensitiveFile(target, 'write')) {
      return { intent: 'write', path: target };
    }
  }
  // Treat any file-arg as a potential read.
  const fileArgs = extractFileArgs(command, cwd);
  for (const arg of fileArgs) {
    if (isSensitiveFile(arg, 'read')) {
      // Only flag if it's not also being written (already handled above).
      if (!writeTargets.includes(arg)) return { intent: 'read', path: arg };
    }
  }
  return null;
}

// Find file-arg tokens referenced in a Bash command, resolved against cwd.
// Strips quotes; ignores flag tokens (starting with -); skips the leading command word.
function extractFileArgs(command, cwd) {
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(command)) !== null) {
    tokens.push(m[1] ?? m[2] ?? m[3]);
  }
  const fileArgs = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t || t.startsWith('-')) continue;
    if (i === 0) continue;
    if (/^(>|>>|<|<<|\||\|\||&&|;|2>|2>&1)$/.test(t)) continue;
    fileArgs.push(t);
  }
  return fileArgs.map((f) => toAbs(f, cwd));
}

// Detect "write intent" in a Bash command and return the list of write-target paths.
// Conservative: redirects, tee, sed -i, mv/cp targets.
function extractWriteTargets(command, cwd) {
  const targets = new Set();

  // Redirects: > file or >> file (not 2>&1)
  const redirRe = /(?<!\d)(?<![&\d])>>?\s*("([^"]+)"|'([^']+)'|(\S+))/g;
  let m;
  while ((m = redirRe.exec(command)) !== null) {
    const t = m[2] ?? m[3] ?? m[4];
    if (t && t !== '&1' && t !== '&2' && !t.startsWith('&')) targets.add(t);
  }

  // tee [-a] file...
  const teeRe = /\btee\b\s+(?:-\w+\s+)*((?:"[^"]*"|'[^']*'|\S+)(?:\s+(?:"[^"]*"|'[^']*'|\S+))*)/g;
  while ((m = teeRe.exec(command)) !== null) {
    const args = m[1].split(/\s+/);
    for (const a of args) targets.add(a.replace(/^['"]|['"]$/g, ''));
  }

  // sed -i ... file
  const sedIRe = /\bsed\b[^|;&]*\s-i(?:\s|=)/;
  if (sedIRe.test(command)) {
    const sedRe = /\bsed\b\s+([^|;&]+)/g;
    while ((m = sedRe.exec(command)) !== null) {
      const tokens = m[1].trim().split(/\s+/);
      for (const t of tokens) {
        if (!t.startsWith('-') && !t.startsWith("'") && !t.startsWith('"') && !t.includes('s/')) {
          targets.add(t);
        }
      }
    }
  }

  // mv SRC DEST  /  cp SRC DEST  → DEST is a write target
  const mvCpRe = /\b(?:mv|cp)\b\s+((?:"[^"]*"|'[^']*'|\S+)(?:\s+(?:-\w+))*\s+(?:"[^"]*"|'[^']*'|\S+))/g;
  while ((m = mvCpRe.exec(command)) !== null) {
    const tokens = m[1].split(/\s+/).filter((t) => !t.startsWith('-'));
    if (tokens.length >= 2) {
      const dest = tokens[tokens.length - 1].replace(/^['"]|['"]$/g, '');
      targets.add(dest);
    }
  }

  return [...targets].map((t) => toAbs(t, cwd));
}

// --- Bash: read-only carve-out for sandbox-disabled calls ---

// True iff every top-level segment is a read-only invocation. Splits on
// top-level | && || ;. False negatives are fine — they fall through to the
// existing prompt path.
function isPureReadOnlyCommand(command) {
  const readOnlyPrefixes = loadList('read-only-commands');
  const segments = command.split(/\s(?:&&|\|\||;)\s|\s\|\s/);
  for (const raw of segments) {
    const seg = raw.trim();
    if (!seg) return false;
    const dewrapped = stripCommandPrefixes(seg);
    if (dewrapped === 'gh api' || dewrapped.startsWith('gh api ')) {
      if (!isReadOnlyGhApi(dewrapped)) return false;
      continue;
    }
    if (!matchesReadOnlyPrefix(dewrapped, readOnlyPrefixes)) return false;
  }
  return true;
}

function matchesReadOnlyPrefix(segment, readOnlyPrefixes) {
  for (const p of readOnlyPrefixes) {
    if (segment === p) return true;
    if (segment.startsWith(p + ' ')) return true;
  }
  return false;
}

// Returns segment with env-var assignments, leading `env`, `timeout DURATION`,
// and the rtk wrapper stripped — keeps subcommand + args intact so
// `git log --oneline` still matches the `git log` prefix.
function stripCommandPrefixes(segment) {
  let s = segment.trim();
  while (true) {
    if (s.startsWith('env ')) {
      s = s.slice(4).trim();
      continue;
    }
    const assign = /^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/.exec(s);
    if (assign) {
      s = s.slice(assign[0].length);
      continue;
    }
    const timeoutM = /^timeout\s+\S+\s+/.exec(s);
    if (timeoutM) {
      s = s.slice(timeoutM[0].length);
      continue;
    }
    if (stripRtkWrapper(s) !== s) {
      s = stripRtkWrapper(s);
      continue;
    }
    break;
  }
  return s;
}

// rtk (https://github.com/rtk-ai/rtk) is a transparent output-filtering proxy.
// Its Claude Code hook auto-rewrites commands segment-by-segment — `git status`
// becomes `rtk git status` — and `rtk proxy <cmd>` runs <cmd> verbatim. Strip
// the wrapper so the underlying command is what the carve-outs evaluate.
// Returns the input unchanged when there is no rtk wrapper (used as the
// loop sentinel by stripCommandPrefixes/leadingCommand).
function stripRtkWrapper(s) {
  if (!s.startsWith('rtk ')) return s;
  let rest = s.slice(4).trim();
  if (rest.startsWith('proxy ')) rest = rest.slice(6).trim();
  return rest;
}

// rtk-rewrite carve-out: when enabled, this hook subsumes the separate
// `rtk hook claude` PreToolUse hook. That hook rewrites bash commands to their
// rtk-proxied form via `updatedInput` but emits no permissionDecision, so a
// prior `allow` from this hook is computed against the ORIGINAL command and
// does not survive the rewrite — Claude Code re-checks its allowlist against the
// rewritten command and prompts. By computing the same rewrite HERE and emitting
// it alongside our `allow` in one hookSpecificOutput, the approval and the
// rewrite come from the same decision, so the rewritten command is auto-approved.
// The rewrite itself is delegated to `rtk hook claude` (authoritative — it knows
// which commands to wrap and which to skip, e.g. `cd`), never reimplemented.
function loadRtkRewriteEnabled() {
  const path = join(homedir(), '.claudeperms', 'config.json');
  if (!existsSync(path)) return false;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return parsed.rtkRewrite?.enabled === true;
  } catch {
    return false;
  }
}

// Ask rtk what it would rewrite this command to. Returns the rewritten command
// string, or null on any failure (rtk missing, timeout, no rewrite, bad output)
// so the caller degrades to emitting the decision without a rewrite.
function computeRtkRewrite(input) {
  const rtkBin = process.env.CLAUDE_PERMS_RTK_BIN || 'rtk';
  try {
    const out = execFileSync(rtkBin, ['hook', 'claude'], {
      input: JSON.stringify(input),
      encoding: 'utf8',
      timeout: 4000,
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    if (!out || !out.trim()) return null;
    const cmd = JSON.parse(out)?.hookSpecificOutput?.updatedInput?.command;
    return typeof cmd === 'string' && cmd.length > 0 ? cmd : null;
  } catch {
    return null;
  }
}

// Attach rtk's command rewrite to an already-decided result. Only fires for a
// claude-harness Bash command we're allowing, when the feature is enabled and the
// command is not already rtk-wrapped. Preserves the existing decision verbatim and
// adds updatedInput carrying the rewritten command (other tool_input fields kept).
function maybeAttachRtkRewrite(result, input, harness) {
  if (harness !== HARNESS.claude) return result;
  if (input?.tool_name !== 'Bash') return result;
  if (result?.hookSpecificOutput?.permissionDecision !== 'allow') return result;
  if (!loadRtkRewriteEnabled()) return result;
  const command = input?.tool_input?.command ?? '';
  if (!command || command.startsWith('rtk ')) return result;
  const rewritten = computeRtkRewrite(input);
  if (!rewritten || rewritten === command) return result;
  return {
    hookSpecificOutput: {
      ...result.hookSpecificOutput,
      updatedInput: { ...input.tool_input, command: rewritten },
    },
  };
}

// `gh api` defaults to GET but can mutate via:
//   -X / --method <verb>           non-GET explicitly
//   --method=<verb>                non-GET, equals form
//   -X<VERB>                       attached form, e.g. -XPOST
//   -f / --field / -F / --raw-field / --input    body flags imply POST
function isReadOnlyGhApi(segment) {
  const tokens = segment.split(/\s+/);
  const readMethods = new Set(['GET', 'HEAD']);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    const attached = /^-X([A-Za-z]+)$/.exec(t);
    if (attached) {
      if (!readMethods.has(attached[1].toUpperCase())) return false;
      continue;
    }

    if (t === '-X' || t === '--method') {
      const next = (tokens[i + 1] || '').toUpperCase();
      if (!readMethods.has(next)) return false;
      i++;
      continue;
    }

    const eq = /^--method=(\S+)$/.exec(t);
    if (eq) {
      if (!readMethods.has(eq[1].toUpperCase())) return false;
      continue;
    }

    if (t === '-f' || t === '-F' || t === '--field' ||
        t === '--raw-field' || t === '--input') return false;
    if (/^--(?:field|raw-field|input)=/.test(t)) return false;
    if (/^-[fF]\S/.test(t)) return false;
  }
  return true;
}

// --- Bash: jq pipeline carve-out ---

// True when the command is a pure pipeline of jq + read helpers, with at least one jq.
function isJqReadPipeline(command) {
  const helpers = new Set(loadList('jq-pipeline-helpers'));
  if (helpers.size === 0) return false;
  const segments = splitTopLevelPipes(command);
  if (!segments) return false;
  let hasJq = false;
  for (const seg of segments) {
    if (!seg) return false;
    const cmd = leadingCommand(seg);
    if (!cmd) return false;
    if (!helpers.has(cmd)) return false;
    if (cmd === 'jq') hasJq = true;
  }
  return hasJq;
}

// Split a command on top-level `|` (shell pipe), respecting single and double quotes.
// Returns null if the command contains top-level `&&`, `||`, or `;` — those signal
// a compound command, not a pure pipeline, so we don't carve out.
function splitTopLevelPipes(command) {
  const segments = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "'" && !inDouble) { inSingle = !inSingle; current += c; continue; }
    if (c === '"' && !inSingle) { inDouble = !inDouble; current += c; continue; }
    if (!inSingle && !inDouble) {
      if (c === '|' && command[i + 1] === '|') return null;
      if (c === '&' && command[i + 1] === '&') return null;
      if (c === ';') return null;
      if (c === '|') { segments.push(current.trim()); current = ''; continue; }
    }
    current += c;
  }
  segments.push(current.trim());
  return segments;
}

// Extract the leading executable name from a pipeline segment, stripping
// VAR=value prefixes, a leading `env`, and any path components.
function leadingCommand(segment) {
  let s = segment.trim();
  while (true) {
    if (s.startsWith('env ')) { s = s.slice(4).trim(); continue; }
    const assign = /^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/.exec(s);
    if (assign) { s = s.slice(assign[0].length); continue; }
    if (stripRtkWrapper(s) !== s) { s = stripRtkWrapper(s); continue; }
    break;
  }
  const m = /^"([^"]*)"|^'([^']*)'|^(\S+)/.exec(s);
  if (!m) return null;
  const tok = m[1] ?? m[2] ?? m[3];
  return tok.split('/').pop();
}

// True when every write target is in a permitted path or a write-exempt prefix
// (or /dev/null). Empty target list returns true.
function allWriteTargetsPermitted(command, cwd) {
  const targets = extractWriteTargets(command, cwd);
  const writeExempt = loadPrefixList('write-permitted-prefixes');
  for (const target of targets) {
    if (target === '/dev/null') continue;
    if (isPathPermitted(target, cwd)) continue;
    if (writeExempt.some((prefix) => target.startsWith(prefix))) continue;
    return false;
  }
  return true;
}

// === WebFetch =========================================================

function checkWebFetch(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return ask(`Invalid URL: ${url}`);
  }

  const { domains, urlPrefixes } = loadApprovedFetchPolicy();
  const hostname = parsed.hostname;

  const hostMatch = domains.some(
    (d) => hostname === d || hostname.endsWith(`.${d}`)
  );
  if (hostMatch) return allow(`Hostname ${hostname} is approved.`);

  const prefixMatch = urlPrefixes.some((prefix) => url.startsWith(prefix));
  if (prefixMatch) return allow(`URL matches an approved prefix.`);

  return ask(
    `URL not in approved list: ${url}. ` +
      `Add to ~/.claudeperms/approved-domains.json under "domains" (single-tenant host) or "urlPrefixes" (multi-tenant path).`
  );
}

// Reads ~/.claudeperms/config.json. Missing/malformed/!enabled/no location → trash disabled.
// Returns { trashEnabled, trashLocation } — location is the raw configured string
// (resolve at the call site via toAbs(location, cwd)).
function loadTrashConfig() {
  const disabled = { trashEnabled: false, trashLocation: null };
  const path = join(homedir(), '.claudeperms', 'config.json');
  if (!existsSync(path)) return disabled;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    const trash = parsed?.trash;
    if (!trash || trash.enabled !== true) return disabled;
    const location =
      typeof trash.location === 'string' && trash.location.length > 0
        ? trash.location
        : null;
    if (!location) return disabled;
    return { trashEnabled: true, trashLocation: location };
  } catch {
    return disabled;
  }
}

// Reads ~/.claudeperms/approved-domains.json. Missing or unparseable → empty lists.
function loadApprovedFetchPolicy() {
  const empty = { domains: [], urlPrefixes: [] };
  const path = join(homedir(), '.claudeperms', 'approved-domains.json');
  if (!existsSync(path)) return empty;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return {
      domains: parsed.domains ?? [],
      urlPrefixes: parsed.urlPrefixes ?? [],
    };
  } catch {
    return empty;
  }
}

// === File tools (Read / Write / Edit / Glob / Grep) ===================

function checkFileToolAccess(toolName, toolInput, cwd) {
  const filePath = toolInput?.file_path ?? '';
  const absPath = filePath.startsWith('/') ? filePath : (filePath ? toAbs(filePath, cwd) : '');

  // Reads use the read list; writes/edits use the write list.
  const kind = toolName === 'Read' ? 'read' : 'write';

  if (absPath && isSensitiveFile(absPath, kind)) {
    return ask(
      `Access to sensitive file (${kind}) detected: ${absPath}. Approve only if intentional.`
    );
  }

  if (filePath.startsWith('/') && !isPathPermitted(filePath, cwd)) {
    const exempt = loadPrefixList(kind === 'write' ? 'write-permitted-prefixes' : 'read-permitted-prefixes');
    if (!exempt.some((prefix) => filePath.startsWith(prefix))) {
      return ask(`Access outside permitted paths (${kind}). Path: ${filePath}`);
    }
  }

  return allow(`Tool ${toolName} passes all security checks.`);
}

function checkGlobOrGrep(toolName, toolInput, cwd) {
  const path = toolInput?.path ?? '';
  const pattern = toolInput?.pattern ?? '';
  const glob = toolInput?.glob ?? '';

  // Sensitive references in pattern/glob/path — checked against read list (these tools read).
  for (const candidate of [pattern, glob, path]) {
    if (!candidate) continue;
    const abs = candidate.startsWith('/') ? candidate : toAbs(candidate, cwd);
    if (isSensitiveFile(abs, 'read')) {
      return ask(
        `${toolName} references a sensitive file: ${candidate}. Approve only if intentional.`
      );
    }
  }

  if (path && path.startsWith('/') && !isPathPermitted(path, cwd)) {
    const readExempt = loadPrefixList('read-permitted-prefixes');
    if (!readExempt.some((prefix) => path.startsWith(prefix))) {
      return ask(`${toolName} path is outside permitted paths. Path: ${path}`);
    }
  }

  return allow(`${toolName} passes all security checks.`);
}

// === Shared utilities =================================================

// --- Decisions ---

function allow(reason) { return decision('allow', reason); }
function ask(reason)   { return decision('ask', reason);   }
function deny(reason)  { return decision('deny', reason);  }

function decision(permissionDecision, permissionDecisionReason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason,
    },
  };
}

// --- Path helpers ---

function expandHome(p) {
  return p.startsWith('~/') ? join(homedir(), p.slice(2)) : p;
}

function toAbs(p, cwd) {
  if (p.startsWith('/')) return p;
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return resolve(cwd || '.', p);
}

// True iff absPath is the trash dir itself OR sits inside it.
// trashLocationAbs must already be absolute (caller resolves via toAbs).
function isInsideTrash(absPath, trashLocationAbs) {
  if (!trashLocationAbs) return false;
  const trashRoot = trashLocationAbs.replace(/\/+$/, '');
  if (absPath === trashRoot) return true;
  return absPath.startsWith(trashRoot + '/');
}

function isPathPermitted(absPath, cwd) {
  if (cwd && absPath.startsWith(cwd)) return true;
  for (const permitted of loadPermittedPaths()) {
    if (absPath === permitted || absPath.startsWith(permitted + '/')) return true;
  }
  return false;
}

// --- Sensitive file matching ---

// A path is sensitive iff at least one positive pattern matches AND no
// negation (!-prefixed) pattern matches. Negation wins regardless of order,
// so `!~/.claude/plans/` can carve a hole out of a broader `.claude/` rule.
function isSensitiveFile(absFilePath, kind) {
  if (!absFilePath) return false;
  const name = kind === 'write' ? 'ask-before-write' : 'ask-before-read';
  let matched = false;
  for (const pattern of loadList(name)) {
    if (pattern.startsWith('!')) {
      if (matchesSensitivePattern(absFilePath, pattern.slice(1))) return false;
    } else if (matchesSensitivePattern(absFilePath, pattern)) {
      matched = true;
    }
  }
  return matched;
}

// Match a file path against a single pattern.
// Pattern forms supported:
//   - Bare basename:     ".env"            (matches any path whose basename is ".env")
//   - Glob with *:       "*.pem"           (matches basename via simple * → [^/]*)
//   - Directory prefix:  "~/.ssh/"         (any path inside that directory)
//   - Absolute prefix:   "/etc/secret/"    (any path inside)
//   - Path-with-suffix:  ".claude/settings.json" (matches path ending in this)
function matchesSensitivePattern(absFilePath, pattern) {
  if (!pattern) return false;
  const expanded = expandHome(pattern);

  // Directory prefix (ends with /)
  if (expanded.endsWith('/')) {
    if (expanded.startsWith('/')) {
      return absFilePath === expanded.slice(0, -1) || absFilePath.startsWith(expanded);
    }
    return absFilePath.includes('/' + expanded) || absFilePath.startsWith(expanded);
  }

  // Glob (contains *)
  if (expanded.includes('*')) {
    const basename = absFilePath.split('/').pop();
    const re = new RegExp(
      '^' + expanded.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$'
    );
    return re.test(basename);
  }

  // Absolute path: exact or prefix
  if (expanded.startsWith('/')) {
    return absFilePath === expanded || absFilePath.startsWith(expanded + '/');
  }

  // Relative path with one or more segments (e.g. ".claude/settings.json"):
  // match if absFilePath ends with /pattern or equals pattern
  if (expanded.includes('/')) {
    return absFilePath.endsWith('/' + expanded) || absFilePath === expanded;
  }

  // Bare basename: match against basename, also support ".env" matching ".env.local" etc.
  const basename = absFilePath.split('/').pop();
  if (basename === expanded) return true;
  if (basename.startsWith(expanded + '.')) return true;
  return false;
}

// --- Config file loaders ---

// Read ~/.claudeperms/<name> as a list of trimmed non-blank, non-comment lines.
// Returns [] when the file is missing or unreadable. Used for every text
// allowlist the hook consults.
function loadList(name) {
  const lines = loadConfigLines(join(homedir(), '.claudeperms', name));
  return lines ?? [];
}

// Same as loadList, but expands ~/ in each line — for prefix lists that are
// matched against absolute paths via startsWith.
function loadPrefixList(name) {
  return loadList(name).map(expandHome);
}

function loadConfigLines(filePath) {
  if (!existsSync(filePath)) return null;
  try {
    const raw = readFileSync(filePath, 'utf8');
    return raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  } catch {
    return null;
  }
}

function loadPermittedPaths() {
  return loadList('permitted-paths').map((line) => {
    const expanded = expandHome(line);
    return resolve(expanded);
  });
}

// Parse ~/.claudeperms/inline-exec-patterns. Each non-comment line:
//   <command> <flag1> [<flag2> ...]
// produces { re: /\b<cmd>\s+(?:--?[\w-]+\s+)*(?:<flag1>|<flag2>|...)\b/, name: "<cmd> <flag1>" }.
function loadInlineExecPatterns() {
  const patterns = [];
  for (const line of loadList('inline-exec-patterns')) {
    const parts = line.split(/\s+/).filter(Boolean);
    if (parts.length < 2) continue;
    const [cmd, ...flags] = parts;
    const alt = flags.map(escapeRegex).join('|');
    const re = new RegExp(`\\b${escapeRegex(cmd)}\\s+(?:--?[\\w-]+\\s+)*(?:${alt})\\b`);
    patterns.push({ re, name: `${cmd} ${flags[0]}` });
  }
  return patterns;
}

function escapeRegex(s) {
  return s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

// Reads ~/.claude/settings.json. User-level only — project/local overrides
// (.claude/settings.json, settings.local.json) are intentionally ignored.
function isSandboxEnabled() {
  const path = join(homedir(), '.claude', 'settings.json');
  if (!existsSync(path)) return false;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return parsed?.sandbox?.enabled === true;
  } catch {
    return false;
  }
}

// === Entry point ======================================================

// Watchdog: if nothing has been emitted within the budget (e.g. stdin never
// closes), fail safe. unref() so the timer never keeps the process alive on the
// normal fast path.
const watchdog = setTimeout(() => failSafe('watchdog timeout'), WATCHDOG_MS);
watchdog.unref();

process.on('uncaughtException', (err) => failSafe(err?.message ?? String(err)));
process.on('unhandledRejection', (err) => failSafe(err?.message ?? String(err)));

main().catch((err) => failSafe(err?.message ?? String(err)));
