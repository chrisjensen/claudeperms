#!/bin/sh
# Deploy the claude-perms hook + defaults into ~/.claudeperms/.
#
# Always overwrites the code (permissions.mjs, check-malicious.mjs).
# Copies config files from defaults/ only if missing — user edits win.
# Runs npm install in ~/.claudeperms/ for check-malicious's runtime dep.
#
# Portable POSIX shell: uses `[ -e dest ] || cp src dest` instead of `cp -n`
# (which prints a portability warning on recent GNU coreutils).

set -e

DEST="$HOME/.claudeperms"
mkdir -p "$DEST"

# Code: always overwrite.
cp hooks/permissions.mjs "$DEST/permissions.mjs"
cp hooks/check-malicious.mjs "$DEST/check-malicious.mjs"
chmod 0755 "$DEST/check-malicious.mjs"

# Defaults: copy if missing. Skip claudeperms-package.json (renamed below).
for src in defaults/*; do
  [ -f "$src" ] || continue
  name=$(basename "$src")
  [ "$name" = "claudeperms-package.json" ] && continue
  [ -e "$DEST/$name" ] && continue
  cp "$src" "$DEST/$name"
done

# Rename claudeperms-package.json → package.json on first install only.
[ -e "$DEST/package.json" ] || cp defaults/claudeperms-package.json "$DEST/package.json"

# Kimi Code CLI wiring: if ~/.kimi exists, register PreToolUse hooks in
# config.toml. permissions.mjs is tagged CLAUDE_PERMS_HARNESS=kimi so it selects
# its kimi adapter; the two suggest scripts run under both harnesses and match
# kimi's Shell tool (Claude's Bash). TOML has no easy CLI merge, so each block is
# appended only when absent (idempotent). Never create ~/.kimi or clobber config.
KIMI_DIR="$HOME/.kimi"
KIMI_CONFIG="$KIMI_DIR/config.toml"

# append_kimi_hook <grep-key> <matcher> <command>
append_kimi_hook() {
  if [ -f "$KIMI_CONFIG" ] && grep -qF "$1" "$KIMI_CONFIG"; then
    echo "kimi: hook '$1' already present in $KIMI_CONFIG — leaving as-is."
    return
  fi
  {
    printf '\n[[hooks]]\n'
    printf 'event = "PreToolUse"\n'
    printf 'matcher = "%s"\n' "$2"
    printf 'command = "%s"\n' "$3"
    printf 'timeout = 30\n'
  } >> "$KIMI_CONFIG"
  echo "kimi: registered hook '$1' in $KIMI_CONFIG."
}

if [ -d "$KIMI_DIR" ]; then
  HOOKS_DIR="$HOME/.claude/hooks"
  append_kimi_hook "claudeperms/permissions.mjs" "" \
    "CLAUDE_PERMS_HARNESS=kimi node $DEST/permissions.mjs"
  append_kimi_hook "long-command-suggest.sh" "Shell" \
    "CLAUDE_PERMS_HARNESS=kimi bash $HOOKS_DIR/long-command-suggest.sh"
  append_kimi_hook "source-commit-enforce.sh" "Shell" \
    "CLAUDE_PERMS_HARNESS=kimi bash $HOOKS_DIR/source-commit-enforce.sh"
else
  echo "kimi: ~/.kimi not found — skipping Kimi Code CLI wiring."
fi

# Install check-malicious's runtime dep (anti-trojan-source) into ~/.claudeperms/.
cd "$DEST" && npm install --omit=dev --no-audit --no-fund
