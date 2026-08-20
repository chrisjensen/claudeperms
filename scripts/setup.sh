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

# Kimi Code CLI wiring: if ~/.kimi exists, register the single permissions.mjs
# PreToolUse hook in config.toml. permissions.mjs is tagged
# CLAUDE_PERMS_HARNESS=kimi so it selects its kimi adapter, and it digests any
# other configured hooks itself (chainedHooks in ~/.claudeperms/config.json), so
# only this one block is registered. TOML has no easy CLI merge, so the block is
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
  append_kimi_hook "claudeperms/permissions.mjs" "" \
    "CLAUDE_PERMS_HARNESS=kimi node $DEST/permissions.mjs"
else
  echo "kimi: ~/.kimi not found — skipping Kimi Code CLI wiring."
fi

# opencode wiring: if ~/.config/opencode exists, deploy the bridge plugin (always
# overwrite — it's our code) and the provider config (copy only if missing — user
# edits win). The plugin spawns permissions.mjs with CLAUDE_PERMS_HARNESS=opencode
# and chains the shared shell hooks. Never create the dir or clobber user config.
OPENCODE_DIR="$HOME/.config/opencode"
if [ -d "$OPENCODE_DIR" ]; then
  mkdir -p "$OPENCODE_DIR/plugins"
  cp defaults/opencode/plugins/claudeperms.mjs "$OPENCODE_DIR/plugins/claudeperms.mjs"
  echo "opencode: installed bridge plugin -> $OPENCODE_DIR/plugins/claudeperms.mjs"
  # Per-family model overlays (always overwrite — our code). Selected at launch
  # via OPENCODE_CONFIG by the hopencode/kopencode/... wrappers to pin model +
  # small_model to one synthetic family.
  mkdir -p "$OPENCODE_DIR/families"
  for fam in defaults/opencode/families/*.json; do
    [ -f "$fam" ] || continue
    cp "$fam" "$OPENCODE_DIR/families/$(basename "$fam")"
    echo "opencode: installed family overlay -> $OPENCODE_DIR/families/$(basename "$fam")"
  done
  if [ -e "$OPENCODE_DIR/opencode.json" ]; then
    echo "opencode: $OPENCODE_DIR/opencode.json exists — leaving as-is (merge provider.anthropic.options.baseURL + synthetic models manually if needed)."
  else
    cp defaults/opencode/opencode.json "$OPENCODE_DIR/opencode.json"
    echo "opencode: wrote provider config -> $OPENCODE_DIR/opencode.json"
  fi
else
  echo "opencode: ~/.config/opencode not found — skipping opencode wiring."
fi

# Install check-malicious's runtime dep (anti-trojan-source) into ~/.claudeperms/.
cd "$DEST" && npm install --omit=dev --no-audit --no-fund
