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

# Install check-malicious's runtime dep (anti-trojan-source) into ~/.claudeperms/.
cd "$DEST" && npm install --omit=dev --no-audit --no-fund
