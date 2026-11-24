#!/usr/bin/env bash
# Compiles the pure-Java DESFire + NTAG 424 DNA cores and their tests and runs them (no Android SDK needed).
# If Node 22+ is installed, also runs the Verity server crypto tests and a Java <-> TypeScript cross-check.
set -euo pipefail
cd "$(dirname "$0")"
OUT=build/core-tests
rm -rf "$OUT" && mkdir -p "$OUT"
javac -d "$OUT" app/src/main/java/nz/cardforge/desfire/*.java app/src/main/java/nz/cardforge/ntag/*.java \
  tests/nz/cardforge/desfire/*.java tests/nz/cardforge/ntag/*.java
java -cp "$OUT" nz.cardforge.desfire.CoreTests
java -cp "$OUT" nz.cardforge.ntag.Ntag424Tests
java -cp "$OUT" nz.cardforge.ntag.Ntag21xTests
if command -v node >/dev/null 2>&1 && node -e 'process.exit(+process.versions.node.split(".")[0] >= 22 ? 0 : 1)'; then
  echo; echo "Verity server crypto (TypeScript)"
  node --experimental-strip-types --no-warnings supabase/tests/ntag.test.ts
  node --experimental-strip-types --no-warnings supabase/tests/crosscheck.ts "$OUT/crossk.json"
fi
