#!/usr/bin/env bash
# Compiles the pure-Java DESFire core + tests and runs them (no Android SDK needed).
set -euo pipefail
cd "$(dirname "$0")"
OUT=build/core-tests
rm -rf "$OUT" && mkdir -p "$OUT"
javac -d "$OUT" app/src/main/java/nz/cardforge/desfire/*.java tests/nz/cardforge/desfire/*.java
java -cp "$OUT" nz.cardforge.desfire.CoreTests
