#!/usr/bin/env bash
# Build the legacy-oracle harness: links Armory's original C++ crypto
# (cppForSwig/EncryptionUtils.cpp + bundled Crypto++) so the Rust rewrite
# can be checked against reference outputs (KDF, AES-CFB, chained keys).
#
# Usage: tools/legacy-oracle/build.sh [build-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/cppForSwig"
OUT="${1:-$ROOT/tools/legacy-oracle/build}"
mkdir -p "$OUT/cryptopp"

# Build Crypto++ out of tree so the legacy source dir stays pristine.
cp -u "$SRC"/cryptopp/*.cpp "$SRC"/cryptopp/*.h "$OUT/cryptopp/"
(
  cd "$OUT/cryptopp"
  objs=()
  for f in *.cpp; do
    case "$f" in
      test.cpp|bench*.cpp|validat*.cpp|datatest.cpp|regtest*.cpp|fipsalgt.cpp|dlltest.cpp|adhoc.cpp) continue ;;
    esac
    o="${f%.cpp}.o"
    [[ "$o" -nt "$f" ]] || g++ -O2 -w -std=c++11 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSSE3 -DCRYPTOPP_DISABLE_AESNI -fPIC -c "$f" -o "$o"
    objs+=("$o")
  done
  ar rcs libcryptopp.a "${objs[@]}"
)

g++ -O2 -w -std=c++11 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSSE3 -DCRYPTOPP_DISABLE_AESNI \
  -I"$SRC" -I"$OUT/cryptopp" \
  "$ROOT/tools/legacy-oracle/harness.cpp" \
  "$SRC/EncryptionUtils.cpp" "$SRC/BinaryData.cpp" "$SRC/BtcUtils.cpp" "$SRC/UniversalTimer.cpp" \
  "$OUT/cryptopp/libcryptopp.a" -lpthread -o "$OUT/harness"

echo "built $OUT/harness"
