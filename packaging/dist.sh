#!/bin/sh
# Portable archive: armory-<version>-<target>.tar.gz with the binary, man page, completions and docs.
# Usage: packaging/dist.sh [cargo target triple]
set -eu
cd "$(dirname "$0")/.."
target=${1:-}
if [ -n "$target" ]; then
    cargo build --release --locked -p armory --target "$target"
    bin=target/$target/release/armory
else
    cargo build --release --locked -p armory
    bin=target/release/armory
    target=$(rustc -vV | sed -n 's/^host: //p')
fi
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
name=armory-$version-$target
out=target/dist/$name
rm -rf "$out"
mkdir -p "$out/completions"
cp "$bin" "$out/"
"$bin" manpage > "$out/armory.1"
"$bin" completions bash > "$out/completions/armory.bash"
"$bin" completions zsh > "$out/completions/_armory"
"$bin" completions fish > "$out/completions/armory.fish"
cp LICENSE crates/README.md "$out/"
tar -C target/dist -czf "target/dist/$name.tar.gz" "$name"
echo "target/dist/$name.tar.gz"
