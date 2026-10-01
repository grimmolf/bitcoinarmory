# Legacy crypto oracle

Python 2 is unavailable on modern Fedora/macOS, so the original test suite cannot run.
This harness instead links Armory's **original** C++ crypto (`cppForSwig/EncryptionUtils.cpp`
and the bundled Crypto++ 5.6.1) to produce reference outputs the Rust rewrite must reproduce
bit-for-bit: the ROMix KDF, AES-256-CFB, and the legacy chained private/public key derivation.

```sh
tools/legacy-oracle/build.sh            # builds into tools/legacy-oracle/build/
tools/legacy-oracle/build/harness       # must match expected-output.txt
```

`expected-output.txt` is the committed reference output; the Rust test suite embeds these
values. Extend `harness.cpp` when a new primitive needs a reference value.
