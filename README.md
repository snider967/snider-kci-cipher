# snider-kci-cipher
This is a passion project merging my two interests, MtG and Cryptography. Within the code provided here, there are the fundemental building blocks to construct a Krark-Clan Ironworks simulator.
That being said the real purpose of this cipher is to attempt to construct a working, fast and secure cipher by using 'n' iterations of infinite loops.  

## KCI-20 (C rewrite, in progress)
The C rewrite on branch `c-refactor` turns the idea into **KCI-20**, a new stream cipher whose key chooses which of 8
Krark-Clan Ironworks loops each of its 20 rounds plays. The spec is `vault/Refactor/KCI-Primitive-Design.md`.

> **Warning:** KCI-20 is original, unreviewed cryptography. It is a research and hobby project; do not use it to protect real data.

**CI** (`.github/workflows/ci.yml`): gcc and clang on Linux x86-64, Linux ARM64 and macOS ARM64, plus ASan/UBSan, portable,
32-bit and CMake builds. Hard rule: the project costs $0 — free standard runners on the public repo only, checked by
`tools/check_ci_cost.py` before anything else runs.

Build and test (GNU make + a C11 compiler):
```
make test        # library + known-answer tests
make sanitize    # same tests under AddressSanitizer + UndefinedBehaviorSanitizer
make vectors     # regenerate tests/kat_vectors.h from tools/kci_ref.py
```
Use (key file or password; output is written only after the integrity check passes):
```
build/kci keygen my.key
build/kci enc -k my.key secret.txt secret.kci
build/kci dec -k my.key secret.kci secret.txt
build/kci enc secret.txt secret.kci          # prompts for a password (PBKDF2, 600 000 iterations)
build/kci selftest && build/kci bench
```
The original 2023 Python versions live in `legacy/python/`. Licensed under the Apache License 2.0 (`LICENSE`).
