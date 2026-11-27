# Repository Map

Back to [[00-Index]]

## Files (upstream HEAD `2a837a4`)
| Path | Lines | Purpose |
|---|---|---|
| `README.md` | 3 | One-paragraph description |
| `snider_kci_cipher.py` | 641 | v1: Tkinter GUI, SHA-256 key derivation, XOR-ECB + PKCS#7 → [[v1-GUI-Block-Cipher]] |
| `kci_cipher_v2_lite.py` | 418 | v2: chained keystream "stream cipher", demo at module level → [[v2-Lite-Stream-Cipher]] |
| `.idea/` | — | PyCharm project files (Python 3.11 SDK). Not relevant to the port. |
| `vault/` | — | This vault (added locally, not upstream) |

No tests, no requirements file, no license, no packaging.

## Dependencies
- v1: `numpy` (only `numpy.power` in `key_gen_function`), `hashlib.sha256`, `tkinter`.
- v2: `random` (demo key), `timeit`/`numpy` (only in the commented-out benchmark).
- The local machine has Python 3.12.3 **without numpy**, and gcc 13.3 + make. No clang or cmake.

## Git history (all 2023-10-11 … 2023-10-12)
```
2a837a4 lite version committed; "functioning stream cipher"; needs speed on weak devices
b2e0444 key_gen_loop_wrapper: key bit length >= message bit length
56ed767 start of lightweight v2 (no hashes)
8920a8b GUI polish, radio buttons
1c20d94 separate decryption
… initial commits
```

## Shared code (duplicated in both files)
`reset_dict`, action functions (`tap_n_sac_mopal`, `tap_n_sac_mstone`, `sac_retriever`, `activate_chromatic_star`,
`activate_sbomb`, `sac_artifact`, `cast_artifact`), `calc_nmp`, `perform_n_iterations`, `loop_0`…`loop_7`,
`perform_kci_loop_s`, `print_kci_dictionary`, and the global `kci_loop_values` dict. → [[KCI-Loop-Model]]

The two versions have different `key_gen_wrapper`/`key_gen_function`.
