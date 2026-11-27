# Porting Map

Back to [[00-Index]] · Architecture: [[C-Architecture-Plan]]

Since the redesign (D-007), this is a **concept map** (old Python idea → new C component), not a line-by-line port.

Status: ⬜ not started · 🟨 in progress · ✅ done + tested · ⛔ dropped

| Python concept | New C component | Status |
|---|---|---|
| `kci_loop_values` dict, `reset_dict` | 16-word state with zones (`kci_core`) | ✅ |
| action fns (`tap_n_sac_mopal`, `sac_retriever`, `cast_artifact`, …) | ⛔ not ported as ops; the loop vectors they produce feed the round constants (spec v0.2 §4.4) | ⛔ |
| `loop_0`…`loop_7` | 8 loops = rotation set + round constant, chosen per round by the key's deck (`kci_round.c`, `kci_deck.c`) | ✅ |
| `perform_n_iterations` (linear multiply) | ⛔ replaced by nonlinear rounds (R3) | ⛔ |
| v1 `string_to_int_hash` + key bits | `kci_kdf_password` = PBKDF2-HMAC-SHA256 (D-020), `kci_sha256.c` | ✅ |
| v1 `key_gen_function` (numpy poly) | ⛔ dropped | ⛔ |
| v1 XOR-ECB + PKCS#7 | ⛔ replaced by counter-mode stream (no padding needed) | ⛔ |
| v2 `key_gen_wrapper` / chain | `kci_stream.c` counter mode | ✅ |
| v2 `enc`/`dec`/`xor_bytes` | `kci_stream_xor` | ✅ |
| v1 Tk GUI | `gui/` (toolkit TBD) | ⬜ |
| v2 demo + timeit | `kci selftest` / `kci bench` | ⬜ |
| SHA-256 (hashlib) | in-house SHA-256 + HMAC for PBKDF2 (Q6 default), `kci_sha256.c` | ✅ |
| — | Poly1305 + AEAD (D-021): `kci_poly1305.c`, `kci_aead.c` | ✅ |
| — | file format v1 + CLI (D-022) | ⬜ |
