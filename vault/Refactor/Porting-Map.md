# Porting Map

Back to [[00-Index]] · Architecture: [[C-Architecture-Plan]]

Since the redesign (D-007), this is a **concept map** (old Python idea → new C component), not a line-by-line port.

Status: ⬜ not started · 🟨 in progress · ✅ done + tested · ⛔ dropped

| Python concept | New C component | Status |
|---|---|---|
| `kci_loop_values` dict, `reset_dict` | `kci_ctx` state words | ⬜ |
| action fns (`tap_n_sac_mopal`, `sac_retriever`, `cast_artifact`, …) | ARX micro-ops in `kci_round.c` | ⬜ |
| `loop_0`…`loop_7` | 8 round schedules (action sequences kept from the Python) | ⬜ |
| `perform_n_iterations` (linear multiply) | ⛔ replaced by nonlinear rounds (R3) | ⛔ |
| v1 `string_to_int_hash` + key bits | `kci_kdf` (salted, cost) | ⬜ |
| v1 `key_gen_function` (numpy poly) | ⛔ dropped | ⛔ |
| v1 XOR-ECB + PKCS#7 | ⛔ replaced by counter-mode stream (no padding needed) | ⛔ |
| v2 `key_gen_wrapper` / chain | `kci_stream.c` counter mode | ⬜ |
| v2 `enc`/`dec`/`xor_bytes` | `kci_xor` | ⬜ |
| v1 Tk GUI | `gui/` (toolkit TBD) | ⬜ |
| v2 demo + timeit | `kci selftest` / `kci bench` | ⬜ |
| SHA-256 (hashlib) | only if the KDF/MAC design needs it (Q6) | ⬜ |
