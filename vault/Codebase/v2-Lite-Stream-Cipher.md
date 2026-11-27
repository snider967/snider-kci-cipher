# v2 — Lite Stream Cipher (`kci_cipher_v2_lite.py`)

Back to [[00-Index]] · Loop model: [[KCI-Loop-Model]] · Issues: [[Known-Issues-and-Quirks]]

## API
- `enc(k: int64, m: str) -> [keystream, ciphertext]`: `m.encode('ascii')`, `k.to_bytes(8,'big')`, keystream
  truncated to `len(m)`, XOR. **Returns the keystream.**
- `dec(keystream, c) -> str`: XOR with the **keystream**, not the key (Q11).

## `key_gen_wrapper(provided_key: bytes) -> 16 bytes`
Bit extraction (this layout is **different from v1**):
- `s = provided_key[0] >> 5` (top 3 bits of the first byte)
- bools from the **last byte**: `cd_b`=bit2, `nmp_b`=bit3, `gat_b`=bit4, `tos_b`=bit5, `sos_b`=bit6 (bits 0, 1 and 7 are unused)
- `n = int.from_bytes(provided_key[:-1], 'big')`, i.e. every byte except the last. n **includes the `s` bits**.
  - first call: 8-byte key → n < 2⁵⁶
  - chained calls: 16-byte block → n < 2¹²⁰

`key_gen_function` (operator precedence worked out):
```
R = ( 200·(cd·cd_b + nmp·nmp_b)·msil + gat·gat_b + 2 + tos·tos_b + sos·sos_b + mpil·msil ) mod (2^128 − 1)
```
Returned as 16 bytes big-endian. Pure Python ints, so exact. No numpy.

Because `d = vec[s]·n`, R is a quadratic in n:
`R = n²·msil₀·(200·(cd₀·cd_b + nmp₀·nmp_b) + mpil₀) + n·(gat₀·gat_b + tos₀·tos_b + sos₀·sos_b) + 2  (mod M)`.

## `key_gen_loop_wrapper(key, len)`
Block chaining: `B₀ = KG(key8)`, `Bᵢ₊₁ = KG(Bᵢ)`; join blocks until the length is ≥ len.
The chain is strictly **sequential**, so it cannot be parallelised (see [[Performance-Notes]]).

## Module-level demo
On import it runs a random 64-bit key, `msg = "Hello my name is Dan"`, and prints the key, keystream, ciphertext, plaintext and the
last loop state. In C this belongs in a CLI/demo, not the library.
