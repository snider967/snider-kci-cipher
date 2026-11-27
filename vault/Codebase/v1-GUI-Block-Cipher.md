# v1 — GUI Block Cipher (`snider_kci_cipher.py`)

Back to [[00-Index]] · Loop model: [[KCI-Loop-Model]] · Issues: [[Known-Issues-and-Quirks]]

## Encryption pipeline (`on_encrypt`)
1. `h` = hash size from the radio button: 64, 128 or 256.
2. `string_to_int_hash(key_str, h)`: `sha256(key_str.encode())` truncated to `h/8` bytes → big-endian int.
   (The `while` loop only ever runs once, because SHA-256 gives 32 bytes ≥ 32.)
3. `int_to_padded_binary_string`: `bin()` of that int, left-padded with zeros to 64/128/256 chars. **The width comes from
   the int's bit length, not from `h`** (quirk #4).
4. `key_gen_wrapper(bits)`. Indices count from the **MSB** (`get_nth_bit_from_end` is misnamed):
   - `s = int(bits[0:3])` → loop selector
   - `cd_b, nmp_b, gat_b, tos_b, sos_b = bits[3], bits[4], bits[5], bits[6], bits[7]`
   - `n = int(bits[7:])` (**overlaps sos_b**; n is 57/121/249 bits)
   - run loop `s` n times → `d = vec[s]·n`
   - `key_gen_function`:
     `(cd^(cd_b+1) + nmp^nmp_b + gat^(gat_b+1) + tos^tos_b + sos^(2·sos_b) + (mpil+msil)^(nmp_b+2)) mod (2^128 − 1)`
     computed with `numpy.power` (quirk #1)
5. `int_to_n_bit_byte_hash(gen_key, h)`: `sha256(str(gen_key).encode())`, i.e. SHA-256 of the **decimal ASCII** string, truncated to `h/8` bytes = block key.
6. `encrypt_ecb_with_padding`: PKCS#7 pad to `h/8`, XOR **every block with the same block key**.
7. Output: hex ciphertext `0x…`; the decrypt fields are auto-filled.

## Decryption (`on_decrypt`)
Same derivation from the key string; XOR; `pkcs7_unpad` (no validation); `.decode('utf-8')`.

## GUI
Tk window 800×750: key and plaintext fields, 64/128/256 radio buttons, Encrypt. A second panel (key, ciphertext, read-only
radio buttons, Decrypt) is enabled only after an encryption. Output goes to a Text widget with scrollbars.

## Port notes (historical, before the redesign decision D-007)
- The whole derivation is pure, so it can be one C function: `kci_v1_derive_block_key(key, keylen, h, out)`.
- The XOR is a repeating-key XOR with period `h/8`; it vectorises easily.
