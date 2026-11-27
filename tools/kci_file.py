"""Independent Python reader/writer for KCI-20 file format 2 (spec v0.4 section 10), built only on tools/kci_ref.py
and hashlib. Used by tests/cli_test.sh to cross-check the C CLI. Slow (pure Python); small files only.

  python3 -I tools/kci_file.py dec (--key-file K | --password-file P) IN OUT
  python3 -I tools/kci_file.py enc (--key-file K | --password-file P) [--iterations N] [--raw] IN OUT
Exit 0 = ok, 2 = authentication failed, 1 = other error.
"""
import hashlib, os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kci_ref as K  # noqa: E402

MAGIC = b'KCI\x02'   # format 2 = KCI-20 v0.4 (D-028)

def keystream_xor(k, nonce, data, raw=False):
    out = bytearray()
    for i in range(0, len(data), 64):
        blk = (k.block_raw if raw else k.block)(1 + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], blk))
    return bytes(out)

def key_from(args, salt, iterations):
    if '--key-file' in args:
        key = open(args[args.index('--key-file') + 1], 'rb').read()
        assert len(key) == 32, 'key file must be 32 bytes'
        return key
    pw = open(args[args.index('--password-file') + 1], 'rb').read().split(b'\n')[0].rstrip(b'\r')
    return hashlib.pbkdf2_hmac('sha256', pw, salt, iterations, 32)

def main(argv):
    cmd, args, src, dst = argv[0], argv[1:-2], argv[-2], argv[-1]
    data = open(src, 'rb').read()
    if cmd == 'enc':
        raw = '--raw' in args
        pw_mode = '--password-file' in args
        it = int(args[args.index('--iterations') + 1]) if '--iterations' in args else 600000
        salt = os.urandom(16) if pw_mode else bytes(16)
        nonce = os.urandom(12)
        hdr = MAGIC + bytes([1 if raw else 0, 1 if pw_mode else 0, 0, 0]) + struct.pack('<I', it if pw_mode else 0) + salt + nonce
        k = K.Key(key_from(args, salt, it))
        if raw:
            body = keystream_xor(k, nonce, data, raw=True)
        else:
            ct, tag = K.aead_encrypt(k.block, nonce, data, hdr)
            body = ct + tag
        open(dst, 'wb').write(hdr + body)
        return 0
    if cmd == 'dec':
        hdr, body = data[:40], data[40:]
        assert hdr[:4] == MAGIC, 'bad magic'
        mode, kdf, it = hdr[4], hdr[5], struct.unpack('<I', hdr[8:12])[0]
        salt, nonce = hdr[12:28], hdr[28:40]
        k = K.Key(key_from(args, salt, it))
        if mode == 1:
            open(dst, 'wb').write(keystream_xor(k, nonce, body, raw=True))
            return 0
        ct, tag = body[:-16], body[-16:]
        _, expect = K.aead_encrypt(k.block, nonce, keystream_xor(k, nonce, ct), hdr)
        if expect != tag:
            print('kci_file.py: authentication failed', file=sys.stderr)
            return 2
        open(dst, 'wb').write(keystream_xor(k, nonce, ct))
        return 0
    print(__doc__, file=sys.stderr)
    return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
