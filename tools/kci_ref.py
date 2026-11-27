"""KCI-20 reference sketch, spec v0.2 (see vault/Refactor/KCI-Primitive-Design.md).

Spec check only. KATs come from the portable C path. Experimental, unreviewed cipher.
Run:  python3 -I tools/kci_ref.py          (checks + provisional KAT)
      python3 -I tools/kci_ref.py --search (re-derive the 8 loop rotation sets; slow, ~1 min)
"""
import os, random, struct, sys

M = 0xFFFFFFFF
rotl = lambda x, n: ((x << n) | (x >> (32 - n))) & M

# Per-iteration loop vectors (cd, mpil, msil, nmp, gat, tos, sos) measured from the 2023 Python (vault: KCI-Loop-Model)
VEC = [(0,5,2,3,5,2,2), (1,10,10,0,10,6,4), (1,9,6,3,9,5,4), (1,7,7,0,8,5,3),
       (0,10,5,5,10,4,4), (2,13,9,4,13,8,5), (0,9,6,3,9,4,4), (0,7,7,0,9,4,4)]
PACKED = [sum(x << (4 * i) for i, x in enumerate(v)) for v in VEC]
PHI = 0x9E3779B9

# Rotation sets per loop: LOOP_ROT = FROZEN below (output of search_rotations(); rho1, rho3 in {8,16,24})

STACK_CONST = struct.unpack('<4I', b'KCI 256-bit loop')   # keystream blocks
DECK_CONST  = struct.unpack('<4I', b'KCI shuffle deck')   # key setup (domain separation)
CHACHA_CONST = struct.unpack('<4I', b'expand 32-byte k')  # cross-check build only
SETUP_SCHED = [r % 8 for r in range(20)]                  # fixed public schedule used only to shuffle the deck

def rc(r, s):
    return (PACKED[s] + (r + 1) * PHI) & M

def qr(x, a, b, c, d, p):
    x[a] = (x[a] + x[b]) & M; x[d] = rotl(x[d] ^ x[a], p[0])
    x[c] = (x[c] + x[d]) & M; x[b] = rotl(x[b] ^ x[c], p[1])
    x[a] = (x[a] + x[b]) & M; x[d] = rotl(x[d] ^ x[a], p[2])
    x[c] = (x[c] + x[d]) & M; x[b] = rotl(x[b] ^ x[c], p[3])

def perm(x, rots, rcs):
    """rots[r] = rotation set of round r, rcs[r] = round constant (0 disables)."""
    x = list(x)
    for r in range(len(rots)):
        x[r & 3] ^= rcs[r]
        p = rots[r]
        if r % 2 == 0:
            qr(x,0,4,8,12,p); qr(x,1,5,9,13,p); qr(x,2,6,10,14,p); qr(x,3,7,11,15,p)
        else:
            qr(x,0,5,10,15,p); qr(x,1,6,11,12,p); qr(x,2,7,8,13,p); qr(x,3,4,9,14,p)
    return x

def core(const, key, ctr, nonce, rots, rcs):
    s = list(const) + list(struct.unpack('<8I', key)) + [ctr] + list(struct.unpack('<3I', nonce))
    return [(a + b) & M for a, b in zip(perm(s, rots, rcs), s)]

def shuffle_deck(key):
    """Key setup: the secret loop schedule s_0..s_19 (3 bits each from words 0 and 1)."""
    w = core(DECK_CONST, key, 0, bytes(12), [LOOP_ROT[s] for s in SETUP_SCHED],
             [rc(r, s) for r, s in enumerate(SETUP_SCHED)])
    return [(w[r // 10] >> (3 * (r % 10))) & 7 for r in range(20)]

class Key:
    def __init__(self, key):
        self.key = key
        self.deck = shuffle_deck(key)
        self.rots = [LOOP_ROT[s] for s in self.deck]
        self.rcs = [rc(r, s) for r, s in enumerate(self.deck)]
    def block(self, ctr, nonce):
        return struct.pack('<16I', *core(STACK_CONST, self.key, ctr, nonce, self.rots, self.rcs))

# ---------- Poly1305 and AEAD (spec 7: RFC 8439 composition with KCI-20) ----------
P1305 = (1 << 130) - 5

def poly1305(key, msg):
    """Big-integer Poly1305 (RFC 8439 2.5): independent of the C 26-bit-limb version."""
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], 'little')
    acc = 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b'\x01', 'little')) * r % P1305
    return ((acc + s) % (1 << 128)).to_bytes(16, 'little')

def _pad16(b):
    return bytes(-len(b) % 16)

def aead_mac_data(aad, ct):
    return aad + _pad16(aad) + ct + _pad16(ct) + struct.pack('<QQ', len(aad), len(ct))

def aead_encrypt(block_fn, nonce, pt, aad):
    """block_fn(ctr, nonce) -> 64-byte block. Returns (ct, tag)."""
    otk = block_fn(0, nonce)[:32]
    ks = b''.join(block_fn(c, nonce) for c in range(1, 1 + (len(pt) + 63) // 64))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    return ct, poly1305(otk, aead_mac_data(aad, ct))

# ---------- rotation-set search (reproducible, seeded by the loop table) ----------
def _aval(rots, samples, seed=7):
    rnd = random.Random(seed); tot = n = 0; mn = 999
    for _ in range(samples):
        s = [rnd.getrandbits(32) for _ in range(16)]; b = perm(s, rots, [0] * len(rots))
        for bit in range(0, 512, 3):
            t = list(s); t[bit // 32] ^= 1 << (bit % 32); o = perm(t, rots, [0] * len(rots))
            d = sum(bin(u ^ v).count('1') for u, v in zip(b, o)); tot += d; n += 1; mn = min(mn, d)
    return tot / n, mn

def search_rotations():
    ref2 = _aval([(16, 12, 8, 7)] * 2, 3)[0]
    sets = []
    for s in range(8):
        rnd = random.Random(PACKED[s])
        while True:
            p = (8 * rnd.randrange(1, 4), rnd.randrange(1, 32), 8 * rnd.randrange(1, 4), rnd.randrange(1, 32))
            if p[0] == p[2] or p[1] == p[3] or p[1] % 8 == 0 or p[3] % 8 == 0: continue
            if not (p[1] % 2 or p[3] % 2): continue
            if p in sets: continue
            m3, mn3 = _aval([p] * 3, 3)
            if m3 >= 254 and mn3 >= 200 and _aval([p] * 2, 3)[0] >= 0.95 * ref2:
                break
        sets.append(p)
    return sets

FROZEN = [(24, 4, 8, 13), (8, 11, 16, 25), (8, 5, 16, 10), (16, 3, 24, 31),
          (8, 29, 24, 10), (24, 25, 16, 18), (16, 21, 24, 30), (8, 22, 16, 27)]
LOOP_ROT = FROZEN

if __name__ == '__main__':
    if '--search' in sys.argv:
        found = search_rotations()
        print('search result:', found, '| matches frozen table:', found == FROZEN)
        sys.exit(0)
    hw = lambda b: bin(int.from_bytes(b, 'big')).count('1')
    key = bytes(range(32)); nonce = bytes.fromhex('000000090000004a00000000')
    # 1. kernel cross-check: ChaCha rotations everywhere, no round constants, ChaCha constants == RFC 8439 2.3.2
    out = struct.pack('<16I', *core(CHACHA_CONST, key, 1, nonce, [(16, 12, 8, 7)] * 20, [0] * 20))
    print('RFC 8439 2.3.2 cross-check:', out.hex().startswith('10f1e7e4d13b5915500fdd1fa32071c4'))
    # 2. loop table, round constants per loop
    for s in range(8):
        print(f'  loop {s}: packed=0x{PACKED[s]:08x} rho={LOOP_ROT[s]}')
    # 3. zero state
    print('zero state fixed point with a loop schedule:', perm([0]*16, [LOOP_ROT[r % 8] for r in range(20)],
          [rc(r, r % 8) for r in range(20)]) == [0]*16)
    # 4. decks: distribution and per-key avalanche
    rnd = random.Random(3)
    counts = [0] * 8
    for _ in range(2000):
        for s in shuffle_deck(bytes(rnd.getrandbits(8) for _ in range(32))): counts[s] += 1
    print('loop pick counts over 2000 keys (ideal 5000 each):', counts)
    for R in (2, 3, 4, 20):
        tot = n = 0; mn = 512
        for t in range(12):
            k = Key(os.urandom(32)); nn = os.urandom(12); c = rnd.getrandbits(32)
            rots, rcs = k.rots[:R], k.rcs[:R]
            base = core(STACK_CONST, k.key, c, nn, rots, rcs)
            for bit in range(0, 256, 9):   # key bit flips with the SAME deck: tests the round function
                k2 = bytearray(k.key); k2[bit // 8] ^= 1 << (bit % 8)
                o = core(STACK_CONST, bytes(k2), c, nn, rots, rcs)
                d = sum(bin(u ^ v).count('1') for u, v in zip(base, o)); tot += d; n += 1; mn = min(mn, d)
        print(f'rounds={R:2}: mean flipped bits {tot/n:6.1f}/512 (ideal 256), min {mn}')
    k = Key(key)
    print('deck for key 00..1f:', k.deck)
    print('provisional KCI-20 block, key 00..1f, nonce 000000090000004a00000000, ctr 1:')
    print(k.block(1, nonce).hex())
