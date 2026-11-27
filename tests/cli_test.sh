#!/bin/sh
# End-to-end tests for the kci CLI, including cross-checks against the independent Python file tool.
# usage: sh tests/cli_test.sh path/to/kci
# Copyright 2026 snider967. Licensed under the Apache License, Version 2.0.
set -u
KCI=${1:?usage: cli_test.sh path/to/kci}
case $KCI in /*) ;; *) KCI=$(pwd)/$KCI ;; esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYFILE="python3 -I $ROOT/tools/kci_file.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/kci-cli-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
cd "$T" || exit 1

pass=0; failn=0
ok()   { pass=$((pass + 1)); }
bad()  { failn=$((failn + 1)); echo "FAIL: $*"; }
check() { if eval "$2"; then ok; else bad "$1"; fi; }
flip() { python3 -I -c "import sys; p,o=sys.argv[1],int(sys.argv[2]); b=bytearray(open(p,'rb').read()); b[o if o>=0 else len(b)+o]^=1; open(p,'wb').write(b)" "$@"; }
size() { wc -c < "$1" | tr -d ' '; }
no_tmp() { ! ls -a | grep -q 'kci-tmp'; }
# every refusal test starts without an output file, so one failure cannot cascade into the next
dec_try() { rm -f out; "$KCI" dec "$@" out 2>/dev/null; }

printf 'correct horse battery staple\n' > pw
printf 'wrong horse\n' > pw.bad
MIN=100000

# --- selftest, keygen
check "selftest" '"$KCI" selftest >/dev/null'
check "keygen" '"$KCI" keygen key && [ "$(size key)" = 32 ]'
check "keygen file is private (0600)" '[ "$(stat -c %a key 2>/dev/null || stat -f %Lp key)" = 600 ]'
check "keygen refuses to overwrite" '! "$KCI" keygen key 2>/dev/null'
cp key key.old
check "keygen -f overwrites" '"$KCI" keygen -f key && ! cmp -s key key.old'
"$KCI" keygen key2

# --- key-file round trips across chunk (64 KiB) and tag-holdback boundaries
for n in 0 1 15 16 17 63 64 65 65519 65520 65535 65536 65537 65552 65553 131072 1048576; do
    head -c "$n" /dev/urandom > p.$n
    if "$KCI" enc -k key p.$n c.$n && "$KCI" dec -k key c.$n d.$n && cmp -s p.$n d.$n \
       && [ "$(size c.$n)" = $((n + 56)) ]; then ok; else bad "key-file round trip, $n bytes"; fi
done
check "two encryptions of the same file differ (random nonce)" '"$KCI" enc -k key p.1048576 c2 && ! cmp -s c.1048576 c2'

# --- password round trips
check "password round trip (minimum iterations)" \
    '"$KCI" enc --password-file pw -i $MIN p.65537 cp && "$KCI" dec --password-file pw cp dp && cmp -s p.65537 dp'
check "password round trip (default 600000 iterations)" \
    '"$KCI" enc --password-file pw p.17 cpd && "$KCI" dec --password-file pw cpd dpd && cmp -s p.17 dpd'
check "iterations below the minimum refused" '! "$KCI" enc --password-file pw -i 99999 p.17 x 2>/dev/null && [ ! -e x ]'

# --- authentication failures: exit 2, no output, no temp files
dec_try --password-file pw.bad cp; rc=$?
check "wrong password -> exit 2, no output" '[ $rc = 2 ] && [ ! -e out ] && no_tmp'
dec_try -k key2 c.1048576; rc=$?
check "wrong key -> exit 2, no output" '[ $rc = 2 ] && [ ! -e out ] && no_tmp'
for spec in "body:40" "body:1000" "body:600000" "tag:-1" "tag:-16" "nonce:28" "nonce:39" "salt-free:12" "mode:4" "reserved:6"; do
    off=${spec#*:}
    cp c.1048576 t; flip t "$off"
    dec_try -k key t; rc=$?
    check "tampered $spec -> refused, no output" '[ $rc != 0 ] && [ ! -e out ] && no_tmp'
done
for f in 8 9 12 27; do   # iterations and salt bytes of a password file
    cp cp t; flip t $f
    dec_try --password-file pw t; rc=$?
    check "tampered password header byte $f -> refused" '[ $rc != 0 ] && [ ! -e out ] && no_tmp'
done
head -c $(( $(size c.65537) - 1 )) c.65537 > t
check "truncated by 1 byte -> refused" '! dec_try -k key t && [ ! -e out ]'
cp c.65537 t; printf 'x' >> t
check "1 byte appended -> refused" '! dec_try -k key t && [ ! -e out ]'
head -c 50 c.65537 > t
check "shorter than header + tag -> refused" '! dec_try -k key t && [ ! -e out ] && no_tmp'
check "not a KCI file -> refused" '! dec_try -k key p.1048576 && [ ! -e out ]'
python3 -I -c "import sys; b=bytearray(open('cp','rb').read()); b[8:12]=b'\xff\xff\xff\xff'; open('t','wb').write(b)"
check "hostile iteration count refused quickly" '! dec_try --password-file pw t'

# --- key type mismatches and overwrite protection
check "key file given for a password file -> refused" '! dec_try -k key cp'
check "password given for a key-file file -> refused" '! dec_try --password-file pw c.17'
check "both key sources -> refused" 'rm -f out; ! "$KCI" enc -k key --password-file pw p.17 out 2>/dev/null'
check "existing output refused" '! "$KCI" dec -k key c.17 d.17 2>/dev/null'
check "-f overwrites output" '"$KCI" dec -f -k key c.17 d.17 && cmp -s p.17 d.17'
check "decrypted output is private (0600)" '[ "$(stat -c %a d.17 2>/dev/null || stat -f %Lp d.17)" = 600 ]'

# --- raw mode
check "raw round trip" '"$KCI" enc --raw -k key p.65537 r 2>/dev/null && "$KCI" dec --raw -k key r dr 2>/dev/null && cmp -s p.65537 dr && [ "$(size r)" = $((65537 + 40)) ]'
check "raw file refused without --raw on dec" '! dec_try -k key r && [ ! -e out ] && no_tmp'
cp c.65537 t; flip t 4
check "downgrade (AEAD file, mode byte flipped to raw) refused" '! dec_try -k key t && [ ! -e out ] && no_tmp'
rm -f out; "$KCI" dec --raw -k key t out 2>/dev/null; rc=$?
check "downgraded file with --raw decrypts to garbage (raw keystream is separate, D-024)" \
    '[ $rc = 0 ] && python3 -I -c "import sys; a=open(\"p.65537\",\"rb\").read(); b=open(\"out\",\"rb\").read(); sys.exit(0 if sum(x==y for x,y in zip(a,b)) < 1024 else 1)"'
cp r t; flip t 4
check "upgrade (raw file relabelled as AEAD) fails authentication" 'dec_try -k key t; [ $? = 2 ] && [ ! -e out ] && no_tmp'
check "raw mode warns" '"$KCI" enc -f --raw -k key p.17 r 2>&1 >/dev/null | grep -q warning'
cp r t; flip t 45
"$KCI" dec -f --raw -k key t dr 2>/dev/null
check "raw mode is malleable (flip passes through undetected)" 'python3 -I -c "import sys; a=open(\"p.17\",\"rb\").read(); b=open(\"dr\",\"rb\").read(); sys.exit(0 if a[5]^b[5]==1 and a[:5]+a[6:]==b[:5]+b[6:] else 1)"'

# --- cross-implementation: C <-> independent Python file tool
head -c 300 /dev/urandom > x
check "C enc (key) -> Python dec" '"$KCI" enc -k key x xc && $PYFILE dec --key-file key xc xd && cmp -s x xd'
check "C enc (password) -> Python dec" '"$KCI" enc --password-file pw -i $MIN x xcp && $PYFILE dec --password-file pw xcp xdp && cmp -s x xdp'
check "Python enc (key) -> C dec" '$PYFILE enc --key-file key x yc && "$KCI" dec -k key yc yd && cmp -s x yd'
check "Python enc (password) -> C dec" '$PYFILE enc --password-file pw --iterations $MIN x ycp && "$KCI" dec --password-file pw ycp ydp && cmp -s x ydp'
check "Python enc (raw) -> C dec" '$PYFILE enc --key-file key --raw x yr && "$KCI" dec --raw -k key yr ydr 2>/dev/null && cmp -s x ydr'
head -c 5000 /dev/urandom > x5
check "C enc (key, 5000 bytes: AVX2 path when available) -> Python dec" '"$KCI" enc -k key x5 x5c && $PYFILE dec --key-file key x5c x5d && cmp -s x5 x5d'
check "Python enc (raw, 5000 bytes) -> C dec" '$PYFILE enc --key-file key --raw x5 x5r && "$KCI" dec --raw -k key x5r x5rd 2>/dev/null && cmp -s x5 x5rd'
cp xc t; flip t 100
check "Python also rejects a tampered C file" '! $PYFILE dec --key-file key t tz 2>/dev/null'

check "no temp files left behind" 'no_tmp'
echo "cli_test: $pass passed, $failn failed"
[ "$failn" = 0 ]
