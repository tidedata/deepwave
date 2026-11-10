#!/usr/bin/env bash
# Download the official hash/HMAC/HKDF test vectors into $ZUI_CORPUS/vectors/hash/upstream/ and
# record url + sha256 of every download in SOURCES.txt (CONTRACTS.md 3.2 rule 4). Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
source "$ROOT/tools/env.sh"
D="$ZUI_CORPUS/vectors/hash/upstream"
mkdir -p "$D"; cd "$D"
get() { # url file
  [ -f "$2" ] || curl -fsSL -m 120 -o "$2" "$1"
  printf '%s  %s  %s\n' "$(shasum -a 256 "$2" | cut -d' ' -f1)" "$2" "$1" >> SOURCES.new
}
: > SOURCES.new
NIST=https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents
get $NIST/shs/shabytetestvectors.zip shabytetestvectors.zip
get $NIST/sha3/sha-3bytetestvectors.zip sha-3bytetestvectors.zip
get $NIST/mac/hmactestvectors.zip hmactestvectors.zip
get https://keccak.team/obsolete/KeccakKAT-3.zip KeccakKAT-3.zip
get https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json blake2-kat.json
W=https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1
for f in hkdf_sha256 hmac_sha256 hmac_sha512 hmac_sha3_256 hmac_sha3_512; do get $W/${f}_test.json ${f}_test.json; done
get https://www.rfc-editor.org/rfc/rfc4231.txt rfc4231.txt
get https://www.rfc-editor.org/rfc/rfc5869.txt rfc5869.txt
get https://www.rfc-editor.org/rfc/rfc7693.txt rfc7693.txt
mv SOURCES.new SOURCES.txt
rm -rf x && mkdir x
unzip -qo shabytetestvectors.zip -d x/sha2
unzip -qo sha-3bytetestvectors.zip -d x/sha3
unzip -qo hmactestvectors.zip -d x/hmac
unzip -qo KeccakKAT-3.zip -d x/keccak
echo "ok: $(wc -l < SOURCES.txt) sources in $D"
