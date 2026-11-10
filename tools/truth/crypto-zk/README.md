# zui-zk-truth

Ground truth for the crypto-zk suites (`groth16`, `poseidon`, `zklogin`), produced by Mysten's own
code: fastcrypto / fastcrypto-zkp at rev `da61cd46013fdd65361e57f7b9d4ae2244f86430` (the rev
sui mainnet-v1.83.1 pins) and sui-types / sui-protocol-config from `$ZUI_SUI_SRC`.

Build (shared target dir, never a per-agent one):

    source tools/env.sh
    cargo build --release --manifest-path tools/truth/crypto-zk/Cargo.toml   # -> $CARGO_TARGET_DIR/release/zui-zk-truth

Commands:

    zui-zk-truth vectors <corpus> [poseidon|groth16|zklogin|zklogin-edge]   # writes $ZUI_CORPUS/vectors/<suite>/
    zui-zk-truth bench <poseidon|groth16-verify|zklogin-verify> --iters N --list FILE
    zui-zk-truth gen-poseidon <out.zig>                         # src/crypto/zk/poseidon_constants.zig

`vectors zklogin` scans every `chk/*.chk` blob of the corpus for zkLogin user signatures and
`AuthenticatorStateInner` JWK sets. Generation is deterministic (seeded RNGs); it reads only
local corpus files (no S3, no network).

## Formats (one JSON object per line)

`vectors/poseidon/fastcrypto.jsonl`

    {"id","fn":"bytes"|"merkle","in":[hex...],"out":hex|null,"err":"<Debug FastCryptoError>"|null}

`bytes` is `poseidon_bytes` (Move `poseidon::poseidon_bn254`): 32-byte LE inputs, LE output.
`merkle` is `poseidon_merkle_tree` (what `poseidon_zk_login` runs): canonical LE field elements.

`vectors/groth16/{bn254,bls12381}.jsonl`

    {"id","op":"prepare","curve","vk":hex,"pvk":[4 hex]|null,"err","nin":int|null,"nin_err"}
    {"id","op":"verify","curve","pvk":[4 hex],"inputs":hex,"proof":hex,"res":true|false|"<Debug err>"}

`prepare` is `api::prepare_pvk_bytes` plus `get_public_inputs_num(vk.len())`; `verify` is
`api::verify_groth16_in_bytes`. Keys come from arkworks setups of a circuit with k = 0..10 public
inputs; mutations flip bits, set the flag bits (0x40, 0x80, 0xc0), truncate, extend, swap in
non-subgroup G2 points and non-canonical scalars.

`vectors/zklogin/fns.jsonl`

    ascii    {"s","max","out":LE hex|null,"err"}          hash_ascii_str_to_field
    dec      {"s","fr":32B BE hex|null,"fr_err","fq":decimal|null,"fq_err"}   Bn254Fr/FqElement::from_str
    addr     {"seed","iss","padded","unpadded"}             get_zk_login_address / try_from_unpadded
    seed     {"salt","name","value","aud","out":decimal|null,"err"}           gen_address_seed
    nonce    {"pk","max_epoch","rnd","out"|null,"err"}      get_nonce
    checkid  {"addr","name","value","aud","iss","pin","res":true|"<Debug err>"}  verify_zk_login_id
    checkiss {"addr","seed","iss","res"}                    verify_zk_login_iss

`vectors/zklogin/jwks.jsonld`: the union of every JWK seen in the corpus' authenticator state
objects, `{"iss","kid","kty","e","n","alg","seen":checkpoint}` (latest sighting wins).

`vectors/zklogin/corpusNNN.items.jsonl` (400 items per file)

    {"id","seq","epoch","pv","delta","mode","legacy","jwks":bool,"sender":hex,"auth":hex (BCS after the 0x05 flag),
     "res":{"parse":"ok"|"<Debug err>","iss","kid","max_epoch","eph":hex(flag||pk),"unpadded","padded",
            "sender_match":"unpadded"|"padded"|"none","epoch_ok":bool,"v1","both","v2"}}

`parse` is `ZkLoginAuthenticator::from_bytes`; `v1`/`both`/`v2` are `verify_zk_login` with
`ZkLoginEnv::Prod` and `ZkLoginCircuitMode::{V1Only,Both,V2Only}` against the JWK union
(`jwks:false` items use an empty JWK map); `epoch_ok` is `verify_user_authenticator_epoch` with
the epoch's protocol-config delta. Each corpus signature also gets mutated variants (`/nojwk`,
`/maxepoch+1`, `/ephpk`, `/seed+1`, `/proofA`, `/proofB`, `/proofCz`, `/imod4`, `/hdr+A`, `/seed0`).

`vectors/zklogin/edge.items.jsonl` (`zklogin` or `zklogin-edge`; needs corpus000 and jwks.jsonld)

Same shape as the corpus items plus `"xjwk":{"iss","kid","n"}|null`. Each item is the first
verifying corpus authenticator with one field replaced: the iss claim text (serde_json escapes,
surrogates, duplicates, nesting depth 125..128, number overflow, long claims up to 6,000 bytes),
the raw iss value for the bit decoder, the JWT header JSON (array form, typ, duplicates, ignored
values up to 90,000 deep, BOM, the 248/279 length limits) or the JWK modulus (leading zeros, 2049/8192/8193 bits,
9,000 bytes, bad base64). When the replaced authenticator parses, `xjwk` adds one JWK for its own
(iss, kid), consulted before the union, so verification runs on into input hashing and Groth16.
