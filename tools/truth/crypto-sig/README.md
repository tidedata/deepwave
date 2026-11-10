# zui-truth-sig

Ground truth for the crypto-sig lane. Every verdict, address, signature and recovered key in
these files is computed by Mysten's code at the versions sui-node mainnet-v1.83.1 runs:
fastcrypto `da61cd4`, ed25519-consensus 2.1.0 (curve25519-dalek 4.1.3), the `secp256k1` crate
0.27 (libsecp256k1), p256 0.13.2 / ecdsa 0.16.9, passkey-types 0.4.0, serde_json 1.0.145,
roaring 0.11.4, base64ct 1.8.0, bcs 0.1.6, and sui-types / sui-protocol-config from the
`tools/sui` tree. The tool generates inputs; it never re-implements a check.

```
source tools/env.sh
(cd tools/truth/crypto-sig && cargo build --release --offline)
T=$CARGO_TARGET_DIR/release/zui-truth-sig
$T vectors  $ZUI_CORPUS/vectors/sig-vectors/upstream/wycheproof $ZUI_CORPUS/vectors/sig-vectors/vectors.jsonl
$T uservec  $ZUI_CORPUS/vectors/sig-vectors/user.jsonl
$T zkvec    $ZUI_CORPUS $ZUI_CORPUS/vectors/sig-corpus/aux-src $ZUI_CORPUS/vectors/sig-vectors/zk   # ~6 s
$T corpus   $ZUI_CORPUS $ZUI_CORPUS/vectors/sig-corpus          # ~12 s on 16 threads (reads vectors/sig-corpus/aux-src/)
$T scan     $ZUI_CORPUS                                         # survey: pinned alias versions, zkLogin txs
$T bench <name> --iters N --list <file>                           # harness baselines
```

All generation is seeded (ChaCha20 / splitmix64), so reruns are byte-identical.

## Verdicts

`"ok"`, or the error the Rust code returned:

| form | where it comes from |
|---|---|
| `pk:<FastCryptoError>` | parsing the public key (`from_bytes`) |
| `sig:<FastCryptoError>` | parsing the signature |
| `verify:<FastCryptoError>` | `verify` / batch verify |
| `recover:<FastCryptoError>` | `recover_with_hash` |
| `parse:<FastCryptoError>` | `GenericSignature::from_bytes` |
| `<SuiErrorKind variant>` | `verify_authenticator`, `SuiAddress::try_from`, `verify_sender_signed_data_message_signatures` (e.g. `InvalidSignature`, `IncorrectSigner`, `KeyConversionError`, `SignerSignatureNumberMismatch`, `SignerSignatureAbsent`) |

## vectors/sig-vectors/vectors.jsonl (suite sig-vectors)

One JSON object per line; `id` names the source (`wycheproof/<curve>/<tcId>`, `zip215/<n>`,
`gen/...`). All byte fields are lowercase hex.

| op | fields | compared |
|---|---|---|
| `ed25519_verify` | `pk`, `msg`, `sig`, `v` (`wy`: Wycheproof's own result, informational) | verdict |
| `ed25519_sign` | `sk` (32-byte seed), `msg`, `out` (64-byte signature) | signature bytes |
| `ed25519_batch` | `items` (`[pk, msg, sig]` list), `v` (ed25519-consensus batch verifier) | verdict |
| `secp256k1_verify`, `secp256r1_verify` | `h` (`sha256` / `keccak256`), `pk`, `msg`, `sig`, `v` | verdict |
| `secp256k1_recover`, `secp256r1_recover` | `h`, `msg`, `sig` (65 bytes, last is the recovery id), `v`, `out` (33-byte compressed key when ok) | verdict and key |

Sources: Wycheproof (C2SP/wycheproof `d17cc89f`, files and sha256 in `upstream/wycheproof/SOURCE`:
ed25519, ecdsa secp256k1/secp256r1 sha256 p1363), every ZIP-215 small-order (A, R) encoding
pair, scalar edges (s = l, s + l, ...), and seeded generated cases per curve: valid signatures,
every recovery id, high s, edge r/s, key encodings (prefixes 00/01/04/05/06/07/ff, x >= p, x = 0),
Keccak and SHA-256, bit flips.

## vectors/sig-vectors/user.jsonl (suite sig-vectors, op `user_sig`)

Synthesized user signatures, each through exactly the path `corpus` uses for a real one:

```
{"id":"user/<kind>/<n>","op":"user_sig","flags":{...},"msg":"<intent bytes>","sig":"<GenericSignature bytes>",
 "author":"<address>","v":"<verdict>","addr":"<hex>"|"err:<kind>"|null}
```

`flags` are the `VerifyParams` booleans for the case (`accept_zklogin_in_multisig`,
`accept_passkey_in_multisig`, `accept_mldsa65_in_multisig` (always false: never on mainnet),
`additional_multisig_checks`, `validate_zklogin_public_identifier`,
`verify_legacy_zklogin_address`), epoch 0. `addr` is `SuiAddress::try_from(&sig)`, null when
`from_bytes` failed. Kinds: `single` (every flag and length, secp256r1 compact keys, high s,
MLDSA65 shape), `passkey` (about 110 clientDataJSON shapes: serde_json grammar, escapes,
surrogates, numbers at the f64 limits, nesting at the recursion limit, duplicate and unknown
fields, the enum-object form of `type`, challenge encodings; plus user-signature variants),
`multisig` and `legacy` (1 to 10 members of every key kind including zkLogin identifiers and
MLDSA65 keys, weights, thresholds, duplicate keys, bitmaps, roaring container forms, base64 key
forms), each with `-mut` (bit flips, truncation, extension) and `-author` (wrong author)
variants. zkLogin signatures themselves are not generated (zk lane).

## vectors/sig-corpus/<seq>.jsonl.zst (suite sig-corpus)

One file per corpus checkpoint. Line 1:

```
{"k":"Header","seq":..,"epoch":..,"pv":..,"flags":{<VerifyParams for that protocol version>},
 "sigs":<user signatures>,"mutations":<mutated items>,"zklogin_txs":<txs with a zkLogin signature>,
 "jwks":[{"iss","kid","kty","e","n","alg"},..]}            # only when zklogin_txs > 0
```

`flags` are the `VerifyParams` the SignatureVerifier builds from the protocol config of the
checkpoint's epoch (mainnet): the booleans, `zklogin_max_epoch_upper_bound_delta`,
`zklogin_circuit_mode` (0 V1Only, 1 Both, 2 V2Only) and `zklogin_supported_providers` (OIDCProvider
Debug names; non-empty for protocol versions 25 to 29). `ZkLoginEnv` is Prod.

`jwks` is the JWK map a validator holds while executing this checkpoint (sui-core
`AuthorityPerEpochStore`): every active JWK of the latest authenticator state written before the
epoch's first checkpoint, then the JWKs of every authenticator state version written in this
epoch up to and including this checkpoint (first insertion wins, nothing is removed inside an
epoch). The state versions come from the input and output objects of every corpus blob plus
`aux-src/`. With aux-src as fetched (CORPUS.md), every zkLogin transaction of the corpus sees the
state version that was current at its checkpoint.

Then per transaction (in order):

```
{"k":"tx","tx":i,"system":bool,"signers":["<required signer>",..],"v":"<verdict>","idx":[..]|null,
 "aliases":[["<signer>",["<alias>",..]],..]}               # only when a signer's aliases are pinned
{"k":"sig","tx":i,"sig":j,"scheme":"..","m":null|"sig:<off>:<xor>"|"msg:<off>:<xor>"|"author:<off>:<xor>",
 "author":"<address used>","addr":"<hex>"|"err:<kind>"|null,"v":"<verdict>"}
```

- `tx` lines: `verify_sender_signed_data_message_signatures` on the transaction as stored, with
  the checkpoint's JWKs and the aliases the checkpoint pins: `CheckpointContentsV2` records, per
  required signer, the version of the AddressAliases object used to verify it. For a pinned
  version the alias list is that object version's `aliases` (sui-core
  `verify_tx_with_current_aliases`; an empty list falls back to the signer); unpinned signers
  are their own only alias. Object versions not written inside the corpus come from the
  checkpoints in `aux-src/`. `idx` is the returned signature index per required signer.
  `signers` is `TransactionData::required_signers()` (deepwave derives it from the bytes and checks
  it against this).
- `sig` lines: the signature bytes are `tx[i].sig[j]` of the dumper truth (BCS byte vector) and
  the intent message is `raw[o-3 .. o+n]` of `tx[i].data` (Intent ++ TransactionData). `m`
  describes a seeded mutation applied before the check: flip `xor` at byte `off` of the
  signature (never the flag byte), of the intent message (never the 3 intent bytes), or of the
  author. Plain Ed25519 signatures get 1 mutation, every other scheme (zkLogin included) 12.
  zkLogin verdicts include `InvalidAddress` (author is neither derived address) and the
  `parse:<FastCryptoError>` of `ZkLoginInputs::init`.

`vectors/sig-corpus/aux-src/<seq>.chk`: mainnet checkpoints outside the corpus plan, read only by
`corpus` (never by deepwave): the writers of the AddressAliases versions pinned by corpus transactions
and of the authenticator state versions current at corpus checkpoints that carry zkLogin
signatures (found with GraphQL `object(address, atCheckpoint|version).previousTransaction`,
fetched from the S3 archive; SOURCE lists them).

## vectors/sig-vectors/user.jsonl, op `user_tx`

```
{"id":"user/alias-<kind>/<n>","op":"user_tx","flags":{...},"msg":"<Intent ++ BCS(TransactionData)>",
 "sigs":["<GenericSignature>",..],"aliases":[["<signer>",["<alias>",..]],..],"v":"<verdict>","idx":[..]|null}
```

`verify_sender_signed_data_message_signatures` with the given aliases over programmable
transactions with a sender and sometimes a sponsor, signed by a pool of Ed25519, secp256k1 and
secp256r1 keys. Kinds: `aliased` (signed only by an alias), `none-signed` (no alias signed,
including the signer itself when it is not in its own set), `both-signed` (signatures for the
signer and its alias, in both alias orders), `self`, and 1,500 seeded `random` cases (alias sets
of 1 to 3 including the signer or not, one signature too many or too few, some signatures over
the wrong message).

## vectors/sig-vectors/zk/NNN.jsonl.zst (suite sig-vectors, op `user_sig`)

```
{"id":"zk/<seq>/<tx>/<sig>/<kind>","op":"user_sig","epoch":<u64>,"flags":{... all VerifyParams fields,
 including zklogin_max_epoch_upper_bound_delta, zklogin_circuit_mode, zklogin_supported_providers},
 "jwks":[{"iss","kid","kty","e","n","alg"},..],"msg","sig","author","v","addr"}
```

Every mainnet zkLogin signature in the corpus (2,008), re-wrapped so its real Groth16 proof and
ephemeral signature go through paths the chain corpus never takes (no corpus transaction has a
zkLogin member inside a MultiSig). The VerifyParams are `params_for(pv)` of the checkpoint's
epoch with the variant's changes; the JWK map is exactly `jwks` (the checkpoint's JWKs with the
signature's kid, or none). Kinds, 24 per signature:
- `ms1`: a 1-of-1 MultiSig whose member key is the signature's own padded
  ZkLoginPublicIdentifier; `-noaccept` (accept_zklogin_in_multisig off), `-legacy-off` /
  `-legacy-on` (verify_legacy_zklogin_address), `-nojwk`, `-expired` (epoch max_epoch + 1),
  `-last-epoch` (epoch = max_epoch, delta 0), `-too-far` (max_epoch > epoch + delta),
  `-providers` (a random provider list), `-flip0..2` (a bit flipped in the member bytes),
  `-unpadded-id` (identifier with the unpadded seed, random validate_zklogin_public_identifier),
  `-wrong-seed`, `-ed-key` (an Ed25519 member key holding the zkLogin signature, random
  additional_multisig_checks), `-ed-sig` (the zkLogin key holding an Ed25519 signature).
- `ms2`: beside an Ed25519 member, both orders, weights 0 to 2, random threshold (some
  thresholds make the key undecodable: `parse:InvalidInput`); `ms2-zk-only`: only the zkLogin
  member signs.
- top level: `top-providers`, `top-padded-legacy-false|true` (the legacy padded address as the
  author), `top-last-epoch`, `top-expired`, `top-nojwk`.
Shards hold whole checkpoints, about 1,000 lines each; the suite runs them in parallel.

## Bench names

`ed25519-verify` (parsed key), `ed25519-verify-bytes` (parse + verify), `ed25519-batch`,
`ed25519-sign`, `secp256k1-verify`, `secp256r1-verify`, `secp256k1-recover`,
`secp256r1-recover` (all over the `ok` items of vectors.jsonl), and `user-sig` (every
non-zkLogin, non-system user signature of the listed `chk` blobs through
`verify_authenticator`, signatures decoded outside the timed loop).
