# Wire format: proofs, weight keys, statements

Adversarial-review finding P12: proof sizes were struct-field sums and the
verifier only ever saw in-memory structs. FlashProve ships `cp_verify`, a C++
verifier that parses untrusted proof files, plus a Lean executable verifier.
`src/tensor/wire.zig` gives us the equivalent: a canonical binary encoding, a
strict bounded decoder, and the `tensor-verify` CLI that verifies from files.

## Files

| file | kind | contents |
|---|---|---|
| `statement.bin` | 3 | the statement (witness / weight shapes, tables, ops, ext ops, publics, ext tables) and the verifier config |
| `key.bin` | 2 | the weight key (root, geometry, infos, offsets) and its one-time key proof (histogram, LogUp-GKR, W(rho), opening) |
| `proof.bin` | 1 | one `protocol.Proof` |

```
tensor-bench product 20 1 54 2 20 --emit out/     # or mlp ... / layer ... --emit out/
tensor-verify out/                                # or: tensor-verify s.bin k.bin p.bin
zig build verify -- out/
```

`tensor-verify` decodes the statement, then the key against it, verifies the
key proof, derives the proof caps, decodes the proof and verifies it. It prints
one JSON line (`ok`, the statement's Blake2s digest, file sizes, security
bits, decode and verify times) and exits 1 with the error name on rejection.
The statement is mixed into the Fiat-Shamir transcript, so a proof is bound to
the statement it was made for; a client pins *which* statement it expects by
its digest.

## Container

```
"STZW"  version:u8 (= 1)  kind:u8  section*
section = tag:u8  len:u32  body[len]
```

- Sections appear in strictly increasing tag order; each body is fully
  consumed by its schema (`SectionLength` otherwise).
- Required sections must be present (`MissingSection`); optional sections
  encode `?T` fields (absent = null). A tag that is not in the kind's tag set
  is `UnknownTag`; a repeated or out-of-order tag is `TagOrder`; anything
  after the last section is `TrailingBytes`.
- The magic + kind byte are the domain tag: a key file is never decoded as a
  proof (`BadKind`), a future format never as this one (`BadVersion`).

Primitive encodings (all little-endian):

| value | encoding | rule |
|---|---|---|
| length | u32 | at most the field's cap, and `n * min_elem_bytes <= bytes left` |
| M31 | u32 | `< P` (`NonCanonicalField`) |
| QM31 | 4 x u32 limbs | each `< P` |
| hash | 32 bytes | |
| bool / presence flag | u8 | 0 or 1 (`NonCanonical`) |
| PoW nonce | u64 | must be 0 when that level's `pow_bits = 0` (the nonce is unchecked then) |

## Schemas

**Proof** (kind 1):

| tag | field | body |
|---|---|---|
| 0x01 | witness_root | hash |
| 0x02 | witness_ood (opt) | QM31; present iff the config runs pcs2 with OOD |
| 0x03 | gkr (opt) | GKR batch proof; present iff the statement has LogUp relations |
| 0x04 | lookup_in_values | vec QM31 |
| 0x05 | op_sumchecks | len, then `sumcheck` each |
| 0x06 | op_finals | len (= op_sumchecks), then vec QM31 each |
| 0x07 | batch_sumcheck | sumcheck |
| 0x08 | witness_value | QM31 |
| 0x09 | witness_opening | opening |
| 0x0a | weight_opening (opt) | opening; present iff the statement has a matmul |
| 0x0b | ext_values | vec QM31 |
| 0x0c | ext_sumchecks | len (= #einsum), then sumcheck each |
| 0x0d | ext_finals | len (= #einsum), then 2 x QM31 each |

- `sumcheck` = `deg:u8  n_rounds:u32  (deg x QM31) per round` (the round
  polynomial's values at 0, 2, .., deg).
- GKR = `n_layers:u32` then per layer `n_polys:u32` and per polynomial
  `n_coeffs:u8 coeffs`; then `n_inst:u32` and per instance `n_masks:u32`, per
  mask `n_cols:u32 (2 x QM31) per column`, then the output claims as vec QM31.
  Polynomials are trimmed (the last coefficient is non-zero), as
  `UnivariatePoly.initOwned` stores them.
- `opening` = variant byte (0 flat, 1 pcs2) then
  - flat: `n_rows:u32`, rows (vec QM31 each), `pow:u64`, `n_cols:u32`, per
    column `index:u32  values:vec M31  path:vec hash`;
  - pcs2: `n_levels:u32`, per level `pow:u64  col_values:vec M31
    decommit:vec hash`, then the final level's rows (`n_rows:u32`, vec QM31
    each), or for a non-final level `inner_root:hash  sumcheck
    limb_vals:4 x QM31  ood_flag:u8 [QM31]`. The fields a level does not use
    are not encoded (the encoder refuses a proof that sets them).

**Key** (kind 2): 0x01 root, 0x02 geometry (`log_rows:u32 log_cols:u32
rows_used:u64`), 0x03 infos, 0x04 offsets (u64 each), 0x10 histogram (256 x
u32), 0x11 GKR, 0x12 value, 0x13 opening. The decoder recomputes the weight
layout of `statement.weights` and `cfg.weight_log_cols` (as `commitWeights`
does) and requires the infos, offsets and geometry to equal it exactly.

**Statement** (kind 3): 0x01 config, 0x02 witness infos, 0x03 weight infos
(`n_dims:u8` + one u8 per used dim; unused dims are zero), 0x04 tables (256
i8 each), 0x05 ops (op tag 1..6 as in `mixStatement`, u32 operands, shift
u8), 0x06 ext ops (einsum / key / lineq with refs, 32-byte label arrays,
exprs of `coeff:i64 ref labels` terms + constant), 0x07 publics (log size +
exactly 2^log i32 values), 0x08 ext lookup tables. The config holds what the
verifier reads: `pcs`, `two_level` (outer, inner, depth, inner_work_shift,
prox_rows, deep, ood), `batch_matmuls`, `weight_outer`, `key_outer`,
`key_alphas`, `weight_log_cols`, `witness_log_cols_max`. Prover-only fields
(threads, accelerators, prefaulting) are not encoded. Hiding mode (`zk.zig`,
a different proof type) is refused by the encoder (`Unsupported`).

## Caps

Every length is bounded before anything is allocated, by a cap derived from
the decoded statement, config and key (`wire.proofCaps`, plus
`protocol.wireShape`, the only hook into `protocol.zig`), and by the bytes
left in the input. All decoded data lives in one arena per file, so a
rejected file frees everything and nothing is allocated beyond a small
multiple of the input size.

| field | cap |
|---|---|
| GKR layers | = max instance log size; layer `l` has exactly `l` round polynomials, <= 4 coefficients each |
| GKR instances / masks / columns / output claims | = #relations (keys + tables) / = the instance's log size / = 2 / = 2 |
| lookup_in_values | <= 2 x #keys |
| op_sumchecks | <= #matmul + #hadamard + #product; rounds <= witness log total; deg 2..3 |
| op_finals | count = op_sumchecks; each <= max(3, 2 x #matmul) |
| batch_sumcheck | rounds = witness log total, deg 2 |
| ext sumchecks / finals | = #einsum; rounds <= n_out + n_k of that einsum |
| ext values | <= #exact einsums with y + #committed terms in key / lineq exprs |
| flat opening | rows = groups + proximity, each 2^log_cols; columns = n_queries; index < 2^(log_cols + blowup); values = rows_used; path = log_cols + blowup |
| pcs2 opening | levels = depth + 1; per level, the shapes `pcs2.levelInfos` gives for every admissible group count (witness and key: exactly one; weights: 1 .. #matmul): col_values <= n_queries x rows_used, decommit <= n_queries x log_ext, final rows count and length in the derived range, inner sumcheck rounds <= log_g + log_cols, deg 2; OOD only on non-final levels and only with `ood` |
| key | geometry, infos, offsets exactly as derived; histogram entries <= 2^n; GKR instances `[n, 8] x key_alphas` |
| statement | <= 4096 tensors / tables, <= 2^16 ops / ext ops / expr terms, tensor log size <= 40, publics <= 2^24 values, ext tables <= 2^20 |
| config | blowup 1..10, queries 1..4096, PoW <= 40, depth <= 8, prox_rows 1..16, key_alphas 1..2, log cols <= 30, log(cols x blowup) <= 30 |

The decoder bounds shapes; the verifier still checks every exact count it
depends on (it is unchanged and also runs on in-memory proofs). Where the
decoder checks a count exactly, it is one the verifier would reject anyway.

## Canonicity

There is one encoding per value: fixed-width integers, explicit lengths,
canonical field elements, 0/1 bools, trimmed GKR polynomials, sumcheck
rounds as exactly `deg` values, zero nonces without PoW, no unused level
fields, sections in a fixed order. Tests check `decode(encode(x)) == x`
(`wire.deepEql`: field elements by value, GKR polynomials by their trimmed
coefficients, sumcheck rounds by their first `deg` values) and that
`encode(decode(encode(x)))` is byte-identical, for the statement, key and
proof of each case.

Not canonical in the semantic sense: the statement file carries config
fields the selected PCS ignores (e.g. `witness_log_cols_max` under pcs2,
`pcs` when `two_level` is set). Two statement files that differ only there
verify the same proofs but have different digests.

## Adding a field

Give it a new section tag in its kind's tag enum (place it where the
transcript order makes sense; tags only need to increase). Make it optional
when older proofs lack it, required otherwise, and bump `VERSION` when old
decoders must refuse the new files (they would reject the unknown tag
anyway). Extend `proofCaps` with its cap and `wire_test.zig` gets roundtrip
and fuzz coverage for free (the fuzzer mutates every length field the
encoder writes).

## Sizes (encoded vs struct-field sum)

conj128 configs (54 queries, rate 1/4, 20-bit PoW, pcs2 depth 2, inner 54
queries), Apple M4 Max on AC power:

| case | struct sum (`proof.sizes()`) | encoded proof | overhead | key (struct / encoded) | statement |
|---|---|---|---|---|---|
| `product 20 1 54 2 20` | 117,976 | 118,123 | +147 B (0.12%) | 5,512 / 5,810 | 162 |
| `mlp 9 11 12 12 54 2 20` | 311,632 | 312,885 | +1,253 B (0.40%) | 179,208 / 179,952 | 485 |
| `layer 9 11 12 4 12 54 2 20 2 1 0 9 1 2 54` | 460,248 | 465,234 | +4,986 B (1.08%) | 202,120 / 202,919 | 1,598,367 |

The overhead is framing: 6 header bytes, 5 bytes per section, a u32 per
vector (every combined row, every opened column vector, every op final list),
a byte per sumcheck degree and GKR polynomial, the flat column indices. The
layer pays most because it has the most sumchecks and GKR polynomials (47 ext
ops). All three files verified from disk with `tensor-verify` (layer: 14.5 ms
verify, 0.2 ms proof decode). The layer statement is 1.6 MB because it
carries its public tensors (RoPE tables, causal-mask biases); a client
verifies it once and pins its digest. `tensor-bench` reports these numbers as
`"encoded_bytes"` and `tensor_compare.py` tables now use them.

## Fuzzing

`wire_test.zig` builds tiny product (2^6, flat Ligero), mlp (T=4, D=16,
F=32; pcs2 depth 2 with OOD, two prox rows, deep levels, separate weight/key
outer parameters, two key alphas) and layer (T=4, D=16, F=32, fused QKV;
pcs2 depth 1 + batched matmuls) cases and mutates their encodings: random
byte flips, truncations, extensions, length-field corruptions (+-1, 0,
2^32-1, 2v+1, random, one bit; at every length offset the encoder wrote),
multi-byte flips, and splices (insert / delete in the middle). Every mutant
must be rejected by the decoder or the verifier with an error.

ReleaseSafe (and ReleaseFast), 1,200 proof + 300 key mutants per case:

| target | mutants | decoder rejects | verifier rejects | accepted |
|---|---|---|---|---|
| product proof | 1,200 | 893 | 307 | 0 |
| mlp proof | 1,200 | 910 | 290 | 0 |
| layer proof | 1,200 | 914 | 286 | 0 |
| keys (3 cases) | 900 | 723 | 177 | 0 |

No panic, crash or leak (Debug runs use the leak-checking test allocator).
Statement-file mutants (450) run the whole file pipeline and are all
rejected too, though for statements an accept would not be a bug in itself
(see Canonicity).

## Not covered

- Hiding-mode proofs (`zk.zig`) have their own proof type; this format
  refuses hiding configs.
- No compression. The decoder caps are upper bounds where the shape depends
  on the proof (pcs2 weight group counts, unique-query counts); the verifier
  enforces the exact values.
- A cross-implementation check (e.g. a second decoder in another language
  or the Lean model reading these files) is future work.
