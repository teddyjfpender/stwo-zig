# Candidate curve, field and Keccak-sponge services: ABI (2026-11-01)

CONTEXT.md is locked, so the ABI of the `0x0003_01xx` candidates lives here.
Executor: `src/frontends/riscv/rv64/ethereum_services/candidate_curves.zig`,
dispatched from `candidate_services.zig` under profile
`ethereum_services_v3_candidate` (execution-only, never promotable). Client
glue: `client_evmone/glue/candidate_curves.hpp`, `curves_stwo.cpp`,
`keccak_stwo.cpp`, patches `0020-evmone-candidate-curves.patch` and
`0021-blst-candidate-curves.patch`. Costs: `proposals/candidate-curve-costs.json`.

The granularity follows ZisK's precompile list (`ziskos/entrypoint/src/syscalls`:
`bn254_curve_add/dbl`, `bn254_complex_mul`, `bls12_381_curve_add/dbl`,
`bls12_381_complex_mul`, `arith384_mod`), plus a Montgomery variant of
`arith384_mod` for blst and a Keccak-256 sponge.

## Common rules

- `a0` = 8-byte aligned packet; `a7` = tag; all registers preserved; one
  retired instruction (the ECALL) per call.
- **Packets hold pointers** (as ZisK's `SyscallArith384ModParams` and its
  two-operand curve calls), except the sponge's `len` and `flags`. Each pointer
  must be 8-byte aligned (`MisalignedAddress` otherwise). The guest passes its
  own field elements in place, so no operand is copied into a packet.
- Values are little-endian u64 limbs, limb 0 least significant: 4 limbs per
  BN254 value, 6 per BLS12-381 / 384-bit value. A point is `x` then `y`; an Fp2
  element is `c0` then `c1` (`c0 + c1·u`, `u² = -1`), contiguous.
- Every input is read and every precondition checked before the single output
  store. A trapping call changes nothing. The output may alias any input.
- Precondition violations trap **`CandidateDomain`**: the AIR for such a call
  is unsatisfiable, so the guest must handle these cases itself.
- Reported `bytes` is 0 except for the sponge.

## Tags

| Tag | Name | Packet | Semantics | Preconditions |
|---|---|---|---|---|
| `0x0003_0100` | `bn254_g1_add` | `r, p, q` | affine `r = p + q` (chord rule, `y² = x³ + 3`) | all coordinates `< p`; `x_p ≠ x_q` |
| `0x0003_0101` | `bn254_g1_double` | `r, p` | affine `r = 2p` (tangent rule) | coordinates `< p`; `y ≠ 0` |
| `0x0003_0102` | `bn254_fp2_mul` | `r, a, b` | `r = a·b` in `Fp[u]/(u²+1)`, plain form | none: inputs are reduced first; output canonical |
| `0x0003_0110` | `bls12_381_g1_add` | `r, p, q` | as `bn254_g1_add` on `y² = x³ + 4`, **Montgomery residues** (`x·2³⁸⁴ mod p`, blst's form) in and out | coordinates `< p`; `x_p ≠ x_q` |
| `0x0003_0111` | `bls12_381_g1_double` | `r, p` | as `bn254_g1_double`, Montgomery residues | coordinates `< p`; `y ≠ 0` |
| `0x0003_0112` | `bls12_381_fp2_mul` | `r, a, b` | `r = a·b·2⁻³⁸⁴` per coefficient of the Fp2 product (blst's `mul_mont_384x`) | none; output canonical |
| `0x0003_0120` | `arith384_mod` | `a, b, c, m, r` | `r = (a·b + c) mod m`; `m = 0` gives `r = 0` | none |
| `0x0003_0121` | `arith384_mont` | `a, b, m, r` | `r = a·b·2⁻³⁸⁴ mod m` (canonical); `m = 1` gives 0 | `m` odd |
| `0x0003_0130` | `keccak_sponge` | `state, in, len, flags` | Keccak-256 sponge (rate 136) over `len` bytes at `in` (any alignment) into the 25 little-endian lanes at `state` | see below |

Points are not checked to be on the curve: the formula is evaluated as is, as
in ZisK. The guest validates precompile inputs (evmone's `validate`, blst's
decompression and subgroup checks) before calling.

Why a Montgomery variant: blst keeps every Fp element as `x·2³⁸⁴ mod p`.
`a·b = r·2³⁸⁴ + q·m` is the same convolution row as `a·b = q·m + r`, so the AIR
cost is the same, and blst needs no change of representation. evmone's BN254
code already runs in plain form in candidate builds (patch 0004's `kPlain`), so
the BN254 services are plain, as in ZisK.

## `keccak_sponge`

- `flags` bit 0 = **finalize**: after the full blocks, absorb the remaining
  `len mod 136` bytes with Keccak padding (`0x01` after the data, `0x80` in the
  last rate byte) and permute. bit 1 = **fresh**: start from the zero state
  (`state` is not read). Other bits trap.
- Without finalize, `len` must be a multiple of 136 (else `CandidateDomain`).
- One permutation per full block plus one for the padded block. The whole
  25-lane state is written back; the digest is lanes 0..3 (bytes 0..32).
- **Padding responsibility:** the service pads only when asked (finalize). A
  guest hashing a message across several calls absorbs whole blocks without
  finalize and passes the tail with finalize.
- `len ≤ 256 MiB` (`CandidateLengthLimit`); `in` needs read permission over
  exactly `[in, in + len)`, `state` needs write permission (and read unless fresh).
- Reported `bytes` = 136 × permutations (rate bytes absorbed, padding
  included), so the cost model charges per permutation.

## Client routing (build groups)

`build.py --profile candidate --candidate-set mem,sha,arith,bn,bls,keccak`:

| Group | Define | Routed |
|---|---|---|
| `bn` (needs `arith`) | `CANDIDATE_BN` | ecMul: `bn254::mul` -> `stwo_bn254_g1_mul` (4-bit fixed window, affine add/double services, scalar reduced mod r); ecAdd: `bn254::add` -> `stwo_bn254_g1_add`; ecPairing: Fq2 `multiply`/`sqr` in the pairing tower -> `bn254_fp2_mul`. The guest handles infinity, `P = Q` (double) and `P = -Q` before calling. |
| `bls` | `CANDIDATE_BLS` | blst `mul_mont_n` and `mul_mont_nonred_n` for 384-bit operands -> `arith384_mont`; `mul_fp2`/`sqr_fp2` -> `bls12_381_fp2_mul`. Covers KZG point evaluation (0x0a) and every EIP-2537 operation (none occur in the basket). |
| `keccak` | `CANDIDATE_KECCAK` | `ethash_keccak256` for inputs over 64 bytes: one fresh+finalize sponge call. Inputs of at most 64 bytes keep the memoized admitted Keccak-f path. |

`bls12_381_g1_add/double` and `arith384_mod` are implemented and tested in the
executor but not used by the client yet (blst's G1 code is Jacobian and rides
on the Fp/Fp2 services; nothing in the client needs a plain 384-bit modmul).

## Tests

- Executor (`zig test src/frontends/riscv/rv64/ethereum_execution.zig`, 15 tests):
  BN254 `G, 2G, 3G, 5G` and `[r-1]G = -G` by double-and-add on the service
  formulas; BLS12-381 `2G, 3G` in Montgomery form (generator equals blst's /
  kzg.cpp's constant); Fp2 and arith384 vectors from an independent Python
  big-integer oracle; preconditions trap with memory unchanged; sponge equals
  `std.crypto` Keccak-256 for lengths 0..559 at two alignments, split
  absorb + finalize, flag and length traps.
- Client host tests (`build.py --host --tests`, `tests/curves_test.cpp`, all
  hooks live with portable blst, services emulated in `glue/host_services.cpp`):
  ecMul on 40 random points × 18 scalars (edge scalars 0, 1, 2, 3, 15-17,
  r-1, r, r+1, 2r, 5r+7, 2²⁵⁶-1, 2²⁵⁵) and ecAdd (P+Q, P+P, P-P, P+O, O+Q) vs a
  naive intx double-and-add; Fq2 multiply/sqr (2,000 each) vs the formula; blst
  Fp/Fp2 products (2,000 each) vs intx Montgomery arithmetic; pairing
  bilinearity `e([a]G1, G2) = e(G1, [a]G2)` and a negative; evmone's KZG unit
  vectors plus a wrong-evaluation negative; sponge vs the admitted-path
  `ethash_keccak256` for every length 0..600 at all 8 alignments. The test
  asserts each service was actually called (`stwo_host_curve_calls`).
- Basket: exact outputs on all 15 blocks for every variant (6 blocks with BN254
  precompiles, 5 KZG point evaluations on 4 blocks).

Not covered: EEST (blocked for the whole client, see client README), EIP-2537
operations end to end (none in the basket; the Fp/Fp2 hooks are exercised by
the pairing and KZG host tests), adversarial off-curve inputs to the services
(the guest validates before calling).

## Reproduce

```sh
C=<scratch>; B=autoresearch/benchmarks/guest_runtime/ethereum/client_evmone
python3 -I autoresearch/guest_efficiency/bench.py build-exec --out $C/exec
python3 -I $B/build.py --out $C/client --profile candidate --candidate-set mem,sha,arith,bn,bls,keccak
python3 -I $B/build.py --out $C/host --host --tests        # adapter host binary + host tests
# score with both cost files swapped into calibration (calibration.json is locked):
python3 -I <scratch>/bench_with_costs.py run --elf $C/client/client-evmone-candidate-mem-sha-arith-bn-bls-keccak.elf \
  --executor $C/exec/bin/rv64-ethereum-execution --cache <cache> --out <out> --set all --jobs 4 \
  --profile ethereum_services_v3_candidate --client evmone \
  --input-adapter "python3 -I $B/adapter.py --host-binary $C/host/client-evmone-host"
```

`bench_with_costs.py` is the sibling track's wrapper extended to load
`candidate-service-costs.json` and `candidate-curve-costs.json` together.
