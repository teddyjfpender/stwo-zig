# RV64 Ethereum guest: lean secp256k1 recovery, 2026-10-31

Guest-side change only. The RV64 execution profile, the service ECALL tags
and packet layouts, the AIR, the prover and the verifier are untouched. The
new guest executes the same pinned block (24,628,607, canonical SSZ input
`845b7c92…8065c`) to the same 43-byte output with 30.1% fewer instructions and
about half the secp256k1 service calls.

| Measure | services-v2 guest | services-v2-lean guest | Change |
| --- | ---: | ---: | ---: |
| Instructions | 213,659,488 | 149,306,899 | −30.1% |
| secp256k1 ADD service calls | 24,960 | 11,496 | −53.9% |
| secp256k1 DOUBLE service calls | 19,968 | 9,768 | −51.1% |
| Keccak service calls | 32,835 | 32,835 | 0 |
| Service RAM word transitions | 1,659,531 | 1,213,995 | −26.8% |
| Loads / stores | 38.4M / 27.2M | 27.7M / 20.0M | −28% / −26% |
| ELF SHA-256 | `31c55e23…a8dc` | `691ff478…e2bb` | |

Every proven batch is CPU rows plus service providers, so this removes about
30% of CPU rows and about half of the secp provider rows from a block proof
before any prover work. The original guest-branch evidence is execution-only;
the mainline proof qualification below is separate.

## Mainline full-block proof qualification

The pinned `691ff478…e2bb` guest now has a complete native proof chain and an
independent fresh-process receiver acceptance on block24,628,607. Both runs below
use16workers on the same M5Max64GiB host. These are single isolated observations
of different guest workloads, not a statistically qualified kernel speedup.

| Measure | Previous v2 guest | Lean guest |
| --- | ---: | ---: |
| Complete producer invocation | 1234.76s | 910.62s |
| Fresh receiver invocation | 13.66s | 12.97s |
| Producer maximum RSS | 36,591,828,992B | 36,058,120,192B |
| Receiver maximum RSS | 3,472,146,432B | 3,441,426,432B |
| Batch proofs, plus one terminal proof | 51 | 36 |
| Total encoded proof bytes | 150,876,796 | 100,582,942 |

This is26.25% less observed producer time and33.33% fewer proof bytes. There is
**no recursive aggregation**. The16GB batch-memory target is not met. Receiver
setup still takes11.66s of12.97s, with32 cache misses and4 hits. Configuration is
q70/P26; this is not an audited128-bit security claim.

`complete-block-isolated-v1.json` pins the tool, configuration, source manifest,
all36 proof/receipt/profile triples and terminal proof. It checks final PC/all32
registers and the expected43-byte output against the independent oracle.
`batch-bottlenecks-v1.{json,csv}` records every batch's phases and memory. CPU
columns remain89.7% of main+interaction source cells. Another178.92s of proving
falls outside the existing named timers; further instrumentation is required.
Experimental Word16 and distributed-aggregate code was inactive in this run.

## What changed

1. **No redundant re-verification in recovery.** `ecdsa::VerifyingKey::
   recover_from_prehash` computed Q = r⁻¹(sR − zG) and then ran a second full
   double-scalar multiplication to verify the signature against Q. That check
   cannot fail once recovery succeeded: z s⁻¹ G + r s⁻¹ Q = R, whose
   x-coordinate reduces to r by construction, and `from_affine` already rejects
   the identity. revm normalizes S before calling recovery, so the low-S policy
   inside k256's `verify_prehashed` is also never exercised. The vendored
   `ecdsa` 0.16.9 (`vendor/ecdsa`) omits the check behind the feature
   `stwo-skip-redundant-recovery-verify` and inverts r in variable time; r is
   public signature data.
2. **Word-packet scalar multiplication.** The GLV double-and-add chain now keeps
   the accumulator and the eight table entries in service word form. Each
   service result feeds the next packet directly instead of decoding to
   5×52-bit limbs, re-normalizing and re-encoding on every call (20.3M
   instructions in the baseline). Table selection indexes directly instead of
   the eight-way constant-time select (16.5M in the baseline). Zero digits emit
   no service call and the accumulator stays identity, with no service call,
   until the first nonzero digit. All of this is public data: recovery has no
   secret scalar. Enabled by the k256 feature `stwo-vartime`, which implies the
   word-service ABI; the constant-time paths remain the default.
3. **Build profile.** `build.py --guest-profile ethereum-services-v2-lean`
   selects `keccak-service,secp-lean` and publishes
   `ethereum-rv64-services-v2-lean.elf`. The VM profile stays
   `ethereum_services_v2`.

The `heap_start` symbol moved from 33,647,392 to 33,647,264 because the data
and BSS sizes changed. Execution and proving requests must take the ABI
symbols from the new ELF; `execution-config.json` here does.

## Evidence

- `build-report.json`: toolchain `nightly-2026-08-08`, source hashes, ELF hash.
- `execution-summary.json` / `baseline-execution-summary.json`: native
  `rv64-ethereum-execution` reports (PC profile and access batches stripped).
- `function-profile.json` / `baseline-function-profile.json`: exact PC census
  by function.
- `services-unicorn-oracle.json` / `baseline-services-unicorn-oracle.json`:
  independent Unicorn 2.1.4 execution with the service ABIs implemented in
  Python (`scripts/riscv64_ethereum_services_oracle.py`), compared field by
  field against the native reports: output, final PC, all 32 registers,
  instruction count, service call counts and RAM word transitions. The
  previous oracle could not execute any services guest.
- Host tests (`projective_service_test`, feature `vartime`, debug and
  release): the word-packet chain equals the registry k256 double-scalar
  multiplication over edge and random scalars; patched recovery returns the
  signer's key for low-S and high-S inputs, and the omitted verification is
  re-run explicitly on every recovered key, including the wrong-parity key.

## Remaining cost in the lean guest

From `function-profile.json`, top of the 149.3M residual:

| Function | Instructions | Share |
| --- | ---: | ---: |
| `compiler_builtins::mem::memcpy` | 37.0M | 24.8% |
| `sha2::compress256` | 11.2M | 7.5% |
| `k256 FieldElement::square` (one inversion and one sqrt per signature) | 9.0M | 6.1% |
| revm mainnet handler | 8.7M | 5.8% |
| zeth MPT RLP node decode | 8.5M | 5.7% |
| `native_keccak256` absorb/squeeze glue | 7.1M | 4.8% |
| revm legacy bytecode analysis | 6.8M | 4.6% |
| `k256 Scalar::invert_vartime` (Stein's over field ops; not cheaper than the chain on RV64) | 5.2M | 3.5% |

The oracle report carries a size and alignment histogram of `memcpy`,
`memset`, `memcmp` and `memmove` entries (the alias symbol tail-jumps into the
`compiler_builtins` implementation, so entry counts are doubled; the PC census
gives 313,045 real memcpy calls at 118 instructions each on average). The stored
histogram uses exact sizes below 64, then **floor** power-of-two buckets:

| Size range established by the archived histogram | Entry events |
| --- | ---: |
| 0–16 | 3.7% |
| 17–32 | 29.7% |
| 33–63 | 17.4% |
| 64–127 | 18.0% |
| 128–255 | 28.6% |
| 256 and above | 2.6% |

Thus 93.6% are in 17–255; the archive does not establish the share at most128.
The capped4096 bucket includes larger sizes as well. About54% have both pointers
8-byte aligned and43% have mismatched alignment, which takes the shift-and-merge
word path. Those are marginal counts: the size/alignment correlation and share
of copied bytes are not available in this archive. New oracle runs record exact
sizes through128, requested-byte totals and size/alignment cross counts; missing
fields in old reports remain unknown. These measurements should guide a small
copy path or DMA service. SHA-256 and field inversion/square root remain further
candidates for host hints or services.

## Reproduction

```sh
python3 autoresearch/benchmarks/guest_runtime/ethereum/rv64/build.py \
  --artifacts /tmp/stwo-rv64-lean --offline --guest-profile ethereum-services-v2-lean
zig build --build-file src/frontends/riscv/rv64/build.zig -Doptimize=ReleaseFast
src/frontends/riscv/rv64/zig-out/bin/rv64-ethereum-execution \
  vectors/reports/rv64-guest-lean-20261031/execution-config.json > execution.json
python3 scripts/riscv64_ethereum_profile.py --execution execution.json \
  --elf /tmp/stwo-rv64-lean/ethereum-rv64-services-v2-lean.elf --output profile.json
/tmp/stwo-rv64-oracle-venv/bin/python -m scripts.riscv64_ethereum_services_oracle \
  vectors/reports/rv64-guest-lean-20261031/execution-config.json \
  --report oracle.json --compare execution.json
cd autoresearch/benchmarks/guest_runtime/ethereum/rv64/projective_service_test && \
  cargo +nightly-2026-08-08 test --release --offline --features vartime
```

## Round 2: memory functions for aligned-only RV64

`autoresearch/benchmarks/guest_runtime/ethereum/rv64/mem` provides strong
`memcpy`, `memmove`, `memset`, `memcmp` and `bcmp` symbols that replace the
weak `compiler_builtins` definitions (crate attribute `no_builtins` keeps LLVM
from rewriting its loops back into calls). The guest traps on misaligned
access, so every word access is aligned: 8-aligned copies run a four-word
unrolled loop, 4-aligned sources use 32-bit loads, and mismatched alignment
uses an aligned funnel-shift loop that never reads a source word outside the
range. Tails up to 15 bytes are straight-line. `memcmp` compares whole words
when both sides are aligned. Host property tests cover every length up to
259 with every source and destination offset up to 15, both overlap
directions for `memmove`, and the lexicographic sign of `memcmp`.

| Measure | round 1 | round 2 |
| --- | ---: | ---: |
| Instructions | 149,306,899 | 138,707,126 (−7.1%) |
| memcpy | 37.0M (313,045 calls, 118 each) | 28.7M (91 each) |
| memcmp | 2.45M | 1.27M |
| memset | 1.96M | 1.46M |
| ELF SHA-256 | `691ff478…e2bb` | `4a0ef215…` (see `round2/build-report.json`) |

Receipts in `round2/`: build report, execution config (new `heap_start`
33,648,256), execution summary, function profile and the services oracle
comparison, which again agrees with the native executor on every field.

Where the remaining memcpy calls come from (Unicorn return-address
histogram): 48% are four struct moves in zeth-mpt's RLP node decode of 32,
128, 128 and 44 bytes per decoded node; 6.8% are `NodeRef` encodes of 32
bytes; 6% are the 96-byte point returned by value from the k256 word table
select (removed in round 3); the rest are allocation growth, Keccak input
copies and EVM memory operations. The struct moves are compiler-generated and
need an upstream change in zeth-mpt to avoid; the memcpy floor for them is
the aligned word loop already in place.

## Round 3: variable-time inversion and word-wise Keccak absorption

1. `vendor/k256/src/arithmetic/stwo_inverse.rs`: a limb-level binary extended
   Euclid (`inv_mod_vartime`) for odd moduli. Under `stwo-vartime` it backs
   `FieldElement::invert` (used by `to_affine` after each recovery) and
   `Scalar::invert_vartime` (the inverse of `r`). Both inputs are public. The
   constant-time addition chains cost about 75k and 67k instructions per call;
   the shared routine costs about 22k. Host tests compare both inverses with
   the registry k256 over edge and random inputs.
2. `src/keccak_service.rs`: unaligned input is absorbed eight bytes at a time
   from aligned loads with a funnel shift. The last funnel word of a chunk is
   only assembled when the aligned load ends inside the input buffer; the
   remainder stays byte-wise, so the sponge never reads past the input. The
   existing sponge test covers all alignments and block boundaries.
3. The k256 word table adds positive digits straight from the table entry
   instead of returning a 96-byte copy.

| Measure | round 2 | round 3 |
| --- | ---: | ---: |
| Instructions | 138,707,126 | 126,471,926 (−8.8%) |
| `FieldElement::square` | 9.0M (39,624 calls) | 4.5M (19,734 calls; square root only) |
| `Scalar` inversion | 5.2M | part of 3.4M `inv_mod_vartime` (156 calls) |
| `native_keccak256` glue | 7.1M | 3.6M |
| ELF SHA-256 | `4a0ef215…` | `5503ce33…` (see `round3/build-report.json`) |

Receipts in `round3/`; the services oracle agrees with the native executor
on every field. The new `heap_start` is 33,648,416.

## Cumulative

| Guest | Instructions | secp ADD / DOUBLE calls |
| --- | ---: | ---: |
| services-v2 (pinned baseline) | 213,659,488 | 24,960 / 19,968 |
| round 1: lean recovery | 149,306,899 | 11,496 / 9,768 |
| round 2: memory functions | 138,707,126 | 11,496 / 9,768 |
| round 3: inversion, Keccak absorb | 126,471,926 | 11,496 / 9,768 |

Total: −40.8% instructions and −53% secp256k1 service calls for the same
block, same 43-byte output, with no change to the execution profile, ECALL
tags, packet layouts, AIR, prover or verifier.

Largest remaining items in the round-3 profile: `memcpy` 28.2M (22%, dominated
by compiler-generated struct moves in zeth-mpt RLP node decode), SHA-256
compression 11.2M (9%, software), the revm mainnet handler 8.7M, zeth-mpt RLP
decode 8.5M, revm legacy bytecode analysis 6.8M, and the secp256k1 square root
in point decompression 4.5M. The square root and SHA-256 are host-hint or
service candidates; the struct moves need an upstream zeth-mpt change.
