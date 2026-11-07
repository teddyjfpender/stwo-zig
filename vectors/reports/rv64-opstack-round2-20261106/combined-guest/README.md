# Combined GLV / pairing / metadata checkpoint

The `canonical-glv` guest completes all six pinned historical OP Mainnet
Ecotone blocks. Native Kona block hashes, RV64 output and Unicorn's exact N-1+1
retirement, registers, PC and service counts agree. `execution.json` and the
six oracle receipts identify the exact ELF and inputs. `metadata-wire-parity.json`
compares every OPX file byte for byte against the previous full guest's inputs.

| Block | Full guest instructions | Combined instructions | Service RAM words, combined |
|---|---:|---:|---:|
| 120794432 | 821,721 | 797,331 | 97,654 |
| 121057303 | 6,394,106 | 5,928,737 | 664,228 |
| 121065789 | 2,500,418,167 | 625,046,890 | 40,326,924 |

The heavy block's instruction reduction is 75.00%. Its service RAM traffic is
15.46% higher than the original full guest, and lower than both previous BN254
adapters. No physical heavy-block proof or speedup is established. G1 doubling
calls fall from 63,408 to 31,908, and plain-Fp2 calls from 1,148,394 to 928,200
relative to the preceding canonical-field experiment.

The guest combines signed joint-window GLV over existing affine services, lazy
validated prepared-G2 reuse, and borrowed/streamed postcard metadata. The
reproducible GLV constant derivation is in `opstack/tools/derive_bn254_glv.py`.
The host still uses the registry Arkworks and upstream MPT implementations.
The guest text grows from 2,038,856 to 2,193,428 bytes; instruction savings are
not a claim of a smaller executable. All ABI, statement and service tags stay
unchanged.

## Complete physical CPU proofs

These are complete native execution/service STARK bundles with fresh reception,
not recursive roots. Four proof workers, one setup worker, one lane, explicit
1,048,575-step batches, conjectured128_b2_q108_p20_fold4 profile, no compilation
or heavy test job during timing. Native runner SHA is retained in each summary.

| Mainnet block | CPU + truth proofs | Producer seconds | Fresh receiver seconds | Producer peak RSS | Binary proof + sidecar bytes |
|---|---:|---:|---:|---:|---:|
| 120794432 | 1 + 2 | 47.762 | 8.344 | 2,931,953,664 | 9,070,026 |
| 121057303 | 6 + 7 | 245.646 | 26.166 | 4,286,492,672 | 41,643,846 |

Each summary is accepted only after the fresh receiver succeeds and two negative
controls reject: mutated durable bytes with their original digest, and the same
mutation with a recomputed transport digest. Rejection requires the precise
transport or proof-verifier error; a crash, timeout or resource failure cannot
pass. Original files are restored on every exit path.

For block 121057303, the source-derived MAIN+INTERACTION payload falls from
34,422,769,024 to 32,232,733,600 bits under the same batch size (6.36%). This is
padded native trace payload, not PCS, composition, openings, recursion or proof
bytes. The old reference has 7 CPU + 7 truth proofs. Its earlier timings had
concurrent development; a quiet same-geometry control remains to be measured.

A separate identical-ELF comparison at 262,143-step geometry found the exact-zero
FFT shortcut's whole producer essentially flat (427.862 versus 425.067 seconds).
All 34 binary proof/sidecar hashes matched. Do not attribute the new guest's
whole-proof timings to that shortcut. The CPU harness now preserves the declared
geometry instead of silently substituting 262,143 steps.

## Engineering gates and remaining work

Thirty Python tests, owned Python/Rust/Zig formatting, the combined native Rust
unit/integration suite, 21 FFT tests, and focused receiver/resource/batch manifest
policy tests pass. Full post-extraction MPT/property and broader native/recursive
Zig suites are continuing. The bounded native batch entry is compiled and its
closed manifest policy is tested; repeated-block end-to-end reception and setup
reuse measurements are still pending at this checkpoint.

`build.json` records an unchanged 7,410-file repository compiler-input inventory,
its digest, modified inputs, exact binaries and commands. The full inventory is
retained locally; the compact checked-in receipt avoids duplicating all upstream
sources and ELF symbols. Rebuilding the native runner reproduced the same SHA.

No current-head/all-fork qualification, authenticated L1 derivation, recursive
root, SP1 replacement, GPU benchmark, or whole-protocol security certification
is claimed. The selected profile remains `security_qualified=false`.
