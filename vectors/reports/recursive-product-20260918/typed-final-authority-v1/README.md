# Final typed native RISC-V and detached recursion qualification

All eleven canonical native infrastructure kinds now use one typed-specialization
admission owner, shared by ordinary native proving/verification and recursive VM
profile reconstruction. This completes the wide-Poseidon equation gap after the
program/memory/clock/table and Merkle batches. Production opcode authority and
recursive compact Poseidon remain typed; retained native evaluators are checked
specializations, not independently admitted semantic definitions.

Wide Poseidon lowers the existing typed permutation and authenticated degree-three
slot map into all 430 direct roots. Admission compares arbitrary-row expressions,
all four ordered lookup events and both LogUp recurrences. Shared typed program
construction and the pure relation contract replace duplicate construction logic;
verifier-side lowering imports no witness executor or native equation kernel.

## Evidence

- Final focused targets: 177 authority/root-import tests (one skipped) and 21 VM
  profile tests; imported test counts overlap. Wide admission rejects 14 deliberate
  specializations, checks arbitrary extension-field rows and propagates every
  allocation failure. Existing witness and relation parity checks also pass.
- All 38 source-ownership checks and both inventory checks pass.
- Fresh CPU/Metal/AOT four-segment products: 384 acceptance/rejection checks and
  21 artifacts identical to the canonical baseline.
- The same binaries and frozen source passed the useful 16-address 1/2/4/8 ladder:
  1,110 checks, 78 baseline-identical artifacts, authenticated continuation,
  standalone roots and same-geometry statement substitution.
- Eight additional fresh root-only executions measured verifier peak RSS. Their
  proof digests match the admitted roots; no execution replay or native inputs
  were supplied to the root verifier.
- Metal telemetry requires 24 native table dispatches and 144 typed dispatches
  per leaf, plus 116 typed dispatches per parent. This remains an explicitly
  hybrid profile, not a claim of strict end-to-end GPU execution.

`summary.json`, `ladder-summary.json`, per-backend/rung summaries and compressed
complete product reports retain commands, hashes, cases and measurements.
`frontend-authority-audit.md` explains the shared implementation and the distinct
terminal/resumable public-I/O contracts. V1 statement names do not imply an
untyped interpreter or AIR.

## Useful receipt measurements

Single observations on this Mac; production excludes builds and hostile replays.
Verifier RSS is measured in a fresh root-only process. Direct leaves means the
sum of cryptographic verification times for detached leaf receipts, not native
execution proofs. These measurements are not a statistical speedup claim.

| Segments | Backend | Production s | Producer peak GB | Root MB | Root verify ms | Verifier peak MB | Direct leaves ms |
|---:|:---|---:|---:|---:|---:|---:|---:|
| 1 | cpu | 9.763 | 2.900 | 2.482 | 73.59 | 19.53 | 73.59 |
| 1 | metal | 8.301 | 2.572 | 2.482 | 73.50 | 19.53 | 73.50 |
| 2 | cpu | 30.509 | 4.077 | 2.419 | 70.71 | 15.75 | 148.46 |
| 2 | metal | 23.855 | 4.525 | 2.419 | 68.03 | 15.75 | 148.73 |
| 4 | cpu | 72.760 | 4.086 | 2.288 | 67.65 | 15.25 | 297.52 |
| 4 | metal | 54.247 | 4.535 | 2.288 | 68.03 | 15.25 | 296.66 |
| 8 | cpu | 152.772 | 4.086 | 2.297 | 69.48 | 15.45 | 593.57 |
| 8 | metal | 115.225 | 4.536 | 2.297 | 69.67 | 15.45 | 595.64 |

At eight segments, one root is about 2.30 MB and verifies in about 69–70 ms,
versus about 594–596 ms for all detached leaves. This consumer saving does not
make total production cheaper: amortizing measured parent-production time solely
through repeated verification would take approximately 143 CPU-produced or 97
Metal-produced consumer verifications. Proof-size savings may have independent
value. Direct leaf verification remains available.

## Replay

From the qualified working source, with Zig 0.15.2 and the physical-Mac Xcode
Metal toolchain installed:

```sh
python3 scripts/riscv_recursive_product.py --backend cpu --output /tmp/typed-cpu-new
python3 scripts/riscv_recursive_product.py --backend metal --output /tmp/typed-metal-new
```

The commands build fresh executables and AOT artifacts; no session binary is an
input. `source.patch.gz` applies to base HEAD
`1358234f1e8a2ac34241658dcd3505bad5feb1fc`; clean-index replay reproduced all
6,184 source hashes in `qualified-source-snapshot.json` without modifying the
user index. This was source replay, not an additional independent build.
`pinned-inputs.tar.gz` contains 114 independently pinned input files at their
repository-relative paths; every archived digest was reread and checked against
`pinned-inputs.json`. These include the canonical command and ladder/substitution
admissions, so replay does not need remote artifact retrieval. Validate the
archive hash before extracting it at repository root. The retained per-rung tree
commands show the admitted binaries and inputs for ladder replay.

## Completion boundary

The typed native/recursive implementation and final proof ladder are qualified.
The original broader baseline goal is not fully complete: a fresh repository-wide
source-conformance run still reports 120 violations, including existing source
ceilings and proposal-authority ownership findings. Historical Linux artifact-store
qualification also remains unproven by this macOS run. See `completion-audit.json`
and `source-conformance.log`; passing product proofs do not make those checks green.

The profile uses development q193 parameters. Production-security review, strict
end-to-end GPU coverage, Ethereum expansion and speed autoresearch are not claimed.
Documentation was finalized after the proof/ladder source freeze.
