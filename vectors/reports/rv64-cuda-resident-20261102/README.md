# First RV64 resident CUDA numerical slice

Base: PR310 `a7f484e34c266bf1a7d220d96502701794fa6d7c`.
Source digests, toolchain and explicit negative qualification flags are recorded
in `validation.json`. This is a numerical backend delivery, not a complete
GPU Ethereum prover or a claim to beat ZisK/zkDTVM.

## Implemented

- Eight-coordinate OM31 arithmetic in the native tower and coordinate order.
- Resident SoA tuple/weight projection with an explicit active mask: padding
  is exactly `(0,1)` and is distinct from a legitimate zero multiplicity.
- Separate base/secure numerator kernels, adjacent fraction trees, fused
  two-level reduction, EqEvals generation, half-split folds and deterministic
  multi-block sumcheck reductions. No extension-field atomics.
- Enqueue-only native ABI authenticates device ranges against the existing
  context allocation registry, selected device/thread and lane; rejects output
  overlap, malformed geometry and insufficient capacities before enqueue.
- Typed Zig generation-checked device slices and poisoned command owners.
- Exact arena layout and a 2/4-device credit scheduler with per-device reserves,
  bounded lanes and generation-tagged tickets. Failed jobs retain credits until
  joined abort; stale/double/forged completion and oversized shards reject.
- Real-context multi-device driver harness with parity, invalid input tests and
  explicitly scoped hot-wave timing. Ready to run on target GPUs.

## Checks completed here

| Gate | Result |
|---|---|
| Zig integration + native numerical bridge, ReleaseSafe | 13/13 pass |
| Same tests, ReleaseFast | 13/13 pass |
| Independent Python polynomial-tower field oracle | 4,196/4,196 pass |
| Host custody boundary tests | Pass, including byte units/bounds/overlap |
| Focused package manifest/import/API/README contract | Pass |
| Source-conformance unit tests | 31/31 pass; no finding names a touched file |
| CUDA `sm_89` and `sm_120` compilation | Pass; no reported register spills |
| Real-context fat-binary harness compilation/link | Pass |
| Hardware execution | **Skipped, exit77: NVIDIA device/driver unavailable** |

The compiler reports 56 registers for the specialized base-numerator
sumcheck on sm120, 40 for the single-level base fraction tree, and no spills
for any kernel. These are compilation properties, not achieved occupancy,
latency or block throughput. The secure-numerator sumcheck still uses128
registers on sm120; profile before selecting register caps or changing fusion.

The source contains no device allocation, host transfer, synchronization,
default-stream or device-switch calls in its numerical launch path. Only the
explicit setup/validation harness transfers host data. Matrices remain resident;
this does not assert that the currently shipping complete proof pipeline is
GPU resident. The engine is not wired into that pipeline yet.

## Remaining qualification

1. Run real-device parity and memcheck/racecheck/synccheck on tiny, tail and
   multiblock sizes, then simultaneous 2/4-device sweeps and Nsight traces.
2. Bind real RV64 metadata/witness producers directly to resident buffers;
   source relation framing and physical binding stay with the native authority.
3. Connect the generic GKR transcript/oracle orchestration and OM31 sampler,
   eight-coordinate PCS/DEEP/FRI/commitment stages without round trips.
4. Qualify the same-security complete block with a fresh receiver, pinned Rust
   protocol oracle and a regenerated receiver-owned roster. GPU kernel parity
   alone is insufficient. Full v3 admission remains closed as in PR310.
5. Integrate recursive leaf/root and its independent security review separately.

## Broad repository gates

`ci.py --fast` stops on six format failures already present at the pinned base:
`candidate_isa.zig`, `ethereum_contract.zig`, `gkr_local/truth_worker_test.zig`,
`services/wire.zig`, `rv64_v3_services_recursion_test.zig` and
`prover/poly/circle/poly.zig`. Each was extracted from the base commit and the
same formatter rejection reproduced. `check_package_workspace.py` stops on an
inherited unsorted API ledger in `src/interop/proof_wire/package.contract.json`.
The whole-repository source layout checker also reports inherited findings;
none names a changed file. Its31 unit tests pass. The touched integration's
focused contract checks pass. Repository-wide CI is
not claimed green. Full hardware/receiver/Rust qualification remains unrun.

The repository's pre-commit hook repeats the inherited broad format failure;
local commit/push hook bypasses, if used, skip feedback only and are disclosed
in the PR. No production admission or hosted CI bypass is introduced.

Review order: design contract → `native/rv64/om31.cuh` → `gkr.cu`/`custody.cuh`
→ native numerical bridge → Zig resident/plan/scheduler → real-driver harness.
The cross-layer slice is intentionally reviewed together: arithmetic, ownership,
ABI, capacity and reference evidence are one invariant. No vendored third-party
code or protocol parameter changes are included.
