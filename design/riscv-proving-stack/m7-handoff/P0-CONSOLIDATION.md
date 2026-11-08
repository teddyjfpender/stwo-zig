# P0 consolidation

Status: **P0 gate PASS; local consolidation complete (2026-11-06)**.
Owner tree: `~/Coding/ge-wt/rv64-m7-integrate`, branch
`codex/rv64-m7-integrate`. No other checkout is used for development.

The scope's branch counts are ancestry counts, not missing-feature counts.
Many commits were already cherry-picked, sometimes with formatting or later
admission fixes. `vectors/reports/rv64-m8-20261105/p0/branches.json` pins all
29 branch tips, exact patch-equivalent commits, non-equivalent commit lists,
and the retained location of every historical receipt blob. Missing receipts
are imported without overwriting current receipts; conflicting historical
versions live under `p0/branch-receipts/`. Non-equivalent source patches are
preserved under `p0/closed-source/` as history, not compiled code.

These branches are closed as development streams. Their already integrated
code remains subject to the gate; the rejected candidates below stay out of
the runtime. No old branch tip is merged over newer integration source.

| Branch suffix | Disposition and review |
|---|---|
| native-gkr | Close as consolidated. Compact ingress, D2, coalescing, rolling PCS, GKR and Poseidon substrates already exist. Preserve unmatched receipts. The old combined-candidate runner is superseded by the canonical stack runner and commit gate. |
| outer-gkr | Close as consolidated/superseded. Retain owner-gap, GKR, Poseidon and capture/setup evidence. Bitmap/setup scheduling negatives and unaudited traversal admission are not activated. Unbuilt query wiring stays historical. |
| owner-cleanup | Close as consolidated; six patch-equivalent commits. Import the previously missing asset-prune receipts. |
| device-fs | Close as consolidated. Current owner controller includes subsequent scope/admission fixes; do not replace it with the old controller. |
| rc-workspace | Close as consolidated; all six unique patches equivalent. Negative VMM/workspace timing preserved. |
| rc-sparse | Close as consolidated; all seven patches equivalent, including the unqualified permit checkpoint. Default remains sparse off. |
| stage1-cost | Close as superseded. Current allocation model has later jump-table input-count and host pack-thread corrections. Early CPU0 path remains off. |
| admission | Close as consolidated; all five patches equivalent. |
| native-witness | Close as consolidated for compact ingress, reject balanced-route/owner-lane activation. Routing evidence shows no qualified gain and an incomplete control. |
| graph-checkpoint | Close as superseded/negative. Capacity refusals and stale pre27 source overrides must not replace current hybrid27 code. |
| early-recursion | Close as consolidated; all four patches equivalent, including the WIP owner-source checkpoint. Its warm failure remains an open P1 gate. |
| device-fs-p2 | Close as consolidated. Current recorder contains actual INTER and RC consumers; retain exact-consumer evidence. Default stays off. |
| callback-retire | Close as unpromoted. D2 parity exists, but M6 and composed performance qualification are incomplete; two lanes are refused by that prototype. Preserve source/receipts for later reconsideration. |
| blake-inputs | Close as consolidated; current sample-prefill implementation and critical-chain receipts supersede the old branch. |
| projection-cost | Close as superseded. WIP source-cost additions are present with later input-count and host-thread fixes. |
| keccak-batches | Close as deferred to P4. Preserve early/late b16 policy and tests in historical patches; q102 has proof-size evidence only and is not promoted for latency. |
| device-lanes-checkpoint | Close as superseded/negative; retain independent-lane failure evidence. Current admission/sessions own the route. |
| device-graph | Close as unpromoted. WIP graph cache has numerical gates and partial M6 parity, but both 22 GiB controls fail; old capacity overrides are incompatible with newer source. |
| device-fs-p1 | Close as superseded. Current P2 recorder already includes the empty-operation check and composition powers; older checkpoint must not remove them. |
| critical-chain | Close as consolidated; both patches equivalent. |
| native-inter-retire | Close as unqualified P1 candidate. Four CPU lifetime tests are not GPU byte parity. Preserve the patch; qualify any port in the single tree. |
| native-capture | Close as consolidated; authority patch equivalent. Preserve its negative/partial latency boundary. |
| memory-census | Close as receipt-only; import the missing memory/admission census. |
| keccak-stream | Close as explicitly parked. Beta4 compact/rolling paths have CPU gates only and no GPU qualification; preserve, do not activate. |
| graph-shape-checkpoint | Close as superseded/negative by the later graph checkpoint; retain its capacity rejection. |
| fold-expanded | Close as consolidated; patch equivalent. |
| fold-circuit | Close as receipt-only. WIP is a historical build recipe, not a new validated runtime. |
| cpu-prestage | Close as receipt-only. WIP adds first-pass-RAM receipts; no new source. Early staging flags remain off. |
| capture | Close as consolidated; immutable program view patch equivalent. |

The unused `STWO_RV64_OUTER_RETIRE_ASYNC=0` preset entry was removed because
the integration runtime does not implement the closed retirement prototype.
The remaining off flags select implemented candidates; P1/P3 still need them
for controlled comparisons. No proof-format parameter changes in P0.

## Gate and provenance

Run on the pod:

```sh
bash scripts/rv64_gate.sh --source-commit <base-commit> \
  --out /workspace/m3/runs/m7-integrate/<unique-attempt>
```

The gate rebuilds the driver and CPU receiver, runs host unit tests, proves
the small block cold and warm using the canonical baseline preset, compares
all native/recursive proof and binding artifacts against the frozen accepted
D2 fingerprints, runs fresh CPU receivers, then runs the required negative
corpus. Missing cases, skipped cases, crashes and mismatches fail the gate.
Source fingerprints detect edits during execution. The gate is correctness
evidence only; canonical interleaved 3+3 timing remains mandatory for changes
that claim performance improvements.

`p0-runtime.json` pins the accepted a25 CUDA image and observation addons as
explicit build inputs. The latest one-stack manifest instead points at the
4273 image; those assets must not be silently confused. Host rebuild success
does not claim that the CUDA image was rebuilt from current source. CUDA
changes require a new built-image manifest and their own composed gate.

Builds use one build lock. The canonical producer owns the GPU lock itself.
The negative corpus uses a read-only accepted opposite-block donor. No new
large-block run or scale probe is part of P0.

## Unit gate repairs

The first complete unit gate exposed stale fixtures: a const-metadata tamper,
an obsolete profile tag and oracle limit, uninitialized optional ownership
fields, and a memory-cost assertion that conflated independent arena-class
peaks. These repairs affect tests only.

The projection-equivalence test also found a native scalar opcode discrepancy
for arbitrary canonical field flags. Its failing load/store opcode was
876440756, whereas both the independent integer-modulo reference and recorded
projection produced 876440816. Changing the opcode reconstruction from an
`inline for` to a runtime `for` passes the original all-role equivalence test
and the added exact fixture. The compiler mechanism is not established; this
is an observed scalar-evaluation repair, not a performance claim. Canonical
execution-row proof parity remains the full gate's responsibility.

All five pod unit targets pass in `p0/unit-preflight/p0-unit-fix-07.log`.
`p0/unit-preflight/summary.json` maps the fixes to retained failure evidence.
Gate02 subsequently exposed the telemetry-file classification error described
below. The corrected full gate, `p0-gate-20261105-03`, passed.

## Next measured experiment

After P0 passes, P1 targets the roughly 22 GB live recursion-node footprint,
starting with the 304-column INTER coefficient/scratch overlap, then MAIN,
composition/GKR and persistent caches. The hypothesis is that two nodes
fitting in the 22 GiB arena can reduce the measured 5.7 s recursion stage
toward the scope's estimated 3.5–4 s. This is an estimate, not a result. The
required evidence remains exact per-node peak at most 11 GB on both dev
blocks, warm composed 3+3, byte identity, fresh acceptance and measured GPU
busy above 54%. No P1 completion or speedup is claimed here.

## Completed P0 result

Receipt: `vectors/reports/rv64-m8-20261105/p0/summary.json`; full gate:
`p0/gate/p0-gate-20261105-03/gate.json`. Build, all five Zig targets and Python
checks pass. Cold/warm small-block proofs each match 32 frozen proof/binding
artifacts byte for byte. Both fresh CPU receivers accept. All 19 required
corpus cases pass (one positive control and 18 rejections), with no crashes or
unexpected accepts. The cross-block-root rejection is a size-cap rejection,
recorded as such, rather than evidence of cryptographic rejection.

The comparator excludes process/timing `*.stages.json` and the
`candidate-fixed-setup.json` cache report. The latter's cold/warm source
validation counters differ by design. Proof bytes, bundle, source bounds and
recursion tree still require exact fingerprints. Gate02's classification
failure is retained, and the corrected comparator has mutation/missing/extra
artifact tests. Gate03's source hashes match the local source exactly.

The 25 clean historical local worktrees and all 29 closed local branch refs
have been removed. Exact remote tips retain their full history. The branch
manifest's 19,910 receipt references match 1,257 retained Git blobs; the
cleanup receipt is `p0/cleanup-plan.json`. Development continues solely on
`codex/rv64-m7-integrate`, as required by the owner prompt.

The table is **diagnostic only**, for block **26235156**. The historical run
was profiled; the gate run was unprofiled, used diagnostic quiet admission,
and is a single service. These are not matched performance measurements.

| Metric | Historical D2/coalesced warm [M, diagnostic] | P0 gate warm [M, diagnostic] |
|---|---:|---:|
| Request | 10.534 s | 10.642 s |
| Capture | 1.720 s | 1.815 s |
| Setup | 0.126 s | 0.137 s |
| Native proving | 3.419 s | 3.488 s |
| Recursion stage | 5.132 s | 5.061 s |
| Kernel-busy GPU-seconds | 8.157546092 | Not measured |
| Recursion-window GPU busy | Not established here | Not measured |
| Sampled whole-device peak | 31.583109120 GB | 31.566331904 GB |
| Exact per-node peak | Not established | Not measured |
| Root proof | 749,464 B | 749,464 B, byte-identical |

Stage walls can overlap and must not be added. Sampled whole-device memory
is not exact process or per-node memory. No speedup or memory-target pass is
claimed. The headline block 24628607 was not retimed in P0; its 12.935 s
historical diagnostic result remains unchanged as the reference.

Default now: D2 plus non-Keccak truth coalescing, automatic arena, one recursion
lane per physical GPU, conjectured-128 and hash-based proofs. Next: P1's
per-node footprint and warm composed two-lane qualification. The current code
already streams beta1 traces and retires outer INTER inputs; measure the
remaining overlap before introducing another mechanism.

Ledger caveat: the two new `m8-integrate.jsonl` rows validate. The global
ledger check and renderer stop at the unchanged historical
`device-fs.jsonl:1` row's missing commit field. Historical rows are preserved;
`p0/progress-check.json` records the failure and the file hash. The generated
progress index remains unchanged. This does not affect the passing proof gate.

Raw historical patches/logs remain byte-exact, including whitespace and old
conflict-marker text inside archived receipts. The active source, scripts,
design documents and new ledger pass the staged whitespace/conflict check.
