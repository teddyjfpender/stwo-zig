# Bounded recursion scheduling problem match

Task: execute an admitted recursive proof DAG, publishing each node to parents
only after independent verification; preserve artifact identities and failures.
Inputs: seven parent nodes of the qualified eight-leaf tree; approximately 4.39 GB
per existing Metal parent process. Existing leaves are admitted prerequisites.
Model: nonpreemptive precedence-constrained list scheduling with memory and worker
admission limits. Runtime estimates are not authoritative; no optimality claim.

Candidates: level barriers (simple but idle behind slow siblings); ready-DAG list
scheduling (selected, permits immediate dependent work); unrestricted parallelism
(rejected, unbounded memory); persistent device workers (required next integration,
not supplied by this first process scheduler). Resource reservations bound admitted
estimates, not actual RSS; measured aggregate-memory admission remains necessary.

Mapping: proof nodes are jobs, child acceptance creates dependency edges, worker
and byte budgets are renewable resources. Each job runs producer then verifier;
only the acceptance callback releases its dependency. Prefer deeper ready nodes,
then stable ID. O(V^2 + E) scheduling scans are immaterial at seven nodes. No
approximation ratio is claimed for heterogeneous resource-constrained jobs.

Source/transfer: Proofman's ready queues, bounded admission and rootward priority:
https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/proofman/src/scheduler.rs
Our previous source-pinned investigation establishes the mechanism; no upstream
code is copied. The gate's global build lock is acquired once around the complete
experiment, not inside every child. This preserves build exclusion while admitting
explicit bounded producer concurrency. Existing gates remain unchanged.

Prediction: overlap independent preparation with sibling proving and reduce tree
wall time; total work may increase through GPU contention. Falsifier: no wall-time
improvement, rejection, identity drift, runaway memory or cancellation failure.
Test: synthetic dependency/verification barriers, resource caps, unschedulable DAG,
producer/verifier failure and process cancellation; then fresh seven-node parent
tree with all outputs independently verified and compared to original admission.
Uncertainty: startup delay observed in the two-process probe remains unexplained;
all timings, including outliers, must be retained. Persistent plans, actual memory
telemetry, circuit fusion and parameter research remain separate goal requirements.
