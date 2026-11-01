# Bounded OM/GKR whole-execution coordinator

The additive `services/gkr_local/coordinator.zig` joins the actual CPU-local-GKR
workers and classic-OM truth workers under one ordered stage-one manifest. It is
an explicit new profile; it does not switch the Ethereum driver or certify a
whole-protocol 128-bit security level.

The producer derives owned request-cell lists before consuming prepared traces,
uses the receiver's independent `execution.Inventory` for program/image/coverage,
endpoints, shapes, local rosters and typed mass bounds, and executes the existing
bounded scheduler twice. Stage two cannot exist until every stage-one worker has
sealed and `Manifest.verifyAndSeal` has checked every CPU local child. The same
manifest bytes are handed to the fresh whole-execution receiver. Each physical
worker verifies FIXED/MAIN against that manifest; the root closes RAM, KIO and
Wire independently after every physical proof succeeds.

CPU source construction is the original shared `services/pipeline.buildCpuSource`
authority; the legacy-Q pipeline delegates to it as well. The new coordinator
does not duplicate memory/bridge/range-merge construction. Setup and advice stay
borrowed; successful source construction consumes prepared CPU traces. Requests
own their initial/terminal cell lists independently of advice and worker memory.
Workers consume sources only after successful initialization, and every failure
joins scheduled jobs before releasing owned workers/results. The returned bundle
owns only request lists, encoded manifest, encoded proofs and physical claims.
CPU local-query caches are retired immediately after sealing; the already
constructed child binding and RAM/bridge metadata retain their obligations.

This first coordinator deliberately permits at most eight workers and separately
caps retained frontend MAIN/backing plus CPU binding cells before construction.
The retained estimate excludes receiver-owned immutable setup and proof-engine
scratch; it is not a total-RSS or GPU memory promise. Each local GKR child and
global witness also receives its own explicit hard budget. A full 25-CPU block
must not be run through this retained-owner path until MAIN/binding parking is
wired and qualified. The reusable stage contexts and scheduler preserve that
future integration seam. The initial fixture uses a 2 GiB CPU-local-GKR cap;
no 512 MiB qualification is claimed.

`coordinator_fixture.zig` constructs two real CPU shards with Keccak, ADD and
DOUBLE calls, plus the three independent truth proofs. It proves seven total
retirements, then the whole receiver replays the ordered manifest, every local
child, all five physical proofs, RAM-image/boundary authority and independent
global closures. A second receiver rebuilds all immutable setup keys afresh.
Negative cases cover an independently changed expected endpoint, changed pure
global debt, swapped CPU proofs, malformed manifest and missing truth proof.
Inventory and retained-owner caps reject before prepared CPU consumption.
The same focused gate includes actual truth proof tests and finite-difference
checks of the joined strict-triple Keccak degree-five and secp degree-three AIR.

Production-size performance, parked full-block lifetime qualification, complete
128-bit soundness accounting, outer recursion and GPU execution remain separate
gates. The accepted small whole-execution fixture establishes functional
integration of this profile, not performance extrapolation.

## Explicit coefficient parking

The coordinator now accepts an optional `retained_store` with parking enabled.
Without it, the existing eight-worker limit remains. Larger inventories require
an explicit `max_workers`, a parking store, nonzero lane-memory admission and a
strict aggregate retained-frontend budget. Disk reservation is preflighted from
page-rounded coefficient bytes before source construction. The store's own
atomic reservations remain authoritative if another caller consumes capacity.

Stage one seals each CPU, retires its local query caches, then parks its MAIN;
truth MAINs park immediately after sealing. Stage two restores only the active
worker before completing its unchanged proof. One complete ordered-manifest
barrier remains. The default profile and every proof/transcript byte stay intact.

Admission counts bindings, narrow retained CPU advice, compact truth local/global
query metadata, source fixed read views, local-proof reserves and conservative
owner headers. Coefficient-only parking ALSO retains all MAIN Merkle node layers;
those are included in `parked_retained_bytes`. Shared immutable setup, original
capture/advice and full PCS/source-construction scratch are separate leases. Lane
estimates preserve the maximum of the previous conservative estimate and the new
partial payload plan, so improved accounting never silently reduces admission.

The small complete fixture is byte-identical across parked/unparked routes for
every physical proof, physical claim and manifest; a receiver with rebuilt keys
accepts the parked result. Store live and mapped byte counters return to zero.
A later CPU-source failure releases an earlier parked worker. Truth spill
allocation failure leaves the sealed owner/root retryable; retry and abort leave
no mapped/reserved file ownership. These gates permit explicitly budgeted larger
inventories; they do not qualify a production-size full block or total RSS.

## Full-node parking and measured phase slots

`Store.initFullyParked` additionally parks every retained MAIN Merkle node layer.
The coordinator discounts only that node-payload bound; descriptors, root cell
and owner metadata stay reserved. Disk admission includes the versioned header,
coefficients and node upper bound, rounded once per file. The optional
`worker_timings` caller-owned array records source, cached-FIXED/MAIN commit,
local GKR, metadata retirement, spill, restore, native completion and phase totals.
It also counts actual nonempty MAIN Merkle layers after sealing and before spill.
Nil metrics cause no clock calls. Timings and storage never enter the transcript.
The full-node fixture uses two lanes against the one-lane resident control and
retains exact proof, claim and manifest parity with fresh acceptance.

The cost CLI `rv64-om-retention-plan BUNDLE_JSON ROM_LOG BLOWUP` invokes the same
source-derived CPU/truth retention authorities without constructing witnesses or
keys. Inputs are cost declarations, never verification authority. The recorded
full 25-CPU/five-truth roster uses ROM log 20: the pinned ELF contains 540,147
executable words and at most 32,607 extra branch rows, bounding ROM rows between
540,147 and 572,754. The report separates unpruned node bounds from the current
host streaming branch, which prunes four bottom layers at committed log >=20.
The latter models 0.891 GiB retained node values across this roster, rather than
claiming the 12.610 GiB unpruned bound as actual savings; runtime counters and
`parkingPlan` remain authoritative.

On that roster, native committed cells including per-proof FIXED references go
from 20,275,416,896 to 18,886,252,608 (6.85147% fewer). MAIN remains
10,230,620,160 cells; interaction cells go from 8,620,202,240 to 7,231,037,952.
The latter includes 3,271,442,944 binding cells plus pure globals/classic truths.
GKR working facts are not committed cells. This does not establish a speedup.

The conservative fully parked frontend reservation is 15.883 GiB, including
12.187 GiB binding planes, 3.438 GiB compact retained metadata, proof/header
reserves, coordinator-owned public-cell copies and a maximum manifest reserve.
The largest local GKR task plans 24.293 GiB; the represented stage-one task bound
is 26.970 GiB. Combining one such task with retained frontend state gives a
42.853 GiB conservative envelope before immutable setup, original capture/advice,
full source-construction/PCS scratch and allocator/kernel overhead. Two worst
stage-one lanes exceed 64 GiB even before those exclusions. No production-size
whole-block memory or performance qualification is inferred from this model.
