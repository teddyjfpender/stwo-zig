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
