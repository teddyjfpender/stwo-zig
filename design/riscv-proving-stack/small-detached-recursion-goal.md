# Small detached recursion and measured scaling

## Execution priorities, 2026-09-17

Complete the implementation and recursion path first, with clear ownership,
explicit compatibility and obsolete routes removed. Performance work follows
functional integration: use measured or known bottlenecks to scope subsequent
autoresearch tasks. Deeper correctness review follows that work; proof acceptance,
statement binding and malformed-proof rejection remain implementation gates.

Keep development loops proportional to the change. Use focused compile checks
and affected tests while implementing. Run the complete small recursive proof
command when integrating protocol or recursion changes, and broad suites at
integration milestones or when a concrete failure warrants them. Do not repeat
entire suites after documentation changes or unrelated local edits.

The checkpoints below qualify their recorded source revisions. Canonical protocol
identity, explicit legacy admission, standalone verifier boundaries and the tiny
1/2/4/8 continuation ladder now have retained complete-proof evidence. Shared
preparation consolidation and parent typed GPU interactions also have complete
proof checkpoints. Larger useful workloads remain open. The formal baseline repair is recorded separately below.


Work window: 2026-09-08 18:27:59 UTC through 2026-09-09 06:27:59 UTC.
The user authorized sustained implementation, optimization and repository cleanup
through this window, followed by the next larger useful proving milestone once
the initial sequence works. This document records acceptance; a passing subset
does not close the full goal.

## Measured tuple projection improvement, 2026-09-18

Profiles of genuine 16-address parents identified source-tuple projection at
1.7–1.9 seconds per parent; Poseidon/range interactions together cost about 12 ms.
The admitted evaluator now streams selected nonzero tuples directly, removing
full diagnostic entry-array construction and unused tuple-tail initialization.
Exact tuple hashing, order, signed weights and error handling remain unchanged.

[Qualification and raw measurements](../../vectors/reports/recursive-product-20260918/streamed-tuple-projection-qualified-v1/README.md)
record eight focused tests, all 29 parent AIRs compared with the diagnostic
projection, 14 ownership checks, and six freshly verified identical benchmark
proofs. Three alternating samples per version give median projection
1.735 -> 1.250 seconds (28.0% lower), and parent process
7.100 -> 6.683 seconds (5.9% lower).

The complete four-segment CPU/Metal/AOT gates pass all 384 cases with all 21
serialized artifacts identical to each other and the canonical baseline.
Uninstrumented Metal parent production is 21.859 seconds versus 23.436 seconds
at the preceding typed-device checkpoint. This is bounded measured progress,
not a broad throughput or production-security claim.

## 16-address ladder qualification, 2026-09-18

The complete 1/2/4/8 CPU and Metal/AOT ladder now passes with 16 memory addresses,
independent expected statements/topology, separately derived leaf/parent keys,
producer destruction and fresh standalone root verification. Parent setup uses
only freshly verified intermediate proofs and creates no candidate root proof.

[Retained qualification and replay instructions](../../vectors/reports/recursive-product-20260918/larger-memory-ladder-qualified-v1/README.md)
record 1,110 checks and 78 identical cross-backend artifacts. The maintained
tree-key setup command replaces the local setup recipe. A focused substitution
command checks genuine and alternate-seed statements once per node without
repeating the malformed-proof suite.

Single complete-production observations for 1/2/4/8 segments are
8.686/28.882/69.502/145.881 seconds CPU and
6.634/21.940/49.595/106.461 seconds Metal. Peak RSS at eight segments is
4.086 GB CPU and 4.533 GB Metal. The eight-segment root is 2.297 MB and verifies
independently in 66.65/65.65 ms for the two retained copies. Production times
exclude builds, locks and hostile cases; these are not statistical speed claims.

This closes the recorded 16-address development ladder, not production security
or Ethereum readiness. Instruction counts remain 35/98/227/482. Further work
must follow the functional milestone and measured bottlenecks rather than repeat
already passing broad suites.

## Larger workload admission, 2026-09-18

The remaining Poseidon/range provider paths already function on CPU; moving
those to GPU is performance work. The next functional milestone scales memory
topology and continuation beyond the single-address ladder.

Tree admissions now select 1/4/16 addresses. Segment-to-parent production can
consume a separately hashed boundary-profile JSON, checked against admitted
children and the parent key. The old tiny profiles remain compatible.
The new route passes 28 fresh-process cases on a retained genuine parent with
identical key, claims and proof. Five focused command tests and all 14 ownership
checks pass.

A separate workload exporter validates VM execution against the existing
instruction/memory model and emits expected statements before keys or proofs.
At 16 addresses, 1/2/4/8 segments and seeds 13/14 yield 30 independently pinned
expected statements. Seed-13 key setup produces 15 leaf keys and no outer proofs.
[Retained admission evidence](../../vectors/reports/recursive-product-20260918/larger-workload-admission-v1/README.md)
includes invalid-pin/topology controls and executable/source hashes.

The larger ladder is not yet qualified. Next derive parent expected statements
and boundary profiles from admitted execution, set up parent keys independently,
then run complete CPU/Metal/AOT trees and measure memory and root verification.
The instruction counts remain the small 35/98/227/482 development workloads;
16-address admission alone is not an Ethereum-scale receipt.

## Formal baseline repair, 2026-09-18

The load/store migration now uses an explicit reviewed revision receipt. It
preserves the historical equivalence receipt and rejects the claim that the new
equations are equivalent to that predecessor. The integrated formal gate passed:
60 reproduced artifacts, 24 production-AIR bindings, 46 opcode certificates,
Lean build and axiom audit. The live Sail bridge retains all 94 theorem and axiom
inventories. All 112 witness tests run without skips; stale fixtures now refresh
once per test session instead of hiding export failures.

Exact source pins, patch and logs are retained in
[formal repair evidence](../../vectors/reports/recursive-product-20260918/formal-reviewed-revision-v1/).
This closes the known baseline rebind failure; it does not establish whole-frontend
verification or proof-system soundness. Shared preparation consolidation, typed GPU
interaction integration and larger useful workloads remain open. The qualified
1/2/4/8 development ladder and standalone verifier boundaries are recorded below.

## Shared transcript preparation, 2026-09-18

The PCS transcript operation model, writer and schedule now live in the shared
recursion frontend, alongside native sponge frame-row construction. CPU integration
modules delegate to those owners; the detached prefix no longer imports the
Ethereum/common-fold program module to construct its PCS suffix. Protocol tags,
operation order and row construction are preserved.

All 14 ownership checks and the focused child/boundary checks passed. The initial
child invocation lacked fixture environment variables; the compiled test was rerun
with authenticated retained inputs and passed. Complete four-segment CPU/Metal/AOT
qualification passed 384 acceptance/rejection cases, with all 21 tracked artifacts
identical across backends and to the canonical baseline. Source snapshot, patch
and logs are in
[transcript preparation evidence](../../vectors/reports/recursive-product-20260918/shared-transcript-preparation-qualified-v1/).

Next, extract the immutable child-view contract and payload classification to let
the prefix and PCS-row owners leave CPU integration. Capture admission and parent
assembly remain to consolidate; typed GPU interactions follow functional integration.

## Shared prefix and PCS rows, 2026-09-18

Immutable child capture views and the segment/parent family tag now have a shared
contract. Detached prefix preparation and PCS transcript row construction live in
the recursion frontend and reuse the shared schedule/frame owners. Payload source
classification also has one owner, used by detached and common-fold preparation.
The integration files retain aliases and genuine-child fixture helpers.

All 14 dependency checks passed with the new owners included. The genuine child
and boundary checks passed, including the retained transcript, both PCS lanes and
hostile changes. Final cleanup removed unused imports before the complete gate.
Complete four-segment CPU/Metal/AOT qualification passed 384 cases; all 21 tracked
artifacts match each other and the canonical baseline. Exact source and results:
[prefix preparation evidence](../../vectors/reports/recursive-product-20260918/shared-prefix-preparation-qualified-v1/).

Remaining ownership work is child capture admission and composition, then the
boundary/parent statement, arithmetic and assembly owners. Batch those related
moves behind focused checks before the next complete-proof qualification.

## Shared capture and parent assembly, 2026-09-18

Detached child capture, recording adapters, composition recording, section/memory
profiles, boundary arithmetic, parent statement/arithmetic, base-row assembly and
parent preparation now have shared recursion owners. CPU integration retains
compatibility exports, named test entries, filesystem fixture ingress and backend
execution. Common transcript logical-row conversion and capture query geometry
also have single shared owners; existing common-fold callers delegate to them.
The full shared preparation dependency closure excludes integrations and concrete
backends, while the separate standalone verifier guards remain intact.

All 14 ownership checks passed. Fifteen affected tests passed across genuine
leaf capture, boundary, adapters, transcript, routing, statement, recursive-parent
capture and preparation. Parent preparation closed 9,116,105 lookup contributions
with zero unmatched tuples and passed aliasing, input destruction, failed-state
cleanup and retry checks. Named integration test wrappers preserve exact test
counts after relocating bodies into the frontend. One initial statement invocation
skipped for absent fixture paths; the authenticated two-segment rerun passed.

Complete four-segment CPU/Metal/AOT qualification passed 384 cases. All 21 tracked
artifacts are byte-identical across backends and to the canonical baseline. The
exact qualified source, compressed patch, logs and result summaries are retained in
[parent preparation evidence](../../vectors/reports/recursive-product-20260918/parent-preparation-owners-qualified-v1/).
This closes the listed detached capture/composition/parent preparation ownership
work. It does not qualify typed GPU interactions or larger useful workloads.

Next integrate the existing admitted device interaction primitives into a real
proof producer, preserving CPU parity and pole/shape rejection, then qualify that
change independently with complete proofs and measurements. Keep implementation
coverage ahead of speculative optimization.

## Parent typed device interactions, 2026-09-18

The shared parent producer now generates all 29 typed components' interaction
columns and claims with the authenticated Metal AOT backend. CPU generation
remains available. Intermediate columns use within-row cumulative sums; the
last secure column uses a cross-row prefix shifted by the average claim. The
shared authenticated AIR exporter owns local bindings, and one row projection
serves ordinary preparation and the device adapter. No relation equations were
copied into the producer. Parent Poseidon and range-provider interactions remain
on CPU.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/parent-device-interactions-qualified-v1/README.md)
records five scan geometries, all 29 parent AIRs through the production AOT
loader with full and padded rows, rejected-output preservation and retry, six
native table regressions, and 14 ownership checks. The complete four-segment
CPU/Metal gates pass all 384 cases; all 21 serialized artifacts equal each other
and the canonical baseline. The Metal command requires 116 successful typed
dispatches per parent (348 total), alongside 96 native-table dispatches.

Single complete-tree observations excluding compilation, lock waits and hostile
cases: CPU leaf/parent production 34.323/33.459 seconds, peak RSS 3.898 GB; Metal
26.023/23.436 seconds, peak RSS 4.393 GB. These are implementation qualification
measurements, not a statistical speed claim. Canonical columns still cross the
host/device commitment boundary. Larger useful receipts and remaining provider
work precede broad performance tuning or Ethereum claims.

## Native device interaction integration, 2026-09-18

The six native lookup tables now execute fraction generation, prefix scans and
claim generation through the admitted recursive-framework AOT profile. The shared
native producer selects the device writer through a backend capability; CPU and
other Metal profiles retain their existing writer. An admitted device failure is
propagated, with denominator poles preserving the native error contract.

Focused tests compare all columns and claims across all six real table geometries,
check malformed shape, poles and recovery, and require dispatch telemetry. The
complete CPU/Metal/AOT proof gate passes 384 cases and all 21 tracked artifacts
remain identical to baseline. Each native segment requires 24 successful device
interaction dispatches, enforced by the runner and the complete-proof command;
the four-segment gate records 96. The AOT shader and export inventory are unchanged;
only the generated pipeline coverage flag changes.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/native-device-interactions-qualified-v1/)
includes exact source, focused checks, full-proof summaries and measurements.
Metal leaf/parent production was 26.081s/26.035s versus 25.879s/26.090s at the preceding
checkpoint; peak process RSS was 4.388GB versus 4.389GB. Single observations do not
establish a performance change. This is functional device integration.

The current bridge stages canonical host columns and copies results into the
existing commitment ABI. Residency and staging costs are subsequent optimization
work. Recursive-parent typed interaction generation remains on CPU; this native
six-table milestone does not claim a fully GPU-resident prover.

## Shared equation ownership, 2026-09-17

Compact Poseidon equation identity and range-table admission now have separate
owners from witness generation. The canonical Poseidon digest is unchanged;
its dependency guard admits only core and the reviewed scalar equation helpers.
The range contract owns source, semantic and physical-binding identities, while
the existing bridge reuses those definitions for writers and backend export.
Table schema and physical layout likewise have one shared definition owner.
Focused checks cover native parity, exact upstream rows, malformed bindings,
allocation failures, backend export and manifest/transcript geometry.

The equation-owner extraction passed complete CPU/Metal/AOT qualification: 192
cases per backend and all 21 serialized artifacts identical across backends and
to the preceding canonical checkpoint. The exact qualified source snapshot and
patch are saved in
[equation-owner evidence](../../vectors/reports/recursive-product-20260917/equation-owners-v1/).
A subsequent small extraction gives typed geometry its own dependency-free owner,
with component APIs delegating to it; that follow-up uses focused admission and
manifest checks and is not included in the saved complete-proof snapshot.
The complete parent verifier still has lower-level witness and prover dependencies
to remove. See the current evidence under
[recursive product reports](../../vectors/reports/recursive-product-20260917/).

## Parent admission ownership, 2026-09-17

Parent parameters and claims now have an owner separate from component construction.
Wide Poseidon layout, shared-provider geometry and typed parameter counts each retain
one declaration owner. The public manifest API delegates geometry, transcript and
claim data to a pure contract; proof-adapter handoff stays in the component-facing API.
The parent admission extraction passed complete CPU/Metal/AOT qualification: 192
cases per backend, with all 21 artifacts identical across backends and to the canonical
baseline. Its source snapshot is in
[parent-contract qualification](../../vectors/reports/recursive-product-20260917/parent-contract-qualified-v1/).

The subsequent SegmentV2 import cleanup gives statement data and canonical wire views
one runner-independent owner. Source conversion imports its runner types directly;
continuation and transcript layout consume the shared contract. The parent key/claim
protocol now has 189 source dependencies, with a guard excluding runner, witness,
prover and component-factory imports. Focused statement boundary/transcript checks
cover this follow-up; it is not included in the preceding complete-proof snapshot.
This boundary is distinct from full standalone verifier component construction, whose
prover dependencies remain to be separated.

## Typed verifier components, 2026-09-18

The typed component factory now shares admission, layout and point-verifier methods
with `universal_typed_verifier_component`. The verifier-only factory exposes core
verifier bindings without a prover method. The existing prover-capable API derives
its public field types from that verifier state and delegates to the same methods;
domain preparation and execution remain in the prover owner. Point/mask allocation
helpers and LogUp predecessor-point equations also have single core-only owners.

Focused checks cover admission of both component types for all 34 typed rows, the
core point-verifier interface with reversed-mask rejection, cubic degree compatibility,
allocation-free prepared domains, parallel cancellation/failure handling and exact
LogUp predecessor geometry. The dependency guard excludes runner, witness and prover
sources. Full standalone integration still needs native Poseidon/range verifier
components and a verifier-only component collection. These changes are not yet part
of a newly qualified complete-proof snapshot.

## Native verifier components, 2026-09-18

Lookup tables and degree-three Poseidon now have verifier-only factories. The existing
prover components derive field types from verifier state and delegate their verifier
callbacks, so constraints, masks and admission checks retain one owner. Table relation
combination and recurrence evaluation live in a pure equations module; shared point
allocation helpers live below both native AIR and recursion.

Focused checks cover both table component APIs, ambiguous placement rejection,
predecessor order, all six table domains, mutation rejection and prepared-domain
allocation/cancellation behavior. Compact Poseidon passes native permutation/mode
parity and prepared-row differential checks; its verifier-only core callback agrees
on nontrivial point samples and rejects short masks and invalid geometry. An explicit
source allowlist restricts both factories and the compact equations to core and
reviewed scalar/schema helpers. The retained wide Poseidon provider and standalone
component collection still need separation. Complete-proof qualification of this
component batch remains pending.

## Retained wide Poseidon verifier, 2026-09-18

Wide Poseidon permutation constraints, lookup entries and interaction recurrences now
live in pure equation owners. Witness materialization delegates its shared round
helpers instead of carrying a second equation implementation. The existing
`poseidon2_degree3_verifier` factory accepts this wide universal layout, retaining
its 445 main columns and 432 constraints without a second verifier adapter.

Focused parity checks compare masks, composition split, constraint count and point
results against the retained native hash component. Pinned Rust column order, honest
rows, malformed rows, padding and lookup cancellation also pass. The named nested
test wrapper became unnamed so narrow test filters discover the actual AIR checks.
Standalone integration still needs shared provider challenge/identity admission and
a verifier-only parent collection; no new complete-proof qualification is claimed.

## Shared provider admission, 2026-09-18

Challenge conversion, cached-power checks and receipt hashing now have a pure shared
owner. Retained Poseidon receipt encoding and digest validation are separated from
witness authentication; both identity APIs delegate to the same codec. Witness and
relation format versions reference that shared format owner, preserving the golden
182-byte preimage and 214-byte receipt.

Poseidon/range cold-admission functions now serve the existing provider adapters and
are available to standalone assembly. They preserve manifest geometry, relation,
claim, trace-bound, canonical range-binding and deliberate identity-compatibility
checks. The prover-side range adapter additionally validates its writer executor.
Strict source guards permit only core and reviewed equation/schema/codec files for
these admission owners. Standalone parent assembly and full-proof qualification of
the combined component changes remain outstanding.

## Parent verifier assembly, 2026-09-18

The standalone parent verifier and its proof preflight now instantiate
`detached_parent_verifier_components_v1`, an immutable owner of the pure typed,
compact/wide Poseidon, and range-table verifier components. Admission uses the
shared cold provider checks and ordered manifest roster. Producer and verifier
share definition construction and partial-failure cleanup through
`detached_parent_definitions_v1`; the producer retains its recording and domain
interfaces. The standalone adapter now names core proof/channel types directly.

The component collection has a checked dependency closure without prover,
runner, or witness modules. The integration still enters through the frontend
facade; this is not yet a claim that the whole standalone executable has a
strict verifier-only source manifest. Focused checks cover canonical and retained
component geometry, preparation, and partial allocation failure. The complete
CPU/Metal gate now passes 192 cases per backend, with all 21 serialized artifacts
identical across backends and to the canonical baseline. The exact qualified
source snapshot and patch are retained in
[verifier assembly qualification](../../vectors/reports/recursive-product-20260918/verifier-assembly-qualified-v1/).
Fresh replay also passes 84 retained compact cases and 27 retained wide root
cases. This qualification covers the preceding statement, typed/native/wide
component, and shared-provider separation batch; it does not complete the whole
executable dependency boundary or the remaining implementation goals.

## Neutral parent verification, 2026-09-18

`detached_parent_verifier_v1` now owns ordinary parent verification in the
frontend. Decoder bounds and the transport allocation limit also have neutral
owners. The integration keeps compatibility exports and the recording-channel
freshness wrapper; ordinary verification does not import recording or transcript
witness construction. Both channel implementations expose the same draw-count
accessor and share one verification body.

The neutral module has a checked 236-source closure using only core, proof-wire,
postcard and frontend sources, with no runner, prover or witness modules. The
standalone executable builds and replays all 111 retained compact/wide cases.
The complete production qualification above predates this latest move; focused
recursive capture verification passes after destroying the original inputs, with
436 public-word and 45 claim/sample mutations rejected. The command entry and build
module still need narrowing before claiming a verifier-only executable boundary.

## Standalone parent dependency boundary, 2026-09-18

The parent verifier executable now builds from the narrow `parent_verifier.zig`
entry module, with only core, postcard and proof-wire dependencies. It no longer
imports the CPU backend, integration facade, frontend facade or prover engine.
The source-closure guard starts at the actual executable entry and checks all
242 sources for runner, prover and witness dependencies.

Shared parent custody/command handling and canonical segment expected-input
ownership moved into neutral modules. Canonical wire decoding, authentication,
and sparse continuation hashing now have one runner-independent owner;
runner-side construction delegates to those same definitions and equations.
The CLI retains both expected-statement derivation and folding operations.

Validation passes: narrowed standalone build, 12 ownership checks, four transport
checks, statement-root tests (312 passed, one skipped), three byte-identical
independently pinned expected derivations, and 195 fresh-process canonical and
retained compact/wide replay cases. Evidence is in
[standalone parent boundary](../../vectors/reports/recursive-product-20260918/standalone-parent-boundary-v1/).
This is parent-executable qualification; leaf-executable ownership and complete
CPU/Metal production qualification after these latest moves remain separate work.

## Leaf verifier admission, 2026-09-18

Leaf verifier isolation has begun with `query_bits_profile`: canonical lane
profiles, reference sealing/validation and their unchanged digest now have one
witness-independent owner. The witness writer aliases the same types, and leaf
admission names the neutral reference directly. Focused profile, mutation,
geometry and direct-writer checks pass, including a fixed reference digest.

The remaining dependency owners are the mixed SegmentV2 manifest/authority
contract, native parameter constants accessed through witness modules,
prover-capable boundary/provider adapters, and the leaf transcript/command
facades. This checkpoint does not claim that leaf verification is isolated.
Evidence: [query profile](../../vectors/reports/recursive-product-20260918/leaf-query-profile-v1/).

## Shared verifier parameters, 2026-09-18

All ten native verifier parameter builders now live in the neutral
`verifier_component_parameters` owner. Fixed tags and query-position kinds have
one `verifier_parameter_tags` owner, reused by witness writers. Query-bit masks
are constructed by the shared profile contract. The integration retains
compatibility aliases; leaf arithmetic selectors use the shared proof-kind type.

The neutral parameter closure excludes witness/prover/runner modules. A fixed
protocol-word digest covers all ten builders in each of the three branch modes.
The focused all39 leaf checks pass (admission, malformed/inactive/provider claims,
allocation cleanup, and symbolic claim recording), alongside profile/writer and
ownership checks. This does not yet isolate the mixed leaf manifest/authority
contract or boundary/provider adapters. Evidence:
[shared verifier parameters](../../vectors/reports/recursive-product-20260918/shared-verifier-parameters-v1/).

## Leaf manifest geometry foundations, 2026-09-18

Universal manifest construction now uses pure typed/shared geometry directly,
without instantiating prover adapters. Statement override metadata has a single
`segment_statement_outer_geometry_v2` owner; its AIR uses shared
`segment_leaf_layout_v2` publication tags and geometry rather than importing
native source custody. Existing source and catalog owners reuse these definitions.

The checked geometry closures exclude runner, witness and prover modules. Three
universal manifest cases, three substantive V2 catalog cases, all four all39
leaf-adapter cases and 12 ownership checks pass. The catalog test root now exposes
inner cases under narrow filters, fixing an observed zero-test selection.
Boundary/provider authority metadata and the mixed claim/proof gate remain to be
separated before the full leaf manifest is verifier-only. Evidence:
[leaf manifest geometry](../../vectors/reports/recursive-product-20260918/leaf-manifest-geometry-v1/).

## Single-segment root foundation, 2026-09-18

The execution fixture, producer dispatch, and tree gate now support 1/2/4/8
segments. The standalone leaf verifier's explicit `--root` mode verifies the
proof under the independent key pin, binds the expected wire against rereading
changes, and applies the shared complete-root coverage contract to a one-segment
job. Pair verification reuses the same expected-wire reload check.
The ordinary segment endpoint remains available for recursive children.

The execution-only ladder passes all 12 combinations of segment count and
1/4/16 memory addresses. A one-segment job retires 35 instructions and records
completion. Its shorter address sweep exposed and corrected a fixture validator
assumption that all configured addresses were touched; exact instruction and
memory-value checks remain in place. Five focused transport/root tests pass,
as do 13 ownership checks, 52 ordinary retained-proof cases, and rejection of
all four valid partial-job leaves as single-segment roots.

Independent seed13/seed14 expected wires are retained in
`vectors/reports/recursive-product-20260918/single-segment-foundation-v1`.
The subsequent independent setup and complete one-segment qualification below
close this foundation checkpoint. Current 2/4/8 proof admissions remain open.

## Independent leaf setup and single-segment qualification, 2026-09-18

The separate `recursive-segment-v2-leaf-key-setup` command accepts a pinned setup
manifest containing independently pinned expected statements. It authenticates
all statements before native proving or output creation, prepares native proofs,
and commits only the recursive fixed columns. Setup and production share fixed
commitment and key construction; setup creates no outer proof. Different memory
seeds produce the same circuit identity and fixed commitment. Six malformed or
substituted setup cases reject before output creation.

Both CPU seeds prove and freshly verify under the first setup key, with 14 root
gate cases each. The normal tree controller also passes on CPU and Metal using
the independent admission, including producer exit and standalone root coverage.
All four serialized artifacts match byte for byte across backends. Metal passes
an additional 14-case root gate with independent same-geometry substitution.
The tree runs add 26 cases; all 13 verifier ownership checks pass.

Single observations: CPU production 8.05 s with 2.90 GB peak process RSS; Metal
production 7.69 s with 2.56 GB peak RSS. The proof is 2,497,739 bytes; one CPU
verification took 69 ms. These are q193 development fixtures, not production
security qualification. The exact source snapshot, patch, independent keys,
admission, binary pins and reports are retained in
[independent setup evidence](../../vectors/reports/recursive-product-20260918/single-segment-independent-setup-v1/).
This documentation update follows that frozen source snapshot. The subsequent
four-segment regression and current 2/4/8 qualification below close those
remaining integration checks.

## Current canonical 1/2/4/8 ladder, 2026-09-18

The shared leaf key-construction extraction passed the complete four-segment
CPU/Metal/AOT command: 384 cases, all 21 tracked proof artifacts identical
across backends and to the canonical baseline. Separate parent setup then
established current compact-Poseidon admissions for two and eight segments,
using independently pinned retained expected statements and leaf keys. Each
key precedes its proof. Eight-segment setup verifies six intermediate proofs
to establish the final key without producing a root candidate.

Fresh complete CPU and Metal trees pass at both sizes: 164 cases for two
segments and 824 for eight, including independent same-geometry statement
substitution for every leaf. All 12 and 60 serialized files respectively
match across backends. The eight-segment trees cover 482 retired instructions,
authenticated continuation through all three parent levels, and standalone
whole-job roots after producer exit.

The [current ladder report](../../vectors/reports/recursive-product-20260918/canonical-ladder-v1/README.md)
records independently pinned admissions, exact source evidence, verification
cost and memory. Eight-segment production is 143.74 s CPU / 109.66 s Metal;
peak process RSS is 3.90 / 4.39 GB. Its root is 2.308 MB and verifies in
65–68 ms. These are single observations of small q193 development fixtures.
The report separates production from lock waits and hostile-case verification.

This closes the bounded current receipt ladder, not the full goal. Shared
preparation still has CPU-integration owners to consolidate, typed GPU
interactions remain unintegrated, and the load/store formal semantic-rebind
receipt needs a truthful successor. Larger useful workloads and security
admission precede the return to Ethereum. This documentation update follows
the frozen qualification snapshot.


## Shared PCS/FRI preparation owner, 2026-09-18

Detached PCS/FRI preparation now lives in shared recursion as
`detached_pcs_preparation_v1`. The former CPU-integration implementation has
been replaced by four compatibility exports. Capture custody, selected-lane
logical rows, graph inputs, Merkle paths, and provider requests retain their
existing behavior. Imports name the required owners directly.

The dependency guard excludes integration and concrete-backend directories
from the complete preparation closure. Preparation may use generic witness and
prover contracts; the separate standalone-verifier guards continue excluding
witnesses and proving code. All 14 ownership checks pass. Real-child replay
checks both selected lanes against the reference preparation, provider outputs,
raw query draws, malformed rows, and boundary rejection after input destruction.

Complete CPU/Metal/AOT qualification passes 384 cases. All 21 tracked artifacts
are byte-identical across backends and to the canonical baseline. The
[qualified snapshot and focused evidence](../../vectors/reports/recursive-product-20260918/shared-pcs-preparation-qualified-v1/)
precede this documentation update. Child capture, transcript-prefix and parent
routing preparation still have CPU-integration owners; this change does not
claim that all shared preparation has moved.


## Standalone leaf verifier boundary, 2026-09-18

Native proof descriptors and Poseidon call data now have shared data-only
owners. Native source preparation and detached verification use the same
statement projection, authority preimage, hash-call emitter, and public-wire
projection. The statement projection retains scalar-program-root rejection;
the emitter retains overlap rejection and canonical sponge framing.

The leaf transcript, STARK verifier, and command now live in neutral recursion
owners. The standalone executable imports only its narrow leaf-verifier module,
core, and proof transport. The source-closure guard starts at the actual runner
and excludes prover, runner, witness, engine, and recording-channel dependencies.
CPU integration retains compatibility exports and a thin fresh-recording-channel
adapter. Real-child capture checks preserve openings and transcript replay after
caller input destruction, including same-geometry statement substitution and
sampled-opening rejection. The initial capture invocation accidentally used a
different-length adjacent statement; replay with the product gate's independently
pinned seed14 same-geometry fixture passes without changing assertions.

Focused preimage, transcript, public-input, source-writer, recording, transport,
and serialized-proof evidence is recorded in
`vectors/reports/recursive-product-20260918/standalone-leaf-boundary-v1`.
Complete CPU/Metal qualification passed: 384 cases, with all 21 serialized
artifacts identical across backends and to the canonical baseline. The exact
source snapshot, patch, binary hashes, and gate summaries are retained in
`vectors/reports/recursive-product-20260918/standalone-leaf-qualified-v1`.
This also qualifies the preceding statement/public-claim extraction. The source
freeze is released; the useful 1/2/4/8 receipt ladder remains incomplete.

## Shared leaf statement and public claims, 2026-09-18

The leaf transcript now uses verifier-only statement-source geometry,
verifier-key authority, native temporal-context identities, and fixed public
arithmetic-wire claim evaluation. Native source preparation aliases those same
types and functions. The expected-public row-36 claim and its symbolic tuple
emitter now live in a shared recursion owner; CPU integration retains compatibility
exports and source-side tests. No key format or identity preimage changed.

Focused checks cover the independently pinned q193 key, four transcript cases,
three expected-public claim cases, native context publication, atomic source
writes, and V1/V2 separation. The dependency guard includes all three new owners.
The remaining native hash-call boundary requires pure descriptor and Poseidon
call contracts before the leaf transcript and command can have fully restricted
dependencies. See `vectors/reports/recursive-product-20260918/leaf-statement-contract-v1`
for evidence. Complete CPU/Metal production qualification for this batch is now included in
`standalone-leaf-qualified-v1`; the preceding leaf-assembly qualification is
preserved separately.

## Pure leaf component assembly, 2026-09-18

The detached leaf verifier now instantiates a verifier-only 39-component
collection. Admission parameters, claim validation, statement inactive-row
claims, the logical catalog, fixed row parameters, and incremental definition
ownership have shared neutral owners. The recursive recorder retains its
prover-capable adapters and uses those same contracts and definition lifecycle.
Typed and native provider point equations remain shared with the existing
adapters; admission authenticates each placement and the complete roster order.

The four focused assembly tests compare all 39 component geometries and
preprocessed indices after caller inputs are destroyed, reject malformed
admission and provider claims in both owners, sample allocation failures in both
owners, and retain symbolic recursive recording. All pass. The pinned q193 key
and 12 dependency ownership checks pass as well. The pure collection excludes
prover, runner, and witness sources; the leaf transcript and command still need
separation. Evidence and complete-proof qualification status are recorded in
`vectors/reports/recursive-product-20260918/leaf-verifier-assembly-v1`.

The frozen batch also passed both complete CPU/Metal four-segment gates:
384 cases total, including fresh serialized verification, malformed proofs,
and same-geometry statement substitution. All 21 serialized artifacts match
across backends and match the canonical baseline byte for byte. Exact source
snapshot, patch, binary hashes, and full gate summaries are saved in
`vectors/reports/recursive-product-20260918/leaf-assembly-qualified-v1`.
The source freeze is released. This qualifies the ownership changes through
leaf and parent-of-parent proof consumption; q193 remains a development profile.

## Pure leaf manifest and claims, 2026-09-18

`segment_outer_manifest_contract_v2` now owns the admitted 39-row manifest,
claim vector, program identity and their exact validation/transcript rules. Its
catalog imports only typed AIR geometry and shared boundary/provider metadata.
Boundary component checks, provider shape, publication authority hashing and
row-17 schedule geometry each have shared neutral owners, reused by writers.
The producer-side `validateAgainstSources` operation remains explicitly typed
and now lives outside the pure Manifest; its four callers use the source facade.

The contract closure has no runner, witness or prover modules. Five catalog/
adapter cases, two substantive source-custody cases, 12 ownership checks and
validation of the independently pinned q193 child key pass. That serialized-key
check also rejects a changed provider authority. Leaf verifier assembly and its
transcript/command integration remain to be isolated; complete production
qualification for this batch remains pending. Evidence:
[leaf manifest contract](../../vectors/reports/recursive-product-20260918/leaf-manifest-contract-v1/).

## Historical checkpoint, 2026-09-09

The parent hot-path pass is complete. Three alternating A/B rounds reduce the
q193 four-segment root median from 26.252 to 21.364s CPU and 20.805 to 15.046s
Metal. Shared quotient row sharding reduces diagnostic composition time from
about 3.4s to 1.4–1.5s; canonical hashing and one exact source projection also
reduce preparation/closure work. All 975 final fresh acceptance/rejection cases
pass, including newly built complete four-segment CPU/Metal trees and changed
memory with all seven keys reused. See the
[measurement index](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/parent-hotpath-measurements.json).
CSP benchmarking was explicitly excluded from this pass by the user.

The strongest next GPU opportunity has an explicit boundary in
[recursive Metal composition admission](recursive-metal-composition.md).
The current parent catalog declines resident GPU composition and uses the shared
host evaluator; Metal still performs commitments. A future exporter must preserve
the authenticated recursive column sources and framework LogUp layout. Do not
substitute existing narrow-memory capabilities or change protocol parameters.
Preparation and exact closure remain measured host costs as well.

Items 1 and 2 have complete proof evidence. Actual 2/4/8-segment development jobs
produce every native child, detached wrapper, intermediate parent and one root
on CPU or Metal. Each serialized proof verifies in a fresh CPU process after
producer exit. All artifact bytes match across backends. These are small RISC-V
memory workloads; Ethereum block proving has not resumed.

The separately admitted experimental q193 profile now also completes 2/4/8 trees
on CPU and Metal, including every recursive parent. Here q193 means 193 FRI
queries. A stronger profile is not itself production-security certification;
formal production admission remains open. The shared parent statement
authenticates 436 public
words, session and endpoint lineage; existing changed-memory runs reuse complete
admitted keys. Focused capture checks cover all 872 transcript limbs, canonical
field encoding and coherent public-word mutations.

The maintained small-tree controller and exact pinned commands are documented in
[the benchmark guide](small-recursive-benchmark.md#complete-cpu-and-metal-tree-controller).
The first complete development gate takes 10.59/23.69/49.76s on CPU and
7.82/17.81/38.05s on Metal for 2/4/8 segments, including hostile cases.
Native production, wrapper preparation/proving, parent production, root
verification and RSS are recorded separately.

A focused wrapper optimization now has three alternating A/B rounds on both
backends and profiles. Reusing CPU commitment coefficients removes about 98.6%
of sampled-opening time. Median CPU wrapper proving falls 0.978 to 0.619s in the
development profile and 9.999 to 6.396s in q193. The stronger two-child producer
falls 32.554 to 25.364s. All 560 fresh cases pass with unchanged artifact bytes.
Metal already evaluates these openings efficiently on the GPU; retention adds
memory without a wrapper improvement, so its existing policy is preserved.

Earlier parent optimizations retain coefficients and use the shared compact
tuple ledger. The final policy passes all eight complete-tree runs and 1,014 fresh cases.
Expanded phase attribution identified repeated domain-audit arithmetic, addressed
by the shared direct-writer pass below. Maintain the
small complete-proof loop; do not use an Ethereum-sized replay as the development
gate. Formal quiet-host CSP preservation remains open; no CSP default, worker
policy or shared RV32 execution path changes in this wrapper optimization.

The next interaction pass now also has measured savings on both backends.
All 16 native-core components consume the existing typed-AIR direct writer and
its per-domain results. Independent cold replay agrees on all 128 component
comparisons; 560 alternating proof checks preserve exact artifacts. Stronger
wrapper medians improve another 11.4% CPU and 15.7% Metal, with stable memory.
Complete two-child medians are 23.896s CPU and 18.671s Metal. The focused
framework gate runs in 272ms after a six-second compile.

All eight full-tree reruns pass 1,014 fresh cases with identical artifacts.
The subsequent stronger 4/8-segment milestone now also passes on both backends.
Its four-segment producer sums are 127.64s CPU / 102.94s Metal; eight segments
take 279.65s CPU / 228.24s Metal. Each aggregate contains N-1 actual parent proofs.
Final root STARK verification stays at 72–81ms, and peak process RSS remains
about 6.7GiB CPU / 7.1GiB Metal for four and eight segments. These are single
observations, not an A/B promotion claim; device allocation memory remains a
separate measurement obligation. See `q193-complete-ladder-measurements.json`.

Changed initial memory now reuses all seven four-tree and all fifteen eight-tree
keys unchanged; every new proof and statement verifies independently. Both
depths also pass the consuming-AIR mutation check, including all 436 public
words. The deeper cached check runs in three seconds. Genuine weaker segment and
parent proofs are rejected before q193 AIR allocation.

Formal CSP preservation, independent production circuit/security admission and
separate device-memory measurement remain open. Keep the existing per-segment
workload small. Do not
extend leaf optimization indefinitely or substitute development-profile trees
for the separately admitted stronger route.

## Required implementation order

1. Make the current small wrapper independently verifiable. A fresh process
   accepts an independently admitted verification key, expected public statement
   and canonical serialized proof. Child verification and statement binding are
   enforced by the AIR. No native capture, native preparation, producer receipt
   or witness-derived validation flag supplies verifier authority.
2. Prove the continuation as a second child and compose both children into an
   actual recursive proof. Authenticate clocks, memory boundaries and exact
   coverage. Reject altered boundaries, swapped children, gaps and duplicates.
   Exercise native children produced by both CPU and Metal.
3. Measure 2/4/8 segments while keeping individual segments small. Separate leaf,
   aggregation, final verification and process-memory costs. Optimize the largest
   measured contributor. Measure an explicitly admitted production-security
   profile separately from the existing development profile.
4. Prove the complete tree on Metal as explicitly requested: native leaves,
   detached recursive wrappers, every intermediate parent and the final root.
   Reuse the same admitted AIR, transcript and verification keys across CPU and
   Metal; retain independent fresh CPU verification as a cross-backend check.
   Require actual GPU execution evidence for recursion, CPU/Metal proof parity,
   and separate end-to-end 2/4/8-tree timings, phase costs, RSS and device memory.
   Native Metal children with CPU aggregation do not satisfy this milestone.
   Finish the stronger CPU two-child root first, then port that working route.
5. Continue into larger recursive proving and measured optimization as the
   preceding gates permit. Consolidate shared admission/transcript definitions,
   remove superseded routes after replacement proof gates pass, and reduce
   compilation dependencies where measurements justify it. Preserve one owner
   for each frontend/protocol fact and backend-specific execution strategies.

The original requested sequence is the attachment `pasted-text-1.txt` supplied
with the active goal. The list above retains every numbered deliverable and the
additional twelve-hour optimization/cleanup direction.

## Admission and correctness requirements

- A key's structural validation or a prover-supplied hash is not independent key
  admission. Reuse the existing pinned, owned key transport where applicable.
- Classify circuit structure, parameters and preprocessing separately from
  statement values, native claims/challenges, openings and other proof inputs.
  A reusable profile must accept distinct proofs under the same admitted key;
  exporting a witness-specific circuit is insufficient.
- Preserve all 39 small-route components, all auxiliary provider claims and
  the 47-domain relation contract. Ethereum ordinary36/Initial38 catalogs are
  different contracts and cannot be substituted by matching row numbers.
- Claims arrive as untrusted proof data and become authenticated through the
  transcript and STARK constraints. Free audit decompositions or host-only child
  verification cannot establish recursive proof acceptance.
- Each child closes independently before canonical adjacent-span composition;
  cross-child cancellation must not repair an invalid child.
- Producer and native-preparation ownership must be destroyed before the fresh
  verifier runs. Retain genuine failure inputs and canonical serialized artifacts
  so the complete proof gate is reproducible outside the producer process.
- Keep CSP defaults, protocol identities and execution separate. The user
  explicitly excluded CSP benchmarking from the current parent optimization
  pass; this pass makes no CSP promotion claim. The historical 16-case
  preservation evidence and its quiet-host limitation remain recorded above.
- Keep RV64 a separately admitted future frontend/profile. No shared RV32
  widening or CSP execution-path change is part of this work.

### Stronger recursive admission boundary

The q193 parent-of-parent review found a shared verifier/transcript route, not a
second protocol implementation. Capture consumes the standalone verifier;
`recursive_segment_v2_detached_prefix.zig` owns admission, claim and interaction
PoW ordering. All 436 parent public words enter canonical split-u16 relations.
Session, endpoint lineage and adjacent spans use the shared continuation rules.

Successful experimental trees do not close production admission. The independent
key hash authenticates the selected bytes; structural key validation does not
certify that Tree0 encodes the intended circuit. Production admission must retain
reproducible fixed-circuit/Tree0 generation and reviewed transitive child pins at
every level. Parent-family construction relies on those child proofs to enforce
child semantics. The configured q193 parameters also need an explicit security
argument covering FRI assumptions, algebraic and lookup error, hash assumptions,
and composition across the admitted depth. `DEVELOPMENT_ONLY` remains true.

For each new experimental tree, require unchanged keys across initial-memory
values, CPU/Metal artifact parity, freshly verified intermediate/root proofs,
and the existing consuming-AIR public-word mutation gate. Retain genuine weak
segment and weak parent inputs that fail a q193 parent before AIR allocation;
mutating a transport header alone does not cover that admission boundary.

### Next bounded optimization candidate

The stronger four-segment root profile isolates one duplicate source projection.
`frontends/riscv/recursion/detached_parent_prepared_v1.zig` evaluates every logical row's
`relation_plan.preparedEntries` during admission to build only the range counter.
Exact closure later projects the same owned rows again. The existing compact
tuple ledger already owns a source range counter.

A candidate main-finalization operation can append source tuples once, derive
the range batch from that counter, fill provider columns and close the actual
provider/public tuples before commitment. Keep direct-constraint admission,
canonicality, destination/alias checks, provider column agreement and the cold
mutated-main audit. Keep the ledger local to finalization rather than extending
its retained lifetime. This is a candidate, not an implemented improvement.

The entire measured graph-to-prepared snapshot interval is only 1.416s CPU and
1.372s Metal; the removable traversal is a subset of it. Therefore this alone
cannot save more than roughly 5–6% of the root request. Measure preparation plus
finalization together so relocated work cannot masquerade as savings. Larger
reductions require separate evidence about graph construction and exact-ledger
aggregation; do not promise an order-of-magnitude gain from this fusion.

## Starting evidence and immediate boundary

Starting clean checkpoint: `51646b44`. The previous native fixed-cost round has
84 small complete-proof runs, a 19-test semantic gate and a 128-launch CSP
diagnostic; see [its evidence index](../../vectors/reports/riscv-proving-stack-reset-20260908/native-fixed-cost-v1/README.md).
The small wrapper remains native-assisted: the outer engine rebuilds a full
cohort from `PreparedNativeV2LeafOuter` during verification, including interaction
generation, authority identities and host closure audits.

Existing detached Ethereum machinery supplies useful pinned key ownership,
canonical proof transport, typed verifier construction and fold consumers. Its
catalog, field transcript and secure profile differ from the small route and
must remain explicitly admitted. The first implementation seam is a witness-free
39-component factory, followed by fixed/dynamic admission and authenticated
public inputs. The native-assisted route remains a parity oracle until the
detached complete-proof gate replaces its operational role.

## Design references

- [Clement Walter research baseline](../typed-air/notes/2026-08-04-research-baseline.md):
  design provenance, reproduced experiment and limits; compiler reuse is not a
  substitute for soundness or measured trace cost.
- [Typed-AIR architecture](../typed-air/ARCHITECTURE.md): immutable owned IR,
  versioned lowering/layout and component boundaries.
- Typed-AIR ADRs 0039, 0040 and 0041: authenticated auxiliary claims, temporal
  composition and complete physical claim layout. Their recorded proposal or
  acceptance status must be distinguished from actual current implementation.

All maintained implementation stays in `src/`, tools in `scripts/`, guidance in
`design/` and evidence in `vectors/reports/`. Heavy jobs use the existing shared
lock; observing a timeout never authorizes starting a replacement producer.

## Verified progress at the detached-child checkpoint

- Two distinct tiny register statements prove under one identical serialized
  key and verify in fresh processes. Memory digest binding and indexed
  statement-hash calls are active in those proofs.
- Both actual segments of a completed 98-instruction memory workload prove with
  native CPU and native Metal. Their outer proofs, keys and expected public
  words are byte-identical across backends. Fresh bundle verification checks
  complete coverage, sparse memory, boundary clocks and lineage; 17-case gates
  reject swapped, duplicated and missing children as well as proof tampering.
- The shared verifier can record the exact child transcript without native
  preparation. Real-capture parity, caller destruction and complete symbolic
  composition evaluation pass on a retained genuine proof. All 41 claim slots
  and four composition-sample limbs are exercised by rejection checks.
- Shared allocation-failure cleanup is committed as `bc0ed210`. The focused
  allocation sweep and real-proof evidence are retained in the same report.

This does not complete item 2: the succinct temporal parent still needs active
AIR binding of the detached transcript's public wire, derived context/hash
boundaries, claims and openings. That is the next critical-path step. The
2/4/8-segment recursive ladder, production-security profile and formal quiet-host
CSP promotion remain outstanding. Detailed evidence:
[detached-child progress](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/progress.md).

## Verified two-child parent checkpoint, 2026-09-09

The next checkpoint now supersedes the outstanding item2 statement above: two
actual children are verified inside the parent AIR, including transcript,
composition, PCS/FRI, dynamic expected wire, sparse memory and clocks. One
serialized parent STARK is independently verified from its admitted key and
expected root. The child retains its existing39-component protocol; the parent
uses its separately versioned30-active-component cohort and47 relation domains.
Six runs cover three memory values and both CPU/Metal native child backends under
one unchanged parent key. All126 fresh-process parent cases pass. The parent
itself is CPU-proved. The maintained parent gate also exercises producer exit
before verification, with independently pinned inputs and retained negative cases.

Parent requests are3.87–4.06s, verification9.7–11.8ms, with roughly655–656MiB RSS
in these development observations. The complete small route is now the boundary
for further changes; a passing preparation check alone no longer replaces it.

Item3 remains open. The immediate larger-tree seam is an authenticated
intermediate statement retaining session and entry/exit lineage, with explicit
non-root versus whole-root admission. Then capture and recursively verify actual
parent proofs using the shared transcript and PCS/composition machinery. Prove
4→2→1 and8→4→2→1 trees; do not count flat bundles or repeated two-child examples
as that ladder. Measure the production-security profile separately and complete
the unchanged CSP preservation gate before performance promotion.

## Complete CPU and Metal tree checkpoint

The earlier CPU-wrapper limitation is now closed: actual 2/4/8 development trees
prove native children, wrappers and all recursive parents with the selected
backend. Every root freshly verifies on CPU; artifact bytes match across
backends. The separately admitted q193 two-segment full Metal route also passes.
These remain tiny RISC-V fixtures, not Ethereum blocks or production-security
certification. See the [current command and measurements](small-recursive-benchmark.md#complete-cpu-and-metal-tree-controller).

The sampled-opening pass is complete: CPU wrappers improve about 36%, while
Metal retains its lower-memory existing policy. The direct-writer pass also removes a repeated batch inversion from domain
auditing, improving both backends. Stronger 4/8 admission and formal CSP
preservation remain open.

## Recursive AIR specialization pass

Starting checkpoint: `ee7de71f`. The user authorized three parallel candidates:
fused verifier arithmetic, specialized opening/FRI arithmetic, and compact
Poseidon AIR. Opening accumulation takes priority over a separate FRI-fold
component because its repeated arithmetic population is substantially larger.

Implementation order and promotion gates:

1. Check each AIR against independent field/permutation operations and the
   original external lookup multiset, including changed outputs, shared nodes,
   exported intermediate values, padding and authenticated geometry.
2. Integrate the candidates in one parent route. Existing child keys retain
   their original verifier components; exact versioned semantic geometry selects
   adapters for native verification and symbolic recursive recording alike.
   New keys require separately reviewed admission. No proof may admit its own
   key or expected statement.
3. Produce a root from retained genuine children, serialize, destroy producer
   state, and freshly verify with the admitted key and independently derived
   statement. Require exact lookup closure before proving.
4. Repeat on CPU and Metal, then consume optimized parents at the next level.
   Check changed memory inputs under the same circuit admission and all existing
   proof/boundary rejection cases.
5. Compare complete requests, phase timings, padded trace cells, logical witness
   storage and process peak RSS against the frozen checkpoint. Report individual
   candidate costs and combined measurements without adding overlapping savings.
   A failed complete proof or reproducible slowdown blocks promotion.

The existing proof parameters stay fixed. These q193 fixtures are development
benchmarks, not production-security certification or Ethereum-sized blocks.
The user excluded CSP performance runs from this pass. Frontend semantic checks
remain small; heavy builds and proofs are serialized. Structural tests alone
do not complete this pass.

### Specialization completion evidence

All five gates above passed for this bounded pass. The combined AIR reduces paired
root median request time 41.8% CPU and 34.1% Metal. Three complete four-segment
trees cover CPU, Metal and changed memory under unchanged per-node keys; optimized
parents are consumed by the next recursive level. See
[the measured specialization report](recursive-air-specialization.md) and its
source/artifact audit. This closes this optimization pass, not production-security
admission or the broader Ethereum goal.


## Shared typed interaction preparation, 2026-09-18

The detached leaf core and Ethereum transcript preparation now delegate cold
interaction generation and exact domain decomposition to
`recursion/air/prepared_interaction_generation.zig`. The shared owner reuses the
framework inverse plane and supports the existing independent cold audit and
tuple ledger. The duplicate generation bodies were removed from CPU integration;
component placement, staging, receipt validation, and publication remain with
the owning callers. Failed diagnostic/ledger work cannot return a publishable
result even if it has written staging columns.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/shared-interaction-preparation-qualified-v1/README.md):
32 focused ReleaseSafe tests, 14 dependency ownership checks, and 384 complete
CPU/Metal acceptance/rejection checks. All 21 serialized key/claim/proof artifacts
remain identical across backends and to the canonical baseline. The focused
allocation test also preserves the Ethereum audit's two-allocation contract.
No speedup claim is made for this ownership change.

Remaining ownership work is concrete: the leaf preparation bundle still binds
its native capture to the CPU engine, the core preflight/authority remains in
`recursive_fri_outer`, and the noncore owner imports that concrete leaf bundle.
These contracts must move before the shared leaf path is complete. The actual
leaf proof still calls the existing cohort interaction writer; extending typed
GPU dispatch to all 37 leaf components remains separate from the already
qualified parent GPU route. Preserve the current staged publication and cached
receipt validation when moving these owners. This checkpoint does not close
those remaining implementation tasks or production-security admission.


## Shared native-leaf bundle ownership, 2026-09-18

`recursion/detached_native_leaf_preparation_v2.zig` now owns capture transfer,
verifier-plan cloning, captured FRI and VM composition preparation, transcript
execution and challenge validation, boundary traces, Poseidon scheduling,
prepared authority, and bundle identity. Its factory takes the verified capture
type and an explicit core-preflight interface. The CPU leaf module is now a
binding and alias facade with no alternate preparation implementation.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/native-leaf-preparation-qualified-v1/README.md):
the transferred 736-line body is identical after factory indentation and the
two dependency alias normalizations; 12 focused ReleaseSafe tests and 14
ownership checks pass. The complete CPU/Metal commands pass 384 checks with
21 serialized key/claim/proof artifacts identical across backends and to the
canonical baseline. Capture error unwinding, validation, hash domains, field
order, and proof parameters are preserved. This is an ownership change without
a speedup claim.

The remaining concrete core authority/preflight is supplied by the integration;
the source-closure guard does not prove that this supplied implementation moved.
The next cohesive work is the noncore owner with its private contract, support,
and runtime, followed by the core namespace's concrete backend binding and
verifier-parameter compatibility import. See the retained
[dependency audit](../../vectors/reports/recursive-product-20260918/native-leaf-preparation-qualified-v1/next-ownership-audit.md).
Keep focused compilation checks while moving these dependencies and qualify
the resulting cohesive ownership change once through the full proof gate.
Typed leaf GPU dispatch and production-security admission remain incomplete.


## Shared core, noncore, and concrete leaf cohort, 2026-09-18

The actual detached leaf path now uses shared frontend implementations for
`detached_fri_core_v2`, `detached_leaf_noncore_owner_v2`,
`detached_leaf_cohort_v2`, and `detached_leaf_tuple_diagnostic_v2`. This moves
core preflight and witness generation, noncore preparation, complete-cohort
assembly, retained interactions, and publication out of the CPU integration.
The integration entry points are bindings and aliases; core backend selection
and prepared-leaf type selection are explicit caller inputs. Thirty-four
private CPU implementation files were removed.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/shared-leaf-owners-qualified-v1/README.md):
all 38 moved files match the recorded transformations, 86 explicit dependency
aliases match the previous source owners, and all ten moved tests retain named
integration wrappers. There are 29 focused ReleaseSafe test executions and 14
passing ownership checks. The three related moves used short focused loops and
one final complete-proof qualification rather than full rebuilds between moves.

The CPU/Metal gates pass 384 acceptance/rejection checks, including fresh
standalone verification and same-geometry statement substitution. All 21
serialized key/claim/proof artifacts remain identical across backends and the
canonical baseline. Both source snapshots match, and native-table plus parent
typed GPU dispatch checks remain active. No equations, proof parameters,
identity domains, capture custody, domain-audit rules, or cached-publication
contracts changed; no speedup claim is made for this ownership move.

Audit shared transaction storage and the legacy outer-proof wrapper before
closing the broader ownership requirement. Typed GPU dispatch for the leaf's
37 typed components is still pending. The AOT exporter currently emits typed
interaction kernels only for parents and already deduplicates shared kernels;
extend that owner, preserve exact leaf audits and staged publication, qualify
all leaf component shapes, and measure complete proofs before promotion.
Production-security admission remains outside these development-proof results.


## Leaf interaction kernels and shared storage, 2026-09-18

The AOT exporter now covers interaction generation for all 37 typed leaf
components and the existing 29 parent components. Deduplication adds 12 kernels:
105 additional recursive-profile exports, 271 total. All 93 previous kernel
names and declaration digests are unchanged. The common parity helper covers
full and padded traces and now compares complete columns after failure/retry.

[Component qualification](../../vectors/reports/recursive-product-20260918/leaf-interaction-kernels-qualified-v1/README.md):
74 leaf and 58 parent cases pass admitted-AOT column/claim parity, pole rejection
without destination mutation, and full-column retry parity. The typed telemetry
assertions cover 1,056 successful dispatches. Existing native-table and resident
composition tests also pass. This checkpoint does not activate leaf proof GPU
dispatch or claim a complete-proof speedup.

Transaction storage and proof worker-pool ownership moved to
`recursion/transaction_storage_v2.zig`; the CPU entry point now aliases it. The
body is unchanged after dependency binding, with 16 focused tests and 14
ownership checks passing. Full-proof qualification of these latest changes is
pending the integrated leaf path, avoiding an extra full rebuild for the
storage-only move.

Next implement the explicit generator interface through the shared core,
noncore, transcript/public/statement, boundary, and input-provider writers.
Preserve the authenticated zero-row-10 fast path, exact domain audits, staged
publication, and cache validation. The concrete call-site plan and lifetime
constraint for committed TreeStorage are in the retained
[integration plan](../../vectors/reports/recursive-product-20260918/leaf-interaction-kernels-qualified-v1/integration-plan.md).
Then qualify complete CPU/Metal proofs and measure whole requests before
promoting the device path. The legacy outer wrapper retains publication and
tracked-allocator bindings that require a separate cohesive audit.


## Leaf device interaction integration, 2026-09-18

The pending leaf generator integration and transaction-storage proof gate above
are complete. An explicit admitted generator now flows through all shared leaf
writers; Host wrappers preserve existing callers. Exact independent domain audits,
framework alias validation, staged publication, cache validation and the inactive
row-10 path remain in place. Audited device output reuses inversion scratch and
is published only after its fallible host audit succeeds.

[Complete qualification](../../vectors/reports/recursive-product-20260918/leaf-device-interactions-qualified-v1/README.md)
records 25 focused host tests, 14 ownership checks, 74 leaf and 58 parent component
cases, and 384 complete CPU/Metal acceptance/rejection checks. All 21 serialized
artifacts remain baseline-identical. Four Metal leaves execute 144 typed
interaction dispatches each; together with native tables and three parents the
complete tree requires 1,020 successful interaction dispatches.

Single complete-production observations were 66.582 s CPU and 50.019 s Metal,
excluding build and verification gates. No leaf speedup is established. The
implementation milestone takes priority over speculative tuning. Next review the
legacy outer-wrapper publication and tracked-allocator bindings cohesively; the
larger ladder still needs qualification of this newly integrated device path.


## Shared producer accounting and current device ladder, 2026-09-18

The allocator implementation moved unchanged into the prover layer. The Ethereum
runtime retains a compatibility alias; recursive producer callers now bind the
shared owner directly. The existing allocator growth/concurrency test runs alone,
and `test-recursive-runtime-ownership` checks the remaining runtime policy without
the broad Ethereum structural group. Three focused tests and 15 ownership checks
pass; there is no duplicated allocator implementation or test body.

[Qualification evidence](../../vectors/reports/recursive-product-20260918/shared-producer-accounting-qualified-v1/README.md)
records 384 fresh canonical CPU/Metal checks and 21 baseline-identical artifacts.
The exact binaries then passed all 1,110 checks on the 16-address 1/2/4/8 ladder,
with 78 artifacts identical to both backends and the previous ladder baseline.
Every Metal leaf executes its required native and newly integrated typed
interactions; every parent retains typed dispatch coverage. This closes the
pending larger-ladder qualification noted above, with current memory, production
and standalone root-verification measurements retained in the report.

The legacy outer-wrapper publication/witness mint remains live and is not
exercised by the detached q193 gate. Its source audit identifies a cohesive move
and the additional legacy proof coverage needed before removing that route.
No production-security or Ethereum-readiness claim follows from these receipts.


## Shared outer transaction and continuation repair, 2026-09-18

The remaining five legacy transaction/publication owners moved into shared
recursion in one source batch. CPU integration retains backend/diagnostic bindings
and public aliases. Private storage/support shims were removed. Protocol suite
aliases, canonical proof identity and the public-wire boundary now have dedicated
shared owners; publication/witness validation has a guarded verifier-only closure.
Private minting remains inside the successful fresh-verifier transaction.

The legacy real-proof gate exposed stale child-admission geometry after successful
39-row proof verification. Its sample/query counts now derive from the current AIR
roster and core composition-split contract, retaining exact capture equality.
The repaired continuation passes transcript replay, opaque admission, captured FRI,
recorder reconstruction and finalized row-18 evaluation with a zero residual.

[Batch qualification](../../vectors/reports/recursive-product-20260918/shared-outer-transaction-qualified-v1/README.md)
records 21 selected tests, 16 ownership checks, 24 source-transfer checks and one
final 384-case CPU/Metal proof gate. All 21 canonical artifacts remain identical,
and Metal interaction dispatch requirements remain enforced. The earlier current-
device 1/2/4/8 ladder remains separate evidence; it was not rerun for this move.
This milestone does not claim production-security admission or a speedup.

## Typed trace production boundary, 2026-09-18

Removed retired opcode evaluators from production trace imports and the final transitional BASE_ALU_IMM semantics export. Moved eight trace tests and their helpers into a test-only root; retained independent oracle equations. The focused `test-trace-authority` target passed 156 tests and all 32 product-closure tests passed, including a new transitive typed-opcode boundary guard. Evidence: `vectors/reports/recursive-product-20260918/typed-trace-retirement-v1/README.md`.

This is production-boundary cleanup, not completion of provider typing or recursion retirement. Next: explicitly separate historical multiplication/wide-Poseidon AIR admission from compact Poseidon digest compatibility before retiring the alternative recursive paths under the complete-proof gate. Speed work remains deferred.

## Canonical detached-parent admission retirement, 2026-09-18

Removed historical multiplication/wide-Poseidon component branches and legacy compact-Poseidon digest admission from detached parent preparation, producer, verifier, lifecycle and recursive recording. Current pinned keys already use the canonical forms; 14 referenced parent keys were hash-checked without rewriting admission. Historical alternative keys now fail closed and require reproving under current admission.

Focused validation passed 223 tests (one skipped), 32 source-closure tests and two inventory checks. Fresh CPU/Metal/AOT four-segment gates passed 384 checks with all 21 artifacts baseline-identical. The direct-program differential now covers the actual 29-entry parent catalog, and the standalone parent verifier cannot import the old multiplication AIR/catalog. Evidence: `vectors/reports/recursive-product-20260918/canonical-parent-retirement-v1/README.md`. Post-proof changes were test-inventory wiring and documentation only.

Remaining focus: compact recursive Poseidon typed authority, then broader legacy outer/temporal route and public API retirement, with final continuation validation. Speed work remains deferred. No claim of complete frontend typing or production security qualification.

## Typed compact-Poseidon authority, 2026-09-18

The compact provider now lowers the canonical typed Poseidon permutation into its 303-column/288-constraint physical AIR. Admission checks the existing executable specialization's direct roots, ordered lookup events and interaction equations against that typed definition. Typed commutative operand ordering is handled by a separate equivalence digest; the existing ordered protocol digest and all pinned admissions remain unchanged.

The new small `test-compact-poseidon-authority` target passed 127 tests; parent admission passed 228 with one skip. Source closure (32) and inventory (two) checks passed. Fresh CPU/Metal/AOT four-segment gates passed 384 checks and all 21 artifacts remained baseline-identical. Evidence: `vectors/reports/recursive-product-20260918/typed-compact-poseidon-authority-v1/README.md`.

After those frozen-source runs, the complete-proof CLI default was corrected to the canonical admission explicitly used by both passing products. Its previously defaulted legacy identity is no longer admitted by canonical parents. Referenced inputs and the unchanged substitution fixture were hash-checked without another proof build.

Next: separate the canonical detached leaf runner/workload helpers from its legacy test harness and remove competing old routes/exports. Compact typed admission is complete; overall frontend/API retirement, final continuation qualification, and production-security claims are not complete. Speed work remains deferred.

## Canonical detached leaf command, 2026-09-18

Native ingress, detached leaf production and execution workloads now have dedicated owners outside the legacy proof test harness. CPU and Metal use the explicitly admitted detached leaf command; its no-argument legacy proof fallback, old executable names and retired workload flags are removed. The command requires an output directory and pinned child keys before producing candidates. Standalone verification remains the acceptance boundary.

Fresh CPU/Metal/AOT four-segment products passed 384 checks with all 21 artifacts baseline-identical. Three parser tests, 33 source-ownership checks, four installed-command rejection checks and four source-transfer checks passed. Evidence: `vectors/reports/recursive-product-20260918/detached-leaf-command-v1/README.md`. Documentation was written after the qualified source snapshot.

Remaining focus: retire competing parent/temporal public routes and exports after mapping their consumers, close the canonical typed-authority dependency boundary, then run the final useful 1/2/4/8 continuation and standalone-root qualification. Existing historical test coverage is not itself a competing production route. Speed and Ethereum expansion remain deferred; production security qualification is not claimed.

## Public recursion route retirement, 2026-09-18

Removed 46 legacy segment/outer/temporal exports from the CPU integration API and both remaining executable wrappers for historical ingress/temporal proof tests. Migrated in-repository member consumers to local owners. Leaf key setup now uses canonical native ingress and reproduced the independently pinned 16-address leaf key without producing an outer proof.

Fresh CPU/Metal/AOT products passed 384 checks with all 21 artifacts baseline-identical. Three command tests, 228 parent-admission tests (one skipped), and 34 source checks passed. A retained historical temporal harness compile found mixed module imports and a stale diagnostic field; both were repaired and its final compile passed. The six post-proof changes are outside the recorded 249-source canonical integration import graph. No historical temporal proof execution was rerun. Evidence: `vectors/reports/recursive-product-20260918/public-route-retirement-v1/README.md`.

Next: migrate V1 trace/public-I/O frontend callers (ELF adapter and benchmark included) before removing their APIs, narrow the canonical parent CLI import boundary, then finish the useful continuation ladder. Historical source files used by tests are not all deleted, and the overall canonical frontend retirement remains incomplete. Speed work remains deferred.

## Canonical producer module boundary, 2026-09-18

CPU and Metal parent commands now share a dedicated producer module instead of importing the broad CPU integration namespace. Removed its five unused detached facade exports and the key-setup module's unused broad binding. A new transitive integration guard covers 24 producer/key-setup sources and rejects historical harness or broad integration imports. All 35 source tests passed. Fresh CPU/Metal/AOT four-segment gates passed 384 checks with all 21 canonical artifacts unchanged. Evidence: `vectors/reports/recursive-product-20260918/canonical-producer-modules-v1/README.md`.

The frontend audit refines the previous next-step assumption: terminal V1 and resumable V2 already share execution and typed opcode geometry; their public-I/O statement contracts differ. V1 names are not themselves evidence of untyped AIR. Next establish the native infrastructure authority inventory (program, memory, Merkle, clock, tables and Poseidon) and close actual typed-definition gaps. A general ELF public-envelope migration requires deliberate I/O compatibility, not mechanical redirection. The final useful continuation ladder and complete frontend-authority audit remain outstanding. Speed work remains deferred.

## Typed native Merkle admission, 2026-09-18

Added an independent typed Merkle definition and symbolic specialization admission for its seven direct roots, five ordered lookup events, three interaction recurrences and external-provider constraints. Native-capture and cold-verifier VM AIR profile reconstruction both invoke the gate. Shared polynomial replay and symbolic relation construction now serve Merkle and compact Poseidon. Recoverable symbolic admission propagates allocation failure before reading incomplete DAGs; a full Merkle allocation-failure sweep passed.

Focused targets passed 150 Merkle/root-import tests (one skipped), 127 compact-Poseidon tests, and 21 VM profile tests; counts overlap. All 36 source checks and both inventory checks passed. Fresh CPU/Metal/AOT four-segment products passed 384 checks with all 21 artifacts baseline-identical. Evidence: `vectors/reports/recursive-product-20260918/typed-merkle-authority-v1/README.md`. Documentation was added after the frozen qualification snapshot.

Next implement program, memory and clock typed definitions/admission as a cohesive provider batch, and finish auditing wide-Poseidon and table-schema bindings. The adjacent 11-kind native infrastructure inventory records that boundary. Merkle is qualified for canonical recursion ingress, not a claim that all native infrastructure or production security is complete. Final useful continuation qualification and speed work remain subsequent steps.

## Typed native boundary authority, 2026-09-18

Program (ordinary/fixed), memory (ordinary/full-state), clock and all six lookup-table kinds now have independent typed equations and native/cold VM profile admission. Eleven policies cover nine new infrastructure kinds. Shared symbolic comparison serves these providers, Merkle and compact Poseidon without changing protocol identity.

Focused boundary tests passed 156 (one skipped), Merkle 150 (one skipped), compact Poseidon 127 and VM profile 21; counts overlap. All 37 source checks and two inventory checks passed, including 73 specialization mutations and full allocation-failure sweeps. Fresh CPU/Metal/AOT products passed 384 checks and preserved all 21 canonical artifacts. Evidence: `vectors/reports/recursive-product-20260918/typed-boundary-authority-v1/README.md`. Documentation was added after the frozen snapshot.

Next: finish wide-Poseidon direct-equation admission, keeping the shared typed plan separate from witness execution; close the supported frontend authority boundary; then qualify final useful 1/2/4/8 continuation. Speed and Ethereum expansion remain deferred.

## Final typed native and recursive continuation qualification, 2026-09-18

Wide Poseidon now lowers the shared authenticated typed degree-three plan into all 430 direct equations, four ordered lookup events and two interaction recurrences. Cold admission compares the native specialization symbolically. Shared typed program construction and a pure relation contract separate verifier equation ownership from witness execution. One exhaustive infrastructure admission owner covers all eleven native kinds and is invoked by native proving, native verification and recursive profile reconstruction.

Focused targets passed 177 tests (one skipped) and 21 VM-profile tests, plus 38 source guards and two inventory checks. Fresh CPU/Metal/AOT complete proofs passed 384 checks and preserved 21 artifacts. The exact same binaries passed all 1,110 useful 16-address 1/2/4/8 continuation checks, preserving 78 artifacts. Eight additional fresh root-only verifications measured RSS. At eight segments the 2.30 MB root verifies in about 69–70 ms with about 15.45 MB peak RSS; production observations are 152.77 s CPU and 115.23 s Metal. These are single observations, not a speedup claim.

Evidence and replay inputs: `vectors/reports/recursive-product-20260918/typed-final-authority-v1/README.md`. Clean-index patch replay reproduced all 6,184 qualified source files; 114 pinned inputs are retained offline. Terminal public-I/O and resumable statements keep their distinct contracts over shared typed implementation. No production-security or strict end-to-end GPU claim follows.

The typed/native recursion milestone is qualified. The broader original baseline objective remains open: a fresh source-conformance run reports 120 violations, and historical Linux artifact-store qualification is not established by macOS proof runs. These are recorded explicitly in the completion audit instead of marking the full goal complete. Speed work and Ethereum expansion remain deferred. This documentation was added after the frozen proof/ladder snapshot.

## Shared polynomial compiler and focused build ownership, 2026-09-18

Moved four generic direct-polynomial compiler owners out of experimental cost-model naming and migrated 27 imports. Production and authoring tools share unchanged executable bodies and stable identities, while production remains barred from proposal/search authority. A transitive compiler guard and adversarial import fixture enforce that distinction.

Replaced 111 repeated focused build-registration calls with one ordered specification catalog, preserving roots, filters, dependency capabilities and count floors. The frontend build owner is now 460 lines. Inventory imports are unchanged while redundant introductory history was condensed.

Validation passed 143 compiler/candidate tests, 43 ownership/isolation tests and both inventory checks. Complete proofs were not repeated for this body-preserving ownership batch; the preceding final typed/continuation report remains the qualified proof checkpoint. Evidence: `vectors/reports/recursive-product-20260918/shared-polynomial-compiler-v1/README.md`.

Source-conformance findings fell from 120 to 112. All proposal-authority findings are resolved; remaining findings are source/build/command-owner size ceilings. The broader baseline goal and Linux artifact-store qualification remain open. Speed work remains deferred.

## Canonical package and build surface, 2026-09-18

Finished the build-factory extraction and audited eleven constructor bodies and
seven product declarations against the retained source. Reviewed CPU/Metal/prover
package contracts now match the implemented boundaries: 51 retired CPU export
declarations removed, dedicated producer/verifier imports declared, obsolete
Metal small-recursion binding removed, and shared allocation ownership exposed
as intended. Updated API documentation and added the canonical typed-recursion
guide. All 103 focused package, build and ownership checks pass; the root build
graph constructs, and formatting/diff checks pass.

Evidence: `vectors/reports/recursive-product-20260918/build-factory-ownership-v1/README.md`.
No complete-proof rebuild was performed for this body-preserving batch. The
prior frozen-source checkpoint remains distinct from the current source. Final
integration qualification remains outstanding; broader baseline and Linux
artifact-store qualification are still open. Speed work remains deferred.

## Canonical public surface qualification, 2026-09-20

The updated typed/native and recursion source passed fresh CPU/Metal/AOT complete
products (384 checks, 21 baseline-identical artifacts), followed by the useful
1/2/4/8 ladder (1,110 checks, 78 identical artifacts). Fresh root-only verification
and device-dispatch requirements pass. Source replay reproduces all 6,189 frozen
files, and 114 archived inputs were rechecked. The external ladder launcher had
an old output path; corrected it and resumed only the ladder with the already
qualified binaries. No source changed during qualification.

Evidence: `vectors/reports/recursive-product-20260918/canonical-surface-qualified-v1/README.md`.
This completes qualification of the canonical typed/native recursion ownership
and public-surface batch. The broader baseline goal remains open; in particular,
an isolated artifact publication identity defect is now reproduced and a candidate
fix tested outside the repository. That candidate is not in this checkpoint.
Speed/Ethereum work remains deferred. These documentation updates follow the
source freeze and do not alter the qualified implementation.

## Stable artifact publication identity, 2026-09-20

Applied atomic no-replace publication at the shared artifact-store owner.
Temporary cleanup no longer changes a freshly cached object's ctime. The three
previously failing identity regressions now pass, and the concurrent test checks
both publishers' subsequent cached resolution. Unsupported publication facilities
fail explicitly; collision validation and full identity checks remain intact.

Validation passed 20 store tests, eight Metal-session consumer tests and 45 package
checks. The changed tests cross-compile for x86_64-linux-musl; Linux execution is
not available locally and remains unqualified. No complete proof run was repeated
for this scoped repair. Evidence:
`vectors/reports/recursive-product-20260918/artifact-publication-applied-v1/README.md`.
The full original baseline goal remains open; speed work remains deferred.

## VM profile identity ownership and focused loop, 2026-09-21

Extracted canonical profile identity encoding into a dependency-free owner with
an enforced import boundary. Post-format audit preserves all hash bodies and both
domains. The profile owner is under its size ceiling; 109 conformance findings
remain. Added a narrow profile-authority target while retaining the broader
composition/provider target. Both pass (six and 21 tests), alongside 44 ownership
checks and two inventory checks. The narrow compile took seven seconds versus
five minutes for the broad target on this machine; no proof-speed claim follows.

Evidence: `vectors/reports/recursive-product-20260921/profile-identity-owner-v1/README.md`.
No complete-proof run was repeated for unchanged identity encoding. The original
baseline goal, including Linux artifact-store runtime qualification, remains open.

## Detached boundary preparation owners, 2026-09-21

Separated graph/sponge inputs, identity binding and continuation constraints from
the shared opaque boundary owner. Thirty-five declarations match their original
bodies after visibility/whitespace normalization. All four owners are under their
size ceiling; 108 repository conformance findings remain. The new frontend-local
boundary target passes three tests, including 222 witness mutations across six
fixtures, segment-index checks and malformed-clock rejection. Forty-four ownership
checks and two inventory checks pass. The focused compile took five seconds and
execution under one second; no full-proof run was repeated for unchanged bodies.

Evidence: `vectors/reports/recursive-product-20260921/boundary-preparation-owners-v1/README.md`.
The original broader baseline goal remains open, including Linux runtime
qualification of the artifact-store repair. Speed work remains deferred.

## Canonical leaf cohort owners, 2026-09-21

Separated observational census/tuple diagnostics from tree ownership and moved
claim/audit closure collection into the existing cohort support owner. Five
function-transfer checks preserve equations, error behavior and admission order;
the diagnostic counter retains its cohort-instantiation scope. The owner is now
843 lines. The concrete cohort/engine contract gate passes 12 tests and all 44
ownership checks pass; 107 source-conformance findings remain.

Evidence: `vectors/reports/recursive-product-20260921/leaf-cohort-owners-v1/README.md`.
No complete proof was repeated for unchanged bodies. The original broader
baseline goal and Linux artifact-store runtime qualification remain open.

## Shared interaction accounting and buffers, 2026-09-21

Separated exact Tree-2 accounting and shared column ownership from backend-generic
native interaction generators, preserving the full moved bodies. Removed 17 unused
claim-phase aliases. The generator is 660 lines. Three buffer regressions cover
allocation rollback, rejected-block custody and transfer surviving producer teardown.
All 124 focused tests, 44 ownership checks and two inventory checks pass. Repository
conformance findings are now 106; no baseline suppression or full proof rerun.

Evidence: `vectors/reports/recursive-product-20260921/interaction-generation-owners-v1/README.md`.
The original broader baseline goal and Linux artifact-store runtime qualification
remain open. Speed research remains deferred.

## Typed session retirement cleanup, 2026-09-21

Removed the canonical session's legacy executor dependency and unreachable
ordinary load/store fallback bookkeeping. Host system instructions retain their
trace and memory-write handling. Every ordinary decoded opcode now requires a
typed retirement authority at compile time; the old executor public export is
retired and guarded against reintroduction. The focused execution-session target
passes 31 tests, with 44 ownership/isolation checks and two inventory checks.

Evidence: `vectors/reports/recursive-product-20260921/typed-session-retirement-v1/README.md`.
Final integrated qualification and the broader baseline goal remain open.

## Binary experiment public-surface retirement, 2026-09-21

Retired four unused binary-parent experiment exports from the CPU integration
and its reviewed package contract. Existing direct protocol tests remain.
The FRI binding has a live separate CSP-tool consumer and is retained.
The canonical CPU/Metal leaf and parent commands already use dedicated modules;
standalone verifier dependency guards remain in force. Sixty-six focused
ownership, proposal-isolation, package and integration-contract checks pass.
Final frozen-source qualification follows this cleanup batch.

## Typed recursion cleanup qualification, 2026-09-21

The final cleanup source passed CPU/Metal/AOT complete products (384 checks,
21 baseline-identical artifacts) and the useful 1/2/4/8 continuation ladder
(1,110 checks, 78 identical artifacts). All eight fresh root-only verification
and memory runs pass without native inputs or replay. Required Metal dispatches
pass. Source remained frozen; patch replay reproduces 6,201 files, and all 114
pinned inputs and their archive contents were rechecked. All processes exited
successfully, with no restarted qualification build.

Evidence: `vectors/reports/recursive-product-20260921/typed-recursion-final-qualified-v1/README.md`.
This qualifies the typed/native recursion cleanup milestone. The original
broader baseline goal remains open: 106 source-size findings and Linux runtime
qualification of artifact publication. The q193 hybrid profile does not claim
production security or strict GPU execution. This entry and the guide link
were updated after the source freeze; qualified implementation is unchanged.

## Linux artifact publication qualified, 2026-09-21

The exact artifact-store source from the final typed-recursion checkpoint passed
all 20 tests on Linux tmpfs and all 20 on ext4 in an isolated x86-64 QEMU guest.
Publication identity, deduplication and concurrent writers pass. No implementation
changes were required; successful logs, tested binary and source/input hashes are
archived. This closes the Linux runtime qualification gap for the publication fix.

Evidence: `vectors/reports/recursive-product-20260921/linux-artifact-publication-v1/README.md`.
The original broader baseline goal remains open with 106 source-size findings.

## Canonical session owners, 2026-09-21

Separated typed/host retirement and borrowed observer/options contracts from
session lifecycle and continuation publication. The moved bodies preserve
semantics and observer order; profile binding and public aliases are unchanged.
The session owner is 829 lines. Focused session checks pass 31 tests, ownership
checks pass 44, and inventory passes two. Source conformance now has 105 size
findings. No full proof rebuild was repeated for unchanged bodies.

Evidence: `vectors/reports/recursive-product-20260921/session-retirement-owners-v1/README.md`.
The broader baseline goal remains open; Linux artifact publication is qualified.

## Duplicate infrastructure opcode AIR retired, 2026-09-21

Removed the unused opcode kind and its point/domain evaluators from the
program/memory infrastructure component. Production opcode assembly already uses
typed semantic and lookup components exclusively. Removed obsolete claims/state;
preserved program/memory equations exactly and moved work profiles to their owner.
The resource fixture reflects the deleted eight-byte state field. Eight focused
infrastructure and 10 typed-semantic tests pass, plus 44 ownership checks and two
inventory checks. Source conformance has 104 remaining size findings.

Evidence: `vectors/reports/recursive-product-20260921/infrastructure-opcode-retirement-v1/README.md`.
No full product rebuild was repeated for this unused-route retirement; the
preceding qualified source remains separately archived. The broader goal is open.

## Retired interaction generator isolated, 2026-09-21

Removed the old monolithic generator from the public AIR namespace and retained
its byte-identical implementation behind the testing namespace. A source guard
restricts imports to test surfaces. Fifty-six isolation/ownership/package checks
and two inventory checks pass. The broad AIR root passed 830 tests with one skip;
a new focused oracle target passes nine tests with a five-second compile.
Source conformance remains at 104 findings.

Evidence: `vectors/reports/recursive-product-20260921/interaction-oracle-retirement-v1/README.md`.
No complete-proof rebuild was repeated; the broader baseline goal remains open.

## Retired memory writer isolated, 2026-09-21

Moved the opcode memory writer and its result ownership into the retired test
oracle; deleted the uncalled monolithic constraint entry. Live committed-layout
and register-boundary bodies remain exact. Thirteen focused interaction/memory
tests, 47 ownership/isolation guards and two inventory tests pass. Source
conformance remains at 104 findings. No full proof rebuild was repeated.

Evidence: `vectors/reports/recursive-product-20260921/memory-oracle-retirement-v1/README.md`.
The broader baseline goal remains open.

## Obsolete executor deleted, 2026-09-21

Deleted the unused executor shim and its redundant refusal tests. Retained typed
retirement/witness/AIR source checks now run in the focused execution-session
suite, alongside real host and continuation behavior. Forty-eight session/authority
tests, 58 retirement/ownership/package checks and two inventory checks pass.
No Zig source references the deleted file; conformance remains at 104 findings.

Evidence: `vectors/reports/recursive-product-20260921/legacy-executor-deletion-v1/README.md`.
No production execution body changed; no complete proof rebuild was repeated.
The original broader baseline goal remains open.

## Commitment witness owners, 2026-09-21

Separated program custody/completion binding and continuation-tree construction
from witness coordination. Seventeen moved function bodies match the prior source
with visibility/whitespace normalized. The focused gate passes 133 tests with one
skip; 48 ownership/isolation guards and two inventory tests pass. Conformance has
103 size findings. No full proof rebuild was repeated.

Evidence: `vectors/reports/recursive-product-20260921/commitment-witness-owners-v1/README.md`.
Final integration qualification must cover the post-checkpoint cleanup changes.

## Typed session host closure, 2026-09-21

The host ABI now has a narrow owner, preserving public aliases while removing
prover/test-oracle reachability from execution session and runtime. A transitive
source guard enforces this boundary. Fifty-five session/host tests, 49 ownership
checks and two inventory tests pass. Registry comments no longer claim a legacy
fallback. Full CPU/Metal/AOT and continuation qualification follows this batch.

Evidence: `vectors/reports/recursive-product-20260921/session-host-closure-v1/README.md`.
The broader baseline goal remains open.

## Final typed execution and recursion closure, 2026-09-21

The post-checkpoint retirement and ownership changes now pass the frozen-source
CPU/Metal/AOT complete products: 384 checks and 21 baseline-identical artifacts.
The useful 16-address 1/2/4/8 ladder passes 1,110 checks and 78 identical artifacts.
All eight fresh root-only verification/RSS runs pass without native inputs.
Required native/leaf/parent device dispatches pass. All qualification processes
exited successfully. No qualification build was restarted.

All 6,208 source files were replay-verified with temporary indexes; all 114 pinned
inputs and archive contents were rechecked. Focused validation before freeze
includes 55 session/host tests, 49 ownership guards and two inventory tests.
The eight-segment root is 2,297,319 bytes and verifies in about 70 ms. This is
implementation qualification for the development q193/hybrid profile, not a
speed claim or production-security certification.

Evidence: `vectors/reports/recursive-product-20260921/typed-recursion-closure-qualified-v1/README.md`.
The typed execution/recursion cleanup milestone is qualified. The original
broader baseline goal remains open with 103 source-size findings. This entry
and the guide link were updated after freeze; qualified implementation is unchanged.
