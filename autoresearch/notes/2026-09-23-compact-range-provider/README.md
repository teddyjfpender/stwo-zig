# Typed compact range providers — implementation checkpoint

Implemented `recursion/air/compact_range_provider.zig` and
`compact_range_witness.zig` for range20, range8/11 and range8/8/4. These are
experimental components, not yet wired into the execution proof roster.

Each provider constrains high bits to booleans and reconstructs the bounded
coordinate from those bits and byte limbs. A shared range8/8 request proves
both byte limbs. The original relation receives the negated signed multiplicity.
Typed `.request` automatically negates the supplied weight; an initial incorrect
double negation was caught by relation-interpreter parity tests and corrected.
Byte census entries are therefore negative, including every padded zero row.

The current typed IR requires exact uint20/uint11/uint4 relation coordinates.
Instead of adding an unchecked type cast, the implementation retains one
reconstructed coordinate column and constrains its equality to the limb sum.
Widths are 8, 7, and 8 main columns, respectively. Both effects fit one shared
LogUp batch (four interaction columns). There are no preprocessed witness
columns; final geometry and protocol admission remain to be integrated.

Witness generation scans the existing signed counter in canonical table order,
writes directly into final circle-domain bit-reversed columns, and separately
owns the additional byte census for later atomic merge. It preserves source
counters, handles empty providers with 16 padded rows, and does not allocate
per-row intermediate arrays. Pinned semantic identities include the corrected
signed requests.

Focused tests authenticate relation bindings, export the polynomial program,
check field-boundary tuples and signed multiplicities, reject nonboolean high
bits and incorrect reconstruction, and establish that out-of-range byte limbs
fail the byte lookup even if direct equations alone hold. They verify padding,
column order, census parity and empty-provider behavior. ReleaseFast focused
qualification passed before adding the allocation-failure test; ReleaseSafe
qualification including allocation failure coverage also passed (`tests-safe.log`).

Not complete: shared component assembly, authenticated geometry and term bounds,
transcript/key/codec versioning, source and prepared-verifier admission, recursive
capture, CPU/Metal proof tests and canonical CSP timing. Existing production
proofs still use full fixed tables; no speedup is claimed from this checkpoint.
The original persistent-plans/fused-PCS/direct-witness/parameter experiment goal
remains active.

## Geometry and component admission checkpoint

`compact_range_geometry.zig` is now the single canonical shape calculation used
by witness generation and component placement. It validates exact real-row
counts, minimal padded logs (minimum 4), and each relation's domain-size cap.
Its identity binds a version, relation kinds, real/padded sizes, column widths,
and all three typed semantic identities. A caller-pinned expected identity is
mandatory for admitted manifest and witness construction. This identity is not
yet part of the production execution transcript or artifact codec.

The additional byte-request bound includes every padded row. Checked addition
rejects integer overflow and bounds at or above the M31 modulus. For the measured
ECDSA demand (557/27/13), the three padded heights are 1024/32/16, adding 1072
byte relation terms. This is geometry evidence, not proof timing.

Extracted `universal_component_roster.zig` from the existing BLAKE3 roster without
changing AIR order, component names, offsets or placement formulas. The BLAKE3
wrapper and the compact roster now share this code. The compact roster builds
actual shared-framework prover/verifier components and validates origin arithmetic.
Origin remains caller-owned placement; the final execution protocol must bind it
through the full admitted statement rather than accepting witness-provided offsets.

The focused safety-enabled gate passes wrong-pin, changed count, noncanonical
log, oversized domain, integer/field overflow, mismatched component log, and
column/claim-index overflow tests. One initial test expected the wrong rejection
name (`InvalidComponentGeometry`); the shared component correctly returned
`InvalidProofShape`, and the expectation was corrected without changing validation.
The existing BLAKE3 Span regression gate is recorded in `roster-regression.log`.

Still pending: connect these admitted components to execution column ownership,
interaction generation and byte-counter merge; replace the three fixed providers
in native assembly; extend coefficient admission; bind geometry in versioned
transcripts, codecs, keys, prepared verifiers and recursive captures; then qualify
canonical CPU/Metal CSP and parent proofs. Production remains on the old providers.

## Interaction and shared ownership checkpoint

Added `compact_range_interaction.zig`: a persistent preparation owner retains
its authenticated typed definition, relation program, admitted shape, and bounded
inversion workspace. It reads final committed witness columns directly and
returns caller-owned interaction columns. Independent owners can be scheduled
separately; one owner is used sequentially.

The focused safety-enabled tests now generate interactions through the production
framework and compare them with the original full-table generator for all three
relations. Compact claim plus byte-table claim equals original full-table claim,
including signed multiplicities and all padded rows. Removing one padding byte
request breaks closure. Repeated generation yields identical claims and columns.
Mismatched witness geometry and wrong preparation pins are rejected.

Added `prover/compact_range_set.zig` as the shared preparation boundary: all three
witnesses must finish before byte demand can be merged. It exposes 23 borrowed
main-column views backed by owned buffers. The merge validates destination shape
and rejects source aliasing before any write, then permits exactly one merge.
Tests confirm unchanged destination counters after rejection and after a later
provider's geometry mismatch unwinds earlier provider allocations. The full
focused gate passes in ReleaseSafe (`interaction-tests.log`).

This is still not a production protocol switch. The next integration is replacing
the three fixed providers in execution assembly and deriving that choice from
versioned admitted statement geometry, then updating transcript/codec/key and
recursive-capture consumers together. Production timing is unchanged.

## Geometry wire contract checkpoint

Added `prover/compact_range_codec.zig`: a fixed 36-byte geometry encoding with
explicit magic/version and all three real-row counts and canonical padded logs.
Decoding performs no allocation and requires a caller-authenticated geometry
identity. It rejects trailing or truncated bytes, altered magic/version, every
single-byte mutation under the original pin, and out-of-range geometry. Encoding
roundtrips canonically. Domain-separated transcript mixing validates the pin
before mutation; changed admitted counts change the transcript digest. Focused
ReleaseSafe tests pass in `codec-tests.log`.

This is the wire contract for the next execution envelope, not a silent change
to the current product artifact. Current `Blake3ExecutionStatement` validation
still requires full fixed-table log sizes, row counts and one multiplicity
column. Its preprocessing and base component assembly likewise assume fixed
tables. Those checks must change together with component selection and the outer
protocol version; accepting compact descriptors while retaining the fixed-table
verifier would be incorrect. No new format is accepted by production yet.

Next implementation seam: native statement descriptors and base assembly must
select the typed compact providers together, using the caller-pinned geometry;
preprocessed/main column counts, lookup term bounds, source decoding, keys and
recursive capture then derive from that same admitted selection. Keep the wire
contract independent of prover-owned column buffers and do not infer authority
from an embedded digest.

## Persistent component assembly checkpoint

Added `prover/compact_range_assembly.zig`, a shared owner for actual typed prover
and verifier handles. It retains the same authenticated definitions and relation
plans used by interaction generation. Rebinding copies challenge ownership into
the stable owner and rebuilds handles against caller-admitted placement and
claims. Any failed bind invalidates exposed handles first. Geometry and component
identity remain shared between proving and independent verification.

Verifier preparation now omits inversion-workspace allocation and cannot expose
prover handles or generate interaction columns. Prover preparation retains its
bounded workspace across rebindings. Focused ReleaseSafe tests exercise two
different challenge/claim bindings, matching prover/verifier degree bounds,
retained preparation pointers, verifier-only ownership, and changed-placement
rejection followed by invalidated-handle rejection. All focused compact-provider
tests pass (`assembly-tests.log`), including the earlier exact relation-closure
and codec checks.

The owner is ready for native execution integration but is not yet selected by
`base_component_assembly.zig`. Current production statements, preprocessing,
transcripts and codecs remain the full-table version. The next patch must wire
selection, admitted geometry and protocol versioning together; this checkpoint
does not claim a new proof format or benchmark speedup.

## Checked component append and execution integration decision

The existing base assembly has a clean extension boundary: retain native opcodes,
clock, and the remaining fixed tables; omit the three replaced full range-table
providers; append the compact group; then place the BLAKE3 group after its end.
This avoids giving legacy fixed-table descriptors an alternate interpretation.
The future admitted statement must explicitly bind compact geometry and claims;
absence of a full table is not sufficient authority to add a provider.

`compact_range_assembly.Owner` now appends prover/verifier handles with all checks
before the first destination write. It requires the existing handle count to
match its admitted origin, enough destination capacity, and a representable end
placement. It exposes the exact column, constraint and claim-index origin for
the next group. Tests pin a nonzero origin advancing by 0/23/12/17 columns and
constraints, and three claim indices. Unbound, repeated/out-of-order and
undersized appends leave destination counts unchanged. The focused ReleaseSafe
gate passes (`append-tests.log`).

Native production selection has not switched yet. Remaining coordinated edits:
explicit compact geometry in the execution statement/wire/transcript; removal of
the three full-table descriptors and witness columns; appended compact main and
interaction columns/claims; shared component append and BLAKE3 offset handoff;
coefficient bounds and independent preprocessing/key generation; recursive
capture and source admissions; then canonical CPU/Metal and parent qualification.

## Real execution witness integration checkpoint

The shared `blake3_execution_trace.Owner` now has explicit experimental compact
preparation. It registers all commitment lookups into the native/precompile
census, derives and prepares all three compact providers, merges their byte
requests, and then materializes only the remaining fixed tables. Both modes
share the same native generation code. The owner releases compact storage with
its normal lifetime. Compact columns remain separately owned for the upcoming
component-group placement; native statement counts describe only native columns.

A real six-step RISC-V guest passes preparation and native interaction generation.
Its native main trace plus compact-provider columns contains 361,092 field cells,
versus 2,982,164 in the full-table path, with distinct range counts 12/3/1. This is
a fixture geometry measurement, not CSP performance or an end-to-end proof.
The byte census equals the original native/hash census plus all compact requests.
The complete compact native claim plus all three generated compact-provider
claims equals the original complete native claim under identical challenges
(`execution-closure.log`, ReleaseSafe). The broader focused compact gate passed
before the additional real-execution claim comparison (`execution-tests.log`).

The current product `generateInteractions` entry point rejects compact owners
with `CompactRangeProtocolNotAdmitted` before mutating their state. An explicit
experimental method permits native interaction preparation for qualification.
This guard must remain until complete proof/verification format integration is
ready. Existing production preparation remains on full tables. Next: admitted
compact statement data, transcript/claims and artifact framing; proof column
joining and component appending; prepared-verifier and recursive-capture support;
then CPU/Metal canonical suite and parent proofs.

## Complete compact geometry/transcript contract checkpoint

Added `compact_execution_contract.zig`, borrowing the native statement plus
compact plan. It validates native/external retirement geometry, rejects any
remaining full range20/range8/11/range8/8/4 provider, validates compact shapes,
and checks commitment-plan/public-root admission before transcript mutation.
Its B3CR/version-1 transcript differs from the old B3EX path and binds the
external retirement count and compact identity. An extension caller must still
independently authorize extension semantics; a count alone is not authority.

PCS main/interaction logs are derived in native/compact/hash order from admitted
metadata, with no witness-buffer inputs. Claims receive a separate B3CC domain
and include all three compact claims. Real-execution tests check old/new domain
separation, unchanged native/hash prefix/suffix logs, compact claim sensitivity,
and no transcript mutation on malformed claim counts. The legacy base proof
API now rejects compact owners in non-consuming `validateForProving`, before
preprocessing or main commitments. Contract qualification is in `contract-tests.log`.

The production proof API has not switched. Next coordinated step: carry the
optional compact plan in statement admission and proof/prepared-verifier state;
use this contract for transcript and PCS logs; join compact columns and claims;
append the shared compact component owner before hashing and shift hash offsets;
then update versioned artifact/capture codecs. Base proof roundtrip must pass
before enabling the same path for Ethereum and guest-Poseidon extensions.

## Full base STARK roundtrip — canonical 70/26

The existing base proof engine now has an explicit `proveCompact` entry point.
It joins native/compact/hash columns in that order, generates compact interactions
using the persistent component owner, includes their claims in global closure,
and binds the group before shifting BLAKE3 component placement. The ordinary
`prove` entry point still rejects compact input. No duplicate proof engine was
introduced.

`PreparedVerifier.initCompact` independently derives fixed columns/root, compact
key identity, PCS logs and complete component geometry from caller-admitted
native statement, range plan and commitment schedules. Compact keys use the
separate transcript contract; ordinary key identities retain their previous
framing. Received proof mode must match prepared mode; unused compact claims in
an ordinary proof are rejected.

The base proof codec now supports explicit version 2 with three additional
canonical compact claims, under caller-pinned compact preparation. Version 1
remains the ordinary format; old preparation rejects version 2. This supersedes
the earlier temporary codec rejection described above. The outer source/artifact
manifest and product CLI have not switched formats.

Qualification: the first functional roundtrip passed with 8 queries / 0 PoW
(`base-proof.log`). The subsequent test passed at **70 queries / 26 PoW bits**,
including serialization, bounded decode and independent STARK verification,
with **494,897 encoded bytes** (`base-proof-canonical.log`). Altering a compact
claim is rejected by relation closure; old-format preparation rejects the new
version. This is a six-step base guest, not the ECDSA/CSP benchmark, and the build
wall time is not a prover timing. No E2E speedup is claimed.

Compact recursive capture deliberately remains rejected with
`CompactRangeCaptureNotSupported`, consuming proof ownership correctly. It must
not expose a receipt that omits compact claims or component placement. Remaining
work: source/outer manifest admission, Ethereum and guest-Poseidon extension
paths, recursive capture/parent consumers, CPU/Metal canonical CSP timing and
parent qualification, then making the single production route compact.

The original base-path regression also passes (`legacy-base-regression.log`),
including artifact verification, child capture, parent proof, parent-of-parent,
and a 70-query/26-bit parent over an 8-query/0-bit child with reused plans.
This demonstrates preservation of the existing recursion path, not compact-child
recursion support. Compact capture remains explicitly unsupported until its
consumers include the additional claims and component layout.

## Source-authenticated compact artifact verification

Added `compact_execution_manifest.zig` with an explicit B3CRADM1 wrapper around
compact geometry and the existing native source/commitment manifest. The caller's
expected outer manifest identity is checked before the embedded geometry identity
is used. Native statement, ELF/input digests, PCS policy and commitment schedules
retain their existing admission checks, with the compact transcript context.
Decoded ownership includes the compact plan by value.

The base profile artifact encoder selects this manifest for compact preparation.
Fresh artifact verification decodes the authenticated plan and constructs a new
`PreparedVerifier.initCompact`, instead of relying on the prover's prepared object.
The existing artifact framing remains unchanged; the nested manifest and proof
formats explicitly distinguish compact admission and version-2 proof claims.
Ordinary manifests continue through their original decoder with a null compact
plan. Extension manifests have not switched.

Canonical 70-query/26-bit compact base proving followed by source-artifact
encoding and fresh verification passed (`source-artifact.log`). The focused
ReleaseSafe real-execution gate additionally passed legacy-manifest roundtrip,
compact-plan roundtrip, changed source digest, manifest byte limit, tampered outer
pin and tampered embedded geometry identity tests (`manifest-tests.log`). A
recomputed outer identity does not bypass consistency of the embedded range ID.

Next is the shared `blake3_extension_proof/prepared/codec` path used by both
Ethereum precompiles and guest Poseidon, not an ECDSA-specific implementation.
Compact recursive capture remains disabled. Product defaults and CSP performance
results are unchanged until the extension/capture paths are qualified.

## Shared extension proof and source-artifact integration

Both typed extension profiles now use the compact range provider through the
same extension proof, prepared verifier, codec and manifest templates.
There are no workload names, CSP fixture checks or ECDSA-specific switches.
The Ethereum fixture executes signer recovery and Keccak; the guest-Poseidon
fixture executes its guest instruction. Guest instruction semantics remain intact.

The extension contract retains each original admission certificate and checks
the extra byte-table multiplicity bound, including all padded compact rows.
The compact contract and effective bound are included in the transcript/key.
Witness construction registers extension requests before deriving compact
geometry and merging its byte-table demand.

The prepared verifier derives compact component placement and logs. Proving
joins native/compact/hash/extension columns; verification includes all three
compact claims in closure. Extension assemblies now explicitly account for
compact columns before placing their own components. Version-2 proof envelopes
carry those claims; version-2 extension manifests authenticate the range geometry
under the caller-pinned manifest identity before creating fresh preparation.
Original version-1 framing and entry points remain available during migration.

Qualification:
- `extension-admission.log`: ReleaseSafe real witness/admission checks for both
  profiles, including changed extension-certificate rejection before transcript
  mutation.
- `extension-proofs-placement.log`: canonical **70 queries / 26 PoW bits** for
  both profiles, proof encode/decode, independent verification and fresh
  source-artifact verification. Altered compact claims fail relation closure;
  changed source-manifest pins fail admission.
- Ethereum encoded proof: **5,399,267 bytes**.
- Guest-Poseidon encoded proof: **861,930 bytes**.
- `extension-proofs.log` records the initial unsuccessful integration run before
  correcting extension column placement. It is not a qualifying result.

These are functional proof tests, not CSP timings. Compact recursive capture
still explicitly returns `CompactRangeCaptureNotSupported`; no incomplete
receipt is exported. Released product defaults and published CSP timings have
not changed.

Next integration is shared recursive capture and parent consumption:
`blake3_execution_capture.zig`, `blake3_extension_capture.zig`,
`recursion/air/blake3_execution_composition.zig`,
`blake3_extension_verifier_components.zig`, and the execution transcript
recorder must agree on geometry, claim order and component offsets. Composition
must record the compact AIR constraints and include their claims in closure;
Ethereum recursive extension geometry must use the shifted offsets too.
Then qualify compact-child recursion, switch the canonical product path, and
measure the full CPU/Metal CSP suite. No speedup is claimed from these tests.

The original extension proof regression also passes
(`legacy-extension-regression.log`): both profiles prove and independently verify
at 70 queries / 26 PoW bits, with artifact round trips, capture mutation rejection,
and recursive composition/DEEP/transcript replay. This qualifies preservation of
the existing path; compact-child recursive capture is still pending.

## Compact recursive verifier integration

The shared base and extension capture receipts now retain compact geometry and
three compact claims. Their seals bind that metadata; validation requires exact
agreement with independently prepared geometry. Altering a compact claim fails
receipt validation. Compact claims are checked for canonical field encoding.

The recursive composition recorder now evaluates the actual typed compact AIRs
between native and hash components, with their own row denominators, signed
lookup shifts and constraint order. Compact claims remain circuit inputs and
participate in global closure. The recursive transcript uses the same compact
statement/claim framing as leaf verification. Shared extension assembly,
Ethereum recursive mask geometry and base DEEP sampling account for the
additional columns.

Focused replay tests perturb a compact claim directly in the composition circuit,
not just its receipt, and require an unsatisfied circuit. The first combined
run (`recursive-replay.log`) passed both extension profiles and the non-proof
compact gates; its base replay still failed during DEEP integration. The next
focused run (`canonical-parent.log`) passed corrected base composition/DEEP/
transcript replay and generated the complete parent witness, then failed parent
proving at the diagnostic helper's 8 GiB host allocation cap.

A separate configurable cap was added to that test helper without changing
production defaults. Canonical compact-parent tests use a 24 GiB cap and report
peak routed allocation. `canonical-parents-budgeted.log` records that
qualification run; completion is pending until its terminal result is recorded.
These are correctness/integration checks, not performance measurements.

The base full-run witness now has `initCompactRun`, matching both extension
constructors and avoiding construction of full tables followed by replacement.
Product default activation, segmented compact orchestration and CPU/Metal CSP
measurements remain pending.

The budgeted run now qualifies the compact base child and canonical parent:
70 queries / 26 PoW bits at both levels, independent parent verification,
parent transcript replay and successful persistent-plan rekey/reuse. The base
worker peak was **15,001,575,082 tracked bytes** under the 24 GiB cap; parent
artifact size was **850,599 bytes**. This is not an ECDSA timing result.

That same run exposed a test-only `ScopedPoolAlreadyBound` error in the extension
parent handoff. The extension test now releases its leaf pool binding and uses
the existing canonical extension-parent helper (four workers, existing 36 GiB
cap), rather than nesting a second binding. Its follow-up qualification log is
`canonical-extension-parents.log`.

The shared CPU/Metal product request source now selects compact full-run
witnesses, compact prepared admission and base `proveCompact` for every supported
execution profile. There is no CSP/workload-name dispatch for this selection.
The installed products have not yet been rebuilt or qualified with this source;
CSP measurements and segmented-path integration are still pending.

Canonical extension qualification now passes (`canonical-extension-parents.log`):
both Ethereum (signer recovery plus Keccak) and guest-Poseidon children and
parents use 70 queries / 26 PoW bits. Parent proofs are encoded and independently
verified after releasing the worker and rows. Ethereum parent artifact:
907,928 bytes, worker peak 32,274,798,164 bytes. Guest-Poseidon parent artifact:
863,595 bytes, worker peak 15,223,762,412 bytes. These functional test runs use
test allocations/four workers and are not CSP performance results.

The original Ethereum/guest-Poseidon full proof tests, fresh artifacts, capture
mutation tests and recursive replay still pass
(`recursive-legacy-regression.log`). This supersedes the earlier temporary
compact-capture rejection: compact capture and single-child parent proving now
work in all three profiles. Segmented orchestration remains to be integrated.

The benchmark artifact inspector now accepts both ordinary and compact
manifests/proofs for all three profiles, checks matching protocol versions and
bounded geometry, and continues to require independent Zig verification for
cryptographic admission. Eighteen focused framing/precompile tests pass
(`csp-framing-tests.log`), including version downgrade and geometry corruption.

The CPU ReleaseFast product build passed (`cpu-product-build.log`). The local
`run_suite.py` follows the earlier source-pinned research pattern without
claiming clean-source suite admission: all 16 positive canonical workloads,
three samples each, plus the software rejection proof, canonical configuration,
ELF/input/output checks, versioned framing checks and separate-process proof
verification. CPU and Metal run serially. Timings are pending until each backend
finishes and every retained proof verifies.
