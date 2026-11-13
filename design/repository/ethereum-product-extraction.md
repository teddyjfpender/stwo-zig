# Ethereum product extraction

Owner: `ethereum-statement`, @teddyjfpender. Delivery issue: [#336](https://github.com/teddyjfpender/stwo-zig/issues/336).
The contract and its recorded amendments are [RFC #352](https://github.com/teddyjfpender/stwo-zig/issues/352).
This note records the current extraction boundary; it does not replace that RFC.

## Destination and compatibility

The destination is `src/products/ethereum/statement`, with the six approved
`statement`, `runner`, `prover`, `frontend`, `cpu`, and `cuda` domains. The two
legacy build exports must reuse the actual frontend and CPU component Module
pointers. Neutral packages must never import the product. Existing profile IDs,
protocol bytes, canonical records, rejection ordering, resource ownership and
named test discovery remain acceptance requirements.

The old `backup/c4-product-ownership-partial-20261110` ref is preservation only.
It has no completed package/module DAG and is not an integration candidate.
Use its reviewed path mapping, not its obsolete imports or duplicate metadata.

## Private dependency cuts

The current prerequisite slice separates these existing shared authorities:

- `rv64/services/call_abi.zig` owns the original SecpCall, Sha256Call,
  Arith256ModCall, CurveCall and Event definitions. Their complete bodies are
  unchanged; the existing session exports alias that single definition. Compact
  tape, tape wire, RAM-word capture and boundary capture import these records
  without importing the product executor. The packet modules still require
  their separate ownership cut before strict placement can pass.
- `rv64_proof_artifact_support.zig` owns the original physical-cell accounting,
  exclusive-file write and durable summary replacement. Seventeen consumers use
  this shared owner directly; the Ethereum receipt keeps its existing callable
  aliases and owns its schema, chain checkpoint and proof/receipt transaction.
  Helper bodies and error/cleanup ordering are unchanged.
- The three previously approved RV64 primitive provider names forward to the
  existing Precompiles implementations. No algorithm is copied or moved back
  into the RV64 executor. Their first additive version was `0.2.0`; the approved
  checkpoint signature transaction now sets this package to `1.0.0`.

The owner approved the two shared public providers and four checkpoint input
signatures in the [recorded RFC amendment](https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6828863621).
They are now installed: RV64 `service_calls` aliases the original call owner,
and CPU `rv64_proof_artifact_support` aliases the original shared helper owner.
The CPU package is `0.3.0`; these source-package versions are not release tags or
proof-protocol revisions. Checkpoint no longer imports the Ethereum session;
its four accessors infer the concrete caller's session pointer at compile time.
The actual memory identity, counters, page checks, error/copy/cleanup ordering
and data records are unchanged.

The real CPU public-consumer test runs beside the private owner tests. The
existing `dev_test.py` compiles these std-only paths directly against the actual
CPU module, holding the canonical build lock. This avoids loading the complete
package build runner for four small tests. Engine validation now runs inside the
unchanged concrete `CpuProverEngine` construction, retaining the assertion for
all consumers of that engine without forcing unrelated artifact consumers to
instantiate it. The package's dedicated test target and default-test consumer
wiring remain; the full build-runner attempt exceeded the laptop's 1 GiB guard
and is not counted as qualification.

Local actual-session checkpoint replay/tamper and canonical identity cases pass
in Debug and ReleaseFast, as do all four public-consumer/private IO cases.
Full product and frozen proof acceptance remain separate. Additional contract
changes discovered in the remaining closure need their own exact ledger and
recorded decision; this amendment is not blanket removal permission.

## Component construction checkpoint

`src/products/ethereum/statement` now has the approved v2 product contract,
manifest, owner routes, graph projection and graph-derived CI lane. Its three
component roots are created once. The primary exposes exactly the six approved
domains; both legacy build keys reuse their actual component pointers. CPU
imports frontend; CUDA imports frontend and CPU. The build checks those pointer
bindings. The primary's direct contract tests pass in Debug and ReleaseFast,
including canonical lower Cpu/Memory/HostInterface and primary/legacy identities.
These direct tests use the actual declared lower source modules and component
bindings; they do not execute the package build runner. Manifest/dependency
resolution (`zig build --fetch=all`) passes. Actual complete configuration and
product execution qualification remain open.

The component facades currently forward the existing owners. They establish
composition identity, not completed implementation ownership: product source
movement, neutral API removals, consumer migration and full discovery/proof
acceptance remain unfinished. No lower package imports this new product.

The next private cuts retain one artifact-framing implementation, with profile
selection outside it, and move curve arithmetic away from candidate dispatch.
Shared curve, bulk and sponge packet modules now live in RV64 `services/`.
Canonical native schemas, rung data and both unchanged embedded vector files
live in CPU `services/native_schema/`. The CpuDeclaration record has one shared
owner; the wire facade aliases it. These are seven physical file relocations,
not a rename of request/image or admission policy into a generic directory.

Focused Debug/ReleaseFast executions pass: 26 packet/capture/reference tests,
25 native schema/chain golden and adversarial tests, the four-profile artifact
framing test, and the planner/default admission regression. The planner test
moves intact out of shared GKR scope into its product-policy test owner and is
explicitly collected by the CPU module. This removes the test-only lower policy
edge without replacing its real planner oracle with copied defaults. All 80
workspace/graph Python checks pass; the graph now contains 37 packages and 173
edges. Source conformance retains the exact same 83 inherited findings.

## Boundary checks and acceptance

The strict product-placement predicate and negative fixtures reject product
paths, including generated paths, and product identifiers on lower public
surfaces. Product-layer dependency validation rejects lower-to-product and
product-to-product edges. These layer rules are active. The placement predicate
is tested but is not yet part of the repository-wide acceptance call: enabling
it belongs to the complete relocation transaction, without an allowlist or
baseline. Its current diagnostic finds 212 placement violations: seven shared-owner relocations remove seven of the original 218, while the separately retained planner test adds one product-owned file awaiting migration. A clean
existing workspace audit is not strict P3 completion.

Local prerequisite checks execute the real capture/tape and tape-wire cases in
Debug and ReleaseFast, including malformed advice, allocation failure and all
service sidecars. Actual file publication tests cover existing-file refusal,
complete summary replacement and staging cleanup on failed publication.
The RV64 identity case pins the shared records and primitive module aliases;
the original primitive arithmetic/oracle cases remain independent.

These bounded checks do not qualify a complete product build or full proof.
Remaining delivery: complete the private service/packet and request/image cuts,
construct the product package and concrete component DAG, migrate every affected
consumer and discovery root, activate strict P3, and run final frontend/CPU
acceptance with semantic negatives and frozen Native proof identity. No GPU,
performance, release or whole-extraction completion claim follows from this
prerequisite slice.

## Budget

The current C4 completion sweep has a planned maximum +3100 net source lines
(originally +800, then +1200),
including tests/build/compatibility wiring. Moves receive no subtraction credit.
New flags and scripts are zero; documentation and configuration are separate.
The private cuts protect shared ownership and failure semantics; rollback must
restore their original aliases, consumers and tests together.

Measured source so far: prerequisite +174 and approved shared-boundary segment
+88, cumulative **262/800**. The latter includes the real public-consumer test,
complete counter-family regression and bounded developer routing. It adds no
flag or script; documentation/configuration remain separate. Source conformance
still has exactly the same 83 inherited findings, with no additions/removals.

The component-construction/shared-owner segment adds 766 source lines and removes
407, net **+359**; cumulative C4 source is **621/800**. The seven moves receive no
removal credit. Configuration adds 87 lines, removes zero; the new package guide
adds 80 documentation lines, with this extraction ledger reported separately.
Flags added/removed: zero; maintained scripts added/removed: zero. The additional
source owns explicit component wiring, compatibility identity and retained
negative/reference coverage. It does not authorize extra neutral public APIs.

## Approved canonical-provider landing

The owner explicitly approved the [bounded follow-up amendment](https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6832806430)
on 2026-11-12. It permits the exact four canonical bindings: frontend prover
`blake3_profile_artifact.ForOwner`, RV64 `service_calls.curves.arithmetic`, and
CPU `rv64_native_schema` / `rv64_native_rungs`. Existing algorithms and schemas
keep their sole definitions. The exact module member lists and implementation
hashes are recorded in that decision. The C4 source allowance is now **+1200**,
with target zero, no new flags/scripts and no removal credit for moves.

This landing publishes those additive bindings first. Four real product-owned
consumer cases require them and first fail on the four missing fields. They
exercise native class/table authority and legacy nominal identity, arithmetic
against integer modular arithmetic, canonical direct/umbrella machine and trace
types, and artifact framing/rejection precedence. They pass in Debug and
ReleaseFast alongside the two existing product identity cases (six named cases
plus the collection hook). Both direct RV32/RV64 dependencies bind the same
module instances already used by the neutral frontend; the actual build checks
those pointers. These source package changes keep CPU's unpublished 1.0.0 major
candidate; they do not publish a release or revise proof bytes.

The approved RV64 service-export removal, product profile-selector move and
strict placement activation remain in the separately preserved, **unqualified**
full migration draft until its complete consumer closure passes. That draft
physically relocates the product implementation and policy sources and has zero
placement findings with P3 active, but still has cross-owner imports. It is not
the pushed qualification state. The canonical-provider landing's existing
placement diagnostic remains 212 with P3 inactive; full C4 completion is not
claimed by this additive slice.

This additive landing is source +74/-2/net **+72**, cumulative C4 **693/1200**.
Configuration is +15/-5; documentation is reported separately. Flags and
maintained scripts added/removed remain zero. All 80 workspace/graph Python
checks pass at this landing (37 packages, 39 public modules, 175 edges), with
exactly the same 83 inherited source findings. The 25-case native golden/chain
suite passes in both modes, including its collection hook. These bounded
results do not establish complete frontend/proof acceptance for the preserved
migration draft.

## Current unqualified migration checkpoint (2026-11-12)

The local extraction draft now relocates 226 implementation/test owners. The
runner result, extension-state selection and profile-owner implementations live
in the product; the native wrappers reuse the canonical RV32 owner factory and
base result records. A bounded direct check runs the existing adjacent-segment
execution-parity test and compares Native/Poseidon/Keccak session, result and
state identities in Debug and ReleaseFast: three executed cases per mode,
502,104,064-byte sampled peak under the 1 GiB aggregate guard. The temporary
operator test root is removed after execution; it is not a new maintained test
entrypoint and does not replace final package acceptance.

Strict P3 is active in this draft and reports zero placement findings. Its five
placement/layer regression cases pass. Source multiset comparison against
`3eb01db13` retains all 9,674 original named Zig tests and adds two native-only
identity cases. This is source retention, not executable discovery parity.
All 353 changed existing/new Zig/zon sources parse through the formatter under
the shared lock and memory guard. Cross-package closure is still failing;
shared CPU provider boundaries, recursion policy separation and complete
consumer/discovery migration remain open. No combined frontend, CPU-negative
or frozen Native proof-byte acceptance is claimed for this draft. The pushed
canonical-provider landing remains the last qualified additive checkpoint.

## Native helper prerequisite landing

The next C4 slice removes request/packet policy from native qualifications
without publishing another neutral API. File SHA-256 pins, immutable executable
mapping collection, bounded byte I/O and tape/ROM profile compatibility each
have one private canonical owner. The original request/batch/packet names alias
those same definitions. CSP/Sail, distributed receipt and coverage consumers
call the shared owners directly. The prepared-job digest domain/offset and all
request/image admission remain with their original product implementation.

All transferred function/record bodies are exact. The two new owning tests
cover pin rejection precedence and bounded I/O truncation/section/buffer edges;
both pass Debug and ReleaseFast (285,933,568-byte sampled peak). A bounded
actual-module check also runs the existing Zbb authority/admission truth table
and exercises real native program mapping, canonical request/type identity,
empty-program refusal and mutable-executable refusal in both modes (three
cases per mode, 448,331,776-byte peak). All 80 workspace/graph tests pass.
The 83 inherited source findings remain; no ceiling or baseline is changed.
The focused checks do not qualify a complete frontend or frozen Native proof.

This slice is source +192/-130/net **+62**, cumulative C4 **755/1200**.
Documentation is separate; configuration, flags and maintained scripts add or
remove zero. Shared bodies are transferred, not counted as deleted code.
The complete product migration remains preserved and unqualified separately.

## Independent reference prerequisite landing

Pure arithmetic and FIPS SHA-256 reference bodies now have one private RV64
service owner. Candidate dispatch aliases those same functions; the AIR tests
call them directly. The independent reference is retained alongside the
optimized witness primitive, so the differential oracle is not weakened.
Curve reference tests use the already-approved canonical arithmetic binding.
All original names, vectors, assertions and production function signatures stay.

Actual candidate FIPS/big-integer cases pass in both modes (five cases including
two collection hooks, 404,373,504-byte peak); AIR arithmetic/curve and random SHA
reference cases also pass both modes (524,091,392 and 376,291,328-byte peaks).
Workspace passes at 37 packages/39 modules/175 edges; the same 83 inherited
source findings remain. Full frontend and frozen-proof acceptance remain open.
Source +53/-47/net **+6**, cumulative C4 **761/1200**; documentation is separate,
configuration/flags/maintained scripts unchanged. No move subtraction credit.

## Approved execution-provider amendment

The owner explicitly approved the exact 11-file execution-provider amendment on
2026-11-12; the [recorded decision](https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6835724702)
pins the full 17-owner member/hash ledger and patch. CPU now exposes the static
`rv64_execution` domains; the neutral artifact facade publishes its existing
Header and validatePcsConfig; expected-image ownership stays in the product.
The borrowed memory adapter infers only its caller’s concrete pointer type;
canonical Image/Statement records and receiver-owned policy remain unchanged.
Two real product consumer cases and the raised 222-case floor are installed.
The C4 source allowance is now +1600, with no new flags/scripts or move credit.
Implementation and combined qualification remain in progress; approval is not
evidence of runtime acceptance or full extraction completion.


## Further consumer and policy ownership checkpoint

The unqualified extraction now uses the product-owned expected image in fifteen
consumer references and the published native rung provider in eight references.
Its compatibility testing facade preserves all 74 original names: 68 retain
native module identities and six resolve to their actual product owners. The
existing component contract case checks those identities and neutral separation.
Four packet-policy test files moved intact; their eleven named cases enter the
CPU component inventory directly, raising the aggregate discovery floor to 375.
Native signer recovery keeps a neutral focused root. The ECDSA Ethereum proof
router moved intact, with import-only body parity; its neutral public alias is
still an explicitly unresolved compatibility boundary awaiting owner decision.

The full source inventory retains all 9,676 original literal named cases, with
four additions. This is source preservation, not executable discovery. Strict
product placement reports zero; the broader workspace still has 463 findings
(231 relative import occurrences, each reported at both owners, plus one missing
named dependency). The combined extraction remains unqualified. Source is
+58,217/-57,644/net +573 versus the pushed head, including physical moves with
zero subtraction credit; cumulative C4 is +1,334/1,600. No flags or maintained
scripts were added. Final runtime, negative-corpus and frozen-proof gates remain
mandatory; the earlier checked prerequisite results do not qualify this draft.


## Owner-authorized completion sweep (2026-11-12)

The owner approved the bounded coordinator amendment, then explicitly authorized
all necessary subsequent changes without repeated approval requests. The exact
review packet and clean pushed-source RED receipt remain in
`/tmp/c4-coordinator-owner-amendment/`. Publishing that factory does not qualify
its consumer tests: the combined native frontend still has policy imports.
The final C4 completion allowance is +2400 (target zero), for explicit canonical
provider/facade/consumer wiring; C3's separate budget is unchanged. File moves
receive no subtraction credit. No proof/security check, source ceiling, flag
limit, golden or rejection classification was relaxed.

The native coordinator now selects no product early owners. Ethereum selects its
actual owner pair once above it; Bundle, timing, stream and encoded records have
one native owner outside the operation specialization. The native page cache
borrows native memory and permission regions, rather than an ExpectedImage type;
its existing first-match rules and caller fallback stay intact. A new real-memory
case checks uniform/mixed rights, absent pages and unaligned addresses.

All production product imports now use explicit canonical native operation
namespaces. Consumer tests use honest native fixture/oracle namespaces; hostile
prover helpers remain private to their product proof-boundary tests. The legacy
AIR and recursion facades keep actual shared records by identity while product
loading/profile policy stays above. Seventeen CUDA orchestration/tool files and
one admission case moved above their device/kernel providers. Two actual direct
dependencies (circuit frontend and CPU backend) are declared and all owned
component roots use the actual lower module pointers. The exact graph pin is
189 dependency edges; its exact-equality assertion remains intact.

Diagnostic streams now share one native journal/hash/data implementation;
Ethereum session selection and receipt-validated candidate policy have a product
adapter. The legacy product dispatch preserves five profiles and its candidate
entrypoint; the native dispatcher admits only its three native profiles and
returns UnsupportedExecutionProfile otherwise. NDJSON byte/observer qualification
and existing candidate gates remain mandatory.

The latest workspace audit has 24 findings, all for twelve remaining native
frontend-to-product import occurrences. Product-to-private relative imports and
undeclared named dependencies are zero. Strict product placement remains zero.
All 9676 original literal named source cases remain, with seven additions; the
current product source discovery floor is 427. These are source inventories,
not executed frontend/prover qualification. Forty-three focused graph/boundary
checks and flag/reference validation pass. The actual Debug public consumer
still fails before execution on eight native frontend policy imports.

The remaining work is CSP/harness and recursion policy separation, typed
caller-protocol BUILD construction, all focused/default consumer wiring and the
original complete Debug/ReleaseFast, CPU-negative and frozen-proof gates.
The current staged draft is preserved as unqualified local work; earlier pushed
prerequisite test results must not be reused as evidence for this full candidate.

## Local ownership and qualification sweep (2026-11-13)

The remaining direct frontend-to-product imports have been cut. Shared VM
composition custody now constructs its program through a static compiler
operation, owns its retained schedule, and exposes one native immutable
`Source`/`View` pair. Ethereum selects its three compilers and claim routing
above that boundary. Owner handles are distinct per compiler and cannot be
confused with read capabilities. Statement arithmetic similarly keeps native
opaque graph/evaluation custody separate from fixed product claim reconstruction.
No proof/IR record is copied into a generic context and no runtime dispatch
registry or cached validation flag replaces admission.

The Initial38 manifest remains typed at the product admission boundary. Its
native descriptor/capture ABI has one fixed count, and the original capacity,
identity, policy, family and stale-manifest adversarial case is retained.
The diagnostic journal has one native streaming kernel; product adapters select
Ethereum sessions and validate candidate capabilities before entering it.

BUILD-only component constructors accept actual caller-selected native modules.
The default build retains the three literal audited export producers. Aggregate
and legacy consumers reuse the same binding implementation; neutral import keys
retain their native owners and deprecated product namespaces select the explicit
compatibility components. Native CPU construction reuses the circuit provider
implementation and the caller's wire/Cairo identities. Its provider factory was
moved below both graph consumers to remove a build import cycle.

Existing CSP ECDSA proof cases and the service-specific harness are product-owned.
The two CPU suites have `test-csp-ecdsa-proof`; the existing Metal JIT/AOT commands
retain their modes and authenticated-bundle option under this product build.
Metal qualification remains outside default tests and has not been executed.
The real Metal backend dependency raises the exact graph from 189 to 190 edges.
No runtime module-export key, protocol flag, security parameter or golden changed.

Local evidence is deliberately separated by scope:

| Scope | Result |
| --- | --- |
| Primary product contracts, actual canonical components | 13 cases pass in Debug and ReleaseFast |
| BUILD constructor identity/isolation unit | Pass in both modes using actual `std.Build` modules |
| Compiler-owner/read-capability separation | Original failing run retained; passes in both modes |
| Ownership, finalization/OOM, borrowed mutation, Initial38 admission | Pass in both modes through the actual frontend root |
| Product profile authority, fixed identities and mutations | Pass in both modes through the actual frontend root |
| Retained leaf context, receipt and capture mutation rejection | Pass in both modes through the actual frontend root |
| Diagnostic journal/candidate closure | Eight previously blocked cases pass in both modes |
| Frozen Native CPU kernel and raw wire | Fresh 8,390-byte proof matches `452fb396032380b7c031fc95f0b7c00d0a3c6e05622321f84f06cb3a801e3b2c`; separate verifier accepts and rejects a changed proof byte |
| Literal source-name preservation | 9,676 original names retained; 9,686 current names; no missing multiplicities |

Bounded frontend partitions cover the whole 154-case source list, with supplemental
single-case and focused runs. Four Debug cases and six ReleaseFast cases remain
unrun after the 1 GiB compiler guard, even when isolated. These are not assertion
passes, and the small Native kernel proof is not the full product CLI/JSON negative
corpus. Combined CPU/CUDA-root attempts also reached the compiler guard. Native
captured-call ABI consumers found by those attempts are being migrated explicitly;
the real Ethereum-session fixtures and their qualification consumers have now moved to product ownership (see the checkpoint below).

The sweep therefore remains an **unqualified local extraction**, not a complete
frontend/CPU/CUDA qualification or a performance result. Full consumer/focused
catalog closure, larger compiler cases, CPU rejection
coverage and final combined discovery remain required before completion.


## Service fixture ownership checkpoint (2026-11-13)

Nineteen additional fixture, policy-test, focused-root and CLI files now live in
this product. They continue to run the real Ethereum executor: no synthetic
executor replaces the independent fixture oracle. Native packet/math fixtures
stay below, and the seven Zbb instruction encoders keep one native implementation
shared by the ROM test and product fixtures. Native source, GKR operation and
recursion bindings refer to their actual canonical owners.

The original services-GKR focused command now runs both its neutral kernel image
and its six product execution-policy cases, retaining the original combined
floor of 38. Product-focused gates cover V3 services, Zbb, sponge, LS-D64 and
service recursion, while the default product discovery floor increases from 434
to 480 (154 frontend, 302 CPU, 13 CUDA and 11 primary named source cases).
All 9,676 baseline literal named cases remain, with the same ten additions.
These counts establish source preservation, not complete runtime qualification.

The workspace audit passes with 37 packages, 39 public modules and exactly 190
dependency edges. The moved secp wire-profile and SHA-256 receiver-derived shape
checks pass in Debug and ReleaseFast through actual canonical component modules.
The larger Zbb admission and compact-execution checks reached the unchanged
1 GiB compiler guard; they remain unqualified. A focused leaf-file invocation
also correctly failed its module-root boundary, and the maintained package-level
root subsequently passed. Both failed and successful receipts are retained.

This checkpoint's source budget is +1,631 net against the last pushed head,
plus the previously landed C4 +761: cumulative +2,392 of the +2,400 allowance.
Moves receive zero subtraction credit; no flags or maintained scripts are added.
The fixture transfer is a policy ownership correction, not a performance claim.


The owner-authorized organization pass has a pre-edit C4 maximum of +2,800
(target unchanged +2,392). Its only permitted growth is explicit private-owner,
consumer and test wiring while splitting twelve moved oversized product files
and the focused build owner under their existing ceilings. No baseline, ceiling,
public runtime surface, proof behavior, flag or script allowance changes. The
real package configure and BUILD/component-boundary execution now pass after
correcting the three Zig 0.15.2 export-registration calls; the initial failing
configure receipt remains retained.


## Organization and real entrypoint checkpoint

Four moved product files now meet the unchanged 850-line ceiling: leaf context
765 lines, incremental composition program 833, setup cache 781 and CPU/truth
planner 766. Private owners hold the existing checked geometry, complete program
equality, authenticated cache wire format and truth-family geometry/selection.
Original public aliases and canonical proof records remain single-owned; helper
exports are private implementation wiring, not new package contract members.
The focused build owner is 388 lines after its unchanged suite/floor catalog was
separated. Source conformance falls from 82 to 77 errors; it is still red, with
eight oversized product owners remaining. No baseline or ceiling was modified.

All sixteen original planner cases pass in Debug and ReleaseFast. The existing
cache identity, round-trip/tamper and single-seal cases pass in both modes (four
executed tests including the maintained collector). The aggregate sample-count
substitution case also passes in both modes after the program authority move.
The new cache focused command's full package-graph execution reached the 1 GiB
guard; direct execution through the real canonical component modules passed.
Those are separate scopes, and the failed package run remains retained.

The real package configure check, BUILD constructor unit and component-boundary
command pass after correcting `modules.put` to Zig 0.15.2's managed-map API.
The workspace export audit and its mutation fixture now require the same actual
API; a RED/GREEN run is retained, including rejection of the invalid allocator
argument. The 125 graph/workspace/developer-entrypoint tests pass. Relocated flag
owner/default-expression pins are updated without changing defaults, names,
status, dates or expiration; the flag validator passes.


The final three CUDA-owner splits have a pre-edit maximum C4 allowance of
+3,100 (measured +2,694 before those edits). Growth is limited to private
install/input/fingerprint and parity-stage wiring; existing public aliases and
canonical records stay intact. This is code organization and host-contract
work only: no GPU execution, timing, rental or hardware qualification is included.
An unused-private-alias sweep removed 133 unreferenced aliases from 35 product
implementation files, retaining every pub declaration and test/algorithm body.


## Final local qualification checkpoint (2026-11-13)

Every one of the 154 frontend source cases was observed executing and passing
in both Debug and ReleaseFast in a source-frozen campaign. `-fstrip` omits debug
symbols; optimization mode, assertions, proof checks and the 1 GiB guard remain
unchanged. This closed all previously unrun frontend cases and exposed private
method access in the moved legacy context test. That private mutation test now
stays beside ContextV1; its original method calls and every assertion remain.
Checked geometry and canonical byte hashing have single private owners, and
ContextV1's private methods remain private.

The full primary product root passes 13 tests per mode. Real package configure,
BUILD constructor and component-boundary commands pass in both modes. The
constructor tests execute actual std.Build module identity/ownership checks;
aggregate wiring now reuses a caller-selected CPU and its actual predecessors,
rejecting Core or predecessor drift. All 13 CUDA component host contracts pass
per mode; both large parity tools type-check without execution. No device test,
GPU qualification, rental or timing result is claimed.

CPU receipt/image/receiver rejection coverage is 10/10 in Debug and 9/10 in
ReleaseFast. The remaining physical-receipt proof test exceeds the unchanged
laptop compiler guard; it is UNRUN, not passed. The exact-source hosted CPU lane
is the fallback for it. All 178 Python graph/workspace/developer/CI contract
checks pass. A fresh 8,390-byte Native CPU proof retains the frozen hash above;
a separate verifier accepts it and rejects a changed proof with RootMismatch.

The CSP proofs were focused-only in the original CPU package. The extraction's
accidental default broadening is corrected: the default product named floor is
478 (154 frontend + 300 CPU + 13 CUDA + 11 primary), with both original CSP cases
preserved under test-csp-ecdsa-proof, minimum two. The hosted Ethereum CPU lane
covers Debug/ReleaseFast defaults and ReleaseFast CSP; no discovery or rejection
check is dropped. The full literal source inventory retains all 9,676 original
names and the same ten additions.

All twelve moved oversized product owners now meet the unchanged 850-line
ceiling, and the focused build owner meets its 500-line ceiling. Repository
source conformance still reports 69 inherited errors outside this product;
no baseline or ceiling was changed. The extraction remains unqualified as a
whole until the remaining hosted/default-package gates pass. The committed
local receipt records scopes, source fingerprint, proof/binary hashes and the
explicit unrun case; prior failures and compiler-guard receipts remain retained.


## Hosted qualification repairs (2026-11-13)

Under the maintainer’s standing authorization, the pre-edit C4 source allowance
is +3,300 net (previous measured +3,068, zero move credit). This bounded repair
covers four failures exposed by exact-source Linux run 43359194474: the bulk
memory external-lane scratch type, runtime neutral coordinator options, proof
tests selecting a backend different from their canonical scheme, and unused
CUDA extern references in Debug symbol metadata. Existing tests, constraint
bodies, canonical protocol types and discovery floors remain mandatory. The
host-only CUDA test image may omit debug symbols; it must still analyse the
legacy builder bodies and execute all thirteen contracts in both modes. No
CUDA stubs, device execution, new flags or maintained scripts are authorized by
this repair. Acceptance is the affected actual-source tests and the complete
CPU-host package lane; a guarded laptop check remains unrun, never passed.

The neutral absence fields now use `?noreturn`: null is their only inhabitant,
but options can be heap-allocated and carry runtime timing/stream fields. Both
coordinator consumer cases and the complete thirteen-case primary root pass
in both modes. The bulk-memory native/circuit residual and mutation test
passes in both modes. The actual stripped CUDA host image cross-links for
Linux without device libraries or stubs. The four official BUILD/boundary
commands, all 178 Python contracts and the 37-package workspace pass. An
initial combined package invocation hit the unchanged laptop guard; separate
official invocations pass, and the failed evidence is retained.

Repair budget against f49fd921d: source +30/-20/net +10; C4 cumulative
+3,078/+3,300, zero move credit. No flags or maintained scripts added/removed;
100 registry flags remain live. Documentation and receipts are counted
separately. Exact-source whole-package hosted qualification remains pending.


The final developer-workflow audit found thirteen moved Word16 proof fixtures
falling back to the entire product suite. Within the existing +3,300 C4 cap,
a pre-edit allowance of +60 source lines restores individual focused commands
for these existing files, with per-image named floors and unchanged default
discovery. This is BUILD/developer routing only; no runtime body, flag, script
or public protocol changes. A consumer regression first fails on all thirteen
old broad fallbacks; configure closure and the actual developer plan are gates.

Both the symbol-bearing and stripped umbrella-root attempts exceeded the
unchanged laptop guard. The pre-edit routing allowance is therefore +80
source lines, still within C4’s +3,300 total, for one actual CPU proof collector
shared by those thirteen commands. The collector imports the same thirteen
existing subjects; each focused command selects a whole subject and enforces
its original named count. This keeps the product’s unrelated default owners
out of the focused compilation. No substitute source or assertion is added.

The routing slice is source +68/-0/net +68; C4 cumulative +3,146/+3,300,
with zero move credit and no new flags or maintained scripts. All 179 Python
contracts and the 37-package workspace pass. Actual package configure exposes
all thirteen commands; removing their descriptor lines restores the prior
default build byte for byte. The focused proof execution still hits the
unchanged laptop guard and is UNRUN locally. The same original proof bodies
remain in the complete hosted default suite; no speed or memory gain is claimed.


The repaired hosted run 43361016571 was cancelled at its 30-minute job limit
while still on the first Debug command. Its retained started receipt and
partial stderr contain frontend semantic seals but no completed-command or
CPU acceptance receipt. It is CANCELLED/UNRUN, not a semantic pass. Under the
standing owner authorization, this host-only combined suite receives the same
90-minute scheduling allowance already used for complete frontend suites.
Laptop caps, proof/resource admission and all test assertions/floors stay fixed.
The commands gain verbose build/summary output to distinguish compiler and
executed-binary progress in future cancelled receipts. Pre-edit source allowance
for this CI contract regression is +8, within C4’s unchanged +3,300 total;
workflow/policy configuration and this evidence note are accounted separately.

The bounded CI metadata amendment also updates the package contract’s
`ci.command` to the identical verbose Debug argv. The workspace checker rejects
the old command once the lane changes; its exact command-identity consumer
regression fails before that amendment. This changes no public runtime API,
dependency, proof suite, test selector or discovery floor.

The timeout also established that sequential mode scheduling blocks every
ReleaseFast result behind the first Debug command. The combined suite is
therefore split into the same two independently selected CPU lanes used for
the native frontend: `ethereum_statement` retains complete Debug;
`ethereum_statement_releasefast` retains complete ReleaseFast and focused CSP.
The latter first runs the existing receiver-boundary gate and one restored
Word16 proof command, so the previously guarded ReleaseFast physical receipt
can qualify without waiting for Debug. The package graph selects both lanes
for affected consumers; no original command, assertion, floor or rejection
case is removed. Both full-suite hosts retain the bounded 90-minute allowance.
Pre-edit CI contract/routing source allowance is +20 (within C4 +3,300);
no new workflow, launcher, runtime flag or public runtime surface is introduced.


Full native Debug at df92791a6 (run 43361021086) executed 3,266 cases:
3,253 passed, eleven skipped, two failed. The failures are stale inventory
membership and the retained Ethereum manifest case calling the now-correctly
neutral dispatcher. A bounded +60 source allowance within C4 +3,300 covers
removing seven no-test inventory entries, moving that exact positive case to
its product owner, and adding a native rejection/no-output boundary case.
No inventory checker, test assertion or discovery floor is relaxed; the product
named floor increases from 478 to 479. Empty focused legacy wrappers revealed
by this audit remain an explicit migration follow-up, not qualified commands.

ReleaseFast run 43361025411 also completed 3,266 cases with the identical two
failures (3,253 pass, eleven skip). Their repairs now execute locally in both
modes: the byte-identical moved manifest assertion passes through the product
dispatcher, the new neutral rejection checks no journal output, and the official
native inventory command passes all three cases after eight no-test entries
are removed (seven umbrella entries and one RV64 helper entry). All 179 Python
contracts pass. The six empty legacy focused wrappers remain unqualified and
are being migrated rather than exempted from discovery.

This repair/scheduling slice is source +36/-21/net +15, C4 cumulative
+3,161/+3,300, with zero move credit. Documentation +59/-1, configuration
+48/-6; no new flags or maintained scripts (100 live). The existing full suites
remain required after the focused-wrapper migration. A cancelled host run and
locally guarded proof compile remain UNRUN; neither is acceptance evidence.


## Final focused-owner migration

Under the standing owner decision for RFC #352, a bounded BUILD-only native
constructor will create the existing retained typed-test module from the
caller-selected frontend source/dependency pointers. Its private source path
stays with the native owner; the product receives only a std.Build.Module.
An executable std.Build identity/immutability test precedes publication. No
runtime API, protocol record, package dependency or module is added. The native
default command will execute that BUILD contract under a separate floor of one.

The former mixed retained target’s original floor21 moves to the product,
joining the twelve existing native typed cases and eight existing product VM
composition cases. The native mathematical subset gets its own named target;
the original mixed floor is never lowered. The empty SWAP target transfers
to the product with its original floor7, and empty partitions are removed
from the bulk/secp targets without changing their floors. All original
assertion-bearing subjects remain in their default owners. Pre-edit allowance
for this factory, consumer wiring and executable BUILD contract is +110 source
lines within C4’s unchanged +3,300; documentation/configuration remain separate.

The BUILD constructor contract and actual developer entrypoint pass Debug and
ReleaseFast. The SWAP command passes both modes with its preserved floor7,
and an independent direct run observes all six selected named assertions
passing in each mode. The official native inventory gate passes all three
cases in both modes after retirement of the six empty collectors. All 180
Python contracts and the package workspace pass. The composed floor21 gate
still exceeds the unchanged laptop compiler cap and remains UNRUN locally;
both complete product host lanes execute it before the broad defaults.
The first operator harness nested the build lock and timed out before
compilation; the corrected harness propagates its held-lock marker. Failed
and guarded evidence is retained separately from passing command records.

Focused-owner slice budget: source +90/-34/net +56; C4 cumulative
+3,217/+3,300, zero move credit. No new flags or maintained scripts (100 live).
Documentation and configuration are measured separately in the commit. The
69 inherited source-size errors remain outside this extracted product; no
ceiling, baseline or exemption changed. Full final-source host gates are pending.
