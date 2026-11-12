# RISC-V package ownership and qualification

This is the implementation map for C3 in RFCs #335, #344 and #352. The
compatibility frontend is the composition root above nine independently
buildable children. It preserves the existing caller-facing entry points;
children expose canonical typed domain interfaces, not a registry of private
filenames. Package contracts remain schema v2.

## Dependency direction

The approved order is ISA, AirLang, Memory, RecursionAir, Precompiles, RV32,
RV64, Recursion and Testing. An edge must be explicitly declared in the
consumer's contract and point to a predecessor; sharing a name prefix grants
nothing. Testing is an unstable qualification package. The umbrella may depend
on every child; no child may depend on the umbrella. Dependency cycles are
rejected unconditionally.

| Owner | Responsibility |
| --- | --- |
| ISA | Instruction decoding, machine/host records and fixed statement frames |
| AirLang | Authoring IR, relation descriptions, polynomial encoding and control rows |
| Memory | Native memory commitments, hash primitives and their typed evaluators |
| RecursionAir | Generic recursive verifier arithmetic and transcript/publication frames |
| Precompiles | Mathematical service primitives, call records and service AIRs |
| RV32 | Native execution, witnesses, proof construction and physical profile facts |
| RV64 | Native RV64 execution and AIRs |
| Recursion | Native verifier graphs, captures, preparation and verification |
| Testing | Shared regression assertions and fixtures that consume multiple children |
| Compatibility umbrella | Existing product profiles, guest adapters and mixed assemblers |

Request admission stays with its original authority. Moving a record below an
assembler does not confer permission to construct or admit a request. The
native omission geometry record lives with native statement geometry; the
Ethereum omission authority still validates the complete request above it.
The native semantic-audit environment name has one definition, with the old
public name an alias. No runtime switch is added.

## Canonical identities

There is one definition of CircuitLayout, ProgramPolicy, CircuitProfileV1,
control Row, SegmentV2 fixed frame/Side, span word-count formula and each native
physical profile record. Compatibility names refer to these definitions.
Polynomial ownership helpers and shared RAM hash primitives likewise have one
implementation. Product-only ELF loading is composed above the generic RV64
memory image API; the old umbrella spelling remains available.

The product factory reads the actual child contracts and creates all children
against the caller-selected protocol modules. It reuses those exact Core,
prover API, prover engine and codec module pointers. It does not instantiate a
second default protocol package for the children. Unknown or forward child
edges fail construction. Standalone package builds use the same declared
predecessor graph.

The postcard codec remains an existing consumer module of recursion wire.
This split does not qualify an independently published package tarball or add
that consumer implementation to the waist's public surface.

## Test ownership

Each child owns a literal inventory, executable signature identity case and
behavior tests. The umbrella's default test command executes ten binaries:
its own plus the nine child binaries. Importing a named module alone is not
accepted as evidence that Zig ran that module's tests. The existing 1,103-test
floor applies across those actual runs, and each child must run its declared
signature case. Source-name retention is an additional audit, not a substitute
for runtime discovery.

Focused tests retain their filters and minimum counts in one catalog. Their
small collector roots live at each package root because Zig's module import
boundary is the root file's directory. Their subjects remain organized in
subdirectories. Test modules receive only their owner's declared dependencies.
A consumer-owned focused command is selected only across an explicitly
registered package dependency; an unknown source takes its broad owner suite.

The original benchmark and environment-dependent exclusions transfer to their
new physical owners, including every partition of an excluded collector.
Two exclusion entries already referred to absent files in the starting tree;
those stale entries are removed. No live named assertion is removed.
Redundant anonymous collectors are retired after their subjects and focused
partitions have canonical owners. The full source audit retains all 3,334
original named Zig test declarations and adds nine signature identity cases
and one strict collector-parser regression (3,344 named cases in total).
Counts alone do not qualify test execution.

Experimental H-009/H-010 authoring interfaces remain under explicit unstable
`testing.proposals` namespaces. Their source-conformance allow-list names exact
moved files and owned test/export roots. It grants no basename or directory-wide
exception to production admission code.

## Acceptance

Local bounded checks establish formatting, workspace closure, developer/CI
routing, actual ISA execution and both directions of inventory membership.
They do not establish full C3 acceptance. Hosted Debug and ReleaseFast child
and frontend runs, fresh native proof verification, graph/authority parity,
the frozen native CPU proof and CSP shape inspection must qualify the final
immutable candidate. Existing arithmetic, formal and report-schema failures
remain failures until independently resolved. No pin may be changed merely to
accept a directory move.

The hardware gate is unrun on the laptop: its synced-pod guard refuses local
execution. No GPU qualification, performance claim, default promotion or
whole-restructuring completion follows from this package split. The broader
C1/C2/C4 and D1–D5 work retains its own gates and merge requirements.

## Product consumer qualification

The product-side collectors also run from their canonical owners. Twenty-three
single-owner RV64 collectors retain their original subject imports; the mixed
execution collector is three real binaries with its original aggregate floor
of 67. The statement-wire contract keeps its six cases in one owned codec
suite, including the unchanged public-input padding assertion. Root module
construction binds the owner's declared predecessor modules from the caller's
existing frontend instance. No independent protocol universe is introduced.

The build catalog reuses the exact ten-root RISC-V family closure across
protocol scopes. The CPU scope declares 225 roots; a bounded construction run
matches that declaration exactly with no foreign dependency, constructor, tool
or runtime-probe addition. The 30 build-policy cases include the aggregate
counter and its missing-execution-metadata refusal.

Two retained LS-D64 parity fixtures allocated 256 KiB stacks despite the
existing Debug kernel contract requiring 1 MiB. They now request the kernel's
production default worker stack (16 MiB). The 1 MiB minimum compiled but
was insufficient for the Debug fused-pair fixture on hosted execution. Worker count, serial/parallel equality and
production stack refusal remain unchanged.

P-003's current source-authority ledger follows the physical ownership moves;
its sixteen families, twenty-three sites, classifications and schema do not
change. Historical receipts are not rewritten or re-pinned. An explicit relocation ledger preserves the released legacy blocker only
when the current matrix context matches exactly. Independent recomputation
still binds every other receipt field, and changed matrix hashes and seal
claims are rejected. Legacy preflight remains inadmissible for new capture;
this replay compatibility is not current qualification. The source-binding and formal gates in #328 remain open.

## Qualification checkpoint, 2026-11-12

The complete frontend Debug and ReleaseFast lanes both passed at `731748325`
([run 43204561808](https://github.com/teddyjfpender/stwo-zig/actions/runs/43204561808)).
The focused transcript command passed in both modes with its original minimum
of 236 ([run 43204545052](https://github.com/teddyjfpender/stwo-zig/actions/runs/43204545052)).
Separate RV64 build-mode jobs retain both exact commands; ReleaseFast also
passed independently at `334489a53`. These results qualify those source
revisions, not every subsequent edit.

Native proof bytes and complete native/product circuit graph receipts match
retained references. Four CPU smoke workloads freshly verify and reject wrong
statements. The remaining CPU profile-partition failures are being repaired
under #368: source checks now bind the live full-width transaction; explicit
one-worker requests must retain their proof-owned pool without helper threads
or legacy global-pool discovery. The final hosted parity/failure-recovery gate
must confirm that repair before acceptance.

The live formal candidate at `cb7be561b` exported fresh AIR and passed the full
Lean theorem build. Its generated Sail composition bridge then rejected FENCE
and LUI source-content identities in
[run 43215529913](https://github.com/teddyjfpender/stwo-zig/actions/runs/43215529913).
No candidate pins were adopted. This remains the explicitly permitted #328
follow-up, alongside circuit-oracle provenance and current source-bound audit
receipts. Shared-runner benchmark failures remain non-blocking measurements;
the LS-D64 projection denominator failure remains an actual integration failure
tracked in #358. None is converted into a passing qualification.

## Integrated flag handoff

The completed #342 handoff at `5c4f5ff24` merges without conflicts over the
owned package graph. It removes 149 live controls and 1,315 net source lines:
249 live flags become 100. Its exact absent-variable defaults, live stronger
artifact settings, fault/rejection coverage and deferred promotion gates stay
intact. Registry/reference checks, 86 flag/CUDA/build-policy contracts and
workspace closure pass locally; 71 changed Zig roots pass formatting. GPU
execution remains unrun. The under-60 C1 target is not met. The maintained
native ambient-reader exception shrinks from seventeen exact files to five;
no new policy ABI or launcher is introduced.
