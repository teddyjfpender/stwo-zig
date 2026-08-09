# Task graph

**Status:** active backlog
**Last updated:** 2026-08-09

## Status vocabulary

- **done** — acceptance evidence exists on this branch.
- **active** — exactly one primary task is being implemented.
- **ready** — dependencies are complete and acceptance is defined.
- **queued** — valid work, dependency not complete.
- **blocked** — external decision or repeated technical blocker is recorded.
- **deferred** — intentionally outside the current delivery.

Priority `P0` protects correctness or the critical path. `P1` completes the
first production milestone. `P2` improves breadth or optimization.

## Milestones

| Milestone | Result | Exit condition | Status |
| --- | --- | --- | --- |
| M0 | Engineering dossier | Branch, canon, architecture, tasks, validation, progress | done |
| M1 | Validated logical IR | Deterministic IR kernel and negative tests | done |
| M2 | Shadow compiler | All 17 current families imported and degree-reported | done |
| M3 | Compatibility lowering | LUI and then all families round-trip exactly | blocked |
| M4 | Pure compiler pilot | Poseidon2 compatibility path verified; H-010 default cohort reviewed | done |
| M5 | Effect/witness pilot | LUI, ADDI, signed load/JALR, DIV vertical slices | ready |
| M6 | Guest precompile | Poseidon2 calls close in one proof | ready |
| M7 | Parallel proving | Component stages scheduled and measured | active |
| M8 | Broad migration | Handwritten witness duplication retired | queued |
| M9 | Recursive aggregation | Bound leaf summaries aggregate two-to-one | deferred |

## Immediate queue

| ID | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- |
| F-001 | Add `air/lang` package skeleton and test inventory wiring | M0 | Package tests execute new focused tests; no production imports | done |
| F-002 | Implement typed IDs, semantic types, source spans, and arena ownership | F-001 | Construction/deinit tests; invalid cross-ID use impossible at compile time | done |
| F-003 | Implement expression nodes and structural interning | F-002 | Stable topological IDs; equivalent expressions intern; order-independent test corpus | done |
| F-004 | Implement constraints, hints, effects, functions, and structural validator | F-003 | Named negative test for every validator error class | done |
| F-005 | Implement canonical logical manifest serialization | F-004 | Two clean builds and insertion-order perturbations produce identical bytes | done |

## Foundation tasks

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| F-006 | P0 | Define typed relation schema registry | F-002 | Existing relation domains represented without strings; invalid roles/arity reject | done |
| F-007 | P0 | Define acyclic function graph and static call validation | F-004 | Recursive cycle and missing callee tests reject deterministically | done |
| F-008 | P0 | Define hint recipe registry and binding metadata | F-004 | Unbound output and unknown recipe reject | done |
| F-009 | P1 | Add stable diagnostic renderer | F-003 | Diagnostics include component, source span, value path, type, and degree | done |
| F-010 | P1 | Add canonical program digest | F-005 | Digest changes for semantic order/type changes and not allocator/address changes | done |
| F-011 | P1 | Add allocation-failure tests for arena finalization | F-004 | All partially initialized owners deinit cleanly | done |
| F-012 | P1 | Document public authoring interface | F-004 | One minimal pure and one effectful example compile in tests | done |

## Shadow analysis and lowering

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| A-001 | P0 | Import current symbolic polynomial DAG | F-004 | Random replay equals `symbolic.replay` | done |
| A-002 | P0 | Import columns, constraints, selector, and ordered lookups | A-001, F-006 | Counts and order match all 17 families | done |
| A-003 | P0 | Implement logical degree propagation | A-001 | Unit corpus covers constants, sums, products, selections, aliases | done |
| A-004 | P0 | Model gates, row windows, boundaries, and interaction degree | A-002, A-003 | Report includes complete final degree, not only root degree | done |
| A-005 | P0 | Emit all-family degree and dependency report | A-004 | Golden machine report and readable summary for 17 families | done |
| A-006 | P0 | Define `compat-v1` physical column mapping | F-005, A-002 | Current column count/name/order reproduced | done |
| A-007 | P0 | Lower direct constraints to current `ConstraintProgram` | A-006 | LUI exact normalized DAG comparison | done |
| A-008 | P0 | Lower typed effects to current ordered lookup entries | A-007, F-006 | LUI event fields and batch order exact | done |
| A-009 | P0 | Reproduce runtime polynomial program | A-007 | Node/root/column identity test | done |
| A-010 | P0 | Reproduce AIR IR v2 projection | A-008 | Byte-identical canonical export for LUI | done |
| A-011 | P1 | Round-trip every current family | A-009, A-010 | 17 compatibility manifests and exports exact | done |
| A-012 | P1 | Add layout diff command/test helper | A-006 | Diff identifies first semantic/layout divergence with names | done |

## Poseidon2 compiler pilot

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| H-001 | P0 | Add typed fixed-size arrays, maps, and folds | F-007 | Static shape and source-span tests | done |
| H-002 | P0 | Author pure M31 Poseidon2 permutation | H-001, A-003 | Output matches current permutation vectors | done |
| H-003 | P0 | Implement deterministic degree-three materializer | H-002, A-006 | Every lowered constraint within bound; stable allocation | done |
| H-004 | P0 | Reproduce 426 existing materializations | H-003 | Current 445-column layout and constraint order exact | done |
| H-005 | P0 | Generate direct-to-final-storage witness | H-004, F-008 | Byte-identical rows; no per-row allocation | done |
| H-006 | P0 | Reproduce Poseidon relations and claims | H-004, F-006 | Honest and forged relation tests match current behavior | done |
| H-007 | P0 | Run real CPU and Metal proof equivalence | H-005, H-006 | Independent verification succeeds on both admitted backends | done |
| H-008 | P1 | Add source-to-materialization diagnostics | H-003, F-009 | All 426 columns trace to semantic source paths | done |
| H-009 | P2 | Prototype cost-aware materialization policy | H-007 | Separate manifest and cost report; no production activation | done |
| H-010 | P2 | Benchmark compatibility and proposed layouts | H-009 | Complete authenticated four-arm log-10/log-14 cohort under PERFORMANCE.md; no production/proof claim | done |

### H-010 completion evidence

The isolated harness and its admission prerequisites are complete:

- exact H-009 artifact, fixed-program, four-arm, proposal, and cut
  authentication;
- checked log-10/log-14 `STWAIRB\0` vectors and a byte-regenerated readable
  index, with log 18 generated only as a non-receiptable opt-in;
- one common retained CPU evaluator with prepared witness/direct capabilities
  and no per-row allocation;
- independent expected-output comparison, all 430 roots on every admitted row,
  and one-at-a-time mutations for all 426 materializations and fixed roles;
- regression-only candidate trace pins, explicit timer boundaries, normalized
  high-water RSS, strict child/report schemas, and serial rotated orchestration;
  and
- source/build isolation from production CPU/Metal executables and explicit
  negative proof, PCS, verifier, Metal-candidate, and promotion capabilities.

Clean implementation commit `82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`
with tree `8cbb9300fa9b820baa079eeb94addf71db97f130` produced two
independently valid and complete default reports. The locally retained ignored
`v2` report is 337,144 bytes with SHA-256
`98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`;
`v3-confirm` is 337,146 bytes with SHA-256
`eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
Each report records 112 fresh sample children with zero failures, retries, or
drops under the same executable and source closure. Candidate deltas remain
inside run-to-run noise, including q0/q100 log-14 witness directions that flip
between reports, so H-010 selects no layout. Proof, Metal-candidate, and
production claims remain false. Any future promotion still requires a separate
accepted decision and full proof-path evidence.

## Typed effects and opcode migration

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| E-001 | P0 | Implement program fetch and state consume/produce effects | F-006, A-008 | Current schemas/order reproduced | done |
| E-002 | P0 | Implement register read/write with strict subclocks | E-001 | Alias and historical self-loop negatives reject | done |
| E-003 | P0 | Implement memory read/write and range effects | E-002 | Load/store masks, gaps, and address bounds represented | done |
| E-004 | P0 | Author LUI in typed surface | E-001, A-010 | Full compatibility and proof gates exact | ready |
| E-005 | P0 | Generate LUI witness in shadow mode | E-004, F-008 | Column equality across corpus | queued |
| E-006 | P0 | Author ADDI | E-002, E-004 | x0, aliases, overflow, carries, Sail differential | queued |
| E-007 | P0 | Generate ADDI witness in shadow mode | E-006 | Column/event equality and forged carry rejection | queued |
| E-008 | P1 | Author signed-load pilot | E-003, E-007 | Sign hint, memory mask, and bound mutations reject | queued |
| E-009 | P1 | Author JALR pilot | E-003, E-007 | Target, bit zero, range, state transition exact | queued |
| E-010 | P0 | Define quotient/remainder hint recipes | F-008, E-003 | All RISC-V exceptional classes specified | ready |
| E-011 | P0 | Author DIV-family pilot | E-010 | 292 operand-class corpus and adversarial tests pass | queued |
| E-012 | P1 | Add generic direct-to-column witness executor | E-005, H-005 | Preplanned storage, bounded dispatch, deterministic errors | queued |
| E-013 | P1 | Switch one family witness to generated authority | E-012 | Old writer test-only; full clean-tree gates green | queued |
| E-014 | P1 | Migrate remaining families in reviewed groups | E-013 | Per-family checklist complete | queued |
| E-015 | P1 | Retire redundant witness writers | E-014 | No production imports; retained history documented | queued |
| E-016 | P2 | Evaluate generated concrete executor | E-014 | Sail/Spike differential and ADR; no authority change | queued |

## Guest precompile

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| C-001 | P0 | Accept guest ABI ADR | H-007 | Explicit extension semantics and failure policy | done |
| C-002 | P0 | Accept guest relation/version ADR | C-001, F-006 | Domain separation and multiplicity policy fixed | done |
| C-003 | P0 | Implement owned typed call buffer | C-002 | Stable order, duplicates, empty case, allocation failure tests | done |
| C-004 | P0 | Implement runner/host invocation boundary | C-003 | Invalid calls reject before mutation; output corpus matches | done |
| C-005 | P0 | Add guest Poseidon component registry entry | C-003 | Stable kind/version and verifier construction | done |
| C-006 | P0 | Extend statement geometry and artifact identity | C-005 | Call count/columns/log size bound and malformed artifacts reject | done |
| C-007 | P0 | Generate guest precompile main trace | C-004, C-006 | Calls map exactly to active rows; padding inactive | ready |
| C-008 | P0 | Generate shared-challenge relation interactions | C-007 | Source/supply sums close; omission/duplication fail | queued |
| C-009 | P0 | Prove and independently verify one guest program | C-008 | CPU proof and new-process verifier green | queued |
| C-010 | P1 | Add Metal component admission | C-009 | Authenticated AOT or reviewed generic path; no CPU fallback | queued |
| C-011 | P0 | Add native-versus-precompile semantic corpus | C-009 | Same advertised outputs; extension labelled | queued |
| C-012 | P1 | Add precompile mutation fleet | C-009 | Input, output, mode, multiplicity, padding, count forgeries reject | queued |
| C-013 | P1 | Benchmark crossover and total work | C-011, C-012 | Complete report under PERFORMANCE.md | queued |

## Parallelism and recursion

| ID | Priority | Task | Depends | Acceptance | Status |
| --- | --- | --- | --- | --- | --- |
| R-001 | P1 | Model component build stages as bounded tasks | C-009 | Explicit dependencies, ownership, cancellation | active |
| R-002 | P1 | Parallelize independent main-trace construction | R-001 | Canonical output; serial differential | queued |
| R-003 | P1 | Parallelize independent interaction construction | R-002 | Shared challenges; canonical claims | queued |
| R-004 | P1 | Integrate with heterogeneous quotient scheduler | R-003 | No nested oversubscription; failure propagation | queued |
| R-005 | P1 | Add component critical-path telemetry | R-004 | queue/run/wait/memory metrics in report | queued |
| R-006 | P1 | Thread-count and workload scaling study | R-005 | verified 1/N-worker sweep and resource disclosure | queued |
| R-007 | P2 | Specify cross-proof relation summary | C-012 | Reviewed soundness argument and serialization | deferred |
| R-008 | P2 | Implement one core/precompile leaf-pair prototype | R-007 | Swapped/omitted/cross-transcript negatives reject | deferred |
| R-009 | P2 | Implement two-to-one aggregation tree | R-008 | Final verifier binds all leaves and statement | deferred |
| R-010 | P2 | Measure recursion crossover | R-009 | Proof size, verifier, memory, total work, wall time | deferred |

### R-001 implementation checkpoint

The exact-capacity scheduler, worker leases, joined cancellation, deterministic
failure selection, resource reservations, and coordinator-prepared composition
capability exist. The current RISC-V component set also has allocation-free
prepared row evaluators with bounded cancellation polling and an admitted
128 KiB row-evaluator stack. This is an active implementation slice, not R-001
or M7 completion:

- the specialized CPU composition backend still runs before the generic
  prepared scheduler and therefore bypasses it in the production CPU proof;
- no full production proof yet establishes predecessor versus graph `N = 1`
  parity or the required proof-byte differential;
- composition work is one task per component rather than row-sharded work; and
- the compatibility entrypoint has not supplied a finite per-request byte
  budget or the R-005/R-006 resource and scaling receipt.

## Cross-cutting validation and tooling

| ID | Priority | Task | Depends | Acceptance |
| --- | --- | --- | --- | --- |
| V-001 | P0 | Wire every new test file into RISC-V inventory | Each code task | Inventory test and count floor updated deliberately |
| V-002 | P0 | Add golden manifest regeneration/check mode | F-005 | Check is fail-closed; regeneration explicit |
| V-003 | P0 | Add root-by-root production differential helper | A-007 | First mismatch names constraint and source path |
| V-004 | P0 | Add hint/column mutation generator | F-008, E-012 | One-at-a-time mutation report with attribution |
| V-005 | P0 | Bind formal regeneration to logical/layout identity | A-010 | Drift fails existing refinement workflow |
| V-006 | P1 | Add CPU/Metal canonical program identity receipt (done) | H-007 | Backend reports same logical/layout digest |
| V-007 | P1 | Add documentation link and task-state checker | M0 | Broken local links and multiple active tasks fail |
| V-008 | P1 | Add clean-tree milestone receipt (done) | M3 | Commit, tool versions, manifests, tests, and digests recorded |

## Critical path

```text
F-001..F-005
      |
      +--> A-001..A-010 --> H-001..H-007 --> C-001..C-009 --> R-001..R-006
      |                         |
      +--> F-006..F-008 --> E-001..E-013
```

The Poseidon and opcode-effect tracks may proceed in parallel after the shared
IR and relation foundations are stable. Broad migration does not block the
first guest precompile.
