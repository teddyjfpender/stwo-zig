# RISC-V proving lane release goal

**Status:** SUPERSEDED on 2026-07-26 by
[`2026-07-26-riscv-sail-contract.md`](2026-07-26-riscv-sail-contract.md).

This file is a historical record of the pre-Sail CP-00…CP-13 process. Its
CP-11/CP-13 commands, owner-dispatch inputs, receipts, bundles, divergence
shapes, and promotion formula must not be executed or cited as current release
authority.

**Created:** 2026-07-18

**Last reconciled:** 2026-07-19 against the committed implementation through
`eaf4f5ff`. The focused product gate passes in 85.5 seconds and the separately
owned exhaustive RISC-V proof/adversarial suite passes in 343.8 seconds on the
measured local host. These are diagnostic results, not release receipts. No
checkpoint is promoted by local evidence alone; the next exhaustive hosted
anchor and fresh candidate challenge remain the acceptance authority.

**Authority:** This is the operative delivery contract for the Stark-V RV32IM
lane. It may be replaced only by a reviewed document that names every changed
acceptance condition. Progress notes, passing unit tests, and benchmark reports
cannot weaken this contract.

**Release decision:** NO-GO until every required checkpoint below is `PASS` on
one identified commit from a clean checkout.

**Completion formula:** `GO = CP-00..CP-13 PASS on one clean candidate` +
`RF-01 promoted gate PASS` + `BA-01 PASS` + `BA-02 PASS` + `BA-03 disabled with
reason or independently PASS` + `zero release-blocking divergences`. Every term
is mandatory. A false term makes the result `NO-GO`.

**Machine authority:** release authorization requires the two-stage hosted
protocol in [riscv-release-evidence.md](riscv-release-evidence.md): one successful
exhaustive anchor producer plus one fresh, exact-candidate challenge that reuses
that anchor only while the complete release-policy domain is byte-identical.
`scripts/riscv_release_gate.py --strict` owns the exhaustive plan and may issue
the anchor's local receipt, but cannot authorize promotion without the hosted
challenge receipt. Both stages reject every active divergence except an
explicitly allowlisted, conditionally gated difference. For the currently
pinned Stark-V revision, the signed `MULH` carry defect is a mandatory documented
limitation: deleting or renaming its ledger row, removing its implementation
`FIX` marker, or claiming corrected semantics without a new pin must fail the
gate. Exact parity with the pinned behavior is required; correcting the upstream
Rust repository is not.

**Goal identity:** Complete and release-gate the Stark-V RV32IM proving lane by
finishing globally sound cross-shard LogUp placement, binding the full public
I/O statement, validating the production prove/verify/benchmark CLI and
schema-v3 artifact, passing pinned-Rust oracle and adversarial evidence gates
from one clean candidate, performing a non-semantic registry promotion, and
completing core-purity/frontend-layering bias audits while keeping RISC-V
autoresearch scoring disabled until independently qualified.

**Last accepted live-oracle evidence:**
`bae4ff484c4f8edb750c2a7924983b36aece3b21`. Its clean local strict candidate
receipt passes all 11 shared boundaries and binds the complete corpus, relation
domains, physical provenance, transcript prefix, and documented pinned
signed-`MULH` limitation. The enclosing local CP-13 run passed in 665.529 seconds
with a clean start and end tree. Hosted run `29682036388` rejected the same
revision before Python discovery because Linux correctly exposes no
`metal-eval-prepare` build step. The local receipt is therefore valid diagnostic
evidence but cannot authorize RF-01 until a policy-compatible hosted exhaustive
anchor and a fresh exact-candidate challenge both pass.

## Goal

Deliver a production-capable `stwo-zig` CLI path that:

1. accepts a supported RV32IM ELF and explicit public input;
2. executes it with Stark-V-compatible semantics;
3. constructs the exact committed witness for every accepted instruction;
4. proves the execution with active AIR constraints and globally balanced
   cross-shard LogUp relations;
5. binds the complete public statement to the proof;
6. writes a versioned, atomic proof artifact;
7. cryptographically verifies that artifact through an independent CLI path;
8. conforms at every shared boundary to the Rust Stark-V oracle pinned in
   [upstream.md](upstream.md); and
9. remains backend-neutral above the integration boundary and structurally ready
   for later performance work.

The delivered system must make a false RISC-V execution harder to accept, not
merely make an honest execution possible to prove. Zig prove/verify agreement is
necessary evidence, but the pinned Rust implementation is the final correctness
oracle wherever the two implementations share semantics.

The goal is not "make the current fixture prove." It is to admit exactly the
declared RV32IM statement, reject every known way to alter that statement or its
execution, and make the same installed CLI path reproducible by a clean release
controller. Throughput work, Metal support, streaming, Cairo, and autoresearch
scoring are outside this release decision.

## Executive acceptance matrix

This is the operator-facing checklist for the current goal. It maps the requested
delivery checkpoints to the detailed contracts below; it does not replace or
weaken them. A checkpoint is complete only when every referenced checkpoint is
`PASS` on the same clean candidate revision and the named gate has emitted the
required evidence.

| Delivery checkpoint | Detailed contract | Required evidence | Unlock condition | Current decision |
| --- | --- | --- | --- | --- |
| **1. Complete cross-shard LogUp placement in the RISC-V AIR** | CP-03 through CP-06, CP-11, CP-12 | Canonical component order; exact committed-buffer tuple provenance; all twelve relation domains independently cancel; one-, two-, and many-shard proofs pass; semantic omission, duplication, tuple, multiplicity, padding, and boundary attacks fail cryptographically; mutation of an existing artifact's shard/claim order fails; live Rust cumulative accumulator and deterministic provenance agree after every component | Unlocks final statement/CLI integration only after semantic, memory, Merkle, Poseidon2, range, and bitwise constraints are active in both on-domain and OODS evaluation | `NO-GO` while any relation source, sink, recurrence, commitment, or verifier consumer is absent |
| **2. Verify the build and visible CLI result** | CP-09, CP-10, CP-13 | `ReleaseFast` installed binary; stable help and diagnostic snapshots; staged prove, independent verify, and benchmark smoke; deterministic machine JSON; bounded schema-v3 artifact; atomic publication and tamper rejection | Candidate CLI evidence may be collected in parallel, but it cannot authorize promotion before checkpoints 1 and 3 pass | `NO-GO` while the CLI projects transitional claims, relies on in-process state, or emits schema v2 |
| **3. Add public I/O binding to the RISC-V statement** | CP-07, CP-08, CP-11, CP-12 | Every public field is canonically transcript-bound and algebraically linked to committed execution; caller-supplied expected statement is enforced; prover/verifier channel traces agree; per-field, ordering, length, address, clock, and root-presence mutations fail; schema-v3 segment geometry is fixed to ordinal `0` of count `1` and every other value is rejected | Unlocks clean candidate evidence only after public compensation closes in the relevant relation domains | `NO-GO` while any public value is prover-chosen, transcript-only, host-asserted, or unconnected to a committed relation |
| **4. Flip the prove-CLI registry entry and release-gate the adapter** | CP-00 through CP-13, then RF-01 | A successful policy-compatible exhaustive hosted anchor provides fresh 11/11 Rust-oracle evidence and zero release-blocking divergences; the exact clean candidate then passes a fresh three-minute challenge against it; a separate non-semantic promotion commit repeats the producer/challenge pair in promoted mode | This is the final release action, never an implementation shortcut. A failure after the flip requires reverting the promotion | `FORBIDDEN` until every prerequisite is `PASS` on one identified candidate |
| **5. Complete the bias audit** | BA-01 through BA-03 | Mechanical core-purity and frontend-layering gates pass on candidate and promoted revisions; audit records all dependency edges and source-debt findings; autoresearch exercise validity either passes independently or remains disabled with an explicit, tested reason | BA-01 and BA-02 are release requirements. BA-03 does not block adapter release while it remains fail-closed, but it blocks RISC-V autoresearch scoring | `NO-GO` for release on BA-01/BA-02 failure; `NO-GO` for autoresearch activation on BA-03 failure |

The dependency order is **1 -> 3 -> 4**. Checkpoint 2 may progress alongside
checkpoints 1 and 3, but its final receipt must exercise their production shapes.
Checkpoint 5 runs throughout implementation and is rerun against both the clean
candidate and the promoted revision. No passing unit suite, local proof
roundtrip, benchmark number, committed vector, or Zig prover/verifier
self-agreement can substitute for a missing gate in this matrix.

### Sign-off protocol

The completion decision is deliberately binary:

1. Land semantic, statement, artifact, and audit work while the registry and
   autoresearch lane remain closed.
2. Ensure the current release-policy revision has a successful exhaustive
   producer in hosted CI. It must include the fresh 11/11 pinned-Rust oracle
   receipt and the complete adversarial fleet. Select one candidate commit with
   a clean tree, then run its fresh challenge against that policy-compatible
   producer. Implementation-only candidates may reuse the unexpired anchor;
   policy, oracle, schema, vector, or compatibility drift requires a new one.
3. Record `PASS` for CP-00 through CP-13, BA-01, and BA-02 only from that exact
   evidence bundle. Close every release-blocking divergence.
4. Make RF-01 a separate, non-semantic promotion commit. Its diff may change
   release surfaces and documentation, but not execution, witness, AIR,
   transcript, proof, artifact, or verification semantics.
5. Run a new exhaustive producer and fresh challenge in `promoted` mode. Revert
   RF-01 if either hosted stage fails.
6. Leave the autoresearch RISC-V group disabled unless BA-03 later obtains its
   own independent activation receipt.

The authoritative candidate dispatches are:

```sh
candidate_sha=$(git rev-parse HEAD)
candidate_short=$(git rev-parse --short=12 HEAD)
candidate_branch=riscv-release-anchor-$candidate_short
candidate_ref=refs/heads/$candidate_branch
git push origin main
git push origin "$candidate_sha:$candidate_ref"
gh workflow run ci.yml --ref main \
  -f gate=riscv-produce-candidate \
  -f candidate_sha="$candidate_sha" \
  -f candidate_ref="$candidate_ref"

producer_run_id=<successful-producer-run-id>
gh workflow run ci.yml --ref main \
  -f gate=riscv-candidate \
  -f candidate_sha="$candidate_sha" \
  -f candidate_ref="$candidate_ref" \
  -f producer_run_id="$producer_run_id"
```

Promoted source uses `riscv-produce-promoted` and `riscv-promoted`. Individual
commands listed by later checkpoints are development gates. They do not replace
either hosted stage.

### Evidence required at every checkpoint

Each `PASS` entry must name:

- the exact clean stwo-zig commit;
- the exact pinned Stark-V commit and clean-tree status when oracle evidence is
  involved;
- the command, optimization mode, start time, duration, exit code, and output
  digest;
- the relevant artifact, corpus, statement, witness-layout, and executable
  digests;
- every required test count and the fact that no required test was skipped; and
- the specific invariant responsible for every expected mutation rejection.

Evidence from an uncommitted tree is diagnostic only. Evidence becomes stale
after a change to accepted semantics, witness layout, relation placement, public
statement, transcript, proof wire, verifier, registry, oracle corpus, or release
controller. Stale evidence must be regenerated; it cannot be carried forward by
assertion.

## Governing documents

The following documents are normative, in this order:

1. [CONTRIBUTING.md](../CONTRIBUTING.md), especially protocol soundness, final
   Rust-oracle evidence, dependency direction, file-size limits, and fail-closed
   backend behavior.
2. [upstream.md](upstream.md), which pins Stark-V commit
   `d478f783055aa0d73a93768a433a3c6c31c91d1c`.
3. This goal document.
4. [riscv-release-evidence.md](riscv-release-evidence.md), which defines the
   hosted exhaustive-anchor and fresh-challenge execution protocol without
   weakening any checkpoint in this goal.
5. [riscv-pr-proof-gate.md](riscv-pr-proof-gate.md), which requires every
   affected pull request to produce and independently verify the bounded
   structural proof corpus before merge.
6. [divergence-log.md](divergence-log.md), which records intentional differences
   and whether each difference blocks release.
7. [2026-07-18-riscv-bias-audit.md](2026-07-18-riscv-bias-audit.md), which records
   the independent NO-GO baseline and the audit requirements that must be closed.
8. [decomposition-plan.md](decomposition-plan.md) and
   [source-baseline.json](source-baseline.json), which govern repository structure
   and existing source debt.

When documents disagree, the stronger correctness or fail-closed requirement
wins. An implementation discovery must update the relevant ledger; it must not
be hidden in code or treated as an oral exception.

## Immediate execution contract

This section turns the delivery request into an ordered, fail-closed execution
plan. The detailed CP-00 through CP-13 requirements below remain authoritative;
this section does not narrow them.

### Delivery sequence and decision points

The active delivery scope is the following six-stage sequence. A stage may be
implemented in parallel with another, but it cannot be marked complete until its
named gate passes against production code. The registry stays closed throughout
stages one through four.

| Stage | Required outcome | Checkpoints | Promotion condition |
| --- | --- | --- | --- |
| D1 Cross-shard LogUp | Exact source, table, public, Merkle, Poseidon2, range, bitwise, state, program, and memory placement; canonical component batching; global cancellation across one, two, and many shards | CP-04, CP-05, CP-06 | Honest proofs pass; semantic omission, duplication, tuple, multiplicity, padding, and boundary attacks fail cryptographically; an existing artifact cannot be reordered without rejection |
| D2 Build and visible CLI result | ReleaseFast build; installed candidate CLI proves, independently verifies, benchmarks, emits deterministic JSON, publishes atomically, and renders stable help/errors | CP-09, CP-10 | Candidate smoke matrix passes using the installed binary and a genuinely multi-shard ELF |
| D3 Public I/O statement | Caller-expected program, input, output, roots, registers, clocks, and geometry are transcript-bound and algebraically bound to committed execution | CP-07, CP-08 | Every public field mutation and every transcript ordering mutation fails in production verification |
| D4 Independent evidence | Eleven live Rust boundaries agree in a policy-compatible exhaustive anchor, the adversarial fleet rejects every named forgery, and the exact candidate passes a fresh hosted challenge against that anchor | CP-11, CP-12, CP-13 | Fresh 11/11 exhaustive anchor plus a fresh exact-candidate challenge, with zero required skips |
| D5 Registry promotion | One non-semantic commit changes only release surfaces from staged to promoted and removes candidate-only admission | RF-01 | The promoted producer/challenge pair passes; otherwise the promotion is reverted |
| D6 Bias audit | Core purity and frontend layering are mechanically enforced on the promoted revision; autoresearch remains independently gated | BA-01, BA-02, BA-03 | BA-01 and BA-02 pass; BA-03 either passes independently or remains disabled with reason |

There is no partial release state between D4 and D5. An internally verifying
proof, a passing CLI smoke, or an 11/11 oracle receipt cannot independently
authorize the registry flip.

### Accepted baseline and open boundary work

At evidence baseline `30bc24ecaa4a5ed21cd4fa2455bed81bbce8553a`, a
clean build of the pinned Rust Stark-V commit and the Zig candidate agrees at
these live boundaries:

- `decode`;
- `execution`;
- `per_family_witness_rows` from the production main-trace buffers;
- `program_tuples` through the content-bearing program-root comparison;
- `ordered_accesses` from the production access records;
- `public_values`;
- `memory_roots`;
- `poseidon2_vectors`; and
- `shared_transcript_prefix`.

That historical receipt remains non-passing because these two proof-placement
boundaries were not yet live at its candidate revision:

- `relation_tuples`; and
- `relation_sums`.

The committed candidate now exposes exact production relation tuples and
cumulative per-component accumulators, including explicit fail-closed evidence
for the pinned signed-`MULH` limitation. A self-comparison, a Zig-only digest, a
reconstructed shadow trace, a Python-derived sum, or two equally omitted sides
of a bus is not evidence. Only the next fresh clean-candidate receipt can move
the historical 9/11 result.

An 11/11 receipt closes only the CP-11 shared-boundary parity prerequisite. It
does **not** close CP-04, CP-05, CP-06, CP-07, CP-08, CP-12, or CP-13 and cannot
authorize RF-01 by itself.

### Current implementation snapshot

The current committed implementation baseline is `d3b6b5c0`. It contains:

- exact six-domain lookup schemas and signed counters through `a5b68b28`;
- a generic lookup-table AIR component through `dee14997`;
- a fail-closed relation-evidence exporter through `f63ae1cf`;
- exact variable-width opcode LogUp generation and constraint consumption for
  all sixteen opcode families through `b6ce38de`;
- exact program, sparse-Merkle, and narrow-Poseidon2 AIR integration through
  `cb793596`;
- explicit opcode/table interaction ownership and exact table-source ingestion
  through `788ac426`; and
- canonical component ordering and bounded table-interaction scratch memory
  through `a54333b6`;
- production opcode semantic constraint placement through `52315ef1`;
- proof-integrated clock-update relations through `ffb4013d`;
- exact predecessor chaining across synthetic register and memory clock-gap rows
  through `e454dafb`; and
- central variable-width claims, exact six-table preprocessed tuples and
  multiplicities, committed-buffer relation provenance, canonical component
  assembly, and mirrored prover/verifier interaction consumption through
  `92456745`;
- fail-closed validation of public input/output shape, address arithmetic,
  clocks, roots, and canonical padding through `f7ab4c83`;
- the exact clock-update claim-width contract required by the production
  interaction columns through `bd9d5af4`;
- one canonical witness-layout digest shared by the frontend and live-oracle
  boundary through `3ea0eccd`; and
- build-time, exact source commit and dirty-state identity for the installed
  prove CLI through `30633196`, including paired archive overrides and no
  runtime Git dependency;
- a decomposed schema-v3 RISC-V artifact and staged CLI with bounded hostile
  preflight, validation, exact wire reconstruction, atomic publication,
  independent verification, tamper rejection, and stable visible diagnostics
  through `6f01c105`;
- decomposed infrastructure trace construction under focused modules, with the
  source-debt baseline reduced accordingly, through `980bc3cc`; and
- a symbol-bearing positive release corpus plus explicit undeclared-program and
  sentinel-loop negative fixtures, all pinned to byte-level Rust trace parity,
  through `dd1a8c1a`; and
- a code-owned active-divergence allowlist and mandatory signed-`MULH` limitation
  record that stop candidate and promoted controllers if the ledger row or
  implementation `FIX` marker disappears; and
- bound default-challenge relation tuple v3 and cumulative-sum v2 evidence over
  retained production buffers, including exact candidate, oracle, workload,
  layout, and diagnostic commitment identities, through `9092a3e1`;
- proof preflight and exact rejection coverage through `20b65f1f`, independent
  twelve-domain relation closure through `5e80b6c8`, canonical-zero relation
  padding through `b6a0e34c`, canonical memory-shard geometry through
  `eb62f4b0`, and focused malicious-proof coverage through `ebb1db1d`;
- proof-enforced narrow RV32IM Poseidon rows through `791fb490`, the fixed
  schema-v3 claim transcript through `e4119c3f`, and a live production
  prover/verifier channel tracer with root and relation-draw mutation probes
  through `93ff11e4`;
- an installed strict CLI boundary, phase-neutral prove/verify receipts,
  hostile-artifact coverage, and independent-process verification through
  `6bcca4bd`;
- deterministic diagnostic opcode-request provenance and a complete
  execution-row ledger through `0b5e1364`; and
- clean candidate/oracle receipt enforcement through `b5725ec1`, plus the
  mandatory pinned signed-`MULH` limitation and implementation marker through
  `60a5d93e`;
- bounded state-clock placement and same-family cross-shard claim-order
  rejection through `1a3c16a8` and `91710ca9`;
- production assembly and verifier consumption of every proof-admitted semantic
  and infrastructure component through `75c6d7a7`;
- retained-production-tree algebraic public binding through `62bc000d`, followed
  by 176 exact public/claim mutation rejections over non-empty input and output
  through `5044dc1f`; and
- separate-process prove/verify receipts bound to the complete final transcript
  state, candidate build identity, and executable digest through `283f16df`.
- production-artifact public-value comparison and typed precommit rejection for
  unsupported statement families through `7e0a4cfc`;
- one shared, closed trace-corpus admission and attestation package through
  `dfa48245`;
- a production-witness signed-`MULH` diagnostic, exact pre-backend admission
  test, and normalized CLI evidence through `a974e591`; and
- pinned-Rust diagnostic receipt production and validation through `09ab473e`,
  freezing all eight invalid requests, source digests, proof/report absence, and
  exact no-residue CLI rejection;
- clean automated Native interop evidence routing through `48e30f7a`, preserving
  the tracked archive for explicit formal publication;
- exactly one transitive generic release gate per RISC-V phase through
  `473071a0`, removing two redundant executions of the expensive prover suite
  without removing any owned test, parity, vector, or benchmark gate; and
- full Python discovery plus retained Native and RISC-V CI evidence ownership
  through `515dd87d`; and
- explicit Darwin preparation and execution of the SN-PIE Metal loader
  integration, removing the last local Python discovery skip, through
  `d3b6b5c0`; and
- exact-output retirement in the proof-checkpoint harness through `bae4ff48`,
  proven by two consecutive 12-case, 288-step matrix passes.

The clean local `bae4ff48` controller exercised cross-shard proof placement,
non-vacuous twelve-domain relation closure, the malicious-witness fleet, public
algebraic binding, transcript symmetry, installed schema-v3 CLI prove/verify,
and the full pinned-Rust oracle. That closes the former local implementation and
evidence gaps for CP-00 through CP-12. Their ledger rows remain `IN_PROGRESS`
because the sign-off protocol requires a policy-compatible hosted exhaustive
anchor and fresh exact-candidate challenge; the failed hosted preflight cannot
be replaced by the valid local receipt.

The original hosted failure was a gate portability defect, not a semantic
divergence: `metal-eval-prepare` is deliberately absent from Linux build graphs.
The corrected candidate conditions that preparation on Darwin, makes the Linux
loader contract an executed zero-skip platform assertion, and installs the exact
`zig-out/bin/metal-eval-prepare` product instead of selecting an ignored cache
executable by modification time. Hosted run `29683986860` then established a
second platform fact: GitHub's `macos-14-arm64` runner has the full Xcode Metal
compiler and linker but exposes no `MTLDevice`. Hosted macOS acceptance therefore
compiles and links the exact SN2 composition under the repository's declared
Metal 3.1/macOS 14 policy, executes the installed loader, and accepts only its
explicit fail-closed `No Metal device available` result. A real-device Darwin
CP-13 run remains the owner of successful library loading and all-program PSO
resolution. Neither platform path skips the test. A new hosted exhaustive
anchor and fresh challenge are mandatory after this change. Uncommitted code
and output remain diagnostic by definition.

The pinned Rust and Zig narrow-Poseidon2 witness generators have reached exact
445-column parity for the focused `Call.narrow(1, 2)` row, and the committed
production HashComponent roundtrip passed its focused ReleaseFast suite before
landing. The production precommit mutation matrix at `fef1a0ae` now also changes
typed Merkle, Poseidon2, memory, opcode-lookup, table-value, and multiplicity
cells and requires production proving or verification to reject each change;
it separately proves that an absent RW root is not interchangeable with a
present default root. CP-06 nevertheless remains `IN_PROGRESS` until the clean
candidate exhaustive evidence passes. Focused parity or a green local suite is
never accepted as release evidence by itself.

The committed staged proof artifact is schema v3 and includes single-read
classification, bounded hostile decoding, exact claim reconstruction,
caller-expected statement enforcement, and independent-process verification.
CP-09 and CP-10 nevertheless remain `IN_PROGRESS` until the production claims
stabilize and the candidate and promoted CP-13 receipts exercise that exact wire
format from clean checkouts.

### Required work packages

The implementation must progress through these packages. Independent work may
run in parallel, but integration and promotion obey the dependency order.

| Package | Required delivery | Governing checkpoint | Exit evidence |
| --- | --- | --- | --- |
| WP-01 | Preserve the closed registry and typed candidate-only `--experimental` admission | CP-00 | Negative CLI and registry tests; candidate artifacts remain `not_release_gated` |
| WP-02 | Export and compare production per-family witness rows and ordered accesses | CP-02, CP-03, CP-11 | Live byte/digest equality against the clean pinned Rust binary |
| WP-03 | Export exact relation tuples and cumulative relation sums after every component | CP-05, CP-11 | All 12 domains independently identified; first divergence is localizable; receipt reaches 11/11 |
| WP-04 | Complete exact cross-shard state, program, memory, public, range, bitwise, Merkle, and Poseidon placement | CP-04, CP-05 | One-, two-, and many-shard global cancellation; cryptographic rejection of semantic omission/duplication/tuple/boundary attacks; existing-artifact reorder rejection; deterministic CP-11 provenance |
| WP-05 | Bind each Merkle parent to the exact pinned Poseidon2 child hash and close all memory/table buses | CP-06 | Root/path/hash/table mutations fail in the production verifier; live root vectors agree |
| WP-06 | Bind the complete caller-expected public statement algebraically and in the transcript | CP-07, CP-08 | Per-field mutation rejection, exact transcript trace, and prover/verifier event symmetry |
| WP-07 | Complete the installed CLI prove, independent verify, and benchmark path with a versioned atomic artifact | CP-09, CP-10 | Candidate and promoted phase smoke tests, security-policy rejection tests, and cross-process verification |
| WP-08 | Run the malicious-witness fleet against production commitments and verification | CP-12 | Every named semantic/relation/public/transcript mutation is rejected for the expected invariant |
| WP-09 | Produce a clean, candidate-bound challenge receipt against an unexpired policy-compatible exhaustive bundle with no skipped required tests | CP-13 | Hosted exhaustive anchor and fresh exact-candidate challenge pass |
| WP-10 | Audit core purity and frontend layering, then perform a non-semantic registry promotion | BA-01, BA-02, RF-01 | Audit is green; every blocking divergence is closed; post-promotion producer/challenge pair passes |

The signed `MULH`/`MULHSU` defect recorded in
[divergence-log.md](divergence-log.md) is an inherited pinned-oracle limitation,
not an instruction to repair Stark-V in this repository. Zig must preserve exact
d478f783 witness and relation-export parity, retain the explicit implementation
`FIX(stark-v-signed-mulh)` marker, and fail closed when the affected family
reaches production proving. A later upstream correction requires a new pin and
fresh signed proof-and-verify evidence before the marker or limitation is removed.
The exact d478 diagnostic contains 24 `range_check_8_11` requests and eight
invalid requests: four table indices are out of bounds and four wrap to an
existing u32 index whose generated tuple differs. The receipt derives this split
through the pinned Rust table's production `index` and `gen_columns` paths; it
does not infer validity from the wrapped index alone.

### Gate hierarchy

Every gate is mandatory. Passing a later-looking functional smoke test cannot
compensate for a missing earlier soundness gate.

| Gate | Question answered | Required result | Failure consequence |
| --- | --- | --- | --- |
| G0 Source and structure | Does the candidate build, format, obey dependency direction, and preserve fail-closed policy? | Formatting, pins, source conformance, release contract, and API parity all pass | Do not merge the slice |
| G1 Component correctness | Do honest production rows satisfy constraints and targeted mutations fail on-domain and OODS? | Family, infrastructure, public, and transcript component tests pass with no required skip | Do not claim proof integration |
| G2 Live oracle parity | Does Zig agree with the actual pinned Rust implementation at every shared boundary? | Fresh, candidate-bound 11/11 receipt from a clean Rust checkout | Keep CP-11 non-passing |
| G3 Global proof soundness | Are all accepted semantics and all 12 relation domains committed, constrained, globally cancelled, and verifier-consumed? | Multi-shard honest proofs pass; forgery fleet fails; every blocking divergence is closed | Keep registry closed regardless of G2 |
| G4 Production CLI E2E | Can an installed binary prove, publish atomically, verify independently, enforce policy, and report deterministically? | Candidate and promoted phase smoke matrices pass | Do not advertise production CLI support |
| G5 Clean candidate release | Can one exact clean commit answer a fresh challenge against complete, policy-compatible exhaustive evidence? | Hosted CP-13 exhaustive anchor and fresh exact-candidate challenge pass with zero required skips | RF-01 is forbidden |
| G6 Atomic promotion | Does the registry-only promotion preserve every gate without semantic changes? | Post-promotion producer/challenge pair and bias audit pass | Revert the promotion commit |

The release controller must fail closed when a command is absent, skipped,
times out, produces malformed evidence, names another candidate, uses a dirty
oracle tree, or leaves the candidate tree dirty. A prose claim, static command
list, cached receipt, or agent report cannot override a failed gate.

The controller must parse [divergence-log.md](divergence-log.md) before running
any build, test, smoke, or oracle command. Both `candidate` and `promoted` phases
must stop with a failing machine-readable receipt when a release-blocking row is
active. The allowlist is code-owned and exact; prose such as "allowed with
tests" cannot waive an unlisted divergence. A known defect tied to the pinned
oracle must remain mandatory until the pin changes to a corrected upstream and
the corresponding signed proof-and-verify evidence is renewed.

### Required evidence bundle

CP-13 must produce one machine-readable bundle under
`zig-out/release-evidence/riscv/` containing or digest-binding:

- candidate commit and clean start/end Git status;
- Zig, Rust, Python, operating-system, architecture, and host identity;
- every executed command, start time, duration, exit code, and output digest;
- the pinned Stark-V repository, commit, clean state, locked build command, and
  executable digest;
- the fresh CP-11 oracle receipt, corpus digest, witness-layout digest, and
  per-case result digests;
- the installed CLI artifact, expected-statement digest, independent verify
  result, benchmark report, and tamper-rejection results;
- the CP-12 mutation matrix with the invariant responsible for every rejection;
- the final divergence ledger and bias audit digests; and
- the overall phase (`candidate` or `promoted`) and fail-closed verdict.

Evidence is invalidated by any later change to accepted opcode semantics,
witness layout, relation placement, public statement, transcript, proof format,
security policy, verifier, registry, oracle corpus, or release-gate code.

## Scope

### Required

- The RV32IM instruction subset explicitly accepted by the decoder.
- Runner, witness, AIR, interaction trace, public statement, proof, verifier,
  artifact, registry, and CLI integration.
- Exact cross-shard placement and cancellation for every relation used by an
  accepted instruction or public boundary.
- Exact memory, Merkle, and Poseidon2 semantics required by the pinned statement.
- A reproducible live comparison against the pinned Rust Stark-V source.
- CPU proving as the first honest implementation of the production path.
- Backend selection at an integration boundary, with unsupported RISC-V backend
  combinations rejected explicitly.
- Human-readable help and machine-readable output for applications, prove,
  verify, and benchmark commands.
- Repository conformance and an updated bias audit.

### Deferred

- Cairo and stwo-cairo parity.
- Metal acceleration for the RISC-V lane.
- Streaming or queued RISC-V proof production.
- Segmented or recursive RISC-V execution proofs. The released CLI accepts one
  complete execution only; schema-v3 fixes its segment geometry to ordinal `0`
  of count `1` and must not accept any other geometry or silently treat a
  partial execution as a complete statement.
- RISC-V throughput optimization and autoresearch promotion.
- RV32A atomics, compressed instructions, privileged instructions, floating
  point, vector extensions, system calls, and any other ISA surface not named by
  the release statement.
- Byte-for-byte Stark-V proof compatibility where the allowed lifted-PCS
  divergence makes that impossible. Shared semantics before the PCS boundary
  remain oracle-governed.

Deferred work must be represented as an explicit unsupported capability or a
tracked TODO outside the active proof path. It must not be approximated, silently
ignored, or accepted without constraints.

## Non-negotiable invariants

1. **No premature registry flip.** The Stark-V adapter remains
   `not_release_gated` until CP-00 through CP-13 pass together. Before promotion,
   an explicit `--experimental` CLI path may exercise the production code, but
   every artifact and report it creates remains permanently marked
   `not_release_gated`.
2. **No premature autoresearch enablement.** The RISC-V workload group remains
   disabled until BA-03 passes after adapter release.
3. **No silent instructions.** Every instruction accepted by execution has a
   complete witness, active constraints, and all required relation entries.
4. **No witness-only checks.** A host-side assertion or standalone evaluator does
   not replace an on-domain and out-of-domain AIR constraint.
5. **No unbound public value.** Every public value is both transcript-bound and
   algebraically connected to a committed relation or boundary constraint.
6. **No local-only oracle claim.** Committed Zig vectors cannot substitute for a
   clean build and live execution of the pinned Rust oracle.
7. **No shape-only verification.** Artifact verification must decode the proof,
   reconstruct the statement, and invoke the cryptographic verifier.
8. **No hidden fallback.** A requested unsupported backend fails before proving.
   Its output must never be labelled as proof from a different backend.
9. **No inactive padding contribution.** Padding rows are constrained, disabled,
   and contribute zero to all relevant buses.
10. **No release from a dirty or mixed revision.** Final evidence is produced from
    a clean checkout of one reviewed commit with exact oracle provenance.

## Status vocabulary and evidence rules

Every checkpoint uses exactly one status:

- `NOT_STARTED`: no implementation evidence has been accepted.
- `IN_PROGRESS`: code exists, but one or more acceptance gates remain open.
- `BLOCKED`: a named external dependency prevents progress.
- `FAIL`: the checkpoint was evaluated and one or more requirements failed.
- `PASS`: every acceptance item passed on the same clean candidate commit.

The current implementation branches and uncommitted working-tree slices are
`IN_PROGRESS`, not `PASS`. A checkpoint moves to `PASS` only when its evidence:

- names the candidate Git commit and has an empty
  `git status --porcelain=v1 --untracked-files=all`;
- records every command and exit status;
- comes from the release optimization mode unless a gate explicitly says both;
- contains no skipped required test;
- records the exact Rust source commit, source-tree state, toolchain, build
  command, and executable digest where oracle evidence is required; and
- is reproducible by CI or a repository-owned release-evidence command.

If any accepted opcode, relation, public field, proof message, or artifact field
changes after a checkpoint passes, every dependent checkpoint is invalidated and
must be rerun.

## Working-tree intake at goal creation

The following uncommitted slices existed when this goal was written. They are
implementation input, not accepted release evidence:

- The witness/layout slice reports exact layouts and generated witnesses for 13
  family groups, decomposed trace/witness modules, `404/404` RISC-V runner tests,
  `475/475` prover tests, and `945` full-suite passes with two skips. It still
  requires explicit rejection of system/fence/atomic mappings and schema-driven
  clock/PC indices for explicit-enabler families.
- The M-extension slice reports MUL, MULH, and DIV-family evaluators, exact
  33/41/65-column layouts, and `400/400` RISC-V tests. Those modules explicitly
  declare the current committed trace incompatible and are not placed in the
  production proof.
- The memory-boundary slice reports exact sparse initial/final snapshots, eight
  main columns, sixteen interaction columns, six active boundary constraints,
  root mutation coverage, and `469/469` prover tests. Section 19 Merkle-node
  emission, exact Poseidon2 AIR, and global opcode/public/range cancellation are
  still open.

These counts came from slice-local runs over a changing shared tree. They must be
reconciled, committed in focused increments, and rerun together before any
checkpoint status advances.

## Delivery checkpoints

### CP-00: Fail-closed release boundary

**Initial status:** IN_PROGRESS. The public registry is closed, but unsupported
instructions are not yet rejected at the required preflight boundary.

Required behavior:

- The registry reports `stark-v-rv32im-elf` as `not_release_gated` with a precise
  reason.
- ELF prove and benchmark routes refuse by default while the adapter is staged.
  They may run only with an explicit `--experimental` flag whose spelling and
  effect are covered by CLI tests.
- Verification may cryptographically verify a staged artifact, but it must
  identify the artifact as non-release-gated and must never emit a release
  acceptance receipt for it.
- `riscv_artifact.RELEASE_STATUS` remains `not_release_gated`.
- The autoresearch RISC-V group remains disabled with a non-empty reason.
- Every unsupported instruction is rejected during decode or preflight before
  proof construction.
- `ECALL`, `EBREAK`, `FENCE`, `FENCE.I`, LR/SC, and AMO instructions either have
  complete release-sound AIRs or reject deterministically. For this goal, reject
  them.
- A Metal request for an ELF workload fails as unsupported until a real RISC-V
  Metal proving path exists.

Gate:

- Negative CLI tests cover every staged command and unsupported capability.
- The only staged execution mechanism is the typed `--experimental` flag. It is
  rejected for non-RISC-V workloads, recorded in the report, and cannot change
  the artifact release status.
- Decoder table tests enumerate the accepted subset and all explicit rejections.
- A repository scan finds no second registry or environment flag that can bypass
  the staged status.

### CP-01: Repository boundaries and progressive disclosure

**Initial status:** IN_PROGRESS.

Required structure:

- `src/frontends/riscv` owns execution semantics, witness construction, AIR,
  public statement, and frontend-neutral proof planning.
- It does not import or construct `cpu_scalar`, Metal, or any concrete backend.
- `src/integrations/riscv_cpu` owns CPU selection and assembly of the production
  proving path.
- CLI modules parse and render; they do not implement AIR, transcript, artifact,
  or proof semantics.
- `src/interop/riscv_artifact.zig` owns the versioned external representation.
- Trace schemas, witnesses, semantic AIRs, component placement, interactions, and
  statement binding are separate modules with narrow interfaces.
- Active source files comply with the CONTRIBUTING soft target and 850-line
  manual-review ceiling. Any justified exception is recorded in the conformance
  baseline with an owner and extraction plan.
- No active semantic path is labelled `legacy`, `placeholder`, or `silent`.

Gate:

```sh
zig fmt --check build.zig src tools
python3 scripts/check_source_conformance.py
python3 scripts/check_api_parity.py
python3 scripts/check_riscv_release_contract.py --structure
```

The `--structure` selector is a required CP-13 checker deliverable. Until it
exists and emits named repository-boundary evidence (or `--all` proves the
equivalent sub-check explicitly), CP-01 remains `IN_PROGRESS`.

The gate must report no unexplained finding. Existing baseline entries touched by
this work must shrink or disappear; moving code without improving dependency or
ownership boundaries is not closure.

### CP-02: Decoder and executor parity

**Initial status:** IN_PROGRESS.

Required behavior:

- One typed manifest at `src/frontends/riscv/opcode_manifest.zig` enumerates
  exactly the pinned 45 opcodes with protocol IDs `0...44`, family, encoding,
  witness schema, semantic component, and required relation domains. It is the
  oracle-parity execution set and can be emitted as canonical JSON by a
  repository-owned conformance tool. Proof admission may exclude a documented
  pinned-oracle limitation only when the production prover fails closed before
  commitment and the divergence ledger records that exclusion.
- The manifest covers ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND, ADDI,
  SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI, LB, LH, LW, LBU, LHU, SB, SH,
  SW, BEQ, BNE, BLT, BGE, BLTU, BGEU, JAL, JALR, LUI, AUIPC, MUL, MULH, MULHSU,
  MULHU, DIV, DIVU, REM, and REMU.
- The manifest is equal, not merely a subset, across decoder acceptance, executor
  dispatch, witness dispatch, AIR selector/program tuple, component placement,
  mutation coverage, and CLI preflight. Removing an opcode is a protocol change
  requiring this document and the oracle ledger to change.
- Signed operations, division by zero, signed overflow, branch direction,
  misalignment policy, sub-word loads, and sub-word stores match the pinned
  Stark-V runner.
- `x0` behavior, PC changes, clock changes, register clocks, and memory clocks
  match the oracle exactly.
- Unsupported encodings and unsupported ELF properties fail closed.
- The Stark-V halt sentinel `jal x0, 0` has the pinned termination behavior and is
  not accidentally committed as an ordinary execution row.
- Entry PC, maximum-step exhaustion, and cancellation behavior match the oracle;
  exhaustion cannot publish a partial proof.
- ELF preflight admits only the exact ELF32, little-endian, `EM_RISCV`, segment,
  alignment, address-range, flag, and relocation policy declared by the release
  manifest. Every rejected property has a named diagnostic.

Gate:

- Table-driven edge tests for each opcode.
- Random differential execution with a fixed, logged seed.
- Live pinned-Rust comparison of final registers, PC, clocks, public I/O, ordered
  memory accesses, and committed trace-row digests.
- Mutation tests cover signedness, zero divisors, overflow, alignment, immediate
  decoding, and wrong next-PC behavior.
- Halt, max-step, entry-point, overlapping-segment, truncated-segment,
  out-of-range-address, unsupported-relocation, and unsupported-flag cases are
  compared with the live oracle.

### CP-03: Exact witness and trace schemas

**Initial status:** IN_PROGRESS; an unaccepted working-tree slice exists.

Required behavior:

- Every accepted family uses the exact field order, width, enabler convention,
  and access ordering declared by pinned Stark-V `schema.rs`.
- Access-first schemas and explicit-enabler schemas are represented deliberately;
  a generic component must not assume identical clock or PC columns across them.
- Clock and PC indices for explicit-enabler families are resolved by the schema,
  not by hard-coded legacy offsets.
- Witness builders are split by family and do not duplicate decoder policy.
- Every witness field is range-valid before field conversion.
- Padding rows have a canonical representation and cannot mimic an active row.
- Main-trace relation inputs are committed before relation challenges are drawn.
- Oracle extraction reads the exact production main-trace buffers immediately
  before the PCS commit. A parallel trace adapter or reconstructed row is not
  acceptable evidence.

Gate:

- Exact row vectors for every family against the live Rust oracle.
- Generated-row semantic tests for active and padding rows.
- Boundary coverage includes signed byte and half-word loads, partial stores,
  maximum shifts, comparison sign edges, branch taken/not-taken, all M-extension
  edges, and first/last rows of every component.
- A schema-layout digest is versioned and checked to prevent accidental column
  reorder. It covers the ordered generated column names and counts from pinned
  Rust `*Columns::NAMES`, not only Zig-owned names, and is included in both the
  proof artifact and Rust-oracle receipt.

### CP-04: Complete opcode semantic AIR

**Initial status:** IN_PROGRESS.

Required behavior:

- Every accepted family has active constraints in the real proof component, not
  only a standalone evaluator.
- The same constraints execute through both trace-domain accumulation and the
  verifier's out-of-domain evaluation.
- Enablers are boolean, active-row selectors are constrained, and padding is
  forced inactive.
- State transition constraints bind current PC/clock to next PC/clock.
- Register and memory operands are obtained through relation buses, not trusted
  free witness columns.
- The decoded program tuple `(pc, opcode, value_1, value_2, value_3)` is consumed
  by the opcode component.
- MUL and DIV modules are compatible with the committed component layout before
  placement. The pinned signed-MULH limitation may retain
  `CURRENT_TRACE_COMPATIBLE = false` only while the complete family fails closed
  before commitment and the exact witness/export path remains available for
  oracle parity.
- There are no zero-constraint or silent components for an accepted family.

Gate:

- Honest generated rows evaluate to zero for every family on-domain and OODS.
- At least one focused witness mutation per constrained field class evaluates
  non-zero.
- Semantic adversarial tests mutate production committed columns through a
  test-only malicious-witness hook *before* commitment, then recompute an honest
  proof. Rejection must reach the semantic composition or LogUp check. Flipping
  bytes in an already-created proof only tests commitment integrity and does not
  count as semantic mutation coverage.
- The 45-entry coverage manifest names, per opcode, its selector column, protocol
  ID, constraint set, relation domains, tuple counts and batching, witness
  builder, and production component ID. Tests exercise each entry on-domain and
  OODS.
- M-extension oracle coverage explicitly includes all MULH/MULHSU/MULHU sign
  combinations, `INT_MIN * UINT_MAX`, maximum carries, signed and unsigned
  zero-divisor results, DIV/REM signed overflow, truncation toward zero, remainder
  sign, and `rd` aliasing `rs1`, `rs2`, and `x0`. Each row class has Rust row
  parity; proof-admitted rows also require malicious-witness rejection. The
  pinned signed-MULH family instead requires an exact fail-closed production test.

### CP-05: Cross-shard LogUp placement and global cancellation

**Initial status:** IN_PROGRESS.

All twelve pinned relation domains must be drawn independently in schema order:

1. `registers_state`
2. `memory_access`
3. `program_access`
4. `merkle`
5. `poseidon2`
6. `poseidon2_io`
7. `bitwise`
8. `range_check_20`
9. `range_check_8_11`
10. `range_check_8_8_4`
11. `range_check_8_8`
12. `range_check_m31`

This list is exhaustive. The production proof has exactly these twelve
Stark-V relation domains. A Zig-only thirteenth bus, a private replacement for
one of these buses, or an aggregate bus that permits one domain to offset
another is a protocol divergence and is forbidden. Diagnostics may decompose
the existing aggregate by domain, but they must not add a challenge pair,
interaction column, claim, or verifier obligation to the proof.

Required behavior:

- Each relation uses its own `(z, alpha)` pair and the pinned alpha-power tuple
  combination. Legacy shared relation-ID challenges are absent from the active
  RISC-V proof.
- Every component emits or consumes the exact tuples required by Stark-V.
- Paired fractions use the exact numerator, sign, batching, and denominator.
- Component sums, shard claims, infrastructure tables, and public compensation
  close to zero globally for each relation domain, not only after indiscriminate
  summation across domains.
- Every manifest entry has a nonzero expected request count for every required
  relation when exercised. Signed tuple-multiset counts and digests match the
  live Rust oracle. Two omitted sides of a bus cannot satisfy this gate.
- Every generated interaction column is committed, opened, recurrence-constrained,
  and consumed by the verifier.
- Semantic exact-once execution is AIR-enforced: every accepted execution step
  contributes its required state, program, access, range, bitwise, Merkle, and
  table requests exactly once, and the public endpoints close the same twelve
  relation multisets. Omitting or duplicating a semantic request, changing its
  tuple, or breaking a shard-boundary state transition must fail the
  cryptographic verifier. A host-side provenance ledger is evidence for this
  property, not a substitute for it.
- Shard boundaries are algebraically linked. Tampering with an existing
  artifact's partition, claim ordering, duplication, omission, or manifest
  cannot preserve acceptance because the commitments, claims, transcript, and
  openings no longer agree.
- Physical row-to-shard placement is a deterministic witness-generation and
  CP-11 provenance contract, not an extra semantic relation. For a selected
  legal shard count, the canonical generator emits one stable placement and the
  oracle receipt records request provenance `(execution_row, family,
  relation, request_ordinal)` plus physical component/shard/row location. A
  newly generated proof that consistently commits a different legal row
  permutation but proves the identical relation multisets and public execution
  is semantically equivalent, not a forgery. It may fail canonical-generation
  or Rust byte/digest parity gates without constituting a proof-soundness
  failure.
- Empty components and padding contribute a canonical zero claim.
- The prover and verifier derive identical component order and shard geometry
  from committed statement data.

Gate:

- Cancellation tests for one shard, two shards, many shards, empty components,
  and uneven component sizes. Empty shards are rejected unless the statement
  specification is deliberately changed and oracle-gated.
- Deterministic placement tests over fixed-seed executions and each supported
  shard count; CP-11 compares the resulting physical provenance and cumulative
  component evidence with Rust.
- Proof-level rejection for semantic row/request deletion or duplication,
  boundary PC/clock tampering, tuple tampering, multiplicity tampering,
  denominator substitution, relation-challenge swapping, and mutation of an
  already-created artifact's shard or component order. A fresh, internally
  consistent permutation of semantically interchangeable rows is not listed as
  a forgery.
- A per-relation diagnostic reports all twelve final sums in tests and requires
  each to equal zero independently.
- The production proof retains Stark-V's canonical randomized aggregate. The
  per-relation decomposition is required oracle/test instrumentation, and a
  cross-domain offset attack must still be rejected.
- Inversion of a zero denominator fails closed in generation and verification.
- In canonical component order, the Zig cumulative accumulator after each
  component is compared with the Rust oracle. This component-by-component check
  is the primary parity loop for locating the first divergent placement.

### CP-06: Memory, Merkle, Poseidon2, range, and bitwise soundness

**Initial status:** IN_PROGRESS; the boundary recurrence exists, but the complete
Merkle-node and exact Poseidon2 AIR remain release blockers.

Required behavior:

- Ordered CPU memory events enter the `memory_access` bus with exact address,
  clock, space, and four-byte values.
- Register address-space events, RW-memory events, clock-gap/update rows, and
  public input/output boundary terms share the pinned `memory_access` and range
  domains. No private parallel memory bus is release-valid.
- Initial and final sparse memory snapshots are bound to public roots.
- Boundary traces constrain first/last values, monotonic clocks, multiplicities,
  address transitions, and public compensation.
- Stark-V Section 19 Merkle-node emission/consumption is active.
- Decoded program bytes become the exact sparse program-tree leaves, traverse the
  Section 19 node and Poseidon2 path, and cancel against the mandatory public
  program root.
- Merkle path direction, address bits, siblings, parents, leaf encoding, and root
  placement are constrained.
- The exact pinned Poseidon2 permutation, constants, round schedule, field
  representation, and narrow `poseidon2` Merkle relation are active. The
  `poseidon2_io` challenge pair is still drawn in schema order but its RV32IM
  contribution is canonically zero unless a future pinned statement adds a
  component that explicitly uses it.
- Any generic placeholder hash is removed from the active RISC-V root path.
- Bitwise and all five range-check table domains are populated and constrained;
  opcode components cannot claim a range/bitwise lookup without the matching
  table multiplicity.
- Memory and hashing high-water allocations are bounded and freed on every error
  path.
- Every Merkle permutation binds its two child inputs and lane-0 parent output
  through the pinned narrow `poseidon2` relation; every internal round is
  constrained on-domain and OODS; inactive and padding rows contribute zero.

Gate:

- Live Rust root and node vectors for empty, sparse, adjacent, non-adjacent,
  updated, and restored memory.
- Exact Poseidon2 known-answer and cross-run vectors.
- Proof-level rejection for wrong leaf, sibling, path direction, address bit,
  intermediate node, root, byte, memory clock, access space, table value, and
  multiplicity.
- Multi-shard and repeated-address cases close all relation sums independently.
- Leak and allocator-failure tests cover construction, proof failure, and verify
  failure paths.
- Tests distinguish an absent root from a present default/zero root.

### CP-07: Public statement binding

**Initial status:** IN_PROGRESS.

The public statement must name and constrain at least:

- initial and final PC;
- the pinned execution clock, with initial state at clock `1` and final state at
  `clock + 1`;
- initial and final architectural register values and register clocks required by
  the pinned statement;
- the exact public program root required by the pinned oracle boundary;
- initial and final memory roots;
- public input words, address, and length;
- public output words, addresses, lengths, and clocks required by Stark-V; and
- shard manifest and component geometry needed to reconstruct verification.

This release profile proves one complete, unsegmented execution. Its input and
output endpoints are therefore always the first and last endpoints. Segment
ordinal/role fields are not part of pinned Stark-V `PublicData`; schema v3 keeps
only the fixed artifact geometry `(ordinal=0, count=1)` and rejects every other
value. A future segmented profile requires a separately versioned statement and
release goal; it cannot reuse this single-execution artifact while suppressing
endpoint compensation.

Required behavior:

- Values are serialized canonically, length-delimited where necessary, and mixed
  into the Fiat-Shamir channel in one documented order.
- Each value is also connected to the appropriate state, program, memory,
  Merkle, or I/O relation exactly once. Transcript binding alone is insufficient.
- Input and output memory events cannot be substituted with private events.
- Empty I/O has one canonical representation.
- Length arithmetic and clock arithmetic reject overflow.
- The verifier accepts an expected statement from its caller and compares the
  verified program root, input, and output policy against it. Returning a
  prover-chosen statement extracted from the artifact is not top-level binding.
- No configurable segment role is accepted. The runner always constructs the
  single first-and-last role, the artifact validator enforces `(0, 1)`, and the
  proof always includes both endpoint compensations.

Gate:

- An honest proof roundtrip covers empty and non-empty public I/O.
- A proof-level mutation test rejects each public field independently, including
  every element and every length/address/clock field of variable-length I/O.
- Reordering, truncating, extending, or duplicating I/O is rejected.
- Public LogUp compensation and component claims cancel per relation.
- Mutations cover the root presence bits, `None` versus `Some(default_root)`, the
  final partial input/output word, nonzero unused bytes, output-length word,
  overlapping input/output classification, clock off-by-one, and clock overflow.
- CLI/help/artifact contract tests prove that no configurable segment role or
  partial-segment admission surface exists and reject non-single geometry.

### CP-08: Fiat-Shamir and prover/verifier symmetry

**Initial status:** IN_PROGRESS.

Required behavior:

- The normative proof sequence is: public data; preprocessed commitment root;
  main commitment root; main claim; the allowed Zig shard-manifest extension;
  PoW nonce; twelve relation-pair draws in schema order; interaction claim;
  conditional interaction commitment root; then downstream PCS messages.
- Prover and verifier mix or draw every event in that exact order, with identical
  domain separators, encodings, lengths, and conditional-presence rules.
- Interaction inputs are committed before relation challenges are sampled.
- The Zig shard-manifest mix is an explicit transcript divergence and must have a
  row in `divergence-log.md`. The last byte-identical Rust transcript event is the
  main claim immediately before that extension. Rust challenge values after the
  extension are not claimed equal; their draw count, field encoding, and semantic
  use remain oracle-governed.
- The lifted-PCS divergence is isolated after the shared semantic statement and
  remains covered by its composition self-check.
- PoW difficulty and all security parameters are artifact-versioned protocol
  constants. They cannot vary with build mode, environment, or caller input.

Gate:

- A byte-level channel tracer compares prover and verifier after every mix and
  draw.
- Shared transcript prefixes compare to the live pinned Rust oracle.
- Mutation probes reverse one mix, one draw, one shard order, and one folded-point
  direction; every probe must fail, then be reverted exactly.
- No verifier value is reconstructed from untrusted artifact data without bounds
  and consistency validation.
- Cross-process verification uses a fresh process of the exact immutable
  candidate executable. Prove and verify receipts must agree on the complete
  final transcript-state digest (channel digest plus draw counter), build
  identity, executable SHA-256, and PoW/security policy.

### CP-09: Production CLI and visible behavior

**Initial status:** IN_PROGRESS and intentionally fail-closed.

Required commands:

- `applications`: emits schema-versioned JSON containing adapter name, exact
  status, supported ISA, and available backend.
- `prove --elf`: executes, proves, verifies before publication, and atomically
  writes a versioned proof artifact.
- `verify --expect-statement-digest <hex>`: reads an artifact independently,
  reconstructs and externally binds the statement, and cryptographically
  verifies it.
- `bench --elf`: runs the same production prove/verify path, with explicit warmup
  and sample counts, and writes a validated `riscv_proof_v1` report.

Required behavior:

- ELF path, backend, public input, output artifact, report path, sample count,
  warmup count, and machine-readable output have explicit flags.
- The exact machine-output contract is one JSON object on stdout when
  `--report-out` is absent, or the same schema written atomically to
  `--report-out` when present. `--help` and diagnostics are human-readable;
  diagnostics go to stderr.
- Before RF-01, `prove --elf` and `bench --elf` require `--experimental` and emit
  only `not_release_gated` artifacts/reports. After RF-01 the same path works
  without that flag; the flag becomes an error instead of a hidden mode.
- Help and errors are concise, deterministic, and identify recovery action.
- Partial artifacts are never published. Existing output is not destroyed on a
  failed prove or verify.
- Benchmark samples count only proofs that immediately verify and are
  byte-identical for identical deterministic inputs.
- Reports distinguish execution, witness, proving, verification, and total wall
  time. Throughput names its numerator.
- Verification reads and parses an artifact once, reconstructs all statement and
  interaction claims without producer memory, requires complete proof-wire
  consumption, and invokes the cryptographic verifier in a fresh process.
- The installed CLI rejects schema v2 explicitly after schema v3 lands. It must
  not reinterpret a rejected RISC-V artifact as another native artifact type.

Visible-result gate:

- Snapshot or golden tests cover `--help`, `applications`, successful staged and
  promoted prove, successful verify, benchmark summary, unsupported backend,
  missing/irrelevant `--experimental`, unsupported instruction,
  malformed ELF, malformed input, corrupt artifact, and failed atomic publish.
- Before RF-01, the installed-binary gate exercises the staged path. RF-01's
  mandatory rerun exercises the promoted path and proves that an old staged
  artifact cannot be relabelled as release-gated.
- The CLI builds in `ReleaseFast` and is exercised as the installed binary, not
  only through imported test functions.
- A fresh user can perform one ELF prove/verify using only the README and CLI
  help; no repository-internal path is required in the artifact.

### CP-10: Versioned proof artifact

**Initial status:** IN_PROGRESS and staged.

Required behavior:

- Schema v3 covers proof bytes, statement, public I/O, roots, clocks,
  program identity, shard/component manifest, security parameters, backend,
  Stark-V oracle pin, stwo-zig commit, witness-layout digest, and schema version.
- Opcode shard records bind family, family shard ordinal/count, row offset,
  domain geometry, main-column count, and the exact family-dependent interaction
  batch count. Infrastructure records bind canonical kind/order/geometry and the
  exact claim widths: program `3`, memory `4`, Merkle `3`, Poseidon2 `2`, each of
  the six lookup tables `1`, and clock update `1`. The clock-update claim is the
  cumulative sum of its four interaction columns; an artifact that omits it
  cannot reconstruct the production verifier claim.
- The wire stores each opcode batch claim and each infrastructure component claim
  separately. It never collapses them to a total. Indices are unique, contiguous,
  canonical, and parallel to the committed manifest.
- Segment ordinal/count are explicitly fixed to `0/1`; validation rejects every
  other geometry and first/last roles are therefore derived rather than trusted.
  The expected-statement digest is domain-separated and binds the ELF, input,
  fixed segment geometry, complete manifest, root presence bits, public values,
  and all sequence lengths before their data. A segmented proof requires a
  future schema version and cannot be decoded as schema v3.
- Decoding is bounded, rejects duplicate/unknown security-critical fields, and
  validates all lengths before allocation.
- Resource validation happens before any domain shift or allocation. It applies
  exact producer limits, fixed lookup-table logs, opcode and infrastructure count
  limits, checked aggregate cell/opening budgets, exact PCS profiles, a 256 MiB
  artifact ceiling, and a 128 MiB decoded-proof ceiling.
- Release status is not caller-controlled.
- Verification does not trust a stored `verified` boolean, digest, timing, or
  backend label.
- Encoding is canonical and deterministic.
- Atomic publication uses a temporary file in the destination filesystem,
  flushes as required by the platform contract, renames only after successful
  self-verification, and cleans up every failure path.

Gate:

- Roundtrip, truncation, extension, wrong-version, oversized-length, duplicate,
  corrupt-proof, wrong-statement, wrong-pin, and unknown-security-parameter tests.
- Hostile tests cover v2 rejection, unknown/duplicate keys, noncanonical field
  limbs, malformed and trailing proof bytes, missing/extra/reordered claims,
  shard omission/duplication/reorder, invalid row offsets and geometry, every
  infrastructure kind/width, exact PCS mismatch, provenance/layout mutation, and
  allocation failure at every nested variable-length boundary.
- Cross-process determinism test for identical input and configuration.
- Artifact verify is run in a new process without the prover's in-memory state.
- Release verification requires caller-supplied expected statement values or a
  caller-supplied expected-statement digest. The copy stored inside the artifact
  is not accepted as its own external expectation.

### CP-11: Final pinned Rust oracle

**Initial status:** FAIL in the audit baseline.

Required oracle procedure:

1. Check out Stark-V commit
   `d478f783055aa0d73a93768a433a3c6c31c91d1c` into a clean, isolated directory.
2. Verify `HEAD`, a clean tree, submodule state, and dependency lockfiles.
3. Build the repository's actual runner/AIR code with a recorded Rust toolchain
   and locked dependencies. A duplicated standalone model is not acceptable.
4. Record repository URL, commit, tree digest, toolchain, build command, build
   mode, executable SHA-256, host architecture, and operating system.
5. Run the declared corpus through that executable and the Zig implementation.
6. Compare every shared boundary: decode, execution, per-family witness rows,
   program tuples, ordered accesses, public values, memory roots, Poseidon2
   vectors, relation tuples, relation sums, and shared transcript prefix.
   Relation comparison covers exactly the twelve pinned domains and records the
   canonical generator's physical request provenance. It must not introduce a
   thirteenth Zig relation. Physical provenance drift fails deterministic oracle
   parity; it is reported separately from an AIR-semantic tuple-multiset
   mismatch.
7. Store a machine-readable receipt and make the release gate validate it.

The required producer command is:

```sh
python3 scripts/riscv_release_oracle.py build-and-compare \
  --stark-v-source "$STARK_V_SOURCE" \
  --candidate "$(git rev-parse HEAD)" \
  --receipt-out "zig-out/release-evidence/riscv/oracle-receipt.json"
```

The required validation commands are:

```sh
python3 scripts/riscv_release_oracle.py validate \
  --receipt "zig-out/release-evidence/riscv/oracle-receipt.json"
python3 scripts/riscv_release_evidence.py \
  --receipt "zig-out/release-evidence/riscv/oracle-receipt.json" \
  --candidate "$(git rev-parse HEAD)"
```

Gate:

- The repository owns one non-optional command that performs the procedure or
  validates a freshly generated CI receipt. An operator-supplied opaque binary is
  insufficient.
- Corpus coverage includes every accepted opcode, every semantic edge listed in
  CP-02/03, multi-shard executions, public I/O, and memory/Merkle cases.
- Committed vectors are regenerated only from this procedure and carry the exact
  source and executable identity.
- The receipt schema includes the witness-layout digest, corpus digest, per-case
  result digests, creation time, candidate commit, and every provenance field in
  the procedure. Validation rejects another candidate, stale corpus, stale
  layout, dirty oracle tree, opaque executable, or expired CI evidence.
- Every intentional mismatch is present in [divergence-log.md](divergence-log.md)
  with its last shared boundary, test, and release status.
- There are zero unexplained shared-boundary mismatches.

### CP-12: Adversarial soundness fleet

**Initial status:** IN_PROGRESS.

The release corpus must include active forgery attempts, not only invalid inputs.
At minimum it must try to preserve superficial proof shape while changing:

- one opcode selector or decoded program field;
- one operand, result, sign bit, carry, quotient, remainder, or next PC;
- one register value or register clock;
- one memory value, address, access space, byte enable, or memory clock;
- one range/bitwise lookup value or multiplicity;
- one Merkle leaf, sibling, direction, node, or root;
- one public input/output value, length, address, or clock;
- one component sum, shard claim, existing-artifact shard order, semantic
  request occurrence, or padding row;
- one transcript field, relation draw, commitment, or artifact parameter; and
- one PCS folded-point direction covered by the allowed divergence.

Gate:

- Each mutation reaches the production verifier and is rejected for a
  cryptographic reason, not only a JSON or host assertion unless the mutation is
  intentionally a format error.
- The test names the invariant that rejects it.
- Multi-shard coverage includes at least one mutation that would pass if shard
  sums were checked independently but not globally.
- The suite is deterministic and has no debug-only code path.

### CP-13: Clean-tree release gate and release evidence

**Initial status:** IN_PROGRESS for the final candidate. The controller and both
hosted stages exist; the current-policy anchor and exact-candidate challenge
receipts remain to be generated.

CP-13 has two machine-enforced stages. The **exhaustive anchor producer** runs
the canonical strict plan, the pinned Rust oracle, all adversarial suites, and
the structural/policy gates. It publishes an immutable, content-addressed v3
bundle. The **fresh candidate challenge** has a hard three-minute job timeout;
it builds only the focused static RISC-V product, derives a nonce-bound
cross-shard program, obtains a candidate proof, verifies it in the distinct
anchor verifier process, and compares public and cumulative relation outputs to
the bundled Rust oracle.

Candidate CP-13 passes only when a policy-compatible producer and the candidate
challenge both succeed. The consumer validates the exact producer run ID,
artifact digest, anchor branch head, candidate branch head, workflow identity,
both tree identities, phase, expiry, and release-policy domain. The anchor and
candidate commits may differ outside that policy domain. A local strict pass, an
expired or incompatible bundle, or a successful producer without a fresh
exact-candidate challenge cannot authorize RF-01.

The producer's canonical plan remains owned by:

```sh
python3 scripts/riscv_release_gate.py \
  --strict \
  --phase candidate \
  --stark-v-source "$STARK_V_SOURCE" \
  --candidate "$(git rev-parse HEAD)"
```

`release-gate-strict` transitively owns the ReleaseFast Zig suite, focused and
exhaustive RISC-V suites, API parity, pinned trace vectors, deep tests, Native
interchange, proof checkpoints, strict benchmarks, profiling, freestanding
shims, and release-evidence manifest. The normal product touchpoint runs only
`test-riscv-cpu-product`; the periodic producer additionally runs
`test-riscv-release-exhaustive` through the compatibility alias
`test-riscv-prover`. The controller must not duplicate either owner or run the
base release gate before the strict superset.

Additional requirements:

- The first and last dirty-tree assertions fail on any tracked or untracked,
  non-ignored path.
- Required tests report zero skipped tests.
- On Darwin, full Python discovery compiles `metal-eval-prepare` first so the
  exact installed `zig-out/bin/metal-eval-prepare` product and the checked-in
  SN-PIE composition metallib loader test execute. On non-Darwin hosts the test
  executes the platform-unavailability contract without a skip. The hosted
  macOS Metal-acceptance lane compiles and links a host-compatible copy of the
  exact SN2 composition. Because the GitHub runner exposes no `MTLDevice`, it
  must then execute the installed loader and observe only the exact fail-closed
  no-device diagnostic. A real-device local Darwin CP-13 run must successfully
  load the library and resolve all 279 programs. CP-13 must not hide either path
  as an optional skip or select an executable by ignored cache order. Its
  controller rejects the hosted-only no-device allowance if inherited from the
  environment, and the hosted branch accepts only exit code 1, empty stdout,
  and the complete normalized two-line no-device diagnostic.
- The live oracle procedure from CP-11 is part of strict release evidence, not an
  optional local flag.
- The installed CLI completes a representative multi-shard ELF prove/verify and
  emits a schema-valid benchmark report.
- The release-evidence bundle records commands actually executed, exit codes,
  durations, Git state, compiler versions, oracle receipt, host identity, and
  artifact digests. A static command list is not execution evidence.
- CI repeats the gate from a clean checkout. A local pass alone is insufficient.

## Registry flip checkpoint

### RF-01: Atomic promotion commit

This checkpoint is attempted only after CP-00 through CP-13 are all `PASS` for
the same candidate commit. The promotion is one focused, reviewed commit that:

- changes the adapter registry entry to `release_gated`;
- changes `riscv_artifact.RELEASE_STATUS` to the matching release state;
- makes the already-tested adapter the default path and rejects the obsolete
  `--experimental` flag;
- updates README command examples and support status;
- closes or narrows every release-blocking RISC-V row in
  [divergence-log.md](divergence-log.md);
- updates the bias audit with the exact evidence commit and a GO/NO-GO result;
- adds no new semantic implementation; and
- reruns CP-13 after the flip as a new promoted producer/challenge pair:

```sh
promoted_sha=$(git rev-parse HEAD)
promoted_short=$(git rev-parse --short=12 HEAD)
promoted_branch=riscv-release-promoted-$promoted_short
promoted_ref=refs/heads/$promoted_branch
git push origin main
git push origin "$promoted_sha:$promoted_ref"
gh workflow run ci.yml --ref main \
  -f gate=riscv-produce-promoted \
  -f candidate_sha="$promoted_sha" \
  -f candidate_ref="$promoted_ref"

producer_run_id=<successful-promoted-producer-run-id>
gh workflow run ci.yml --ref main \
  -f gate=riscv-promoted \
  -f candidate_sha="$promoted_sha" \
  -f candidate_ref="$promoted_ref" \
  -f producer_run_id="$producer_run_id"
```

If either post-flip stage fails, revert the promotion commit. Do not patch around
a failing gate by relaxing the registry, artifact, verifier, or CI contract.

## Bias audit and autoresearch checkpoints

Adapter release and autoresearch activation are separate decisions. RF-01 does
not enable research scoring automatically.

### BA-01: Core purity

- `src/core` imports no frontend or concrete backend.
- RISC-V implementation types do not enter generic core APIs.
- RISC-V protocol policy remains in the frontend or interop boundary.
- The source conformance checker encodes these rules and has no unexplained
  exception.

Gate:

```sh
python3 scripts/check_source_conformance.py
python3 scripts/check_riscv_release_contract.py --core-purity
```

The `--core-purity` selector is implemented through `75a74318` and passes on
that revision. It must be rerun by CP-13 against the final candidate and again
against the promoted revision; an earlier passing receipt cannot support RF-01.

The evidence records the candidate commit, complete dependency-edge inventory,
and zero unbaselined core-to-frontend or core-to-concrete-backend imports.

### BA-02: Frontend layering

- RISC-V frontend code depends only on core and backend-neutral prover
  capabilities.
- Concrete CPU construction lives in `src/integrations/riscv_cpu`.
- CLI selection, artifact encoding, and benchmark reporting remain separate from
  AIR and witness logic.
- Touched giant files are decomposed and corresponding source-baseline debt is
  reduced.

Gate:

```sh
python3 scripts/check_riscv_release_contract.py --frontend-layering
```

The `--frontend-layering` selector is implemented through `75a74318` and fails
closed on the current active `silent` paths and oversized frontend files. Those
findings are release blockers, not baselined exceptions. The named selector must
pass independently in CP-13 against the final candidate and promoted revisions.

The checker must reject concrete backend construction/imports, CLI dependencies,
artifact serialization, benchmark reporting, active `legacy`/`placeholder`/
`silent` paths, and unexplained file-size debt inside the frontend.

### BA-03: Autoresearch exercise validity

Before the RISC-V group may change to `enabled: true`:

- the release-gated CLI produces validated `riscv_proof_v1` reports;
- the board contains representative small, wide, and deep workloads;
- a RISC-V-specific held-out generator changes real ELF/program/input dimensions
  instead of irrelevant native flags;
- mechanism telemetry for G3 is implemented and capable of failing;
- judge and promotion workflows are installed under `.github/workflows` and
  required by branch protection;
- per-class anchors and A/A dispersion are measured and frozen on the designated
  judge host;
- editable paths are deliberately scoped so a candidate cannot weaken the
  statement, verifier, workload, oracle, or scoring contract; and
- promotion continues to require verified, deterministic artifacts and exact
  board ownership.

Gate:

```sh
GH_TOKEN="$(gh auth token)" \
  python3 scripts/capture_autoresearch_github_settings.py \
  --repository teddyjfpender/stwo-zig \
  --output "$GITHUB_SETTINGS_RECEIPT"

python3 scripts/check_autoresearch_activation.py \
  --board riscv \
  --github-settings-receipt "$GITHUB_SETTINGS_RECEIPT"
```

The broader staged diagnostic matrix remains deliberately non-promotable. Run
and validate all 32 reviewed proof, execution-only, and expected-rejection rows
with:

```sh
python3 scripts/riscv_benchmark_matrix.py run \
  --stark-v-source "$STARK_V_SOURCE" \
  --artifact-dir zig-out/riscv-matrix-v2 \
  --report-out zig-out/riscv-matrix-v2.json

python3 scripts/riscv_benchmark_matrix.py validate \
  --report zig-out/riscv-matrix-v2.json \
  --require-complete
```

`scripts/check_autoresearch_activation.py` is a required BA-03 deliverable and
does not exist at the accepted baseline. BA-03 therefore remains explicitly
non-passing until the checker, its adversarial tests, and the settings receipt
validation are implemented.

The settings receipt must be obtained through an authenticated repository API,
name the repository and default branch, carry an immutable observation time and
digest, and prove that the required judge/promotion checks are branch-protected.
A checkout-only assertion cannot establish repository settings.

The autoresearch activation commit must be separate from RF-01. Until BA-03
passes, disabled-with-reason is the correct production state.

## Required implementation order

The critical path is deliberately ordered to prevent downstream work from being
built on an unsound statement:

1. Preserve CP-00 fail-closed registry, candidate admission, and unsupported
   capability behavior throughout every intermediate commit.
2. Finish the exact 445-column Poseidon2 schedule inside the production
   HashComponent, remove all debug/bisection code, and restore the full
   `test-riscv-prover` ReleaseFast roundtrip before integrating more consumers.
3. Make exact opcode LogUp the production relation consumer, ingest its committed
   rows into all six table counters, place every table component, and remove the
   transitional opcode buses without duplicating the main tree.
4. Enforce the canonical 27-component interaction claim and public compensation
   across one, two, and many shards; close every one of the twelve relation
   domains independently and in the canonical randomized aggregate. Do not add
   a thirteenth Zig-only bus. Keep canonical physical row placement in witness
   generation and CP-11 provenance while enforcing semantic exact-once requests
   in the AIR.
5. Complete CP-04 and CP-06 semantic, memory, Merkle, Poseidon2, range, bitwise,
   padding, and allocation-failure mutation coverage.
6. Bind the complete public statement and exact transcript sequence under CP-07
   and CP-08.
7. Stabilize the internal claim model used by the committed artifact/CLI wire
   schema v3, then pass its bounded hostile-decoding, independent-verification,
   candidate, and promoted gates under CP-09 and CP-10.
8. Exercise the committed bound `relation_tuples` and cumulative per-component
   `relation_sums` over the full release corpus; obtain a fresh clean,
   candidate-bound 11/11 pinned-Rust receipt under CP-11.
9. Run the complete production adversarial fleet under CP-12, including every
   shard, claim, public-field, transcript, Merkle, table, and artifact mutation.
10. Preserve exact signed `MULH`/`MULHSU` witness/export parity with the pinned
    oracle, retain the explicit `FIX(stark-v-signed-mulh)` record, and keep the
    affected production proving path fail closed. Do not make an upstream Rust
    correction a prerequisite for this repository's adapter release.
11. Remove active source-debt blockers and pass CP-01, BA-01, and BA-02.
12. Produce clean-tree candidate evidence under CP-13 with every prior checkpoint
    passing on the same commit.
13. Perform RF-01 as a non-semantic promotion commit and rerun CP-13 in promoted
    mode.
14. Leave BA-03 disabled unless its independent activation gates
   are also complete.

Performance tuning begins only after RF-01. Measurement instrumentation may be
added earlier, but no MHz result from the staged lane is a release or optimization
claim.

## Progress ledger

This table is updated only with accepted evidence. A row with uncommitted code
remains `IN_PROGRESS`.

| Checkpoint | Status | Evidence baseline | Required closure evidence |
| --- | --- | --- | --- |
| CP-00 Fail closed | IN_PROGRESS | Typed candidate-only `--experimental`, closed registry, exact proof preflight, and rejection corpus ownership are committed through `20b65f1f`; the release controller reads the typed capability owner and fails closed on registry drift through `30ecc5c7` | Preserve closed release and autoresearch registries; obtain the candidate producer/challenge evidence |
| CP-01 Structure | IN_PROGRESS | Infrastructure trace construction is decomposed through `980bc3cc`; the prover frontend is decomposed through `ca3c3d56`; focused product and periodic exhaustive test ownership are separated through `eaf4f5ff`; source conformance passes with no new debt | Preserve the clean mechanical result and touched-source-debt reduction in final candidate evidence |
| CP-02 Execute | IN_PROGRESS | Live decode and execution boundaries pass at `30bc24ec`; the release corpus executes every protocol opcode ID `0...44`, including signed/unsigned branch edges, through `994107ad`; the typed manifest ties all 45 admitted opcodes to encoding, witness, semantics, relation, and proof ownership through `387249f4` | Obtain fresh clean oracle evidence under the documented signed-`MULH` limitation |
| CP-03 Witness | IN_PROGRESS | Production-buffer per-family rows and ordered accesses pass live Rust comparison at `30bc24ec`; canonical production layout and provenance are committed; the 45-entry manifest is mechanically checked against live witness schemas and relation placement through `387249f4` | Bind the current layout/provenance digests into fresh final-candidate evidence |
| CP-04 Semantic AIR | IN_PROGRESS | Production opcode semantic placement is committed through `52315ef1`; every proof-admitted family is assembled on-domain/OODS through `75c6d7a7`; signed-`MULH` admission fails closed; the public/claim matrix reaches 176 exact verifier rejections; complete admitted-opcode ownership is checked through `387249f4` | Preserve this coverage and obtain fresh Rust evidence on the clean candidate |
| CP-05 Cross-shard LogUp | IN_PROGRESS | Exact batching/constraints, ownership, order, clock relations, and central 27-component assembly are committed through `92456745`; twelve domains close independently through `5e80b6c8`; canonical-zero padding lands through `b6a0e34c`; state-clock wraparound and existing-artifact same-family claim swaps are rejected through `1a3c16a8` and `91710ca9` | Preserve one-, two-, and many-shard proof evidence and obtain full-corpus cumulative and deterministic-provenance Rust parity on the clean candidate |
| CP-06 Memory/hash/tables | IN_PROGRESS | Live roots, exact lookup tables, exact Rust/Zig 445-column parity, production HashComponent integration, six-table placement, and memory range sources are committed through `92456745`; padding multiplicities, canonical memory geometry, narrow Poseidon mode, and production verifier assembly advance through `75c6d7a7`; the typed precommit matrix rejects 13 committed-witness mutation classes and distinguishes absent from present-default RW roots through `fef1a0ae` | Preserve the mutation matrix and complete memory closure evidence in the clean candidate exhaustive anchor |
| CP-07 Public I/O | IN_PROGRESS | Public values pass live; fail-closed shape/address/clock/root/padding validation is committed through `f7ab4c83`; the program and optional RW roots close through committed Merkle/Poseidon rows; a nonempty nine-byte partial-word input proves/verifies in Zig through `1cfcd6dd`; exact pinned-Rust parity for its public data, 27 component prefixes, 12 relation domains, tuple streams, and nonzero public compensation is machine-gated through `3dc744ac`; 176 verifier mutations cover every public field and I/O shape | Preserve the single-execution `(0,1)` artifact restriction and rerun the full evidence on the clean candidate |
| CP-08 Transcript | IN_PROGRESS | Shared public-data prefix passes at `88870d2c`; fixed schema-v3 claim mixing lands through `e4119c3f`; the full production event trace and mutation probes land through `93ff11e4`; separate-process receipts bind final digest plus draw count and executable/build identity through `283f16df` | Rerun the transcript-state receipt and full mutation evidence on the clean candidate |
| CP-09 CLI | IN_PROGRESS | Installed strict candidate prove/verify boundary and independent-process verification are committed through `6bcca4bd`; complete transcript-state receipts land through `283f16df`; the adapter remains staged | Exercise the full installed multi-shard prove/verify/benchmark matrix and post-RF-01 promoted matrix from clean checkouts |
| CP-10 Artifact | IN_PROGRESS | Bounded schema v3, atomic path, owned statement, external expected digest, hostile preflight, exact wire reconstruction, provenance validation, security-policy checks, and occupied-output preservation are committed through `6bcca4bd` | Bind the final exact shard/infra claims, complete hostile-decoding and DoS coverage, then pass candidate/promoted clean evidence |
| CP-11 Rust oracle | IN_PROGRESS | Clean local `bae4ff48` receipt passes all 11 boundaries, exactly 12 relation domains, canonical physical provenance, and the pinned signed-`MULH` limitation; the deterministic nonempty partial-word case is an exact Rust/Zig machine gate through `3dc744ac` | Reproduce the fresh 11/11 receipt on the next exact candidate in hosted CP-13 and preserve it after RF-01 |
| CP-12 Adversarial fleet | IN_PROGRESS | Padding, memory geometry, narrow Poseidon, transcript, CLI, artifact, and cross-shard mutations advance through `91710ca9` and `93ff11e4`; the production public/claim matrix rejects 176 attempts; all previously orphaned malicious-witness, MULH-limitation, transcript, and full-prover suites are owned by the exhaustive target through `eaf4f5ff`; the typed precommit matrix at `fef1a0ae` requires each of 13 witness mutation classes to fail in production proving or verification without claiming that every invalid witness can first be proved | Preserve the complete fleet in the final hosted exhaustive anchor and fresh challenge |
| CP-13 Release gate | IN_PROGRESS | The typed controller fix is committed through `30ecc5c7`; focused and exhaustive ownership is split through `eaf4f5ff`; focused product and exhaustive diagnostic gates pass locally in 85.5 and 343.8 seconds; the hosted producer has a 90-minute fail-safe and the consumer a hard three-minute timeout | Produce the initial current-policy hosted anchor, pass a fresh exact-candidate challenge against it, then repeat the producer/challenge pair after RF-01 changes the release policy |
| RF-01 Registry flip | NOT_STARTED | None | Atomic promotion commit and post-flip gate |
| BA-01 Core purity | IN_PROGRESS | Named mechanical checker passes in clean local `bae4ff48` CP-13 evidence | Reproduce it in the hosted candidate and promoted exhaustive anchors |
| BA-02 Frontend layering | IN_PROGRESS | The active `silent` path is removed; infrastructure and prover ownership are decomposed through `ca3c3d56`; the named selector passes in clean local `bae4ff48` CP-13 evidence | Reproduce the selector and no-drift proof in the hosted candidate and promoted exhaustive anchors |
| BA-03 Autoresearch | FAIL | Correctly disabled at `c0720031` | Keep disabled, or satisfy independent activation gates |

## Definition of done

This goal is complete only when:

- CP-00 through CP-13 pass on one clean candidate revision;
- RF-01 is committed and its post-flip exhaustive producer and fresh challenge
  pass in hosted CI;
- BA-01 and BA-02 pass on the promoted revision;
- BA-03 is either independently passed in a later commit or remains explicitly
  disabled with its reason intact;
- every release-blocking divergence is closed;
- the pinned Rust Stark-V oracle accepts every declared shared-boundary parity
  check;
- the installed CLI proves and independently verifies a supported RV32IM ELF;
- every unsupported operation and backend fails closed; and
- the final bias audit names the evidence, residual allowed divergence, and GO
  decision without qualification.

Anything less is progress toward the goal, not completion of the goal.
