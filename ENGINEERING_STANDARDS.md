# Engineering Standards

Status: **normative**. This document is the contribution specification for the
repository. Every contributor, human or agent, MUST follow its collaboration,
boundary, evidence and review rules. Automation is only one enforcement method;
an absent CI check does not authorize a new violation. Existing rollout gaps
remain explicit in section 11 and MUST NOT be presented as completed work.

[CONTRIBUTING.md](CONTRIBUTING.md) holds the domain engineering practice (Zig,
memory, SIMD, GPU, cryptographic parity, benchmarking) that implements this
standard. Where the two disagree, this document wins and CONTRIBUTING.md is
corrected.

Source: the maintainer-supplied **Engineering Collaboration.docx**
(SHA-256 `066a32ddc38e7325648ae5745838bd5edf4a624f2543098447c6482af5b880d1`).
This standard makes that document's collaboration model operational for this
repository, together with the maintainer's delivery rules. The Word document
need not be installed or available to contribute; the requirements are here.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

## 1. Enforcement status

Each rule names how it is checked:

| Mark | Meaning |
| --- | --- |
| **Enforced** | A gate in this repository fails the change today. |
| **Review** | Checked by the reviewer against the checklist in section 9; no automated gate yet. |
| **Phase N** | Rollout work in Phase N of [the restructure plan](design/repository/restructure-plan.md). Review applies now; automated coverage is incomplete and must not be claimed. |

The phases are: **Phase 0** trunk and gates; **Phase 1** thin waist;
**Phase 2** complexity paydown; **Phase 3** evidence out, process in.
Section 11 lists the current gaps honestly. A gap is not a waiver.
Any exception MUST name the invariant owner, exact affected scope, reason,
expiry or removal condition, retained safety checks and rollback in a GitHub
issue. A temporary exception does not exempt unrelated code or silently change
a gate. An approved follow-up is not evidence that the deferred work passed.

## 2. Model of collaboration

The goal is maximum parallel velocity without a complexity explosion.

Contributors collaborate the way independent engineering teams collaborate on
one stack: each contributor, and each contributor's tooling, is free to work
however it likes *inside* a boundary, and no one depends on anyone else's inner
process. What all contributors MUST agree on is the invariants at the
boundaries.

- The **unit of collaboration** is an API contract plus its executable
  specification. Work starts from a GitHub issue that states both.
- The **unit of progress** is a thin vertical slice that integrates
  continuously: contract, implementation, tests and evidence for one behavior,
  merged as a whole.

Three principles govern every change:

1. **No complexity leaks.** A boundary exposes only what its contract states.
2. **Complexity is debt** owed to current collaborators and to everyone who
   must later learn the system. It is spent deliberately and paid back.
3. **No cross-boundary leaks.** Representation, policy and concurrency details
   stay behind the boundary that owns them.

Contributors MAY choose their own tooling and internal process. They MUST NOT
require another contributor to understand that process, a private representation
or an undeclared configuration convention to use a package. The collaboration
surface is the declared contract and its executable specification.

The invariant owner decides changes to that surface. A contributor or agent
MUST NOT infer approval from silence, a passing implementation test, ownership
of a product roadmap, or the ability to edit a contract file. Delegation must be
explicit in the issue; a delegated decision must identify itself as such.

People own decomposition, contract design and review for correctness, security
and taste. Agents implement, exercise edge cases and refactor within the agreed
boundary. Generated code, confident explanations and agreement between agents
do not replace contract tests, independent verification or human accountability.

## 3. Thin-waist architecture

The repository has a narrow, boring, stable core interface with fast-moving
work on either side of it.

- **The waist** (stable): protocol types and laws, backend capability
  contracts, the prover API and interchange formats. Today these are the
  packages with layer `protocol`, `contract`, `api` and `interchange`
  (for example `src/waist/core`, `src/waist/backend`, `src/waist/prover_api`,
  `src/waist/proof_wire`).
- **Above the waist** (may churn): frontends, integrations and products —
  Cairo PIE proving, RISC-V Ethereum block proving, OP Stack, Tensor, SM83.
- **Below the waist** (may churn): backends and performance work — CPU, Metal,
  CUDA, kernels, residency, scheduling.

Rules:

- **TW-1.** Changes above or below the waist MUST NOT require a change to the
  waist. A change that does is a contract change (section 6). *Phase 1.*
- **TW-2.** Package dependencies MUST follow the declared layer graph
  (`protocol` depends on nothing; `contract`/`api`/`interchange` on `protocol`;
  `engine` on the waist; `frontend` and `backend` on the waist and `engine`;
  `integration` composes). Checked by `scripts/repo/check_package_workspace.py`
  (`zig build package-workspace`). *Enforced*: the `Package workspace contracts`
  PR check is required following PR #339. Its zero-finding result covers the
  checker's declared workspace; it does not certify every legacy placement or
  undeclared product boundary elsewhere in the repository.
- **TW-3.** Generic prover code MUST NOT name or branch on a concrete backend,
  and backend runtime details (Objective-C, MSL, CUDA) MUST NOT cross into
  waist types. *Review*; import edges checked by TW-2.

## 4. Boundaries are contracts

A boundary is not a document. It is a schema, a set of tests and a
compatibility rule. Each of the 27 packages under `src/` declares its boundary
in `package.contract.json` (schema `stwo-zig-package-contract-v2`: `package`,
`version`, `layer`, `owner`, `public_modules`, `dependencies`,
`injected_modules`, `api_surface`, `api_contract`, `ci`) and its build closure
in its own `build.zig.zon`.

**Anything not covered by a package's contract suite does not exist to its
consumers.** Consumers MUST NOT depend on undeclared symbols, file layout,
side effects or timing; owners MAY change those freely.

Every boundary MUST have:

| ID | Requirement | How it is checked |
| --- | --- | --- |
| BC-1 | **Schema / types.** The public module and exact top-level API are declared (`public_modules`, `api_surface`). | *Enforced* by the required workspace check; public declarations must match `api_surface`. |
| BC-2 | **Error model.** Each public operation documents which errors it returns, when, and whether a retry is safe; error sets are part of the API. Where a boundary is a process or wire boundary, errors carry stable codes; retry, idempotency and timeout semantics are stated. | *Phase 1.* No stable error-code model exists today. |
| BC-3 | **Executable invariants.** Signature and invariant tests are listed in `api_contract` and resolve to exactly one test reachable from the public module. | *Enforced* for declaration/reachability by the required workspace check; actual behavior still requires execution of the owning suite. |
| BC-4 | **Consumer-driven contract tests.** Each consumer of a waist package owns tests, run in the provider's lane, that pin the behavior it relies on. A failing CDC test means a collaboration rule was broken. | *Phase 1.* Not present today. |
| BC-5 | **Property tests** for core invariants (field laws, transcript determinism, serialization round-trips, fold/commit equivalence), with fixed seeds. | *Phase 2.* Coverage is sparse today. |
| BC-6 | **Golden vectors** for trusted behavior: proofs and transcripts that MUST stay byte-identical unless the protocol revision changes. | *Enforced*: committed vectors under `vectors/`, `zig build vectors`, Rust-oracle parity (`conformance/upstream.md`), and `scripts/rv64_gate.sh` (frozen D2 golden fingerprints, fresh CPU receivers, semantic negative corpus). |
| BC-7 | **Explicit compatibility policy.** `version` follows semantic versioning: a removed or changed public symbol or behavior is a major bump; an addition is a minor bump. | *Phase 1.* All packages are at `0.1.0` and versions are not yet checked against API diffs. |
| BC-8 | **Named owner.** `owner` names the invariant owner role (section 6) for the boundary. | *Enforced* for declared roles and exact CODEOWNERS routes by the workspace check. Review routing does not itself grant an RFC decision or configure branch protection. |

Rules for contributors:

- **BC-R1.** Anyone MAY improve an implementation as long as its contract
  suites stay green. *Enforced* by the package `ci` command and
  `scripts/dev_test.py`.
- **BC-R2.** A change to `api_surface`, `public_modules`, `dependencies`,
  `layer`, a golden vector, or a documented error or compatibility rule is a
  contract change and MUST follow section 6. *Review*; *Phase 0* via
  CODEOWNERS-style ownership of contract files.
- **BC-R3.** Proof checks, pins, ceilings, test discovery and rejection
  classification MUST NOT be relaxed to obtain a passing result. *Review*;
  golden and corpus gates *enforced*.

Contract coverage MUST exercise the behavior consumers actually use, including
failure and cleanup paths. A schema parser, declaration search or compile-only
test MUST NOT be reported as executed consumer behavior. Stable error codes at
process/wire boundaries, retry and idempotency rules, timeout ownership and
failure timing belong to the contract. A new side effect or timing guarantee
is a contract change even if a function signature stays the same.

## 5. Repository structure

- **RS-1. No loose source files in high-level directories.** Every directory
  under `src/`, `tests/` and `tools/` is either a *package* (it has
  `package.contract.json`, `build.zig.zon` and one declared root module) or a
  *container of packages* that holds no source of its own. Test roots, CLIs and
  code generators live inside the package that owns what they exercise.
  *Phase 0* (structure checks in the package-workspace audit). Remaining legacy
  and product-placement work is tracked in the restructure plan; a passing
  workspace audit MUST NOT be used as a claim that all such work is complete.
- **RS-2. Relative imports MUST NOT enter another package.** Cross-package use
  goes through the declared module name. *Enforced* by
  `check_package_workspace.py` (current violations are tracked by RS-1).
- **RS-3. Product-line separation.** A product line depends on its frontend,
  the backends it targets and the waist. It MUST NOT depend on another product
  line. Code that two product lines need enters the waist (or a shared engine
  package) only through the API change protocol, never by cross-import or
  copy. *Enforced* for package edges by TW-2; product-to-product edges
  *Phase 1*.
- **RS-4. Where things belong.**
  - Source: inside its owning package under `src/` (or a tool crate under
    `tools/`).
  - Tests: next to the code, or in the package's declared test root.
  - Fixtures and golden vectors: `vectors/`, content-addressed or hash-pinned,
    with provenance. Large binary fixtures need a reason, hash and retention
    policy.
  - Machine-read policy and pins: `conformance/`.
  - Design notes and decisions: `design/`; package READMEs carry the public
    contract summary.
  - Evidence and receipts (benchmark runs, gate receipts, captured source
    snapshots): out of the source tree. New receipts MUST NOT add source copies
    under `vectors/reports/`. *Phase 3*.
- **RS-5. Entry points.** The developer entry points are
  `scripts/dev_test.py` (inner loop), `scripts/rv64_gate.sh` (before every
  push) and `scripts/rv64_m8_bench15.py` (regression basket), plus
  `scripts/ci.py` for the hosted gate. Contributors MUST extend these and their
  shared libraries and MUST NOT add another top-level launcher. *Enforced*:
  `scripts/tests/test_script_reachability.py` and the productionisation budget
  (`scripts_added_budget: 0`).

## 6. API change protocol

Contracts are the collaboration surface, so changing them is rare and
disciplined. Decisions belong to **invariant owners**: the role named in a
package's `owner` field, accountable for the invariants that constrain
collaboration across that boundary (not for product priorities).

When a contract change is believed necessary:

1. **Open an RFC issue** using the *Contract change (RFC)* template: invariant
   owner, affected contract, proposed change, compatibility and versioning
   impact, contract tests to add first, deprecation plan.
2. **Discuss** in the issue and the team's discussion channel. Discussion
   outside the issue is not binding until summarized there.
3. **Record the decision** (approved, rejected, deferred, with reasons) as a
   comment on the issue. The invariant owner, or a delegate, records it.
4. **If approved**, implement in this order:
   1. add or modify the contract tests (and CDC tests of affected consumers);
   2. implement the change backward-compatibly, or add a versioned interface
      next to the old one;
   3. bump `version` per BC-7;
   4. deprecate the old form with a dated removal plan, then remove it in a
      later change once no consumer uses it.

Use the team's discussion channel for discussion when applicable, and copy the
decision back to the issue. An agent sends messages to other people only when
explicitly authorized; this rule is not permission to post automatically.
Record affected consumers, migration order and the test evidence for removal.
The default is compatibility first, not a simultaneous break that forces every
consumer to follow a moving implementation.

Rules:

- **AC-1.** A PR that changes a contract (BC-R2) MUST link an approved RFC
  issue. *Review* (PR template); *Phase 0* blocking.
- **AC-2.** A contract MUST NOT be broken and fixed in the same change unless
  all its consumers are updated in that change and the RFC says so. *Review*.
- **AC-3.** Protocol revisions that change proof bytes MUST bump the protocol
  revision and regenerate golden vectors from the pinned oracle in the same
  change. *Enforced* by vector and parity gates.

## 7. Complexity budget

Complexity is budgeted and enforced like a performance budget: a change that
spends budget without payoff is rejected.

**Repository budget.** `conformance/rv64-productionisation-budget.json` is the
repository-wide subtraction budget. Its default is zero net code growth, zero
new flags and zero new top-level scripts; each entry records a change's
`net_code_budget`, flag and script budgets and, for positive growth, a
`positive_growth_justification`. `STWO_RV64_*` environment flags are declared
in `conformance/rv64-flags.json` with owner, default and status; an undeclared
flag fails the source conformance check. Other flag families are not yet
registered (*Phase 2*). *Enforced* (`zig build source-conformance`,
`scripts/repo/check_source_conformance.py`); per-PR budget comparison *Phase 0*.

**Module budget.** Track public surface (`api_surface` size), dependency count
and allowed dependency classes, cyclomatic complexity on hot paths, and
allocation counts and latency ceilings where relevant. File-size and nesting
ratchets are useful proxies; they do not prove cyclomatic, allocation or latency
bounds. Surface and dependencies are *enforced* as exact ledgers. Complete
per-package numeric and runtime-budget enforcement remains rollout work;
measurement and owner review are required when spending complexity now.

**CB-1.** Set a subtraction budget before editing. Every commit and PR MUST
report the measured delta in this format:

```text
Complexity budget
  code lines:  +A / -R / net N        (source and tests; generated counted separately)
  flags:       +a / -r / live L       (from conformance/rv64-flags.json)
  scripts:     +s / -t
  separately:  docs +/-, config +/-, receipts/vectors +/-
  justification (required if net > 0 or flags/scripts added): <invariant or owner>
```

- Moves and renames are not removals; a moved line counts as neither added nor
  removed. *Review*.
- **CB-2.** Positive net code growth, a new flag or a new script MUST state
  the invariant it protects or the owner it makes explicit, plus:
  a measurable benefit (latency, throughput, memory, developer experience,
  safety); a containment argument (why it does not leak across the boundary);
  and a rollback plan or flag if it is risky. *Review*; budget entry
  *enforced* where the budget file covers the change.
- **CB-3.** "Clean it up later" is not a plan. A slice is finished when its
  temporary code, flags and exploratory exports are gone. Known follow-up work
  goes in a linked issue, not in the code. *Review*.
- **CB-4.** Do not build a permanent ABI, schema or configuration layer merely
  to preserve controls already scheduled for retirement. Delete obsolete
  behavior with its exclusively retired tests; retain tests for live behavior.
  Any temporary exception follows section 1 and keeps the remaining check
  strict. A new flag needs an owner, default, status and expiry/removal plan;
  it is not the default rollback mechanism for every change. *Review*.

## 8. Way of working

- **WW-1. Executable specification first.** Feature work starts from an issue
  (the *Feature / vertical slice* template) that states the contract and the
  failing tests or vectors that define done. *Review*.
- **WW-2. Trunk-based integration.** Start a short-lived branch from current
  `main`, one coherent item or mechanical sweep per PR; merge when its stated
  gates pass. Long-lived integration stacks are not a delivery mechanism.
  Push after each green slice and keep at most two unpushed commits. Preserve
  necessary incomplete work on an explicitly unqualified backup ref, with its
  missing gates; a backup is not merge evidence. *Review*.
- **WW-3. Tests are the arbiter.** Agents and people do not argue
  correctness; the contract suites, golden vectors and verifiers decide.
  For correctness work, reproduce the failure and protect the invariant before
  repairing it. Mechanical moves/deletions use existing ownership, discovery,
  CPU and byte-identity gates; they do not require invented per-line evidence.
  RED → GREEN → REFACTOR describes the feedback loop, not a reason to add tests
  that only mirror an implementation. *Review*.
- **WW-4. Division of labor.** People own decomposition, contract design and
  review for correctness, security and taste. Agents implement, enumerate edge
  cases and refactor *within* a boundary. An agent MUST NOT change a contract
  without an approved RFC (section 6). *Review*.
- **WW-5. Gates before push.** Run `scripts/dev_test.py` while editing and
  `scripts/rv64_gate.sh` before every push that touches the RV64 path; run the
  regression basket (`scripts/rv64_m8_bench15.py`) for performance claims.
  Local gate receipts are the merge evidence where hosted CI cannot run a lane.
  *Enforced* by the pre-push hook for touched products; *Review* for receipts.
- **WW-6. Bound execution.** Heavy compiler or complete-block work MUST NOT
  run on the laptop. Use hosted CPU CI or the qualified host. Small local
  checks require `memguard` or an equivalent enforced memory cap; `-j1` alone
  is not a memory limit. Freeze source for builds/measurements and use the
  shared build lock; hardware harnesses own the GPU lock. Hardware spending
  and GPU execution remain subject to the user's authorization. *Review*.
- **WW-7. Stop and hand over.** An explicit stop/pause ends new work
  immediately. If preservation is requested, limit it to committing/pushing
  existing changes and recording exact heads, receipts, failures and next
  gates. Stop owned workers/measurements, verify their terminal state, and
  disclose any ordinary CI left running. Do not add fixes during wrap-up or
  resume a paused campaign without a new instruction. *Review*.
- **WW-8. Set the merge bar.** State affected suites, CPU acceptance, selected
  frozen byte-identity reference and required negative corpus before a PR
  grows. Check the final head and keep scope fixed. Infrastructure timeouts
  may be repaired without changing commands, floors, thresholds or audits.
  Classify inherited failures against an exact baseline and record any
  owner-approved follow-up; do not suppress a correctness failure or describe
  a partially green workflow as wholly green. *Review*.

## 9. Review checklist: no complexity leaks

Reviewers (and their agents) MUST answer each question for every PR. A "yes"
means: pull it back behind the boundary, or make it a first-class contract
concept with tests (and, if it changes a waist contract, an RFC).

General:

- [ ] Does the change expose new types, errors or configuration knobs that
      consumers must now understand?
- [ ] Does it add optional parameters that are really implementation escape
      hatches?
- [ ] Does it add a flag, script or entry point? Is it in the budget report?

Boundary-specific (apply those that fit the change):

- [ ] Does it leak **concurrency semantics** — locks, ordering, queue or
      stream behavior, caching — into an API?
- [ ] Does it leak **representation** — device residency, buffer layout,
      proof or transcript internals, serialization details, storage keys?
- [ ] Does it leak **policy** — timeouts, retries, budgets, fallback,
      backend selection — without a stable abstraction?
- [ ] Does a product line now reach into another product line or a backend's
      internals?
- [ ] Does anything rely on behavior not covered by the provider's contract
      suite?

Before approving, verify the issue and any RFC decision, affected consumers,
error/compatibility semantics, measured benefit and containment for budget
growth, rollback/removal plan, and the exact scope of executed evidence.
Reviewers MUST request changes when a requirement is violated; fluent prose or
an unrelated green lane is not a substitute for these checks.

## 10. Determinism, reproducibility and security

Reproducibility is an invariant, not a convenience:

- **DR-1.** Builds are self-contained: Zig dependencies are path-local or
  content-hash pinned in `build.zig.zon`. *Enforced* by the Zig build.
- **DR-2.** Toolchains are pinned in-repo (Zig, Rust, Python, Lean). *Phase 0*:
  CI pins Zig `0.15.2` in workflows, but no toolchain pin file exists.
- **DR-3.** One command runs the whole suite for a change: `python3 scripts/ci.py`
  (`--fast` for the compile-free subset). *Enforced* by hosted CI and hooks.
- **DR-4.** Randomness in tests is seeded and the seed is printed on failure.
  *Review*; *Phase 2* gate.
- **DR-5.** No hidden machine state: results depend only on pinned source,
  binaries, runtime and workload, recorded in the receipt. *Enforced* for RV64
  gate receipts; *Review* elsewhere.
- **DR-6.** Report PASS, FAIL, UNRUN, CANCELLED or DEFERRED for each required
  gate, with the exact source, command, environment and receipt. Compile-only,
  host/fake-device, hardware correctness, physical memory and qualified timing
  are distinct evidence. Preserve negative results. Verify proof bytes and
  independent acceptance before trusting timing; component tests and warm
  timings do not qualify a complete production path or a default flip. *Review*.

Agents increase supply-chain and leakage risk, so these gates run
automatically ([`.github/workflows/standards.yml`](.github/workflows/standards.yml)):

- **SL-1. Secret scanning.** Every PR and push to `main` scans the commits it
  introduces with a pinned, checksum-verified gitleaks
  (policy: `.github/gitleaks.toml`). *Enforced* from the workflow's merge. A
  leaked secret is rotated, not allowlisted.
- **SL-2. Dependency and licence policy.** PRs that add or change Cargo,
  Python or other manifest-tracked dependencies are checked for high-severity
  advisories and for licences incompatible with Apache-2.0 distribution.
  *Enforced* from the workflow's merge. New dependencies also need the
  assessment in CONTRIBUTING.md ("Dependencies"). Zig package dependencies
  are not seen by the dependency graph: *Review*.
- **SL-3. Fuzzing and property tests on boundaries** that parse untrusted
  input (program, block, proof and wire formats). *Phase 2.*
- **SL-4.** Suspected vulnerabilities are reported privately per
  [SECURITY.md](SECURITY.md), never in a public issue.

## 11. Known gaps

This is an implementation-status ledger, not an exception to the rules above.
Read the current contracts, workflows and linked issues when claiming closure;
unmerged branches and draft prototypes are not installed enforcement.

The required workspace gate landed in PR #339; named owner routing is recorded
in issue #341, and branch archival/deletion landed in PR #337. CODEOWNERS routes
the invariant-owner roles to `@teddyjfpender`. It routes review, not approval.
These results do not establish complete boundary, security or release coverage.

| Gap | Rules | Phase |
| --- | --- | --- |
| Branch lifetime/push discipline is reviewed; no blanket automated branch-age or two-unpushed-commit check is claimed. | WW-2 | 0 |
| Remaining RISC-V subpackage and Ethereum product ownership work; zero workspace findings do not prove every product boundary. | TW-2, RS-1, RS-3; issues #335, #336 | 0 |
| Complete reproducible setup across all pinned toolchains and supported hosts. CI version checks alone are insufficient. | DR-1, DR-2 | 0 |
| Stable process/wire error codes and semantics across all waist boundaries remain incomplete. | BC-2; issue #359 | 1 |
| Consumer-owned execution across all five waist providers remains incomplete; one candidate consumer is not full coverage. | BC-4; issue #366 | 1 |
| Waist release-candidate freeze and API-diff compatibility enforcement remain incomplete. | BC-7; issue #354 | 1 |
| Populated, blocking per-package complexity budgets, hot-path complexity and runtime ceilings remain incomplete. | CB-1, CB-2; issue #370 | 1/2 |
| RV64 live-flag target remains below 60; other flag families also need complete registration. Read the registry for current counts. | CB-4; issue #332 | 2 |
| Complete property/fuzz coverage, including both Debug and ReleaseFast for numerical invariants. | BC-5, SL-3; issue #347 | 1/2 |
| Remaining vector ownership and historical evidence/source-snapshot extraction. | RS-4; issue #362 | 3 |

## 12. The short form

Extreme Programming for agentic teams:

- Contracts are executable: schemas plus contract, property and golden tests.
- Trunk-based development with flags: continuous integration, minimal drift.
- Complexity budgets, measured and enforced.
- Thin-waist architecture: stable boundaries, local freedom.
- A strict, compatibility-first API change protocol.
- A deterministic, reproducible development environment.
