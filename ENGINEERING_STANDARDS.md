# Engineering Standards

Status: **normative**. This document is the contribution specification for the
repository. Every change, whether written by a person, an agent, or both, MUST
conform to it. A pull request that violates a rule marked *enforced* is rejected;
a pull request that violates a rule marked *planned* is rejected at review once
that rule's phase begins, and SHOULD conform before then.

[CONTRIBUTING.md](CONTRIBUTING.md) holds the domain engineering practice (Zig,
memory, SIMD, GPU, cryptographic parity, benchmarking) that implements this
standard. Where the two disagree, this document wins and CONTRIBUTING.md is
corrected.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

## 1. Enforcement status

Each rule names how it is checked:

| Mark | Meaning |
| --- | --- |
| **Enforced** | A gate in this repository fails the change today. |
| **Review** | Checked by the reviewer against the checklist in section 9; no automated gate yet. |
| **Phase N** | Becomes a blocking gate in Phase N of [the restructure plan](design/repository/restructure-plan.md). Until then it is a review rule. |

The phases are: **Phase 0** trunk and gates; **Phase 1** thin waist;
**Phase 2** complexity paydown; **Phase 3** evidence out, process in.
Section 11 lists the current gaps honestly. A gap is not a waiver.

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

## 3. Thin-waist architecture

The repository has a narrow, boring, stable core interface with fast-moving
work on either side of it.

- **The waist** (stable): protocol types and laws, backend capability
  contracts, the prover API and interchange formats. Today these are the
  packages with layer `protocol`, `contract`, `api` and `interchange`
  (for example `src/core`, `src/backend`, `src/prover_api`,
  `src/interop/proof_wire`).
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
  (`zig build package-workspace`). *Phase 0*: the checker exists but reports
  830 findings at `51897dc26` (374 undeclared imports, 215 stale contract
  entries, 50 loose `src/` roots reaching into packages) and runs only in the
  release workflow; it becomes passing and blocking on every PR in Phase 0.
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
| BC-1 | **Schema / types.** The public module and exact top-level API are declared (`public_modules`, `api_surface`). | Checked by `check_package_workspace.py` (fails when the public declarations differ from `api_surface`); not yet passing or PR-blocking, see TW-2. *Phase 0.* |
| BC-2 | **Error model.** Each public operation documents which errors it returns, when, and whether a retry is safe; error sets are part of the API. Where a boundary is a process or wire boundary, errors carry stable codes; retry, idempotency and timeout semantics are stated. | *Phase 1.* No stable error-code model exists today. |
| BC-3 | **Executable invariants.** Signature and invariant tests are listed in `api_contract` and resolve to exactly one test reachable from the public module. | Checked by `check_package_workspace.py`; not yet passing or PR-blocking, see TW-2. *Phase 0.* |
| BC-4 | **Consumer-driven contract tests.** Each consumer of a waist package owns tests, run in the provider's lane, that pin the behavior it relies on. A failing CDC test means a collaboration rule was broken. | *Phase 1.* Not present today. |
| BC-5 | **Property tests** for core invariants (field laws, transcript determinism, serialization round-trips, fold/commit equivalence), with fixed seeds. | *Phase 2.* Coverage is sparse today. |
| BC-6 | **Golden vectors** for trusted behavior: proofs and transcripts that MUST stay byte-identical unless the protocol revision changes. | *Enforced*: committed vectors under `vectors/`, `zig build vectors`, Rust-oracle parity (`conformance/upstream.md`), and `scripts/rv64_gate.sh` (frozen D2 golden fingerprints, fresh CPU receivers, semantic negative corpus). |
| BC-7 | **Explicit compatibility policy.** `version` follows semantic versioning: a removed or changed public symbol or behavior is a major bump; an addition is a minor bump. | *Phase 1.* All packages are at `0.1.0` and versions are not yet checked against API diffs. |
| BC-8 | **Named owner.** `owner` names the invariant owner role (section 6) for the boundary. | *Enforced* (field required); role resolution *Phase 0*. |

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

## 5. Repository structure

- **RS-1. No loose source files in high-level directories.** Every directory
  under `src/`, `tests/` and `tools/` is either a *package* (it has
  `package.contract.json`, `build.zig.zon` and one declared root module) or a
  *container of packages* that holds no source of its own. Test roots, CLIs and
  code generators live inside the package that owns what they exercise.
  *Phase 0* (structure gate in the package-workspace audit). Today `src/` holds
  ~36 loose files and `tests/` holds loose Zig roots; Phase 0 removes them.
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

**Module budget.** Each package tracks: public surface (`api_surface` size),
dependency count and allowed dependency layers, file size and control-flow
depth ceilings (source conformance ratchets), and, where relevant, allocation
and latency ceilings. Surface and dependencies are *enforced* as exact
ledgers; per-package numeric budgets are *Phase 2*.

**CB-1.** Every PR MUST report its complexity budget in this format:

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

## 8. Way of working

- **WW-1. Executable specification first.** Feature work starts from an issue
  (the *Feature / vertical slice* template) that states the contract and the
  failing tests or vectors that define done. *Review*.
- **WW-2. Trunk-based integration.** Changes integrate into `main` in small,
  complete slices behind flags where necessary; long-lived branches and
  integration stacks are not a delivery mechanism. A flag has an owner, a
  default and a removal date in the flag registry. *Phase 0*: `main` became the
  trunk when the long-lived integration stack merged (PR #314); keeping it that
  way is a review rule until branch-age checks exist, and ~297 RV64 flags are registered (~260 live) against a live
  target of 59.
- **WW-3. Tests are the arbiter.** Agents and people do not argue
  correctness; the contract suites, golden vectors and verifiers decide.
  RED → GREEN → REFACTOR is the loop.
- **WW-4. Division of labor.** People own decomposition, contract design and
  review for correctness, security and taste. Agents implement, enumerate edge
  cases and refactor *within* a boundary. An agent MUST NOT change a contract
  without an approved RFC (section 6). *Review*.
- **WW-5. Gates before push.** Run `scripts/dev_test.py` while editing and
  `scripts/rv64_gate.sh` before every push that touches the RV64 path; run the
  regression basket (`scripts/rv64_m8_bench15.py`) for performance claims.
  Local gate receipts are the merge evidence where hosted CI cannot run a lane.
  *Enforced* by the pre-push hook for touched products; *Review* for receipts.

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

These are the places where the repository does not yet meet this standard.
Each is owned by a phase of [the restructure plan](design/repository/restructure-plan.md).

| Gap | Rules | Phase |
| --- | --- | --- |
| Trunk-based development only just started (the integration stack merged into `main` in PR #314); ~538 remote branches remain. | WW-2 | 0 |
| Package-workspace audit is not blocking on PRs and currently reports 830 findings (undeclared imports, stale contract entries, loose `src/` roots). | TW-2, RS-1, RS-2 | 0 |
| No toolchain pin files. | DR-2 | 0 |
| Contract-change ownership is not enforced by CODEOWNERS (owners are roles, not people). | BC-8, AC-1 | 0 |
| No stable error-code model at process and wire boundaries. | BC-2 | 1 |
| No consumer-driven contract tests. | BC-4 | 1 |
| All 27 packages at `0.1.0`; versions not checked against API diffs. | BC-7 | 1 |
| ~297 registered RV64 environment flags (~260 live) against a live target of 59; other flag families unregistered. | WW-2, CB-2 | 2 |
| Little property or fuzz testing. | BC-5, SL-3 | 2 |
| Evidence, receipts and source snapshots stored inside the source tree. | RS-4 | 3 |

## 12. The short form

Extreme Programming for agentic teams:

- Contracts are executable: schemas plus contract, property and golden tests.
- Trunk-based development with flags: continuous integration, minimal drift.
- Complexity budgets, measured and enforced.
- Thin-waist architecture: stable boundaries, local freedom.
- A strict, compatibility-first API change protocol.
- A deterministic, reproducible development environment.
