<!--
Every PR must conform to ENGINEERING_STANDARDS.md. PRs that violate it are rejected.
Delete guidance comments, not sections. Write "none" where a section does not apply.
-->

## Summary

<!-- Behavior changed, why, and the starting issue it closes (Closes #...). -->

- Invariant owner and acceptance/merge bar:

## Contract and boundary impact

- Packages touched (`package.contract.json` owners):
- Contract change? <!-- api_surface, public_modules, dependencies, layer, golden vectors, error or compatibility rules -->
  - [ ] No — implementation only; contract suites stay green.
  - [ ] Yes — approved RFC issue: # <!-- required; see ENGINEERING_STANDARDS.md section 6 -->
- Version bump (semver per BC-7):
- Product-line or waist edges added:
- Consumer-owned tests/provider lane, failure/retry/idempotency/timeout impact:

## Complexity budget

```text
code lines:  +A / -R / net N
flags:       +a / -r / live L
scripts:     +s / -t
separately:  docs +/-, config +/-, receipts/vectors +/-
justification (required if net > 0 or flags/scripts added):
```

<!-- Moves and renames are not removals. -->
<!-- Declare the budget before editing and include measured deltas in every commit. -->

- Measurable benefit, containment and rollback for budget growth:

## No complexity leaks

- [ ] No new types, errors or config knobs that consumers must now understand (or they are contract concepts with tests).
- [ ] No optional parameters acting as implementation escape hatches.
- [ ] No leaked concurrency semantics (locks, ordering, queues, caching).
- [ ] No leaked representation (residency, layout, proof/transcript internals, serialization, keys).
- [ ] No leaked policy (timeouts, retries, budgets, fallback, backend selection) without a stable abstraction.
- [ ] No product line depends on another product line; no relative import enters another package.
- [ ] No loose source files added outside a package; no source copies in evidence.
- [ ] No proof check, pin, ceiling, test discovery or rejection classification relaxed.
- [ ] Owner/RFC decisions and any exception's scope, retained safety checks and expiry are recorded in the issue.
- [ ] No consumer depends on behavior outside the contract suite; migration and deprecation are explicit.

## Flags and rollback

- Flags added/removed (owner, default, removal date in `conformance/rv64-flags.json`):
- Rollback plan:

## Evidence

<!-- Exact source head, commands, host/toolchain and receipt links. State PASS/FAIL/UNRUN/CANCELLED/DEFERRED per gate; unchecked means not claimed. Compile-only is not runtime acceptance. -->

- Pinned source/binary/workload and selected frozen byte-identity reference:
- Required negative/property/consumer cases and qualified performance evidence:
- Inherited failures (exact baseline, owner decision/follow-up) or remaining gates:

- [ ] `python3 scripts/dev_test.py`
- [ ] `python3 scripts/ci.py --fast`
- [ ] `scripts/rv64_gate.sh` (RV64 path; receipt:)
- [ ] `scripts/rv64_m8_bench15.py` (performance claims; receipt:)
- [ ] Other:
