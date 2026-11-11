<!--
Every PR must conform to ENGINEERING_STANDARDS.md. PRs that violate it are rejected.
Delete guidance comments, not sections. Write "none" where a section does not apply.
-->

## Summary

<!-- Behavior changed, why, and the issue it closes (Closes #...). -->

## Contract and boundary impact

- Packages touched (`package.contract.json` owners):
- Contract change? <!-- api_surface, public_modules, dependencies, layer, golden vectors, error or compatibility rules -->
  - [ ] No — implementation only; contract suites stay green.
  - [ ] Yes — approved RFC issue: # <!-- required; see ENGINEERING_STANDARDS.md section 6 -->
- Version bump (semver per BC-7):
- Product-line or waist edges added:

## Complexity budget

```text
code lines:  +A / -R / net N
flags:       +a / -r / live L
scripts:     +s / -t
separately:  docs +/-, config +/-, receipts/vectors +/-
justification (required if net > 0 or flags/scripts added):
```

<!-- Moves and renames are not removals. -->

## No complexity leaks

- [ ] No new types, errors or config knobs that consumers must now understand (or they are contract concepts with tests).
- [ ] No optional parameters acting as implementation escape hatches.
- [ ] No leaked concurrency semantics (locks, ordering, queues, caching).
- [ ] No leaked representation (residency, layout, proof/transcript internals, serialization, keys).
- [ ] No leaked policy (timeouts, retries, budgets, fallback, backend selection) without a stable abstraction.
- [ ] No product line depends on another product line; no relative import enters another package.
- [ ] No loose source files added outside a package; no source copies in evidence.
- [ ] No proof check, pin, ceiling, test discovery or rejection classification relaxed.

## Flags and rollback

- Flags added/removed (owner, default, removal date in `conformance/rv64-flags.json`):
- Rollback plan:

## Evidence

<!-- Commands run and results. Name any gate that could not run and why. -->

- [ ] `python3 scripts/dev_test.py`
- [ ] `python3 scripts/ci.py --fast`
- [ ] `scripts/rv64_gate.sh` (RV64 path; receipt:)
- [ ] `scripts/rv64_m8_bench15.py` (performance claims; receipt:)
- [ ] Other:
