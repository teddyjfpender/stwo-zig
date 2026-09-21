# Canonical detached-parent admission and legacy AIR retirement

Detached parent preparation, parameter admission, producer component construction, verifier component construction, definition lifecycle, and recursive composition recording now use only the current parent catalog and canonical compact-Poseidon identity. Removed the historical multiplication and wide-Poseidon component storage, initialization, selection, and cleanup branches. Historical parent keys using those AIRs or the old compact-Poseidon source digest now fail admission; they must be reproved under current admission. Generic compatibility helpers used by other paths remain outside this cutover.

The current four-segment and useful-memory scaling admissions already select the canonical multiplication AIR and compact-Poseidon digest. All 14 parent-key references inspected had matching content hashes; no key, expected statement, manifest, or admission pin was rewritten. See `admission-audit.json`.

The direct-program pruning differential now iterates all 29 entries of the actual detached-parent catalog. It previously used the old catalog plus manual substitutions and omitted row 14. The standalone parent verifier's transitive source guard now forbids the old multiplication implementation and universal catalog.

## Validation

- `python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-parent-canonical-admission -Doptimize=ReleaseSafe --summary all`: 223 passed, 1 skipped. Includes current producer/verifier geometry agreement and rejection of independently resealed historical multiplication, wide Poseidon, old compact identity, and forged identity; snapshot/claim/allocator failure coverage retained.
- `python3 -m unittest scripts.tests.test_product_closure`: 32 passed.
- Fresh CPU and Metal/AOT four-segment products: 384 checks. Producers exit before standalone verification; hostile and same-geometry substitution checks passed. All 21 proof/key/claim artifacts match the canonical baseline across both backends. Required native/leaf/parent Metal interaction dispatch assertions passed.
- Two test-inventory checks passed after registering eight existing/new test roots and removing two entries for files whose tests had moved.

`qualified-source-snapshot.json` records identical frozen sources for both proof gates. Only test-inventory wiring changed afterward, checked separately; documentation was appended after evidence capture. No full-suite rerun was used.

## Remaining scope

This retires alternative AIR admission inside detached parents, not the entire older outer/temporal API surface. Compact recursive Poseidon still derives constraints from its generic equation owner; completing its typed authority remains required. Range provider geometry and relation binding already have a typed contract. Provider typing, broader route/API retirement, and the final useful continuation ladder remain separate completion obligations. This report does not assert production security qualification.
