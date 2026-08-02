# Production automation boundary

`scripts/` contains only automation that is reachable from a current build,
installed workflow, correctness or soundness contract, release process, hook,
or production owner guide. Benchmark exploration, profiling, peer comparison,
and one-off diagnostics belong under `autoresearch/`.

The boundary is enforced rather than maintained by convention:

- `scripts/tests/test_script_reachability.py` rejects every unreachable
  top-level script. Historical prose and `autoresearch/` are deliberately not
  roots, so a stale mention cannot keep dead automation alive.
- `scripts/tests/test_source_conformance.py` checks entrypoint size, package
  ownership, and declared dependency direction.
- `scripts/tests/test_ci_package_graph.py` and
  `scripts/tests/test_focused_ci_contract.py` require script changes to select
  bounded hosted lanes rather than the full product matrix.

Only two human-operated entrypoints are intentionally not installed as gates:
`performance_epoch_gate.py` manages authenticated performance epochs, and
`riscv_operand_classes.py` regenerates the Sail-derived operand corpus. Their
owner and purpose are declared in the reachability test.

Support packages use the `<entrypoint>_lib/` convention where practical. An
independent Rust oracle, sidecar, or fixture generator belongs in `tools/` and
must be registered in
[`conformance/tooling-surface-v1.json`](../conformance/tooling-surface-v1.json).
Retired implementations remain recoverable from Git; they are not carried as
disabled jobs, dormant parsers, or archival compatibility layers on `main`.
