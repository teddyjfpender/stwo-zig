# Strict Metal boundary and framework export checkpoint

This checkpoint does not claim a GPU-only proof or a significant performance
improvement. The current strict route deliberately rejects known host witness
and recursive preparation before producing artifacts. Production framework AOT
and resident dispatch remain the next integration boundary.

## Complete proof evidence

`final-tree-checkpoint.json` pins the current producer binaries, source snapshot,
commands, reports and all 21 serialized proof/key/claim artifacts. The hybrid
Metal four-segment request contains four native proofs, four wrappers, two
intermediate parents and one root. It passed all 136 fresh acceptance/rejection
cases after producer exit. Every artifact matches the retained baseline exactly.

The one measured production sum was 65.034657166 seconds: 32.380268084 seconds
for native leaves plus wrappers and 32.654389082 seconds for parents. The full
hostile-input gate took 68.687635542 seconds; maximum observed process RSS was
4,370,006,016 bytes. This is a single correctness run, not a paired speedup claim.
The fixture retires 227 instructions and touches one address; it is not Ethereum.

The parent receipts now report 31 host composition components and two GPU PoW
dispatches each, despite the legacy `cpu_fallbacks=0` value. That distinction is
intentional. The interaction nonce search now uses the shared backend operation;
proof byte parity establishes that the transcript/nonce result is unchanged on
this fixture.

`final-strict-parent-rejections.json` proves rejection of both strict host
preparation and an invalid policy value using the final parent binary. The
`strict-tree-rejected` report retains the full controller's expected failure
before leaf witness generation, with no proof produced. These are negative
boundary gates, not positive strict proving.

`source-snapshot.json` was captured during the final producer build and checked
unchanged after it. Subsequent test-only corrections/coverage additions are
reported separately; the snapshot describes the binaries used by the tree.

## Kernel and formal evidence

The framework export tests exercise admitted real AIR plans and owned runtime
parameters. The expanded isolated device gate passes 10/10 tests: 108 cases and 144
completed dispatches, comparing 29,568 coordinates across four kernel shapes.
It covers 33-word lookups, sole/final pairs and reordered direct roots. Test-only Metal compilation is not production AOT admission.
`final-formal-check.json` records the source correspondence and local Lean axiom
check. These local results do not prove compiler refinement or prover security.

The initial `hybrid-parent-accepted.json` is a retained real gate failure: its
producer succeeded, but the old telemetry parser rejected the additional
host/Pow fields. The corrected `hybrid-parent-v2-accepted.json` and final tree
passed. The initial `pcs-commitment-tests.log` also retains failures exposed by
the broader ReleaseSafe check. `pcs-commitment-tests-final.log` passes all
161 tests (845 ms test execution, 39 s compilation). Corrections use wrapping
fixture-data generation, count distinct point-list plans separately from trees,
and move packed-leaf boundaries onto live FRI accounting. The obsolete 155-line
accounting helper/test was removed. `post-proof-check-source-snapshot.json`
identifies these test/unused-code changes after the frozen producer build.

## Next acceptance gate

Admit the generated framework kernels through the production AOT profile, bind
the actual resident buffers and runtime parameters, and dispatch actual exported
components. Require CPU parity and complete fresh proof verification before
removing host paths. Provider/range coverage, witness/closure/interaction work
and FRI inverse preparation remain explicit outstanding work. See
[the complete goal](../../../../design/riscv-proving-stack/strict-metal-goal.md).
