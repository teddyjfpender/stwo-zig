# BLAKE3 execution span in a recursive parent

The explicit execution parent now admits a leaf Span against the verified
child's complete public data and commitment plan. Admission checks program,
protocol/config identity, instruction count, PCs/registers, public-I/O edges,
ordinary-memory custody and both full-memory endpoints. The versioned BLAKE3
I/O identities preserve full u32 words; output identities exclude proof-only
access clocks. This profile reserves the separate machine I/O-state digest as
zero because complete memory carries the I/O contents and edge claims expose
application input/output.

The parent includes the admitted conversion paths as actual G/XOR, byte-route,
private-word and public-boundary rows. Public byte constants feed hash inputs
directly, removing the unnecessary caller-to-private-copy bridge from this
specialized public-custody path. The underlying typed update AIRs are reused.
Conversion namespace isolation follows circuit identifiers from authenticated
relation effects, including older AIRs whose identifiers occupy main columns.
It does not confuse unrelated field values with circuit IDs.

A transactional column appender writes the added witnesses into the final
parent layout. Unchanged cohort buffers stay owned by the original parent;
changed cohorts copy their existing columns and append new rows. Domain growth
remaps the committed row permutation. Replacements transfer only after all
fixed-column, geometry and allocation checks succeed.

Execution-parent key version 2 binds the Span identity and conversion binding
in addition to the full child key, arithmetic/transcript identities, parameters,
AIR geometry and preprocessing root. Parent-of-parent preparation preserves
this admitted Span identity through the child's key. Existing keys are not
silently relabeled. Keys remain specialized to admitted public statements and
schedules; these metadata objects alone are not proofs.

## Validation scope

The real runner executes six instructions and publishes one nonzero output byte.
Its full final-memory root differs from its ordinary root. The test attaches its
complete one-segment Span and eight byte conversions before proving its parent,
then independently verifies a second parent.
Mutation checks cover registers, full memory roots, output identities, fixed
conversion schedules, duplicate attachment and the new key fields. Final
completion admission rejects an unretired program fetch at a mere segment
boundary. Separate
focused checks exercise column growth and I/O identity semantics.

This is diagnostic q8/PoW0 CPU qualification, not distinct-child aggregation,
canonical-security recursion performance, continuation scheduling, Metal parity,
extension/CSP orchestration or production default promotion. The original
performance and complete BLAKE3 replacement goals remain unfinished.

## Terminal results

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe --summary all`

Passed: 2 minutes build/test, 5 GiB peak RSS. Parent artifacts are 126,640 and
124,256 bytes. The first parent retains 562,836,736 bytes after adding eight
exit updates; the second retains 523,271,232 bytes. Both round-trip artifacts
and independently verify after releasing proving plans. Span and custody
identities are preserved across the second level. These are diagnostic
structural counts, not isolated proof timings or speedup measurements.

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update -Doptimize=ReleaseSafe --summary all`

Passed: 32 seconds build/test, 1 GiB peak RSS. The guard requires six named tests,
including the earlier chained-update STARK, real-runner conversion, public
custody, I/O identity and final-completion admission checks.

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update '-Driscv-test-filter=BLAKE3 memory update proves parent append' -Doptimize=ReleaseSafe --summary all`

Passed: 6 seconds, 564 MiB peak RSS. This separately qualifies the final namespace
regressions: unrelated public field values do not reserve circuits, while both
fixed and witness-column circuit identifiers do. It also checks column remapping
across a domain-size increase, zero padding, and failure without replacing columns.

The full proof gate was rerun with the final completion guard and the nonzero
output fixture. The subsequent API export aliases do not change implementation.
No repository-wide suite, canonical security benchmark or Metal gate ran.
