# Recursive scalar/source columns: ID14 source handoff

Status: root’s serialized ReleaseFast semantic/codegen gate passed12/12.
The allocation-failure gate found and fixed partial optional-owner publication
at the sample source→pack boundary before this qualification. No agent built
or ran the batch independently. Execution segments, STARK proofs and benchmarks remain stopped.
It extends the prior borrowed pack11/sparse matcher work. It changes no AIR
equation, relation challenge, fixed schedule, component order, public term,
source-key grammar, artifact codec or verifier authority.

The common native/execution parent assembler now emits scalar cohort12 into
count-admitted main columns plus compact fixed metadata. Native claimed-sum
selector inputs are counted before allocation and appended in their original
order before the scalar owner freezes. The input inventory and native PCS
matcher reconstruct one transient scalar row from this immutable column owner,
alongside the existing borrowed pack11 view. There is no Builder.rows[12] or
Builder.fixed[12] allocation for the canonical parent path.

The sparse matcher retains one plan across counting and emission. Its output
columns have separate allocation ownership; growing or filling output cannot
invalidate the borrowed input owner. Both passes finish before the parent frees
the original scalar columns and adopts the filtered scalar/native/opening
outputs. Failure before that release leaves the original owner with the parent;
failure after it sees cleared slots and cleans only the new owners. The parent
callback may release upstream row/column sources only after the final input
columns have stopped borrowing them; arithmetic graphs retain their existing
required lifetime. Public boundaries and arithmetic public terms remain in the
same schedule as before.

Canonical execution payload preparation now calls
`blake3_execution_sample_links.prepareColumns`. Sample scalar and pack rows are
emitted directly into their upstream column owners, with no retained live or
dense fixed row arrays. Scalars preserve sample-coordinate order even if
composition source nodes are not ordered by sample ID. Packs preserve the
original composition-node order. Scalar multiplicities include exact DEEP,
composition and encoding uses; zero-use composition packs remain absent.
Mapping and graph-use scratch uses the freeing backing allocator and is
released before Prepared returns. `Prepared.appendInputs` counts/scatters
borrowed columns into the common parent owner, rejecting mixed legacy/direct
fields or incomplete emission. Explicit `prepare` remains the row oracle for
fixtures. Claim/challenge/terminal source preparation outside this sample slice
still has legacy upstream rows; this is not a claim that ID14 is fully finished.

Memory work reduction is a layout calculation, not a measured speedup. For N
sampled secure values and K required packs, old upstream live+fixed outputs
occupy224N+96K bytes before arena/capacity overhead. The new sources occupy96N
bytes of fixed metadata plus4*pow2ceil(4N) main bytes; packs occupy32K fixed
bytes plus16*pow2ceil(K) main bytes, with a minimum two-row domain. At ordinary
nonempty sizes this is112–128 bytes/sample and48–64 bytes/pack, excluding small
column descriptors and allocator overhead. Canonical scalar assembly also
replaces52 bytes/logical row of old live/compact-fixed inventory arrays with24
fixed bytes plus one padded4-byte main column. Tiny/empty cohorts retain normal
padding overhead. Input and fused output owners overlap during the matcher;
register/clock/caller/recursion arithmetic is not made free by this change.

Focused nonproving root:
`src/frontends/riscv/block_v5_recursive_scalar_columns_test_root.zig`.
New upstream tests use authentic small recorder and DEEP graph evaluations,
without child proofs or guest execution. They compare the legacy/direct source
and pack schedules (including reversed sample/node order and zero-use packs),
exercise the actual count/scatter API, reject mixed/incomplete/missing/duplicate/
changed sources, and inject every allocation failure through the owned pipeline.
The inventory fixture adds borrowed scalar value/circuit/duplicate mutations;
the sparse matcher fixture adds immutable source parity and allocation failures
through both passes. The root also retains concrete native/execution parent,
owned/borrowed hash-column assembler and canonical payload preparation bodies
for code generation. Existing direct cohort tests now include cohort12.
The existing execution artifact fixture also reads the canonical sample-column
view when checking the additional encoder multiplicity; it no longer assumes
that canonical payload preparation retains a dense sample row array.

Useful filters: `direct recursive scalar` (new upstream tests),
`direct recursive inventory`, `native query fusion`, and
`direct recursive assembled parent`. The full root contains only nonproving
source/column/arithmetic/custody/codegen fixtures. Required next evidence is
root's serialized semantic/codegen gate, then independently authorized actual
recursive proof/key/root parity qualification; none has been inferred here.

Qualified evidence: `cpu-performance-gates-v1/direct-recursive-scalar-source-columns-v1.log` and `direct-recursive-scalar-source-columns-qualified-v1.json`. These pin this scalar/sample source snapshot; later upstream migrations require their own gate.
