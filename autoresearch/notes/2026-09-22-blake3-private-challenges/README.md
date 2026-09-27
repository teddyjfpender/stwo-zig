# Private BLAKE3 transcript challenges

The joined parent fixture exports every accepted secure transcript draw. Protocol
builders assign semantic identities (universal relation index, composition,
OODS seed, DEEP randomness, FRI layer) before compiling the transcript. Receipts
own the exact final accepted-block wire address. Default public draw/PCS APIs
retain their existing behavior.

Canonical DEEP/FRI binding tags supply the scalar destinations; composition input
creation records its node identities. Admission requires every expected role and
coordinate exactly once. No value matching or guessed transcript operation index
selects a destination. One scalar route consumes each accepted coordinate and
emits its downstream multiplicity. Weighted QM31 packing supplies composition;
scalar routes supply DEEP and FRI. The OODS seed feeds both composition and DEEP.
Unused composition challenges still consume their transcript output, emitting
zero downstream copies. All corresponding public input/output anchors are gone.
Existing AIR equations and identity digests are unchanged.

Validation: first serial build exited 0, 16/16 steps and 6/6 tests passed.
Focused serial targets are
`test-qm31-pack-wire`, `test-blake3-routed-transcript`,
`test-blake3-transcript-sequence`, and `test-blake3-combined-fri`.

Scope: the combined test generates an original native STARK and a joined parent
STARK with constrained transcript, composition, DEEP, FRI, and authentication.
This is still an experimental, per-capture fixture. Commitments, query routing,
nonces and rejection/scheduling geometry need further qualification. Production
remains Poseidon; no Metal implementation, reusable production key, recursive
parent-of-parent, end-to-end speedup, or 128-bit soundness claim follows.

The first run took 692 ms for the mapping unit, 4 s each for the two transcript
fixtures, and 29 s / 6 GiB peak RSS for the combined proof test. These are test
execution diagnostics, not proof speedup measurements. Compiles took 5/24/22/36 s.
Review corrected the exported-boundary assertion to use circuit/wire columns
5/6 and added an exact eight-sink difference against public mode. The focused
transcript rerun exited 0: 4/4 steps and 2/2 tests passed, 4 s runtime / 352 MiB,
24 s compile / 1 GiB. No prover implementation changed after the first run.
Formatting and `git diff --check` also pass.

Next concrete step: make commitment roots share private bounded byte sources
between transcript absorption and every authentication path. Existing byte_route
accepts a field-valued output multiplicity; an identity route with p-1 consumes
both its hash output source and a matching canonical root tuple. This is a
candidate reuse of existing equations, not yet an implemented or tested root link.
