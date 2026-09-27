# Canonical resident BLAKE3 transcript operations

2026-09-22. Added resident word/felt/integer/root absorption and secure-field
sampling using the canonical BLAKE3 framing owner. State is eight full digest
words, LE64 draw counter in two words, and a sticky error word. Absorptions reset
the counter; draws retain the digest and increment the full u64 counter.
Word/felt frames carry the exact u64 element count. Whole eight-word draw blocks
must pass the canonical <2*p predicate before reduction; odd secure-felt counts
discard unused coordinates. No retry cap or modulo-biased alternative is used.

The API validates buffer spans, state/data overlap, operation shapes and canonical
M31 felt coordinates. Counter exhaustion sets the error flag rather than wrapping;
subsequent calls reject that failed state. Output can be partial if exhaustion
occurs after earlier accepted blocks; callers must discard output on failure.
Host admission currently requires shared/mapped arena contents. The MSL helper
is available for later cascade integration, but that integration is not done.

ReleaseSafe transcript/leaf/shader gates: 36/36 tests, 9/9 steps. The actual
transcript device test compares full arena contents and CPU channel state across
10 absorption cases: empty words/felts, widths near chunk boundaries, 1,025-word
and 1,028-coordinate messages, integer and root. After each absorb it compares
secure draws of 0,1,2,3,7 values. Additional cases cross 2^32 and approach u64
exhaustion; exhausted/sticky-error states, overlaps, short output and malformed
felts reject. The rare random-block rejection branch was not forced by these
vectors; its predicate/reduction was inspected against the CPU implementation.

The shared frame-prefix helper also serves leaves; the all-leaf regression
continues to pass. The core inventory/source pin now covers 175 core and 180
Ethereum kernels. Device execution is source JIT; AOT declarations/inventory are
checked, but no AOT execution or end-to-end speedup is claimed.

Commands:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal update-abi-declaration-digests -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-transcript test-blake3-leaves test-shader-authority -Doptimize=ReleaseSafe --summary all
```

Next: integrate the 11-word state and canonical mix/draw helper into the FRI
cascade and parent-tail transcript handoff without reusing BLAKE2s' narrower
counter/error layout. Query-draw, PoW transcript continuation, full Metal proof
qualification and canonical CSP timing remain. Prover-owned Poseidon identities
and production recursion remain in scope. Defaults/global suite admission are
unchanged. Algorithm mapping is archived in the source snapshots.
