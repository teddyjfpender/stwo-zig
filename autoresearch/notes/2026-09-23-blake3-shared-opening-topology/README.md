# Shared recursive-opening topology: geometry qualification

Five standalone ReleaseSafe tests pass: canonical ordering and duplicate uses,
invalid geometry, allocation-failure cleanup, reconstruction against independently
built BLAKE3 trees, and rejection of changed routes and consumer counts.
The canonical 70-query / 26-bit PoW parent census also passes and checks the
new topology counts against its independently counted per-root openings.

This topology is not wired into production witness emission. It establishes
neither AIR soundness for a shared layout nor a proving-time improvement.
The existing estimate remains 2,124,248 G rows, above the 2^21 threshold;
sharing alone therefore does not shrink the current padded G domain.

Further implementation is deferred until the ReleaseFast E2E measurement gate.
