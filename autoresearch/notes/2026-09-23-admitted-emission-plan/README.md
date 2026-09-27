# Reuse the admitted commitment plan during witness emission

`Owner.prepareMain` previously built a source-derived Plan and checked its identity against the persistent owner's admitted identity, then discarded that admission and called `components.emit`, which built a second source-derived Plan. The method now passes the already admitted candidate directly to the shared emitter. The candidate stays alive for the complete emission; the emitter still revalidates admission before writing rows. Failed preparation still clears main-ready and bound state before any work.

The focused ReleaseSafe integration test passes: independently emitted logical rows match the persistent final columns, padding and interaction columns match, changing program multiplicity rejects re-admission, stale main/component views remain unavailable after failure, and a valid retry reuses the same column buffers. This removes duplicate plan allocation/construction; it does not remove independent verifier admission or establish an E2E speedup.

Command: `python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Driscv-test-filter='BLAKE3 execution commitment integration binds native and hash components' -Doptimize=ReleaseSafe --summary all`.

No new product binary or CSP benchmark was produced for this small setup cleanup. The preceding parallel-column-projection measurements remain frozen evidence for their own source snapshot. Persistent recursion plans, arithmetic fusion, direct witness generation and parameter research remain the broader active objective.
