# Full-width ordinary public root contract

The shared ordinary execution statement now provides `Blake3PublicData` with
three optional full-width digest roots and RVST transcript version 2. Legacy
`PublicData` retains scalar roots and its version-1 call layout. Both types use
the same execution, I/O, completion and register validation implementation.
BLAKE3 roots serialize as sixteen u16 limbs each, with explicit presence flags.

Validation: `python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all` passed (37 s, 1 GiB).
The gate explicitly imports public_data and selects its legacy tests and new
BLAKE3 test. The latter checks all 768 root bits, absent-versus-zero roots,
version separation and shared rejection of missing program roots, nonzero x0
and absent completion. Legacy transcript order/call-length tests also run.

This changes the shared statement contract, not production proof assembly or
artifact admission. Production memory still uses Poseidon. Full-width program
commitments, joined memory components, continuation and key/artifact admission
remain required before selecting this statement in a production prover.
