# Retain composition coefficients independently of commitment scratch

Resident composition previously retained one kind-2 lease containing compact
coefficients, expanded commitment evaluations, forward twiddles and column
descriptors. PCS consumes only the compact coefficients, so the expanded data
remained live across DEEP/FRI/openings without a reader.

On the established beta1 columns-transform route, coefficients now own an exact
kind-2 lease. LDE, twiddles and column-log metadata occupy a separate kind-0
scratch lease. Finalization writes coefficients once; the existing column N2B
kernel expands directly into scratch, and Merkle hashing reads that scratch.
The joined job releases scratch before returning to PCS. Returned column spans
retain the coefficient lease's original scope, token and generation.

For global composition log25/split1, compact coefficients occupy1GiB. The old
lease held an additional2GiB LDE,64MiB forward twiddles and384 descriptor bytes.
The retained allocation therefore drops from3.0625GiB to1GiB. This is a source-
derived allocation calculation, not a measured speedup or whole-prover memory
ratio. During commitment the same numerical working set remains live; it is
retired earlier rather than parked or read back.

Older images lacking the compact column N2B entry point, and beta>1 profiles,
retain the existing addressed route. There is no new kernel, transcript, AIR,
proof encoding, security profile or coefficient copy. Independent source review
passes, and all three production semantic checks pass. Actual proof-byte parity
and largest-production memory admission remain separate gates.
