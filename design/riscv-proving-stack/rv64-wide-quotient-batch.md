# Bounded cross-row inversion for the wide DEEP quotient

The OM31 quotient provider now batches quadratic denominator inversions across
at most 1,024 domain rows. Previously `beginRow` inverted its QM31 half-field batch
once per row. The actual core denominator microprofile (65,536 rows, eight sample
batches) measured a median 34.47 ms scalar versus 9.04 ms batched on a shared M5 host,
about 3.81x for that substage. This is not a full quotient or block speedup.

The implementation retains the core quadratic denominator and finalization
laws. It uses the existing batch-major cross-row helper, gathers each row's
inverses and preserves numerator-group and finalization order. Bit-reversed
lifted domain points and mixed-height group geometry are unchanged. Every
sample batch is evaluated even if the corresponding numerator is zero; a pole
still returns DivisionByZero, without redraw. Empty sample sets return zero.

Per-proof scratch is explicit: 1,024 base-field points and two inner-field arrays
of rows times sample batches. Eight batches cost 270,336 requested bytes. The
checked plan is charged against the caller's quotient buffer limit before group
materialization; remaining admission goes to aggregate coefficients/evaluations
and FFT twiddles. Metadata and small stack storage remain separate. No source
LDE, process cache or unbounded cross-row matrix is retained.

Safe/Fast gates preserve durable physical proof hashes for uniform, mixed and
hybrid retained/compact inputs at FRI folds 1 and 4, with decoded fresh receivers
and exhaustive compact-pipeline allocation failures. New tests cover multiple
tiles, partial tails, scratch caps, empty sample sets and zero-numerator poles.
The legacy QM31 provider dispatch is unchanged. Its current-source proof/receiver
tests pass and the pinned 381,800-byte historical Q control retains its SHA256 and
fresh acceptance through the existing qualified receiver binary. That control
is historical LS20/tail18, not an LS7 performance claim.

Receipts retain the six before/after OM proof hashes, exact commands, control
provenance and micro samples. Production 128-bit security, recursion and device
qualification are independent gates.
