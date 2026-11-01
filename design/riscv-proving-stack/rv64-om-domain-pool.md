# One expanded coset, bounded parallel packed rows

The actual 4.19M-row OM/GKR prefix still spent66.30seconds in native completion
after pooled GKR reduced total proving from143.34to106.31seconds. A live sample
placed180/181 active-worker stacks in the serial packed role evaluator while
helpers slept. This remained far slower than the historical QM31 classic
control and is not a positive LogUp or equal-security comparison.

All four wide role wrappers passed a null pool. The shared evaluator now inherits
only the existing scoped pool for coset FFTs and then splits packed row blocks
into bounded contiguous ranges. Original MAIN and INTER columns are expanded
once per component/coset. Each job borrows that immutable evaluation and owns a
separate heap scratch slot; no helper allocates, mutates shared scratch or
changes the freshness cursor. The caller decides fresh-store versus add for
the entire coset, joins all callbacks, propagates ordinal errors and advances
the cursor once. No pool or process cache is created.

A checked ScratchOwner reserves at most8MiB and at most16 jobs. Its requested
byte plan and allocation-failure cleanup have focused tests. Existing FFT,
immutable setup and pool-stack admission remain separate. Small jobs and nested
or unavailable leases fall back to scalar work. Optional
`STWO_ZIG_PROFILE_OM_DOMAIN` diagnostics distinguish prep, FFT and packed rows;
normal execution performs no clock calls.

Safe/Fast actual K and ADD/DOUBLE CPU shard proofs preserve scalar-versus-pooled
artifact hashes, physical claim vectors and fresh verification. These fixture
gates do not establish a full-prefix speedup. The next required gate is the
same4.19M-row request/configuration measured before and after this change.
