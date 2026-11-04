# Experimental mixed fold and waking-oracle sum

This successor is isolated from the qualified negative fold-next-sum comparison.
It is OFF by default. The preceding candidate passed native proof-byte parity
and two fresh offhost CPU receivers, but warm GKR adapter time rose from 845.402
to 852.447ms and launches from 15,190 to 15,514 per complete seven-CPU-proof
block. Those single-run observations do not justify activation.

The previous candidate prefetched active oracles while newly waking oracles
still ran through a separate ordinary-sum grid and reduction. This successor
submits both sets together after the current shared challenge. Active rows use
the existing `fold_sum_tile`; waking rows use the established ordinary
`sum_term_base` or `sum_term`. Both have count/8 tiles. A waking oracle has
count/2 input elements and does not fold or advance its banks. Both sets become
prefetched, eliminating the next ordinary-sum submission. The shared draw,
weights, corrections, masks and terminal fold remain unchanged. Variables-zero
oracles are never submitted as waking numerical jobs.

The new optional symbol `stwo_rv64_batch_mixed_fold_sum_on` preserves the old
168-byte job layout. Only this new entry interprets BOTH all-zero output planes
as the waking variant. The old entry and non-null Zig Plane type remain
unchanged. A separate extern Zig output-plane type explicitly permits null
pointers; field sizes and offsets are checked at compile time. Partial-null,
nonzero reserved metadata, invalid shapes and any writable alias reject before
the first kernel. Existing allocation custody, multi-CTA grids and reduction
order remain. The new symbol is preferred only when the existing explicit
fold-sum opt-in is enabled; images without it keep the old qualified fallback.

Qualification is limited to 18 focused host tests and a full GNU production
semantic check. Tests exercise base and extension waking numerators, count8 to
count4, vars0 exclusion, raw readiness before each shared draw, native failure
poisoning, source preflight, explicit nullable ABI packing and fallback paths.
The connected native-golden CUDA harness has an UNEXECUTED optional mode,
`STWO_RV64_TEST_MIXED_FOLD_SUM=1`, including alias/partial-null/reserved metadata
negatives and a positive route counter. It retains all native golden and poison
checks. No numerical result is claimed for that mode yet.

CUDA source has NOT been compiled or run for this successor. The existing lease
was reserved for accepted basket and FIXED-control gates, then expired. No
runtime was linked or promoted, and no new GPU job or lease restart was made.
SM120 compilation, actual native-golden parity, sanitizer checks and controlled
full-block performance are mandatory before qualification or activation.
