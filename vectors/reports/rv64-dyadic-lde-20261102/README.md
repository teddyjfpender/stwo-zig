# Dyadic zero-top FFT elimination

The allocation-free shared transform duplicates the nonzero coefficient window
in place of leading zero-child butterflies, then runs the original globally
indexed FFT tail. Existing fused2x remains unchanged; tiny constant cases use
the dense fallback. Safe/Fast tests cover2x/4x/8x, dirty upper slots, independent
pointwise evaluation, dense FFT parity, pooled operation, aliases, shape/domain
errors and all portable PCS allocation failures.

The first portable-only candidateCPU0 ABBA produced identical four authoritative
files and fresh acceptance every run, but mean proving16.4747→16.5325s and
transform2.3549→2.3624s were flat. This was NOT an actual owned MAIN/INTER
performance qualification: borrowed backing forces the separate combined CPU
hook, which had not yet been wired to the new transform. No speed promotion
is claimed for that initial dispatch. The follow-up must qualify the actual
combined hook and its exact skipped-layer work receipt.
