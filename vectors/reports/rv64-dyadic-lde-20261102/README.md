# Dyadic zero-top FFT elimination

The allocation-free shared transform duplicates the nonzero coefficient window
in place of leading zero-child butterflies, then runs the original globally
indexed FFT tail. Existing fused2x remains unchanged; tiny constant cases use
the dense fallback. Safe/Fast tests cover2x/4x/8x, dirty upper slots, independent
pointwise evaluation, dense FFT parity, pooled operation, aliases, shape/domain
errors and all portable PCS allocation failures.

The first portable-only candidate CPU0 ABBA produced identical four authoritative
files and fresh acceptance every run, but mean proving16.4747→16.5325s and
transform2.3549→2.3624s were flat. This was NOT an actual owned MAIN/INTER
performance qualification: borrowed backing forces the separate combined CPU
hook, which had not yet been wired to the new transform. No speed promotion
is claimed for that initial dispatch. The follow-up must qualify the actual
combined hook and its exact skipped-layer work receipt.

The actual owned-backing combined CPU hook is now wired to the SAME qualified
transform. It preserves the existing 2x branch, propagates errors through the
existing job owner and reports the actual dyadic skipped-layer count. No extra
allocation, retained expansion or global cache is introduced. Own backend-package
Safe/Fast gates each execute 13 tests, including canonical 2x/4x/8x/tiny behavior,
actual execution receipts and every allocation failure. Independent review of
the combined hook and portable path passed. Metal uses its own execution receipts;
no CUDA/Metal method aliases the CPU skip authority or inherits a false 4x claim.

Actual candidate CPU0 ABBA on the combined hook yields:

| Metric | Frozen FRI baseline | Dyadic owned hook |
|---|---:|---:|
| Mean proving |16.3306s |16.2551s |
| Physical streaming transform |2.31215s |2.23760s |
| Producer extension job sum, including setup |7.67537s |7.27305s |
| Producer interpolation job sum, including setup |1.53959s |1.54422s |
| Mean process maximum RSS |12,104,523,776B |12,104,523,776B |

The transform stage decreases 3.22% and summed extension jobs decrease 5.24%.
Job intervals overlap and include immutable setup; they must not be added to
wall time. Mean proving moves 0.46%, below the observed old-run spread
(15.864–16.797s). This is a modest measured target-stage improvement and explicit
removal of unnecessary FFT layers, NOT an established significant whole-prover
speedup. All 16 authoritative artifact hashes match and all 4 frozen fresh receiver
checks accept. Source-binding and 60-artifact byte-exact regeneration checks still
pass. Full-block performance promotion and GPU execution remain separate gates.
