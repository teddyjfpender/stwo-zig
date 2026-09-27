# CSP full-width BLAKE3 regression investigation

CSP recovery is the current priority; recursion-only performance work is deferred.
These are source-pinned dirty-tree diagnostics on Apple M5 Max / 64 GiB, ReleaseFast,
16 workers, canonical inputs and 70 queries / 26 PoW bits. No clean-source suite
admission was bypassed. This is not a claim that historical performance is restored.

## ECDSA paired results

Same-binary control/candidate/candidate/control order for each backend, two cold
samples per arm, no warmups. Controls disable parallel lookup counting and all
coefficient retention; candidates use bounded private counters and a 1 GiB total
coefficient budget across trace and composition commitments. The cache holds
coefficients already computed for the same proof; it is not a cross-statement
witness cache. Larger trees fall back to LDE sampled-value evaluation.

| Backend | Control median complete transaction | Candidate median | Speedup |
| --- | ---: | ---: | ---: |
| CPU | 11.094906 s | 6.349760 s | 1.747x |
| Metal | 11.389569 s | 6.790643 s | 1.677x |

All eight final paired proofs passed fresh verification and share SHA-256
007ce5f9ad02ab821affd7003dc3acd8608d38483cbf1af40d63f654457016fb,
identical to the earlier full-width artifact. Input, ELF, output, PCS parameters
and proof statement are unchanged. These gains are within the full-width route,
not a BLAKE3-versus-Poseidon comparison. The historical approximately 1-second
route remains much faster.

Tracked host peaks: CPU 3,831,857,292 bytes; Metal 3,731,688,788 bytes. Physical
process-lifetime peaks: CPU 3,861,237,432 bytes; Metal 5,335,044,704 bytes. Caching
trades additional retained coefficients for faster sampled evaluation; host
allocation budgets remain enforced. Raw reports and logs are authoritative.

Root-level pair files retain the intermediate trace-only cache experiment
(7.526555 s CPU / 7.702361 s Metal). Final results are under composition-cache.
The profile-source, candidate-source, and composition-cache/source overlays record
successive changes over ../2026-09-23-blake3-releasefast-e2e/source.tar.gz.
Executable hashes and successful CPU/Metal build logs are retained for each batch.

## Other CSP workloads: baseline complete

run_suite.py validates manifest-v2 inputs, ELF hashes, expected outputs and cycles,
70/26, and verifies every retained proof independently. It runs all 16 positive
cases sequentially on CPU then Metal. One cold sample per case. All 32 CPU/Metal cases have independently verified;
see [the complete table](BASELINE_RESULTS.md) and suite/results.json. A 40 GiB RSS watchdog bounds each
process; resource failures are recorded, never treated as benchmark results.
This diagnostic does not replace the official clean-source suite reader.

The first SHA-256/128 CPU case verified at **85.044773 s**, with 39,320,401,512-byte
physical peak. Its phase breakdown is 13.129966 s witness, 3.604943 s admission,
64.688892 s proving, and 3.586364 s fresh verification. Historical CPU SHA-256/128
was approximately 2.074658 s proving plus 0.192373 s verification. The regression
therefore extends well beyond ECDSA and requires further work.

## Structural investigation

Parsing the already verified SHA-256/128 commitment plan gives 4,799 program
words, 1,297 initial-memory words and 1,320 final-memory words. Applying the same
per-root shared-topology count as the prover gives 57,626 program, 15,666 initial,
and 15,944 final BLAKE3 compression blocks: **4,997,216 G rows**, padded to 2^23.
ECDSA has 489,328 G rows padded to 2^19. These are geometry counts, not runtime
fractions. Of the 4,799 program words, 4,632 have nonzero fetch multiplicity;
merely omitting unused program words will not materially solve this case.

See NEXT.md for the current investigation boundary. Public program data may
permit authenticated preprocessing instead of proving its hashes repeatedly,
but no such circuit or admission change is implemented or qualified here.
