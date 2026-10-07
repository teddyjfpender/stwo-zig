# Problem match: offload the smallest useful live range

**Task and exactness.** Preserve the canonical Cairo proof while fitting PIEs
just above a 5090's 32,607 MiB HBM limit. Host placement is a performance
hint for managed pages; it cannot change witness values, AIR equations,
transcript inputs, or output bytes.

**Measured case.** `15574540_15574549` has 3,999,626 OS steps. Its physical
arena reservation is 33,501,400,016 bytes, plus about 2.17 GB of fixed
preprocessing. The no-placement managed proof reached the constraint phase
in 3.063 s but failed with CUDA allocation status 2 after 8.172 s. The
existing capacity policy host-prefers multiple ranges including lookup
inputs, scratch, both trace-evaluation sets, and main coefficients, causing
large slowdowns before the capacity pressure actually appears.

**Canonical match.** This is a weighted live-range spill problem. The arena
plan identifies exact slot sizes and lifetimes: for this input, main trace
evaluations occupy 4,543,662,080 bytes, interaction evaluations
3,687,732,736 bytes, main coefficients 2,271,831,040 bytes, and interaction
coefficients 1,843,866,368 bytes. A minimal host-preferred range should free
enough device space while preserving hot trace-writer inputs in HBM. The
candidate first host-prefers interaction evaluations before their first write,
leaving all other arena slots under the existing managed-memory policy.

**Falsifier.** A complete proof must match the historical H200 proof SHA-256
`0d74ce722cfdadc65b046057fcef2a5a2da52d9fccc74fd85b69154b8cc90a39`
and pass the pinned Rust verifier. Record full command, ingress, proof stage,
publication, sampled device peak, host RSS, and stage split. If the proof
still fails or the selective spill is slow, compare the main-evaluation slot
and narrow per-stage lifetimes before adding more offloads.

The economic bound for this PIE is 4.5 times the historical H200 proof
execution of 0.454 s (2.043 s), or 4.5 times 4.635 s adapted-input-to-proof
(20.858 s). The historical H200 build differs from this source, so these are
screening bounds until a source-matched H200 pair is available.

**Whole-slot result and revised search.** Selectively host-preferring the
entire 3.69 GB interaction-evaluation slot produced the exact proof and
passed Rust verification. It cut adapted-input-to-publication from the
146.249 s broad capacity policy to **22.659 s**, proof execution to
19.025 s, and sampled GPU peak to 29.115 GiB. Main-evaluation-only placement
also proved exactly but took 28.967 s to publication, so interaction
evaluations are the better spill target. The 22.659 s result narrowly misses
the historical H200-derived 20.858 s e2e screen. Constraint evaluation took
14.870 s of 19.025 s proof execution, consistent with repeated use of the
host-preferred evaluation range.

The next exact variant varies the *fraction* of the interaction-evaluation
slot placed on host, rounded up to managed pages. Start at 50% and move toward
the smallest fraction that still completes without allocation failure; also
compare the first versus last span. This tests whether a bounded spill can
retain most constraint inputs in HBM and cut the 14.870 s stage. A full exact
proof and verifier pass are required for every promoted fraction.

**Larger geometry.** The 8M-step `15554590_15554599` arena is
42,539,794,128 bytes on this source. Its interaction-evaluation range is
6,429,261,312 bytes and main-evaluation range is 8,576,383,488 bytes.
Offloading 75% of the interaction range plus all three trace Merkle-hash
ranges still reached the CUDA memory ceiling during constraint evaluation.
The next exact experiment spills a separate, adjustable fraction of main
evaluations as well. This is a weighted live-range selection: retain
frequently reused columns in HBM, and evict the smallest aggregate cold
fraction that lets the whole proof complete. Failed trials are informative
capacity bounds, never performance results.
