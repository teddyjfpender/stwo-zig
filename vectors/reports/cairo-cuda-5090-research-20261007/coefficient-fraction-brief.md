# Problem match: keep evaluation sources in HBM

The 5.34M-step PIE proves on a 5090 when all trace Merkle trees and 75% of
interaction evaluations are host-preferred. The exact proof takes 29.76 s to
publish versus 5.103 s in the saved H200 run. Constraint evaluation alone
takes 18.39 s, indicating that the spilled evaluation source is on the hot
path. The current arena is 37.70 GB and the interaction-evaluation slot is
5.08 GB.

Hypothesis: spill a comparable fraction of the 8.28 GB main-coefficient slot
*before its first GPU write*, while keeping interaction evaluations resident.
This should move work to trace generation and relation generation, which may
be cheaper than repeated host faults during constraint evaluation. The first
trial uses 50% main-coefficient host preference, all three trace Merkle trees
host-preferred, and a forced managed arena. The exact proof SHA-256 must remain
`7ddd6f9ce107c224f5823f4ee7535533c96327e61778118cfe74c39400b56f81`
and pass the pinned Rust verifier. The performance target is under 22.96 s
input-to-publication (4.5 times the historical H200 5.103 s), with measured
device headroom rather than merely a successful allocation.

Failure or slower execution rejects this placement; it does not justify
moving work outside the timing boundary.
