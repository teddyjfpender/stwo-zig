# One inversion buffer across native AIR cohorts

The producer allocates one maximum-sized QM31 scratch buffer from its bounded
worker allocator and lends exact prefixes to each typed interaction workspace.
The canonical column generator now accepts an external workspace while retaining
its preflight, alias and arithmetic paths. Outputs remain in request staging;
the inversion buffer is freed before commitment, including on failures.

ReleaseSafe focused hash + native gates: 8/8 steps, 7/7 tests pass. Hash parity
includes caller-owned scratch, invalid capacity and failing output allocation.
Both parent proofs independently verify with unchanged key and 116,382-byte codec.
Hash tests run 794 ms/28 MiB; native tests 43 s/1 GiB reported MaxRSS.

Tracked worker peak falls from 1,600,143,854 to **982,008,191 bytes**, a
618,135,663-byte (38.63%) reduction. This resolves the prior prepared-column
worker regression; it is also below the older row-handoff peak of 1,567,077,617.
Preparation peak remains 600,657,997 and handoff retention 130,557,704 bytes.
No timing A/B or production-profile speed claim. Keys, distinct-child aggregation,
parent-of-parent and Metal qualification remain separate unfinished work.
