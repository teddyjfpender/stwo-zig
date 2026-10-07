# Problem match: relation lookup residency on the large PIE

The 20.85M-step PIE's qualified capacity placement proves exactly but takes
about 310 s proof time. Relation generation alone consumes about 136 s.
The policy host-prefers the 2.28 GB writer lookup-input slot before writers,
even though it has random-address consumers in the relation graph; the
observed GPU peak with interaction coefficients retained is 27.24 GiB.

Hypothesis: keep the lookup-input slot in HBM and preserve the other capacity
placements. Its size appears to fit the roughly 4.1 GiB sampled headroom.
This trades a small capacity increase for fewer remote random loads or
managed-memory faults during relation generation. A direct source-matched
trial must report relation and whole-proof times, device peak, exact proof
SHA-256 `fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb`,
and the pinned Rust verifier. It should be rejected if it fails capacity or
does not materially reduce the relation stage. It must not change lookup
contents, pointer tables, or transcript inputs.

NVIDIA's current [managed-memory guidance](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/unified-memory.html)
supports the possibility of direct host mappings under `SetAccessedBy`, but
the runtime already applies that hint. The experiment targets residency and
access locality, not another hint that is already present.
