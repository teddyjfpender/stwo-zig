# Problem match: partial cold Merkle-tree placement

The 4.00M-step PIE verifies with its 4.29 GB preprocessed Merkle tree
host-preferred, using 28.49 GiB of 31.36 GiB usable HBM. Its preprocessed
commitment takes about 1.73 s, and publication takes 9.12–9.28 s over three
runs. Without placement it fails during constraint evaluation. The unused
device headroom suggests that a full-tree spill may be more than necessary.

Experiment: host-prefer only the final 75% and then 50% of the tree, before
its first GPU write, retaining the upper part in HBM. Because the tree layout
may put hot nodes at one end, compare head and tail selection. Each candidate
must reproduce proof SHA-256
`0d74ce722cfdadc65b046057fcef2a5a2da52d9fccc74fd85b69154b8cc90a39`
and pass the pinned Rust verifier. Report proof, publication, whole-device
peak, and stage times. Reject a faster point if it consumes essentially all
usable HBM; it cannot be a robust 5090 service default.

The hypothesis is that leaving the upper Merkle layers resident will reduce
commitment and decommit cost without moving preparation outside the timer.
