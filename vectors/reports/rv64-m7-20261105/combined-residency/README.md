# Preserved negative 22 GiB admission experiments

Status: **22 GiB device-arena qualification failed.** These are the negative predecessors to the accepted automatic-arena M6 and D2 runs documented in `../d2-composed/README.md`. They are not performance improvements or evidence that the 28 GB/device target passes.

The first attempt enabled the outer role workspace and refused the small block for insufficient memory. The second disabled that workspace: the small block passed full M6 byte comparisons and fresh CPU verification, but the headline block failed during native proving. Both receipts preserve exact driver/image/source hashes, flags and raw pod run paths. The final accepted preset uses automatic arena and leaves the role workspace disabled. The separate global memory-admission work and the two-proofs-per-GPU gate remain open.

`driver-build.log` is an empty successful-build log; provenance comes from the frozen driver/source hashes in the receipts, not that empty log.
