# Active OM31 AIR packed arithmetic

This slice changes the actual `PackedOmSecure` frontend type, which is distinct from the core grouped wrapper. The earlier core-only helper experiment did not change this caller and supplies no evidence of an AIR speedup.

The frontend secure product now invokes the existing concrete packed OM multiplication helper. For weighted base residuals with no optional scale, a pointer accumulator splats one native pack of the scalar weight and updates each native pack directly. It avoids passing a 512-byte splatted weight through `mulBase`, returning another 512-byte weighted residual, and adding that temporary. It allocates no heap, retains no extra planes, and preserves the original field operations and constraint order.

Scaled, secure, scalar OODS, and circuit paths retain their existing sink authority. The domain evaluator still applies the vanishing inverse once after accumulation; no constraint, commitment, transcript, geometry, or security profile changes.

Independent scalar tests cover all eight coordinates and sixteen lanes, including zero and negative base residuals, dense secure residuals, mixed emission and zero slots, initial accumulator, point and weighted sinks, null and lane-dependent non-null scale. Whole services proof/fresh-receiver gates and actual artifact parity are recorded separately below. No performance claim follows from source inspection or the small tests.

The compiled caller audit is part of qualification: packed full-product out-of-line sites fall from 140 to 4, leaving only the separate classic witness numerical inverse/contribution kernels. The active AIR product sites are gone. Scaled/fallback `mulBase` still exists; its static call count cannot measure the dynamic null-scale branch. The native executable grows from 3,195,512 to 3,475,192 bytes.

Six alternating real prefix runs cover four CPU shards plus Keccak, ADD, and DOUBLE truth proofs. Every run has ten authoritative artifacts; all sixty hashes match and all six independently fresh receivers accept. On this shared host, the median prove time is 38.292 to 37.219 s; summed CPU-domain row evaluation is 3.067 to 2.794 s while its FFT time is 2.779 to 2.776 s. Summed native composition is 8.838 to 8.444 s. Unchanged numerical work also drifts by about 1.3%, so the observed overall 2.8% reduction is modest rather than an isolated causal estimate. This prefix qualification establishes neither a full-block speedup nor whole-protocol 128-bit security.
