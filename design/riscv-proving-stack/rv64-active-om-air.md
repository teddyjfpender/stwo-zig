# Active OM31 AIR packed arithmetic

This slice changes the actual `PackedOmSecure` frontend type, which is distinct from the core grouped wrapper. The earlier core-only helper experiment did not change this caller and supplies no evidence of an AIR speedup.

The frontend secure product now invokes the existing concrete packed OM multiplication helper. For weighted base residuals with no optional scale, a pointer accumulator splats one native pack of the scalar weight and updates each native pack directly. It avoids passing a 512-byte splatted weight through `mulBase`, returning another 512-byte weighted residual, and adding that temporary. It allocates no heap, retains no extra planes, and preserves the original field operations and constraint order.

Scaled, secure, scalar OODS, and circuit paths retain their existing sink authority. The domain evaluator still applies the vanishing inverse once after accumulation; no constraint, commitment, transcript, geometry, or security profile changes.

Independent scalar tests cover all eight coordinates and sixteen lanes, including zero and negative base residuals, dense secure residuals, mixed emission and zero slots, initial accumulator, point and weighted sinks, null and lane-dependent non-null scale. Whole services proof/fresh-receiver gates and actual artifact parity are recorded separately below. No performance claim follows from source inspection or the small tests.
