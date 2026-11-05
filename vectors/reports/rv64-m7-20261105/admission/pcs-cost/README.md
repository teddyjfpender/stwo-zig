# Legacy PCS allocation envelope [M unit gates, source-derived model]

The pod CPU gate passes 11 tests, including two new PCS geometry/format tests and the imported admission/streaming gates. No GPU operation or request benchmark is performed.

`pcs_allocation_cost.zig` enumerates C-owned allocation requests from the legacy M31/Blake32 native PCS pipeline and applies physical arena rounding per allocation. It deliberately sums all requests instead of subtracting retired temporaries or crediting best-fit reuse. It always charges coefficient copies and a cold immutable domain reservation. This is a conservative device envelope, not a measured or exact simultaneous peak, and not a placement guarantee. Existing live allocations must still be charged by the shared physical ledger.

The host freezes the stream budget as an input. Imported OODS with beta1 uses rolling source rebuild; beta2 (D2) remains the full workspace branch. A new Poseidon/36-byte PCS ABI is outside the supported format. Canonical source-group/tree partitions are required so repeated groups cannot undercharge coefficient-log uploads. Large count headers, malformed spans and incompatible FRI/source geometry are rejected.

Production owner enforcement, borrowed-lease exactness, preparation/ingress/readback host allocations and physical retirement are not qualified here. `host_cost_known=false`; no PCS coverage bit is enabled. The planner must refuse an unknown host cost. The cost helper alone does not close the M7 memory gate or permit a GKR request.
