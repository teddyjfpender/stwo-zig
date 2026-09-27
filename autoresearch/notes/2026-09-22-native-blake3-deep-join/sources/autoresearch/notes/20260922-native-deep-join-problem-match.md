# Native BLAKE3 PCS/DEEP sample join

Task: reuse canonical DEEP graph on a real BLAKE3 V2 capture and join its scalar
sample inputs to the native composition/encoding producers. Mandated algorithms:
existing PCS quotient graph, geometry expansion and scalar wire routing. No new
cryptography or arithmetic law. Source authorities: GeometryV2 from native profile,
pcs_arithmetic_capture.Owned, pcs_deep_circuit, blake3_sample_links and shared
arithmetic use counts. Exact keyed join on sample index and coordinate; O(nodes
+ samples) work/storage, apart from existing graph compilation/validation.
Invariants: geometry comes from authenticated native profile, not proof values;
all four sample coordinates mapped once; real capture must satisfy DEEP outputs;
composition source multiplicity increases exactly once per DEEP input; DEEP
consumer uses graph-derived counts. Reject altered sample values and geometry.
Validation: real native BLAKE3 capture, complete sample route/value parity, altered
sample rejected by canonical DEEP evaluator. No performance claim; complete parent
and public-boundary authority still required.
