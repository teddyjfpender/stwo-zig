//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const manifest_mod = context.d_manifest_mod;
        const SegmentPublication = context.d_SegmentPublication;
        const SegmentRecursiveWitness = context.d_SegmentRecursiveWitness;
        const OuterProofCapture = context.d_OuterProofCapture;

        pub const TemporalChildArtifactV2 = struct {
            manifest: *const manifest_mod.Manifest,
            publication: *const SegmentPublication,
            witness: *const SegmentRecursiveWitness,
            capture: *const OuterProofCapture,
        };

        // Owned, source-sealed row-1 authority for both authenticated child lanes.
        // Rows and provider calls share the same retained inputs; provider conversion
        // performs no permutation and allocates nothing.
    };
}
