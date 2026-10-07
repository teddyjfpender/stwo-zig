//! Verified V2 outer transaction staged for a globally positioned V3 leaf.
//!
//! The 39-row proof authenticates the bounded local V2 child. Global V3
//! position remains a checked host link until the separate V3 wrapper cohort
//! proves the typed link/arithmetic, child field authorities and LogUp closure.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");
const outer_engine = @import("recursive_segment_v2_outer_engine.zig");

const recursion = frontend.recursion;
const stage_manifest = recursion.segment_leaf_wrapper_stage_manifest_v3;

pub const V3_RECURSIVE_PUBLICATION_AVAILABLE = false;
pub const VerifiedLocalOuterStage = struct {
    receipt: outer_engine.Receipt,
    capture: outer_engine.OuterProofCapture,
    publication: outer_engine.VerifiedSegmentV2PublicationV1,
    recursive_witness: outer_engine.RecursiveWitnessV1,
    manifest: stage_manifest.StageManifestV3,

    pub fn deinit(self: *VerifiedLocalOuterStage, allocator: std.mem.Allocator) void {
        self.capture.deinit(allocator);
        self.* = undefined;
    }

    pub fn requireRecursiveV3Publication(self: *const VerifiedLocalOuterStage) error{V3WrapperProofUnavailable}!void {
        return self.manifest.requireRecursiveV3Publication();
    }
};

/// The only stage constructor: the concrete V2 outer kernel independently
/// rebuilds its prover and verifier cohorts, verifies the canonical proof,
/// and mints the local publication before the host V3 join is checked.
pub fn proveAndVerifyPrepared(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    global: *const recursion.segment_leaf_local_authority_v3.MetadataV3,
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
    execution: outer_engine.ExecutionOptions,
) !VerifiedLocalOuterStage {
    try prepared.validate();
    try link.validateAgainst(
        global,
        &prepared.capture.public_data.data,
        &prepared.capture.receipt,
    );
    const Kernel = outer_engine.EngineKernel(outer_cohort.Cohort);
    var capture: outer_engine.OuterProofCapture = undefined;
    var publication: outer_engine.VerifiedSegmentV2PublicationV1 = undefined;
    var recursive_witness: outer_engine.RecursiveWitnessV1 = undefined;
    const receipt = try Kernel.proveAndVerifyWithExecution(
        allocator,
        prepared,
        execution,
        &capture,
        &publication,
        &recursive_witness,
    );
    errdefer capture.deinit(allocator);
    try receipt.validate();
    try publication.validate();
    const manifest = try stage_manifest.StageManifestV3.init(
        global,
        link,
        &prepared.capture.public_data.data,
        &prepared.capture.receipt,
        &publication,
    );
    return .{
        .receipt = receipt,
        .capture = capture,
        .publication = publication,
        .recursive_witness = recursive_witness,
        .manifest = manifest,
    };
}
