//! Owned, re-admissible output of one successfully verified temporal node.
//!
//! Publication, artifact, proof capture, and composition graph cross the
//! verifier transaction together. A caller cannot construct this value from
//! proof bytes: the artifact requires the opaque success evidence minted only
//! after the native verifier and global-closure replay both succeed.

const std = @import("std");

const driver = @import("recursive_binary_outer.zig");
const pair_mod = @import("recursive_temporal_parent_pair_authority_v1.zig");
const cohort_mod = @import("recursive_temporal_level2_cohort_v1.zig");
const suffix_mod = @import("recursive_temporal_level2_suffix_v1.zig");
const composition_mod = @import("recursive_temporal_level2_composition_v1.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const MINIMUM_HEIGHT: u8 = pair_mod.FIRST_MULTI_LEVEL_HEIGHT;

pub const ChildInputV1 = suffix_mod.ChildInputV1;
pub const PairV1 = pair_mod.PreparedTemporalNodePairV1;

const Kernel = driver.NativeEngineKernelForManifest(
    cohort_mod.Cohort,
    manifest_mod,
);

pub const VerifiedTemporalNodeV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    publication: publication_mod.VerifiedPublicationV1,
    artifact: artifact_mod.VerifiedTemporalParentArtifactV1,
    capture: driver.OuterProofCapture,
    composition: composition_mod.CaptureV1,
    receipt: driver.Receipt,

    pub fn deinit(self: *VerifiedTemporalNodeV1) void {
        const allocator = self.allocator;
        self.composition.deinit();
        self.capture.deinit(allocator);
        self.* = undefined;
    }

    pub fn validate(self: *VerifiedTemporalNodeV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidTemporalNode;
        }
        try self.artifact.validateAgainst(&self.publication);
        try self.artifact.recursive_admission.validateAgainst(&self.capture);
        try self.composition.validateRetained();
        const statement = try self.artifact.child.statement();
        if (statement.slots.height < MINIMUM_HEIGHT or
            !std.meta.eql(self.publication.capture_id, self.composition.capture_id) or
            !std.meta.eql(self.artifact.artifact_id, self.composition.artifact_id) or
            self.receipt.canonical_proof_bytes !=
                self.publication.canonical_proof_byte_count)
        {
            return error.InvalidTemporalNode;
        }
    }

    pub fn childInput(self: *VerifiedTemporalNodeV1) ChildInputV1 {
        return .{
            .publication = &self.publication,
            .artifact = &self.artifact,
            .capture = &self.capture,
            .composition = &self.composition,
        };
    }
};

/// Proves, independently verifies, and then records the exact authenticated
/// composition graph before publishing one owned node. All caller-visible
/// state is written only after every fallible stage succeeds.
pub fn proveAndVerify(
    allocator: std.mem.Allocator,
    pair: *const PairV1,
    children: [2]ChildInputV1,
    execution: driver.ExecutionOptions,
) !VerifiedTemporalNodeV1 {
    try pair.validate();
    for (children) |child| try child.validate();
    const inputs = cohort_mod.AuthorityInputs{
        .pair = pair,
        .children = children,
    };
    var capture: driver.OuterProofCapture = undefined;
    var publication: publication_mod.VerifiedPublicationV1 = undefined;
    var artifact: artifact_mod.VerifiedTemporalParentArtifactV1 = undefined;
    const receipt = try Kernel.proveAndVerifyWithExecutionAndArtifact(
        allocator,
        inputs,
        execution,
        &capture,
        &publication,
        &artifact,
    );
    errdefer capture.deinit(allocator);

    var cohort = try cohort_mod.Cohort.init(allocator, inputs);
    defer cohort.deinit();
    var composition = try composition_mod.CaptureV1.initForCohort(
        cohort_mod.Cohort,
        allocator,
        &cohort,
        &capture,
        &publication,
        &artifact,
    );
    errdefer composition.deinit();

    var result = VerifiedTemporalNodeV1{
        .allocator = allocator,
        .publication = publication,
        .artifact = artifact,
        .capture = capture,
        .composition = composition,
        .receipt = receipt,
    };
    try result.validate();
    return result;
}
