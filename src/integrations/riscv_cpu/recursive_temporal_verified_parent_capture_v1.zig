//! Fail-atomic owner for the first real temporal-parent proof transaction.
//!
//! The native parent gate publishes through a consumer callback so ordinary
//! tests can discard its large proof capture. Multi-level recursion instead
//! moves the publication, artifact, capture, composition graph, and receipt
//! into this single owner; partial or duplicate publication is rejected.

const std = @import("std");

const driver = @import("recursive_binary_outer.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const composition_mod = @import("recursive_temporal_level2_composition_v1.zig");
const suffix_mod = @import("recursive_temporal_level2_suffix_v1.zig");

pub const VerifiedParentCaptureV1 = struct {
    allocator: std.mem.Allocator,
    publication: ?publication_mod.VerifiedPublicationV1 = null,
    artifact: ?artifact_mod.VerifiedTemporalParentArtifactV1 = null,
    capture: ?driver.OuterProofCapture = null,
    composition: ?composition_mod.CaptureV1 = null,
    receipt: ?driver.Receipt = null,

    pub fn init(allocator: std.mem.Allocator) VerifiedParentCaptureV1 {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *VerifiedParentCaptureV1) void {
        if (self.composition) |*composition| composition.deinit();
        if (self.capture) |*capture| capture.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn validate(self: *VerifiedParentCaptureV1) !void {
        const publication = if (self.publication) |*value|
            value
        else
            return error.MissingParentPublication;
        const artifact = if (self.artifact) |*value|
            value
        else
            return error.MissingParentPublication;
        const capture = if (self.capture) |*value|
            value
        else
            return error.MissingParentPublication;
        const composition = if (self.composition) |*value|
            value
        else
            return error.MissingParentPublication;
        const receipt = self.receipt orelse
            return error.MissingParentPublication;
        try publication.validate();
        try artifact.validateAgainst(publication);
        try artifact.recursive_admission.validateAgainst(capture);
        try composition.validateRetained();
        if (!std.meta.eql(publication.capture_id, composition.capture_id) or
            !std.meta.eql(artifact.artifact_id, composition.artifact_id) or
            receipt.canonical_proof_bytes != publication.canonical_proof_byte_count)
        {
            return error.ParentPublicationMismatch;
        }
    }

    /// Consumer contract used by `proveTemporalParentWithConsumer`. Returning
    /// true transfers both allocation-owning captures to this owner.
    pub fn consume(
        self: *VerifiedParentCaptureV1,
        publication: *const publication_mod.VerifiedPublicationV1,
        artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
        capture: *driver.OuterProofCapture,
        composition: *composition_mod.CaptureV1,
        receipt: driver.Receipt,
    ) !bool {
        if (self.publication != null or self.artifact != null or
            self.capture != null or self.composition != null or
            self.receipt != null)
        {
            return error.DuplicateParentPublication;
        }
        try publication.validate();
        try artifact.validateAgainst(publication);
        try artifact.recursive_admission.validateAgainst(capture);
        try composition.validateRetained();
        self.publication = publication.*;
        self.artifact = artifact.*;
        self.capture = capture.*;
        self.composition = composition.*;
        self.receipt = receipt;
        try self.validate();
        return true;
    }

    pub fn childInput(self: *VerifiedParentCaptureV1) !suffix_mod.ChildInputV1 {
        try self.validate();
        return .{
            .publication = &self.publication.?,
            .artifact = &self.artifact.?,
            .capture = &self.capture.?,
            .composition = &self.composition.?,
        };
    }
};
