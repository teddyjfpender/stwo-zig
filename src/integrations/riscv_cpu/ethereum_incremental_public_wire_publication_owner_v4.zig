//! Create-only transaction owner for the STWIPW04 companion publication.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const capture = @import("ethereum_incremental_capture_publication_v4.zig");
const publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;

pub const PublicationOwnerV4 = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    execution: capture.ExecutionAuthorityV4,
    committed: std.ArrayList(publication.CommittedSegmentV4) = .empty,
    sealed: bool = false,

    pub fn initExisting(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        execution: capture.ExecutionAuthorityV4,
    ) !PublicationOwnerV4 {
        try execution.validate();
        const root = try artifact_io.resolveAbsolute(allocator, root_path);
        errdefer allocator.free(root);
        const manifest_path = try publication.manifestPathAlloc(allocator, root);
        defer allocator.free(manifest_path);
        try capture.requireAbsent(manifest_path);
        return .{
            .allocator = allocator,
            .root = root,
            .execution = execution,
        };
    }

    pub fn deinit(self: *PublicationOwnerV4) void {
        self.committed.deinit(self.allocator);
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn publishedCount(self: *const PublicationOwnerV4) u32 {
        return @intCast(self.committed.items.len);
    }

    /// Publish or cold-adopt one wire only after its STWIMR04 is durable.
    pub fn captureAndPublish(
        self: *PublicationOwnerV4,
        public_wire: *const frontend.air.public_data_v2.PublicDataV2,
        v4_segment: capture.CommittedSegmentV4,
    ) !publication.CommittedSegmentV4 {
        if (self.sealed) return error.IncrementalPublicWireAlreadySealedV4;
        try v4_segment.validate();
        const expected_index = std.math.cast(u32, self.committed.items.len) orelse
            return error.IncrementalPublicWireSizeOverflowV4;
        if (v4_segment.segment.segment_index != expected_index or
            v4_segment.segment.segment_count != self.execution.segment_count)
        {
            return error.SegmentIndexMismatch;
        }
        try public_wire.validate();
        if (!std.meta.eql(
            public_wire.wireId(),
            v4_segment.segment.segment_public_wire_id,
        )) return error.IncrementalPublicWireSegmentBindingMismatchV4;

        const coordinate = publication.CoordinateV4{
            .segment_index = expected_index,
            .segment_count = self.execution.segment_count,
        };
        const wire_bytes = try publication.encodeWireAlloc(
            self.allocator,
            coordinate,
            public_wire,
        );
        defer self.allocator.free(wire_bytes);
        const wire_path = try publication.wirePathAlloc(
            self.allocator,
            self.root,
            expected_index,
        );
        defer self.allocator.free(wire_path);
        try publishOrCompare(
            self.allocator,
            wire_path,
            wire_bytes,
            publication.max_wire_bytes,
        );

        const expected_ref = publication.SegmentRefV4{
            .coordinate = coordinate,
            .wire_id = public_wire.wireId(),
            .wire_artifact = capture.ArtifactIdentityV4.fromBytes(wire_bytes),
            .v4_segment_reference = v4_segment.reference,
            .source = v4_segment.segment.source,
            .journal_record_sha256 = v4_segment.segment.journal_record_sha256,
        };
        const ref_bytes = try publication.encodeSegmentRefAlloc(
            self.allocator,
            expected_ref,
        );
        defer self.allocator.free(ref_bytes);
        const ref_path = try publication.referencePathAlloc(
            self.allocator,
            self.root,
            expected_index,
        );
        defer self.allocator.free(ref_path);
        try publishOrCompare(
            self.allocator,
            ref_path,
            ref_bytes,
            publication.reference_byte_count,
        );

        var opened = try publication.coldOpenSegment(
            self.allocator,
            self.root,
            expected_index,
            v4_segment,
        );
        defer opened.deinit();
        if (!std.meta.eql(opened.reference.segment, expected_ref))
            return error.IncrementalPublicWireSegmentBindingMismatchV4;
        try self.committed.append(self.allocator, opened.reference);
        return opened.reference;
    }

    /// STWIPF04 is the last publication and is accepted only after STWIMF04
    /// has been durably published and independently identified.
    pub fn finalize(
        self: *PublicationOwnerV4,
        final_bindings: capture.FinalBindingsV4,
        v4_manifest: capture.ArtifactIdentityV4,
    ) !publication.OwnedManifestV4 {
        if (self.sealed) return error.IncrementalPublicWireAlreadySealedV4;
        if (self.committed.items.len != self.execution.segment_count)
            return error.IncompleteIncrementalPublicWirePublicationV4;
        try final_bindings.validate();
        try v4_manifest.validate(false);
        const bytes = try publication.encodeManifestAlloc(
            self.allocator,
            self.execution,
            final_bindings,
            v4_manifest,
            self.committed.items,
        );
        defer self.allocator.free(bytes);
        const path = try publication.manifestPathAlloc(self.allocator, self.root);
        defer self.allocator.free(path);
        try artifact_io.publishCreateOnlyDurable(path, bytes);
        var cold = try publication.coldOpenPublication(
            self.allocator,
            self.root,
            self.execution,
            final_bindings,
            v4_manifest,
        );
        errdefer cold.deinit();
        self.sealed = true;
        return cold;
    }
};

fn publishOrCompare(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    max_bytes: usize,
) !void {
    artifact_io.publishCreateOnlyDurable(path, expected) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const retained = try artifact_io.readFileBounded(
                allocator,
                path,
                max_bytes,
            );
            defer allocator.free(retained);
            if (!std.mem.eql(u8, retained, expected))
                return error.IncrementalPublicWireResumeArtifactMismatchV4;
        },
        else => return err,
    };
}
