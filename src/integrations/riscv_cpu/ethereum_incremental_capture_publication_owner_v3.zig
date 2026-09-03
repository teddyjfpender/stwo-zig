//! Process-local transaction owner for retained-authority STWIMT03 capture.
//!
//! Resume never restores VM state.  The caller reexecutes the deterministic
//! session from segment zero; this owner recomputes every compact tape and
//! transition from that live execution, byte-compares a durable prefix, and
//! adopts or publishes only after a full V3 cold reconstruction succeeds.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v3 = @import("ethereum_incremental_boundary_artifact_v3.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const capture_mod = @import("ethereum_incremental_boundary_capture_v2.zig");
const publication = @import("ethereum_incremental_capture_publication_v3.zig");

pub const PRODUCTION_ACTIVE = false;
pub const NATIVE_PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;

pub const PublicationOwnerV3 = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    capture: *capture_mod.SessionCaptureV2,
    execution: publication.ExecutionAuthorityV3,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    committed: std.ArrayList(publication.CommittedSegmentV3) = .empty,
    sealed: bool = false,

    pub fn initCreateOnly(
        allocator: std.mem.Allocator,
        parent: []const u8,
        basename: []const u8,
        capture: *capture_mod.SessionCaptureV2,
        execution: publication.ExecutionAuthorityV3,
    ) !PublicationOwnerV3 {
        const root = try artifact_io.resolveCreateOnlyChild(
            allocator,
            parent,
            basename,
        );
        artifact_io.createDirectoryCreateOnly(root) catch |err| {
            allocator.free(root);
            return err;
        };
        return initOwnedRoot(allocator, root, capture, execution);
    }

    pub fn initExisting(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        capture: *capture_mod.SessionCaptureV2,
        execution: publication.ExecutionAuthorityV3,
    ) !PublicationOwnerV3 {
        const root = try artifact_io.resolveAbsolute(allocator, root_path);
        return initOwnedRoot(allocator, root, capture, execution);
    }

    fn initOwnedRoot(
        allocator: std.mem.Allocator,
        root: []u8,
        capture: *capture_mod.SessionCaptureV2,
        execution: publication.ExecutionAuthorityV3,
    ) !PublicationOwnerV3 {
        errdefer allocator.free(root);
        try execution.validate();
        if (capture.poisoned or capture.nextSegmentIndex() != 0)
            return error.InvalidIncrementalCaptureSessionV3;
        const expected_session = try execution.sessionIdentity();
        const actual_session = capture.sessionIdentity();
        if (!std.mem.eql(
            u8,
            &actual_session,
            &expected_session,
        )) return error.IncrementalCaptureSessionIdentityMismatchV3;
        const manifest_path = try publication.manifestPathAlloc(allocator, root);
        defer allocator.free(manifest_path);
        try publication.requireAbsent(manifest_path);
        return .{
            .allocator = allocator,
            .root = root,
            .capture = capture,
            .execution = execution,
            .initial_root = capture.currentRoot(),
            .initial_prior_authority_id = capture.priorAuthorityId(),
        };
    }

    pub fn deinit(self: *PublicationOwnerV3) void {
        self.committed.deinit(self.allocator);
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn publishedCount(self: *const PublicationOwnerV3) u32 {
        return @intCast(self.committed.items.len);
    }

    /// The caller must validate a terminal segment's exact output before this
    /// method is entered.  That ordering is enforced by the sibling observer,
    /// not represented as a caller-selected boolean in the durable wire.
    pub fn captureAndPublish(
        self: *PublicationOwnerV3,
        segment_index: u32,
        snapshot: *const frontend.runner.memory_state.Snapshot,
        replay_touched_addresses: []const u32,
        expected_entry_root: u32,
        expected_exit_root: u32,
        compact_bytes: []const u8,
        source: publication.ArtifactIdentityV3,
        journal_record_sha256: [32]u8,
        segment_public_wire: *const frontend.air.public_data_v2.PublicDataV2,
        public_authority: boundary_v3.SegmentPublicAuthorityV3,
    ) !publication.CommittedSegmentV3 {
        try self.requireOpenNext(segment_index);
        try source.validate(false);
        if (allZero(&journal_record_sha256))
            return error.InvalidJournalRecordIdentityV3;
        const compact_identity = publication.ArtifactIdentityV3.fromBytes(
            compact_bytes,
        );
        try publishOrCompare(
            self.allocator,
            try publication.compactTapePathAlloc(
                self.allocator,
                self.root,
                segment_index,
            ),
            compact_bytes,
            frontend.runner.minimal_trace.ethereum_wire.MAX_ENCODED_BYTES,
        );

        var transition = try self.capture.apply(
            segment_index,
            snapshot,
            replay_touched_addresses,
            expected_entry_root,
            expected_exit_root,
        );
        defer transition.deinit();
        const transition_bytes = try artifact_v2.encodeAlloc(
            self.allocator,
            &transition,
            artifact_v2.default_limits,
        );
        defer self.allocator.free(transition_bytes);
        const artifact_bytes = try artifact_v3.encodeAlloc(
            self.allocator,
            transition_bytes,
            segment_public_wire,
            artifact_v3.default_limits,
        );
        defer self.allocator.free(artifact_bytes);
        const artifact_path = try publication.segmentArtifactPathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(artifact_path);
        try publishOrCompareOwned(
            self.allocator,
            artifact_path,
            artifact_bytes,
            artifact_v3.default_limits.max_bytes,
        );

        var decoded = try artifact_v3.decodeAlloc(
            self.allocator,
            artifact_bytes,
            artifact_v3.default_limits,
        );
        defer decoded.deinit();
        var reconstructed = try artifact_v3.coldReconstruct(
            self.allocator,
            &decoded,
            segment_public_wire,
            public_authority,
            artifact_v3.default_limits,
        );
        defer reconstructed.deinit();

        const expected_ref = segmentRef(
            &decoded,
            publication.ArtifactIdentityV3.fromBytes(artifact_bytes),
            compact_identity,
            source,
            journal_record_sha256,
        );
        const ref_bytes = try publication.encodeSegmentRefAlloc(
            self.allocator,
            expected_ref,
        );
        defer self.allocator.free(ref_bytes);
        const ref_path = try publication.segmentReferencePathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(ref_path);
        try publishOrCompareOwned(
            self.allocator,
            ref_path,
            ref_bytes,
            publication.segment_ref_byte_count,
        );

        var opened = try publication.coldOpenSegment(
            self.allocator,
            self.root,
            segment_index,
            false,
        );
        defer opened.deinit();
        if (!std.meta.eql(opened.reference.segment, expected_ref))
            return error.IncrementalCaptureSegmentRefMismatchV3;
        var reopened = try artifact_v3.coldReconstruct(
            self.allocator,
            &opened.artifact,
            segment_public_wire,
            public_authority,
            artifact_v3.default_limits,
        );
        defer reopened.deinit();
        try self.committed.append(self.allocator, opened.reference);
        return opened.reference;
    }

    pub fn finalize(
        self: *PublicationOwnerV3,
        final_bindings: publication.FinalBindingsV3,
    ) !publication.OwnedManifestV3 {
        if (self.sealed) return error.IncrementalCaptureAlreadySealedV3;
        if (self.committed.items.len != self.execution.segment_count or
            self.capture.nextSegmentIndex() != self.execution.segment_count or
            self.capture.poisoned)
        {
            return error.IncompleteIncrementalCapturePublicationV3;
        }
        try final_bindings.validate();
        const encoded = try publication.encodeManifestAlloc(
            self.allocator,
            self.execution,
            final_bindings,
            self.initial_root,
            self.initial_prior_authority_id,
            self.capture.currentRoot(),
            self.capture.priorAuthorityId(),
            self.committed.items,
        );
        defer self.allocator.free(encoded);
        const path = try publication.manifestPathAlloc(self.allocator, self.root);
        defer self.allocator.free(path);
        try artifact_io.publishCreateOnlyDurable(path, encoded);
        var cold = try publication.coldOpenPublication(
            self.allocator,
            self.root,
            self.execution,
            final_bindings,
        );
        errdefer cold.deinit();
        self.sealed = true;
        return cold;
    }

    fn requireOpenNext(
        self: *const PublicationOwnerV3,
        segment_index: u32,
    ) !void {
        if (self.sealed) return error.IncrementalCaptureAlreadySealedV3;
        const expected = std.math.cast(u32, self.committed.items.len) orelse
            return error.IncrementalCaptureSizeOverflowV3;
        if (segment_index != expected or
            self.capture.nextSegmentIndex() != expected)
        {
            return error.SegmentIndexMismatch;
        }
    }
};

fn segmentRef(
    artifact: *const artifact_v3.OwnedArtifactV3,
    artifact_identity: publication.ArtifactIdentityV3,
    compact_identity: publication.ArtifactIdentityV3,
    source: publication.ArtifactIdentityV3,
    journal_record_sha256: [32]u8,
) publication.SegmentRefV3 {
    const authority = artifact.transition_v2.authority;
    return .{
        .segment_index = artifact.coordinate.segment_index,
        .segment_count = artifact.coordinate.segment_count,
        .entry_root = authority.entry_root,
        .exit_root = authority.exit_root,
        .touched_word_count = @intCast(authority.touched_words.len),
        .changed_word_count = authority.changed_word_count,
        .frontier_node_count = @intCast(authority.frontier_nodes.len),
        .entry_hash_calls = authority.work.entry_hash_calls,
        .exit_hash_calls = authority.work.exit_hash_calls,
        .total_hash_calls = authority.work.total_hash_calls,
        .max_shard_log = authority.work.max_shard_log,
        .artifact = artifact_identity,
        .compact_tape = compact_identity,
        .source = source,
        .artifact_content_sha256 = artifact.content_sha256,
        .transition_v2_content_sha256 = artifact.transition_v2.content_sha256,
        .segment_public_wire_id = artifact.segment_public_wire_id,
        .journal_record_sha256 = journal_record_sha256,
        .prior_authority_id = authority.prior_authority_id,
        .authority_id = authority.authority_id,
    };
}

fn publishOrCompare(
    allocator: std.mem.Allocator,
    owned_path: []u8,
    expected: []const u8,
    max_bytes: usize,
) !void {
    defer allocator.free(owned_path);
    return publishOrCompareOwned(allocator, owned_path, expected, max_bytes);
}

fn publishOrCompareOwned(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    max_bytes: usize,
) !void {
    if (!try publication.pathExists(path)) {
        try artifact_io.publishCreateOnlyDurable(path, expected);
        return;
    }
    const retained = try artifact_io.readFileBounded(allocator, path, max_bytes);
    defer allocator.free(retained);
    if (!std.mem.eql(u8, retained, expected))
        return error.IncrementalCaptureResumeArtifactMismatchV3;
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}
