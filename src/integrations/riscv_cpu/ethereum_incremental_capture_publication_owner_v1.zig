//! Process-local owner for create-only incremental-capture publication.
//!
//! The canonical wire and independent cold-open surface live in
//! `ethereum_incremental_capture_publication_v1.zig`. This owner borrows a
//! `SessionCaptureV2`, publishes artifacts before refs, and seals the manifest
//! last. It never creates proof or recursion admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_mod = @import("ethereum_incremental_boundary_artifact_v2.zig");
const capture_mod = @import("ethereum_incremental_boundary_capture_v2.zig");
const publication = @import("ethereum_incremental_capture_publication_v1.zig");

pub const PRODUCTION_ACTIVE = false;
pub const NATIVE_PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;

/// Owns publication ordering but borrows the process-local capture. A caller
/// may reconstruct that capture from the first authenticated snapshot and use
/// `resumeCommittedPrefix` to replay STWIMT02 transitions without VM execution.
pub const PublicationOwnerV1 = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    capture: *capture_mod.SessionCaptureV2,
    bindings: publication.SessionBindingsV1,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    committed: std.ArrayList(publication.CommittedSegmentV1) = .empty,
    sealed: bool = false,

    pub fn initCreateOnly(
        allocator: std.mem.Allocator,
        parent: []const u8,
        basename: []const u8,
        capture: *capture_mod.SessionCaptureV2,
        bindings: publication.SessionBindingsV1,
    ) !PublicationOwnerV1 {
        const root = try artifact_io.resolveCreateOnlyChild(
            allocator,
            parent,
            basename,
        );
        artifact_io.createDirectoryCreateOnly(root) catch |err| {
            allocator.free(root);
            return err;
        };
        return initOwnedRoot(allocator, root, capture, bindings);
    }

    pub fn initExisting(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        capture: *capture_mod.SessionCaptureV2,
        bindings: publication.SessionBindingsV1,
    ) !PublicationOwnerV1 {
        const root = try artifact_io.resolveAbsolute(allocator, root_path);
        return initOwnedRoot(allocator, root, capture, bindings);
    }

    fn initOwnedRoot(
        allocator: std.mem.Allocator,
        root: []u8,
        capture: *capture_mod.SessionCaptureV2,
        bindings: publication.SessionBindingsV1,
    ) !PublicationOwnerV1 {
        errdefer allocator.free(root);
        try bindings.validate();
        if (capture.poisoned or capture.nextSegmentIndex() != 0)
            return error.InvalidIncrementalCaptureSession;
        const manifest_path = try publication.manifestPathAlloc(
            allocator,
            root,
        );
        defer allocator.free(manifest_path);
        try publication.requireAbsent(
            manifest_path,
            publication.manifest_max_byte_count,
        );
        return .{
            .allocator = allocator,
            .root = root,
            .capture = capture,
            .bindings = bindings,
            .initial_root = capture.currentRoot(),
            .initial_prior_authority_id = capture.priorAuthorityId(),
        };
    }

    pub fn deinit(self: *PublicationOwnerV1) void {
        self.committed.deinit(self.allocator);
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn publishedCount(self: *const PublicationOwnerV1) u32 {
        return @intCast(self.committed.items.len);
    }

    pub fn captureAndPublish(
        self: *PublicationOwnerV1,
        segment_index: u32,
        snapshot: *const frontend.runner.memory_state.Snapshot,
        replay_touched_addresses: []const u32,
        expected_entry_root: u32,
        expected_exit_root: u32,
    ) !publication.CommittedSegmentV1 {
        try self.requireOpenNext(segment_index);
        const artifact_path = try publication.segmentArtifactPathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(artifact_path);
        const reference_path = try publication.segmentReferencePathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(reference_path);
        try publication.requireAbsent(
            artifact_path,
            artifact_mod.default_limits.max_bytes,
        );
        try publication.requireAbsent(
            reference_path,
            publication.segment_ref_byte_count,
        );

        var authority = try self.capture.apply(
            segment_index,
            snapshot,
            replay_touched_addresses,
            expected_entry_root,
            expected_exit_root,
        );
        defer authority.deinit();
        const encoded = try artifact_mod.encodeAlloc(
            self.allocator,
            &authority,
            artifact_mod.default_limits,
        );
        defer self.allocator.free(encoded);
        try artifact_io.publishCreateOnlyDurable(artifact_path, encoded);
        return self.adoptCommitted(segment_index, true);
    }

    /// Replays every complete contiguous artifact/ref pair. If a durable
    /// STWIMT02 exists without its ref (crash after artifact publication), the
    /// artifact is cold-validated and the missing ref is published before it
    /// is admitted. No VM instruction is executed by this path.
    pub fn resumeCommittedPrefix(self: *PublicationOwnerV1) !u32 {
        if (self.sealed) return error.IncrementalCaptureAlreadySealed;
        while (self.committed.items.len < publication.CANONICAL_SEGMENT_COUNT) {
            const index: u32 = @intCast(self.committed.items.len);
            const artifact_path = try publication.segmentArtifactPathAlloc(
                self.allocator,
                self.root,
                index,
            );
            defer self.allocator.free(artifact_path);
            if (!try publication.pathExists(
                artifact_path,
                artifact_mod.default_limits.max_bytes,
            )) {
                const reference_path = try publication.segmentReferencePathAlloc(
                    self.allocator,
                    self.root,
                    index,
                );
                defer self.allocator.free(reference_path);
                if (try publication.pathExists(
                    reference_path,
                    publication.segment_ref_byte_count,
                )) return error.IncrementalCaptureReferenceWithoutArtifact;
                break;
            }
            _ = try self.adoptCommitted(index, true);
        }
        return self.publishedCount();
    }

    pub fn finalize(self: *PublicationOwnerV1) !publication.OwnedManifestV1 {
        if (self.sealed) return error.IncrementalCaptureAlreadySealed;
        if (self.committed.items.len != publication.CANONICAL_SEGMENT_COUNT or
            self.capture.nextSegmentIndex() !=
                publication.CANONICAL_SEGMENT_COUNT or
            self.capture.poisoned)
        {
            return error.IncompleteIncrementalCapturePublication;
        }
        const encoded = try publication.encodeManifestAlloc(
            self.allocator,
            self.bindings,
            self.initial_root,
            self.initial_prior_authority_id,
            self.capture.currentRoot(),
            self.capture.priorAuthorityId(),
            self.committed.items,
        );
        defer self.allocator.free(encoded);
        const path = try publication.manifestPathAlloc(
            self.allocator,
            self.root,
        );
        defer self.allocator.free(path);
        try artifact_io.publishCreateOnlyDurable(path, encoded);
        var cold = try publication.coldOpenPublication(
            self.allocator,
            self.root,
            self.bindings,
        );
        errdefer cold.deinit();
        self.sealed = true;
        return cold;
    }

    fn requireOpenNext(
        self: *const PublicationOwnerV1,
        segment_index: u32,
    ) !void {
        if (self.sealed) return error.IncrementalCaptureAlreadySealed;
        const expected = std.math.cast(u32, self.committed.items.len) orelse
            return error.IncrementalCaptureSizeOverflow;
        if (segment_index != expected or
            self.capture.nextSegmentIndex() != expected)
        {
            return error.SegmentIndexMismatch;
        }
    }

    fn adoptCommitted(
        self: *PublicationOwnerV1,
        segment_index: u32,
        publish_missing_ref: bool,
    ) !publication.CommittedSegmentV1 {
        const expected = std.math.cast(u32, self.committed.items.len) orelse
            return error.IncrementalCaptureSizeOverflow;
        if (segment_index != expected) return error.SegmentIndexMismatch;
        var opened = try publication.coldOpenSegment(
            self.allocator,
            self.root,
            segment_index,
            publish_missing_ref,
        );
        defer opened.deinit();

        const next = self.capture.nextSegmentIndex();
        if (next == segment_index) {
            var replayed = self.capture.tree.apply(
                segment_index,
                opened.artifact.authority.touched_words,
            ) catch |err| {
                self.capture.poisoned = true;
                return err;
            };
            defer replayed.deinit();
            const replayed_bytes = try artifact_mod.encodeAlloc(
                self.allocator,
                &replayed,
                artifact_mod.default_limits,
            );
            defer self.allocator.free(replayed_bytes);
            if (!std.mem.eql(u8, replayed_bytes, opened.artifact_bytes)) {
                self.capture.poisoned = true;
                return error.IncrementalCaptureReplayMismatch;
            }
        } else if (next == std.math.add(u32, segment_index, 1) catch
            return error.SegmentIndexOverflow)
        {
            const actual_prior = self.capture.priorAuthorityId();
            if (self.capture.currentRoot() != opened.reference.segment.exit_root or
                !std.mem.eql(
                    u8,
                    &actual_prior,
                    &opened.reference.segment.authority_id,
                ))
            {
                return error.IncrementalCapturePendingMismatch;
            }
        } else return error.SegmentIndexMismatch;

        try self.committed.append(self.allocator, opened.reference);
        return opened.reference;
    }
};
