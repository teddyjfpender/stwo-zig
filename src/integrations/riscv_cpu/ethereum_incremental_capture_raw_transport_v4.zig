//! Early create-only custody for the two VM-produced restart authorities.
//!
//! A live segment callback may publish STWEMT01 and STWIPW04 here before any
//! incremental-transition work begins.  A crash between the two files is
//! resumed by recomputing and byte-comparing both from the deterministic VM
//! execution.  This owner deliberately cannot publish STWIMT04, STWIMR04,
//! STWIPR04, or either seal-last manifest; those belong to cold postprocessing.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const capture = @import("ethereum_incremental_capture_publication_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const minimal = frontend.runner.minimal_trace;
const public_data_v2 = frontend.air.public_data_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const segment_v2 = frontend.recursion.segment_statement_v2;

pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const VM_REEXECUTION_REQUIRED_FOR_MISSING_RAW = true;
pub const TRANSITION_PUBLICATION_DEFERRED = true;
pub const PUBLIC_WIRE_REFERENCE_DEFERRED = true;

pub const RawSegmentV4 = struct {
    segment_index: u32,
    segment_count: u32,
    compact_tape: capture.ArtifactIdentityV4,
    public_wire: capture.ArtifactIdentityV4,
    public_wire_id: public_data_v2.Digest,

    pub fn validate(self: RawSegmentV4) !void {
        try self.compact_tape.validate(false);
        try self.public_wire.validate(false);
        if (self.segment_count < 2 or
            self.segment_count > capture.MAX_SEGMENT_COUNT or
            self.segment_index >= self.segment_count or
            allZero(std.mem.asBytes(&self.public_wire_id)))
        {
            return error.InvalidIncrementalRawSegmentV4;
        }
    }
};

/// This is an ordered transport owner, not an execution-resume capability.
/// Existing bytes grant no authority: every call receives freshly recomputed
/// canonical values and compares their complete bytes before advancing.
pub const EarlyRawOwnerV4 = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    execution: capture.ExecutionAuthorityV4,
    next_segment_index: u32 = 0,

    pub fn initExisting(
        allocator: std.mem.Allocator,
        root_path: []const u8,
        execution: capture.ExecutionAuthorityV4,
    ) !EarlyRawOwnerV4 {
        try execution.validate();
        const root = try artifact_io.resolveAbsolute(allocator, root_path);
        errdefer allocator.free(root);
        const transition_manifest = try capture.manifestPathAlloc(
            allocator,
            root,
        );
        defer allocator.free(transition_manifest);
        const wire_manifest = try wire_publication.manifestPathAlloc(
            allocator,
            root,
        );
        defer allocator.free(wire_manifest);
        try capture.requireAbsent(transition_manifest);
        try capture.requireAbsent(wire_manifest);
        return .{
            .allocator = allocator,
            .root = root,
            .execution = execution,
        };
    }

    pub fn deinit(self: *EarlyRawOwnerV4) void {
        self.allocator.free(self.root);
        self.* = undefined;
    }

    pub fn publishedCount(self: *const EarlyRawOwnerV4) u32 {
        return self.next_segment_index;
    }

    /// Publish the exact existing codecs in the required early order:
    /// STWEMT01 first, then STWIPW04.  No reference is minted here.
    pub fn publishOrCompareLive(
        self: *EarlyRawOwnerV4,
        segment_index: u32,
        compact_bytes: []const u8,
        public_wire: *const public_data_v2.PublicDataV2,
        retained: *const global_v3.MetadataV3,
    ) !RawSegmentV4 {
        if (segment_index != self.next_segment_index or
            segment_index >= self.execution.segment_count)
        {
            return error.SegmentIndexMismatch;
        }
        var compact = try minimal.decodeEthereumMinimalArtifactAlloc(
            self.allocator,
            compact_bytes,
        );
        defer compact.deinit();
        if (compact.leaf.segment_index != segment_index)
            return error.IncrementalRawCompactCoordinateMismatchV4;

        const session_identity = try self.execution.sessionIdentity();
        const metadata = try validateWireAgainstRetainedMetadata(
            public_wire,
            retained,
            support.sessionDigest(session_identity),
        );
        if (metadata.segment_index != segment_index or
            metadata.segment_count != self.execution.segment_count)
        {
            return error.IncrementalRawPublicWireCoordinateMismatchV4;
        }
        try requireSameExecutionBoundary(&compact, metadata, retained);

        const wire_bytes = try wire_publication.encodeWireAlloc(
            self.allocator,
            .{
                .segment_index = segment_index,
                .segment_count = self.execution.segment_count,
            },
            public_wire,
        );
        defer self.allocator.free(wire_bytes);

        // This ordering is part of the restart contract. A failure during the
        // second publication leaves a safely comparable STWEMT01 prefix.
        const compact_path = try capture.compactTapePathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(compact_path);
        try publishOrCompare(
            self.allocator,
            compact_path,
            compact_bytes,
            minimal.ethereum_wire.MAX_ENCODED_BYTES,
        );
        const wire_path = try wire_publication.wirePathAlloc(
            self.allocator,
            self.root,
            segment_index,
        );
        defer self.allocator.free(wire_path);
        try publishOrCompare(
            self.allocator,
            wire_path,
            wire_bytes,
            wire_publication.max_wire_bytes,
        );

        const result = RawSegmentV4{
            .segment_index = segment_index,
            .segment_count = self.execution.segment_count,
            .compact_tape = capture.ArtifactIdentityV4.fromBytes(compact_bytes),
            .public_wire = capture.ArtifactIdentityV4.fromBytes(wire_bytes),
            .public_wire_id = public_wire.wireId(),
        };
        try result.validate();
        self.next_segment_index += 1;
        return result;
    }

    pub fn requireComplete(self: *const EarlyRawOwnerV4) !void {
        if (self.next_segment_index != self.execution.segment_count)
            return error.IncompleteIncrementalRawPublicationV4;
    }
};

fn requireSameExecutionBoundary(
    compact: *const minimal.EthereumMinimalArtifactV1,
    metadata: public_data_v2.Metadata,
    retained: *const global_v3.MetadataV3,
) !void {
    const local_cycles = std.math.sub(
        u32,
        metadata.global_cycle_end,
        metadata.global_cycle_start,
    ) catch return error.IncrementalRawExecutionBoundaryMismatchV4;
    const expected_first_cycle = std.math.add(
        u64,
        retained.global_cycle_start,
        1,
    ) catch return error.IncrementalRawExecutionBoundaryMismatchV4;
    if (compact.leaf.global_first_cycle != expected_first_cycle or
        compact.leaf.cycle_count != local_cycles or
        compact.leaf.cycle_count != retained.local_cycle_count or
        !std.meta.eql(compact.leaf.entry_cpu, cpu(metadata.entry_cpu)) or
        !std.meta.eql(compact.leaf.exit_cpu, cpu(metadata.exit_cpu)))
    {
        return error.IncrementalRawExecutionBoundaryMismatchV4;
    }
}

/// Exact local-wire projection check shared with the VM-free postprocessor.
/// Snapshot tuple IDs/counts are replayed while only the independently sealed
/// STWESG31 continuation roots are reused.
pub fn validateWireAgainstRetainedMetadata(
    public_wire: *const public_data_v2.PublicDataV2,
    retained: *const global_v3.MetadataV3,
    expected_session_id: segment_v2.Digest,
) !public_data_v2.Metadata {
    try retained.validate();
    const view = try segment_v2.authenticateCanonicalWireReusingRoots(
        public_wire.words(),
        snapshot(&retained.entry),
        snapshot(&retained.exit),
    );
    const local = try projection_v3.localStatementFromMetadata(retained);
    const local_words = try local.canonicalWords();
    const metadata = try public_wire.metadata();
    if (!std.meta.eql(view.statement.base_statement_words, local_words) or
        !std.meta.eql(view.statement.session_id, expected_session_id) or
        !std.meta.eql(view.statement.entry_snapshot_id, retained.entry.snapshot_id) or
        view.statement.entry_snapshot_count != retained.entry.snapshot_count or
        view.statement.entry_continuation_root != retained.entry.continuation_root or
        !std.meta.eql(view.statement.exit_snapshot_id, retained.exit.snapshot_id) or
        view.statement.exit_snapshot_count != retained.exit.snapshot_count or
        view.statement.exit_continuation_root != retained.exit.continuation_root or
        !std.meta.eql(
            view.statement.entry_memory_clock_id,
            retained.entry.memory_clock_id,
        ) or view.statement.entry_memory_clock_count !=
        retained.entry.memory_clock_count or
        !std.meta.eql(
            view.statement.exit_memory_clock_id,
            retained.exit.memory_clock_id,
        ) or view.statement.exit_memory_clock_count !=
        retained.exit.memory_clock_count or
        !std.meta.eql(
            view.statement.entry_register_clocks,
            retained.entry.register_clocks,
        ) or !std.meta.eql(
        view.statement.exit_register_clocks,
        retained.exit.register_clocks,
    ) or !std.meta.eql(view.statement.completion, retained.completion) or
        metadata.segment_index != retained.segment_index or
        metadata.segment_count != retained.segment_count or
        metadata.global_cycle_start != 0 or
        metadata.global_cycle_end != retained.local_cycle_count)
    {
        return error.IncrementalRawRetainedMetadataMismatchV4;
    }
    return metadata;
}

fn snapshot(value: *const global_v3.BoundaryV3) segment_v2.SnapshotIdentity {
    return .{
        .id = value.snapshot_id,
        .count = value.snapshot_count,
        .root = value.continuation_root,
    };
}

fn cpu(value: public_data_v2.CpuBoundary) frontend.runner.Cpu {
    return .{ .pc = value.pc, .regs = value.registers };
}

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
                return error.IncrementalRawResumeArtifactMismatchV4;
        },
        else => return err,
    };
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}
