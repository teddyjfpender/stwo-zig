//! VM-free sequential mint and independently parallelizable cold publication.
//!
//! The caller must first cold-authenticate each retained STWEMT01/STWIPW04
//! pair against STWESG31, journal, ELF, input, and output.  This owner then
//! advances the one stateful sparse-tree authority chain in segment order and
//! emits self-contained `ColdJobV4` values. Jobs own no live capability and
//! may be cold-verified/published concurrently because every output path is
//! segment-disjoint. Manifests remain absent until every ordered result closes.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const boundary_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const public_data_v2 = frontend.air.public_data_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;

pub const PRODUCTION_ACTIVE = false;
pub const NATIVE_PROOF_ADMISSIBLE = false;
pub const VM_REEXECUTION_REQUIRED = false;
pub const SEQUENTIAL_AUTHORITY_MINT_REQUIRED = true;
pub const COLD_JOBS_PARALLELIZABLE = true;
pub const MANIFESTS_SEAL_LAST = true;

/// Exact cold-authenticated inputs for one chain step. The borrowed slices and
/// public values must outlive `SequentialMintOwnerV4.mint`; the returned job
/// owns all bytes required by its later publication.
pub const MintInputV4 = struct {
    segment_index: u32,
    compact_tape: publication.ArtifactIdentityV4,
    public_wire: publication.ArtifactIdentityV4,
    source: publication.ArtifactIdentityV4,
    journal_record_sha256: [32]u8,
    touched_words: []const boundary_v1.TouchedWordV1,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,

    pub fn validate(
        self: MintInputV4,
        execution: publication.ExecutionAuthorityV4,
    ) !void {
        try execution.validate();
        try self.compact_tape.validate(false);
        try self.public_wire.validate(false);
        try self.source.validate(false);
        if (self.segment_index >= execution.segment_count or
            allZero(&self.journal_record_sha256))
        {
            return error.InvalidIncrementalPostprocessInputV4;
        }
        const metadata = try self.segment_public_wire.metadata();
        try self.public_authority.validate();
        if (metadata.segment_index != self.segment_index or
            metadata.segment_count != execution.segment_count or
            self.public_authority.coordinate.segment_index != self.segment_index or
            self.public_authority.coordinate.segment_count != execution.segment_count or
            self.public_authority.continuation_roots.entry !=
                metadata.entry_continuation_root or
            self.public_authority.continuation_roots.exit !=
                metadata.exit_continuation_root)
        {
            return error.InvalidIncrementalPostprocessInputV4;
        }
    }
};

pub const ColdJobV4 = struct {
    allocator: std.mem.Allocator,
    segment_index: u32,
    artifact_bytes: []u8,
    segment_ref_bytes: []u8,
    public_ref_bytes: []u8,
    segment: publication.CommittedSegmentV4,
    public_segment: wire_publication.CommittedSegmentV4,

    pub fn deinit(self: *ColdJobV4) void {
        self.allocator.free(self.public_ref_bytes);
        self.allocator.free(self.segment_ref_bytes);
        self.allocator.free(self.artifact_bytes);
        self.* = undefined;
    }

    pub fn validate(self: *const ColdJobV4) !void {
        try self.segment.validate();
        try self.public_segment.validate();
        if (self.segment.segment.segment_index != self.segment_index or
            self.public_segment.segment.coordinate.segment_index !=
                self.segment_index or
            !std.meta.eql(
                self.segment.reference,
                publication.ArtifactIdentityV4.fromBytes(self.segment_ref_bytes),
            ) or !std.meta.eql(
            self.public_segment.reference,
            publication.ArtifactIdentityV4.fromBytes(self.public_ref_bytes),
        ) or !std.meta.eql(
            self.segment.segment.artifact,
            publication.ArtifactIdentityV4.fromBytes(self.artifact_bytes),
        ) or !std.meta.eql(
            try publication.decodeSegmentRef(self.segment_ref_bytes),
            self.segment.segment,
        ) or !std.meta.eql(
            try wire_publication.decodeSegmentRef(self.public_ref_bytes),
            self.public_segment.segment,
        )) return error.InvalidIncrementalColdJobV4;
    }
};

pub const ColdResultV4 = struct {
    segment: publication.CommittedSegmentV4,
    public_segment: wire_publication.CommittedSegmentV4,

    pub fn validate(self: ColdResultV4) !void {
        try self.segment.validate();
        try self.public_segment.validate();
        if (self.segment.segment.segment_index !=
            self.public_segment.segment.coordinate.segment_index or
            self.segment.segment.segment_count !=
                self.public_segment.segment.coordinate.segment_count or
            !std.meta.eql(
                self.segment.reference,
                self.public_segment.segment.v4_segment_reference,
            ) or !std.meta.eql(
            self.segment.segment.source,
            self.public_segment.segment.source,
        ) or !std.mem.eql(
            u8,
            &self.segment.segment.journal_record_sha256,
            &self.public_segment.segment.journal_record_sha256,
        ) or !std.meta.eql(
            self.segment.segment.segment_public_wire_id,
            self.public_segment.segment.wire_id,
        )) return error.InvalidIncrementalColdResultV4;
    }
};

pub const SealedPublicationsV4 = struct {
    transition: publication.OwnedManifestV4,
    public_wire: wire_publication.OwnedManifestV4,

    pub fn deinit(self: *SealedPublicationsV4) void {
        self.public_wire.deinit();
        self.transition.deinit();
        self.* = undefined;
    }
};

pub const SequentialMintOwnerV4 = struct {
    allocator: std.mem.Allocator,
    execution: publication.ExecutionAuthorityV4,
    tree: boundary_v1.SessionTree,
    initial_root: u32,
    initial_prior_authority_id: [32]u8,
    expected_segments: std.ArrayList(publication.CommittedSegmentV4) = .empty,
    expected_public: std.ArrayList(wire_publication.CommittedSegmentV4) = .empty,
    poisoned: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        execution: publication.ExecutionAuthorityV4,
        initial_words: []const boundary_v1.SparseWordV1,
        expected_initial_root: u32,
    ) !SequentialMintOwnerV4 {
        const session_identity = try execution.sessionIdentity();
        var tree = try boundary_v1.SessionTree.init(
            allocator,
            session_identity,
            0,
            initial_words,
            expected_initial_root,
        );
        errdefer tree.deinit();
        return .{
            .allocator = allocator,
            .execution = execution,
            .initial_root = tree.currentRoot(),
            .initial_prior_authority_id = tree.priorAuthorityId(),
            .tree = tree,
        };
    }

    pub fn deinit(self: *SequentialMintOwnerV4) void {
        self.expected_public.deinit(self.allocator);
        self.expected_segments.deinit(self.allocator);
        self.tree.deinit();
        self.* = undefined;
    }

    pub fn mintedCount(self: *const SequentialMintOwnerV4) u32 {
        return self.tree.nextSegmentIndex();
    }

    pub fn mint(
        self: *SequentialMintOwnerV4,
        input: MintInputV4,
    ) !ColdJobV4 {
        if (self.poisoned) return error.IncrementalPostprocessOwnerPoisonedV4;
        self.expected_segments.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            return err;
        };
        self.expected_public.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            return err;
        };
        return self.mintInner(input) catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    fn mintInner(
        self: *SequentialMintOwnerV4,
        input: MintInputV4,
    ) !ColdJobV4 {
        try validateMintInput(input, self.execution, self.tree.nextSegmentIndex());
        var authority = try self.tree.apply(
            input.segment_index,
            input.touched_words,
        );
        defer authority.deinit();
        const validated = try boundary_v1.ValidatedIncrementalBoundaryAuthorityV1
            .init(&authority);
        const transition_bytes = try artifact_v2.encodeValidatedAlloc(
            self.allocator,
            &validated,
            artifact_v2.default_limits,
        );
        defer self.allocator.free(transition_bytes);
        const artifact_bytes = try artifact_v4.encodeAlloc(
            self.allocator,
            transition_bytes,
            input.segment_public_wire,
            input.public_authority,
            artifact_v4.default_limits,
        );
        errdefer self.allocator.free(artifact_bytes);
        var decoded = try artifact_v4.decodeAlloc(
            self.allocator,
            artifact_bytes,
            artifact_v4.default_limits,
        );
        defer decoded.deinit();
        const segment_value = segmentRef(
            &decoded,
            publication.ArtifactIdentityV4.fromBytes(artifact_bytes),
            input.compact_tape,
            input.source,
            input.journal_record_sha256,
        );
        const segment_ref_bytes = try publication.encodeSegmentRefAlloc(
            self.allocator,
            segment_value,
        );
        errdefer self.allocator.free(segment_ref_bytes);
        const segment = publication.CommittedSegmentV4{
            .segment = segment_value,
            .reference = publication.ArtifactIdentityV4.fromBytes(
                segment_ref_bytes,
            ),
        };
        const public_value = wire_publication.SegmentRefV4{
            .coordinate = .{
                .segment_index = input.segment_index,
                .segment_count = self.execution.segment_count,
            },
            .wire_id = input.segment_public_wire.wireId(),
            .wire_artifact = input.public_wire,
            .v4_segment_reference = segment.reference,
            .source = input.source,
            .journal_record_sha256 = input.journal_record_sha256,
        };
        const public_ref_bytes = try wire_publication.encodeSegmentRefAlloc(
            self.allocator,
            public_value,
        );
        errdefer self.allocator.free(public_ref_bytes);
        const public_segment = wire_publication.CommittedSegmentV4{
            .segment = public_value,
            .reference = publication.ArtifactIdentityV4.fromBytes(
                public_ref_bytes,
            ),
        };
        self.expected_segments.appendAssumeCapacity(segment);
        self.expected_public.appendAssumeCapacity(public_segment);
        const job = ColdJobV4{
            .allocator = self.allocator,
            .segment_index = input.segment_index,
            .artifact_bytes = artifact_bytes,
            .segment_ref_bytes = segment_ref_bytes,
            .public_ref_bytes = public_ref_bytes,
            .segment = segment,
            .public_segment = public_segment,
        };
        try job.validate();
        return job;
    }

    pub fn sealAfterCold(
        self: *SequentialMintOwnerV4,
        root: []const u8,
        final_bindings: publication.FinalBindingsV4,
        results: []const ColdResultV4,
    ) !SealedPublicationsV4 {
        if (self.poisoned or
            self.tree.nextSegmentIndex() != self.execution.segment_count or
            results.len != self.execution.segment_count or
            results.len != self.expected_segments.items.len)
        {
            return error.IncompleteIncrementalPostprocessV4;
        }
        for (results, 0..) |result, index| {
            try result.validate();
            if (!std.meta.eql(result.segment, self.expected_segments.items[index]) or
                !std.meta.eql(result.public_segment, self.expected_public.items[index]))
            {
                return error.IncrementalPostprocessColdResultMismatchV4;
            }
        }
        const transition_bytes = try publication.encodeManifestAlloc(
            self.allocator,
            self.execution,
            final_bindings,
            self.initial_root,
            self.initial_prior_authority_id,
            self.tree.currentRoot(),
            self.tree.priorAuthorityId(),
            self.expected_segments.items,
        );
        defer self.allocator.free(transition_bytes);
        const transition_path = try publication.manifestPathAlloc(
            self.allocator,
            root,
        );
        defer self.allocator.free(transition_path);
        try publishOrCompare(
            self.allocator,
            transition_path,
            transition_bytes,
            publication.manifest_max_byte_count,
        );
        var transition = try publication.coldOpenPublication(
            self.allocator,
            root,
            self.execution,
            final_bindings,
        );
        errdefer transition.deinit();

        const public_bytes = try wire_publication.encodeManifestAlloc(
            self.allocator,
            self.execution,
            final_bindings,
            transition.file,
            self.expected_public.items,
        );
        defer self.allocator.free(public_bytes);
        const public_path = try wire_publication.manifestPathAlloc(
            self.allocator,
            root,
        );
        defer self.allocator.free(public_path);
        try publishOrCompare(
            self.allocator,
            public_path,
            public_bytes,
            wire_publication.manifest_max_byte_count,
        );
        const retained_public_bytes = try artifact_io.readFileBounded(
            self.allocator,
            public_path,
            wire_publication.manifest_max_byte_count,
        );
        defer self.allocator.free(retained_public_bytes);
        var public_wire = try wire_publication.decodeManifestAlloc(
            self.allocator,
            retained_public_bytes,
        );
        errdefer public_wire.deinit();
        try public_wire.value.validateAgainst(
            self.execution,
            final_bindings,
            transition.file,
        );
        if (public_wire.value.segments.len != self.expected_public.items.len)
            return error.IncrementalPostprocessColdResultMismatchV4;
        for (public_wire.value.segments, self.expected_public.items) |
            actual,
            expected,
        | if (!std.meta.eql(actual, expected))
            return error.IncrementalPostprocessColdResultMismatchV4;
        return .{ .transition = transition, .public_wire = public_wire };
    }
};

/// Stateless after entry. Distinct segment jobs may call this concurrently.
pub fn coldVerifyAndPublish(
    allocator: std.mem.Allocator,
    root: []const u8,
    job: *const ColdJobV4,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    retained_metadata: *const global_v3.MetadataV3,
) !ColdResultV4 {
    try job.validate();
    const wire_bytes = try wire_publication.encodeWireAlloc(
        allocator,
        job.public_segment.segment.coordinate,
        segment_public_wire,
    );
    defer allocator.free(wire_bytes);
    if (!std.meta.eql(
        publication.ArtifactIdentityV4.fromBytes(wire_bytes),
        job.public_segment.segment.wire_artifact,
    )) return error.IncrementalPostprocessPublicWireMismatchV4;
    var decoded = try artifact_v4.decodeAlloc(
        allocator,
        job.artifact_bytes,
        artifact_v4.default_limits,
    );
    defer decoded.deinit();
    var reconstructed = try artifact_v4.coldReconstruct(
        allocator,
        &decoded,
        segment_public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer reconstructed.deinit();

    try publishSegmentBytes(allocator, root, job);
    var opened = try publication.coldOpenSegment(
        allocator,
        root,
        job.segment_index,
        false,
    );
    defer opened.deinit();
    if (!std.meta.eql(opened.reference, job.segment))
        return error.IncrementalPostprocessColdResultMismatchV4;
    var reopened = try artifact_v4.coldReconstruct(
        allocator,
        &opened.artifact,
        segment_public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer reopened.deinit();

    try coldReopenPublicSegment(
        allocator,
        root,
        job,
        retained_metadata,
    );
    const result = ColdResultV4{
        .segment = opened.reference,
        .public_segment = job.public_segment,
    };
    try result.validate();
    return result;
}

fn coldReopenPublicSegment(
    allocator: std.mem.Allocator,
    root: []const u8,
    job: *const ColdJobV4,
    retained_metadata: *const global_v3.MetadataV3,
) !void {
    const wire_path = try wire_publication.wirePathAlloc(
        allocator,
        root,
        job.segment_index,
    );
    defer allocator.free(wire_path);
    const wire_bytes = try artifact_io.readFileBounded(
        allocator,
        wire_path,
        wire_publication.max_wire_bytes,
    );
    defer allocator.free(wire_bytes);
    var wire = try wire_publication.decodeWireAllocAgainstRetainedMetadata(
        allocator,
        wire_bytes,
        retained_metadata,
    );
    defer wire.deinit();
    const ref_path = try wire_publication.referencePathAlloc(
        allocator,
        root,
        job.segment_index,
    );
    defer allocator.free(ref_path);
    const ref_bytes = try artifact_io.readFileBounded(
        allocator,
        ref_path,
        wire_publication.reference_byte_count,
    );
    defer allocator.free(ref_bytes);
    const reference = wire_publication.CommittedSegmentV4{
        .segment = try wire_publication.decodeSegmentRef(ref_bytes),
        .reference = publication.ArtifactIdentityV4.fromBytes(ref_bytes),
    };
    try reference.validate();
    if (!std.meta.eql(reference, job.public_segment) or
        !std.meta.eql(
            reference.segment.wire_artifact,
            publication.ArtifactIdentityV4.fromBytes(wire_bytes),
        ) or !std.meta.eql(reference.segment.wire_id, wire.data.wireId()) or
        !std.meta.eql(reference.segment.v4_segment_reference, job.segment.reference) or
        !std.meta.eql(reference.segment.source, job.segment.segment.source) or
        !std.mem.eql(
            u8,
            &reference.segment.journal_record_sha256,
            &job.segment.segment.journal_record_sha256,
        )) return error.IncrementalPostprocessColdResultMismatchV4;
}

fn validateMintInput(
    input: MintInputV4,
    execution: publication.ExecutionAuthorityV4,
    expected_index: u32,
) !void {
    try execution.validate();
    try input.compact_tape.validate(false);
    try input.public_wire.validate(false);
    try input.source.validate(false);
    if (input.segment_index != expected_index or
        input.segment_index >= execution.segment_count or
        allZero(&input.journal_record_sha256))
    {
        return error.InvalidIncrementalPostprocessInputV4;
    }
    const metadata = try input.segment_public_wire.metadata();
    try input.public_authority.validate();
    if (metadata.segment_index != input.segment_index or
        metadata.segment_count != execution.segment_count or
        input.public_authority.coordinate.segment_index != input.segment_index or
        input.public_authority.coordinate.segment_count != execution.segment_count or
        input.public_authority.continuation_roots.entry !=
            metadata.entry_continuation_root or
        input.public_authority.continuation_roots.exit !=
            metadata.exit_continuation_root)
    {
        return error.InvalidIncrementalPostprocessInputV4;
    }
}

fn segmentRef(
    artifact: *const artifact_v4.OwnedArtifactV4,
    artifact_identity: publication.ArtifactIdentityV4,
    compact_identity: publication.ArtifactIdentityV4,
    source: publication.ArtifactIdentityV4,
    journal_record_sha256: [32]u8,
) publication.SegmentRefV4 {
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

fn publishSegmentBytes(
    allocator: std.mem.Allocator,
    root: []const u8,
    job: *const ColdJobV4,
) !void {
    const artifact_path = try publication.segmentArtifactPathAlloc(
        allocator,
        root,
        job.segment_index,
    );
    defer allocator.free(artifact_path);
    try publishOrCompare(
        allocator,
        artifact_path,
        job.artifact_bytes,
        artifact_v4.default_limits.max_bytes,
    );
    const segment_ref_path = try publication.segmentReferencePathAlloc(
        allocator,
        root,
        job.segment_index,
    );
    defer allocator.free(segment_ref_path);
    try publishOrCompare(
        allocator,
        segment_ref_path,
        job.segment_ref_bytes,
        publication.segment_ref_byte_count,
    );
    const public_ref_path = try wire_publication.referencePathAlloc(
        allocator,
        root,
        job.segment_index,
    );
    defer allocator.free(public_ref_path);
    try publishOrCompare(
        allocator,
        public_ref_path,
        job.public_ref_bytes,
        wire_publication.reference_byte_count,
    );
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
                return error.IncrementalPostprocessResumeArtifactMismatchV4;
        },
        else => return err,
    };
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}
