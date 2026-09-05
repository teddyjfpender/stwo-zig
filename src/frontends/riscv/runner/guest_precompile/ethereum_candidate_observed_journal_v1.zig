//! Transactional journal builder for the live combined Ethereum candidate.
//!
//! `diagnostics.segment_manifest.streamCandidateObserved` owns execution and
//! lends each configured segment to this observer. An integration-owned
//! provider must first persist/cold-reopen the bulk tape and return its typed
//! execution-only custody. No proof bit is manufactured here, and the
//! resulting journal is intentionally rejected by Product while any nonempty
//! bulk capture remains execution-only.

const std = @import("std");

const execution_profile = @import("../../isa/execution_profile.zig");
const capability_mod = @import("ethereum_candidate_execution_capability_v1.zig");
const journal_mod = @import("ethereum_candidate_execution_journal_v1.zig");
const combined_result = @import("../ethereum_candidate_combined_result_v1.zig");
const result_mod = @import("../result.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const proof_or_fresh_verification = false;

/// Per-segment authority returned only after the integration codec has
/// persisted and cold reopened the live tape. `manifest_record_identity` is
/// transport custody; it is checked for exact execution adjacency but is not
/// relabelled as an AIR or proof identity.
pub const SegmentExecutionCustodyV1 = struct {
    manifest_record_identity: Digest,
    base_segment_capture_identity: Digest,
    bulk_execution_artifact: ?journal_mod.ExecutionArtifactCustody,
    stack_swap_custody_identity: Digest,

    pub fn validateAgainst(
        self: SegmentExecutionCustodyV1,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        expected_manifest_record_identity: Digest,
    ) !void {
        try capability.validate();
        const base = &candidate.ethereum.base;
        const external_step_origin = candidate.bulk_memcpy.externalStepOrigin();
        if (isZero(self.manifest_record_identity) or
            !std.mem.eql(
                u8,
                &self.manifest_record_identity,
                &expected_manifest_record_identity,
            ) or isZero(self.base_segment_capture_identity) or
            isZero(self.stack_swap_custody_identity))
        {
            return error.InvalidEthereumCandidateSegmentExecutionCustody;
        }
        if (candidate.bulk_memcpy.rows().len == 0) {
            if (self.bulk_execution_artifact != null)
                return error.UnexpectedEthereumCandidateExecutionArtifactCustody;
        } else {
            const custody = self.bulk_execution_artifact orelse
                return error.MissingEthereumCandidateExecutionArtifactCustody;
            try custody.validateAgainst(
                capability,
                base.segment_index,
                external_step_origin,
            );
        }
    }
};

/// Integration-owned persistence callback. The callback may write a
/// create-only artifact/receipt, but must return only after cold reopening it.
/// The segment borrow ends when `capture` returns.
pub const SegmentCustodyProviderV1 = struct {
    context: *anyopaque,
    capture_fn: *const fn (
        context: *anyopaque,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) anyerror!SegmentExecutionCustodyV1,

    pub fn capture(
        self: SegmentCustodyProviderV1,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) !SegmentExecutionCustodyV1 {
        const result = try self.capture_fn(
            self.context,
            capability,
            candidate,
            manifest_record_identity,
        );
        try result.validateAgainst(
            capability,
            candidate,
            manifest_record_identity,
        );
        return result;
    }
};

pub const OwnedJournalV1 = struct {
    header: journal_mod.Header,
    segments: []journal_mod.Segment,
    summary: journal_mod.Summary,
    allocator: std.mem.Allocator,

    pub fn view(self: *const OwnedJournalV1) journal_mod.JournalView {
        return .{
            .header = self.header,
            .segments = self.segments,
            .summary = self.summary,
        };
    }

    pub fn validateAgainst(
        self: *const OwnedJournalV1,
        capability: capability_mod.Capability,
    ) !void {
        try self.view().validateAgainst(capability);
    }

    pub fn deinit(self: *OwnedJournalV1) void {
        self.allocator.free(self.segments);
        self.* = undefined;
    }
};

pub const ObserverV1 = struct {
    allocator: std.mem.Allocator,
    capability: capability_mod.Capability,
    header: journal_mod.Header,
    custody_provider: SegmentCustodyProviderV1,
    segments: std.ArrayList(journal_mod.Segment) = .empty,
    previous_record_identity: Digest,
    complete: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        capability: capability_mod.Capability,
        input_identity: Digest,
        session_identity: Digest,
        segment_step_budget: usize,
        clock_frame: result_mod.SegmentClockFrame,
        custody_provider: SegmentCustodyProviderV1,
    ) !ObserverV1 {
        try capability.validate();
        if (capability.executable_class != .combined_candidate or
            !capability.final_candidate_executable)
        {
            return error.FinalEthereumCombinedCandidateCapabilityRequired;
        }
        const budget = std.math.cast(u64, segment_step_budget) orelse
            return error.EthereumCandidateSegmentBudgetOverflow;
        const header = try journal_mod.Header.create(
            capability,
            input_identity,
            session_identity,
            budget,
            clock_frame,
        );
        return .{
            .allocator = allocator,
            .capability = capability,
            .header = header,
            .custody_provider = custody_provider,
            .previous_record_identity = header.identity,
        };
    }

    pub fn deinit(self: *ObserverV1) void {
        self.segments.deinit(self.allocator);
        self.* = undefined;
    }

    /// Called exactly once for every configured segment emitted by the
    /// manifest stream. Capacity is reserved before the persistence callback,
    /// so a successfully persisted capture is appended without a later OOM
    /// split-brain boundary.
    pub fn observe(
        self: *ObserverV1,
        comptime profile: execution_profile.ExecutionProfile,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) !void {
        if (comptime profile != .rv32im_zkvm_ethereum_v1)
            @compileError("combined candidate observer requires Ethereum profile");
        if (self.complete) return error.EthereumCandidateJournalAlreadyComplete;
        const expected_segment_index = std.math.cast(
            u32,
            self.segments.items.len,
        ) orelse return error.EthereumCandidateJournalSegmentIndexOverflow;
        if (candidate.ethereum.base.segment_index != expected_segment_index)
            return error.EthereumCandidateJournalSegmentIndexMismatch;
        try self.segments.ensureUnusedCapacity(self.allocator, 1);

        const custody = try self.custody_provider.capture(
            self.capability,
            candidate,
            manifest_record_identity,
        );
        const external_step_origin = candidate.bulk_memcpy.externalStepOrigin();
        const captures = try journal_mod.captureCombinedResultExecutionMembers(
            self.capability,
            candidate.ethereum.base.segment_index,
            external_step_origin,
            candidate,
            custody.bulk_execution_artifact,
            custody.stack_swap_custody_identity,
        );
        const segment = try journal_mod.Segment.createFromValidatedMemberCaptures(
            self.capability,
            self.header,
            self.previous_record_identity,
            custody.base_segment_capture_identity,
            &candidate.ethereum,
            captures,
        );
        self.segments.appendAssumeCapacity(segment);
        self.previous_record_identity = segment.identity;
        self.complete = candidate.ethereum.base.isComplete();
    }

    pub fn finish(self: *ObserverV1) !OwnedJournalV1 {
        if (!self.complete or self.segments.items.len == 0)
            return error.IncompleteEthereumCandidateJournal;
        const owned_segments = try self.segments.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned_segments);
        const summary = try journal_mod.Summary.create(
            self.capability,
            self.header,
            owned_segments,
        );
        const result = OwnedJournalV1{
            .header = self.header,
            .segments = owned_segments,
            .summary = summary,
            .allocator = self.allocator,
        };
        try result.validateAgainst(self.capability);
        self.complete = false;
        return result;
    }
};

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        journal_mod.production_active or journal_mod.proof_or_fresh_verification or
        capability_mod.production_active or
        capability_mod.proof_or_fresh_verification)
    {
        @compileError("combined candidate observed journal became active");
    }
}

test "combined candidate observed journal keeps live bulk execution-only" {
    const registry_mod = @import("../../isa/ethereum_candidate_private_registry_v1.zig");
    const receipt_mod = @import("ethereum_candidate_combined_elf_receipt_v1.zig");
    const test_elf = @import("test_elf.zig");
    const segment_manifest = @import("../../diagnostics/segment_manifest.zig");

    const elf = test_elf.buildEthereumCombinedCandidate();
    const elf_identity = receipt_mod.hashBytes(&elf);
    const source_files = [_]receipt_mod.FileIdentity{
        .{
            .path = "candidate/guest.rs",
            .bytes = 17,
            .sha256 = patternedDigest(20),
        },
        .{
            .path = "candidate/Cargo.lock",
            .bytes = 19,
            .sha256 = patternedDigest(21),
        },
    };
    const source_closure = try receipt_mod.SourceClosure.create(&source_files);
    const receipt = try receipt_mod.createFromReopened(
        std.testing.allocator,
        "/private/tmp/test-ethereum-combined-observed.elf",
        &elf,
        elf_identity,
        .{
            .path = "/private/tmp/test-ethereum-combined-observer",
            .bytes = 23,
            .sha256 = patternedDigest(22),
        },
        "/private/tmp/test-ethereum-combined-source",
        source_closure,
        true,
    );
    const capability = try capability_mod.mintCombinedCandidate(
        std.testing.allocator,
        receipt,
        &elf,
        source_closure,
        try registry_mod.Registry.canonical(),
    );

    var fixture = FixtureCustodyProvider{};
    var observer = try ObserverV1.init(
        std.testing.allocator,
        capability,
        patternedDigest(23),
        patternedDigest(24),
        24,
        .leaf_local,
        .{
            .context = &fixture,
            .capture_fn = FixtureCustodyProvider.capture,
        },
    );
    defer observer.deinit();
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try segment_manifest.streamCandidateObserved(
        std.testing.allocator,
        capability,
        &elf,
        &.{},
        24,
        false,
        .leaf_local,
        &output.writer,
        &observer,
    );
    var owned = try observer.finish();
    defer owned.deinit();
    try std.testing.expect(fixture.called);
    try owned.validateAgainst(capability);
    try std.testing.expectEqual(@as(usize, 1), owned.segments.len);
    try std.testing.expectEqual(
        journal_mod.CaptureKind.canonical_execution_artifact,
        owned.segments[0].member_captures[0].?.capture_kind,
    );
    try std.testing.expectError(
        error.EthereumCandidateBulkProofCustodyRequired,
        owned.view().requireCanonicalBulkArtifactCustody(capability),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.written(),
        "\"family\":\"stwo.riscv.bulk-memcpy.candidate-v1\",\"calls\":1,\"execution_rows\":1",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.written(),
        "\"family\":\"stwo.riscv.u256-swap.v1\",\"calls\":1,\"execution_rows\":1",
    ) != null);
}

const FixtureCustodyProvider = struct {
    called: bool = false,

    fn capture(
        erased: *anyopaque,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) !SegmentExecutionCustodyV1 {
        const self: *FixtureCustodyProvider = @ptrCast(@alignCast(erased));
        self.called = true;
        const base = &candidate.ethereum.base;
        const origin = candidate.bulk_memcpy.externalStepOrigin();
        const bulk = if (candidate.bulk_memcpy.rows().len == 0)
            null
        else
            try journal_mod.ExecutionArtifactCustody.create(
                capability,
                base.segment_index,
                origin,
                patternedDigest(25),
                patternedDigest(26),
            );
        return .{
            .manifest_record_identity = manifest_record_identity,
            .base_segment_capture_identity = patternedDigest(27),
            .bulk_execution_artifact = bulk,
            .stack_swap_custody_identity = capability.admission_receipt_identity,
        };
    }
};

fn patternedDigest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return result;
}
