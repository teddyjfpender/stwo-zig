//! Fast retained V4 capture and VM-free postprocess command.
//!
//! Phase one reexecutes the VM exactly once and publishes/adopts only the raw
//! STWEMT01 -> STWIPW04 pair for every retained segment. Phase two never
//! executes the VM: it mints the stateful STWIMT04 authority chain in order,
//! cold-verifies and publishes segment-disjoint jobs with a bounded worker
//! count, then seals STWIMF04 followed by STWIPF04. An unsealed prefix is
//! always recomputed and byte-compared; no runner continuation is restored.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const guest_profile = @import("ethereum_guest_pc_profile.zig");
const authority_mod =
    @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const postprocess = @import("ethereum_incremental_capture_postprocess_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const raw_observer_mod =
    @import("ethereum_incremental_capture_raw_observer_v4.zig");
const raw_recovery =
    @import("ethereum_incremental_capture_raw_recovery_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");

pub const command_name = "ethereum-incremental-capture-fast-v4";
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const VM_EXECUTION_COUNT = 1;
pub const MAX_COLD_WORKERS: usize = 32;
pub const MAX_RECOVERY_REPLAY_WORKERS: usize = 8;
pub const RESUME_REQUIRES_TYPED_COLD_OPEN = true;
pub const RAW_ONLY_RECOVERY_REPLAYS_COMPACT_TAPES = true;
pub const RAW_ONLY_REOPEN_VM_FALLBACK = false;

/// Shared ownership primitive for parallel cold-open slots. Tests instantiate
/// it with a counted mock; production instantiates it with OwnedMintInputV4.
pub fn OwnedOptionalV4(comptime T: type) type {
    return struct {
        value: ?T = null,

        const Self = @This();

        pub fn take(self: *Self) !T {
            const value = self.value orelse
                return error.IncompleteIncrementalOpenBatchV4;
            self.value = null;
            return value;
        }

        pub fn deinit(self: *Self) void {
            if (self.value) |*value| value.deinit();
            self.value = null;
        }
    };
}

pub const BatchOrderAuthorityV4 = struct {
    pub fn validateCompletionPermutation(
        start: usize,
        completion_order: []const u32,
    ) !void {
        if (completion_order.len == 0 or
            completion_order.len > MAX_COLD_WORKERS)
        {
            return error.InvalidColdWorkerCountV4;
        }
        var seen = [_]bool{false} ** MAX_COLD_WORKERS;
        for (completion_order) |ordinal| {
            const ordinal_usize: usize = @intCast(ordinal);
            if (ordinal_usize < start or
                ordinal_usize >= start + completion_order.len)
            {
                return error.InvalidIncrementalConcurrentOpenOrderV4;
            }
            const offset = ordinal_usize - start;
            if (seen[offset])
                return error.InvalidIncrementalConcurrentOpenOrderV4;
            seen[offset] = true;
        }
    }

    pub fn requireMintOrdinal(
        start: usize,
        offset: usize,
        ordinal: u32,
    ) !void {
        if (offset >= MAX_COLD_WORKERS)
            return error.IncrementalMintOrderMismatchV4;
        const expected = std.math.cast(u32, start + offset) orelse
            return error.IncrementalMintOrderMismatchV4;
        if (ordinal != expected)
            return error.IncrementalMintOrderMismatchV4;
    }
};

const root_basename = "ethereum-incremental-capture-v4";
const profile_receipt_basename = "execution-profile-receipt.json";
const compact_manifest_basename = "compact-capture-manifest.json";

pub const RootModeV4 = enum { create_under_parent, reopen_unsealed };

pub const OptionsV4 = struct {
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    root_mode: RootModeV4,
    cold_workers: usize,

    pub fn parse(arguments: []const []const u8) !OptionsV4 {
        if (arguments.len != 6) return error.InvalidArguments;
        var materialization: ?[]const u8 = null;
        var root: ?[]const u8 = null;
        var root_mode: ?RootModeV4 = null;
        var workers: ?usize = null;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            const name = arguments[index];
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(
                u8,
                name,
                "--retained-materialization-result",
            )) {
                if (materialization != null) return error.DuplicateArgument;
                materialization = value;
            } else if (std.mem.eql(u8, name, "--publication-root-parent")) {
                if (root != null) return error.DuplicateArgument;
                root = value;
                root_mode = .create_under_parent;
            } else if (std.mem.eql(u8, name, "--publication-root")) {
                if (root != null) return error.DuplicateArgument;
                root = value;
                root_mode = .reopen_unsealed;
            } else if (std.mem.eql(u8, name, "--cold-workers")) {
                if (workers != null) return error.DuplicateArgument;
                workers = std.fmt.parseUnsigned(usize, value, 10) catch
                    return error.InvalidArguments;
            } else return error.InvalidArguments;
        }
        const worker_count = workers orelse return error.InvalidArguments;
        if (worker_count == 0 or worker_count > MAX_COLD_WORKERS)
            return error.InvalidColdWorkerCountV4;
        return .{
            .retained_materialization_result = materialization orelse
                return error.InvalidArguments,
            .publication_root = root orelse return error.InvalidArguments,
            .root_mode = root_mode orelse return error.InvalidArguments,
            .cold_workers = worker_count,
        };
    }

    pub fn resolve(self: OptionsV4, allocator: std.mem.Allocator) !OwnedOptionsV4 {
        const materialization = try artifact_io.resolveAbsolute(
            allocator,
            self.retained_materialization_result,
        );
        errdefer allocator.free(materialization);
        const root = switch (self.root_mode) {
            .create_under_parent => try artifact_io.resolveCreateOnlyChild(
                allocator,
                self.publication_root,
                root_basename,
            ),
            .reopen_unsealed => try artifact_io.resolveAbsolute(
                allocator,
                self.publication_root,
            ),
        };
        return .{
            .retained_materialization_result = materialization,
            .publication_root = root,
            .root_mode = self.root_mode,
            .cold_workers = self.cold_workers,
        };
    }
};

pub const OwnedOptionsV4 = struct {
    retained_materialization_result: []u8,
    publication_root: []u8,
    root_mode: RootModeV4,
    cold_workers: usize,

    pub fn deinit(self: *OwnedOptionsV4, allocator: std.mem.Allocator) void {
        allocator.free(self.publication_root);
        allocator.free(self.retained_materialization_result);
        self.* = undefined;
    }
};

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len == 0) return error.InvalidArguments;
    return run(allocator, arguments[1..]);
}

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    var total_timer = try std.time.Timer.start();
    const parsed = try OptionsV4.parse(arguments);
    var options = try parsed.resolve(allocator);
    defer options.deinit(allocator);
    switch (options.root_mode) {
        .create_under_parent => try artifact_io.createDirectoryCreateOnly(
            options.publication_root,
        ),
        .reopen_unsealed => try requireDirectory(options.publication_root),
    }

    var retained = try retained_mod.RetainedAuthorityV4.open(
        allocator,
        options.retained_materialization_result,
    );
    defer retained.deinit();
    const execution = try retained.executionAuthority();
    if (execution.segment_count != publication.CANONICAL_SEGMENT_COUNT)
        return error.CanonicalIncrementalSegmentCountRequired;

    if (options.root_mode == .reopen_unsealed) {
        if (try authenticateCompleteRawResume(
            allocator,
            &retained,
            options.retained_materialization_result,
            options.publication_root,
            options.cold_workers,
        )) |final_bindings| {
            try runPostprocess(
                allocator,
                &retained,
                options.publication_root,
                options.cold_workers,
                final_bindings,
            );
            return;
        }
        const recovered_bindings = try recoverCompleteRawResume(
            allocator,
            &retained,
            options.retained_materialization_result,
            options.publication_root,
            options.cold_workers,
        );
        try runPostprocess(
            allocator,
            &retained,
            options.publication_root,
            options.cold_workers,
            recovered_bindings,
        );
        return;
    }

    var observer = try raw_observer_mod.RawObserverV4.init(
        allocator,
        &retained,
        options.publication_root,
    );
    defer observer.deinit();
    var journal_writer = std.Io.Writer.Allocating.init(allocator);
    defer journal_writer.deinit();
    var stream_timer = try std.time.Timer.start();
    try frontend.diagnostics.segment_manifest.streamObserved(
        allocator,
        retained.elf_bytes,
        retained.input_bytes,
        @intCast(execution.segment_step_budget),
        true,
        .leaf_local,
        &journal_writer.writer,
        &observer,
    );
    const stream_wall_ns = stream_timer.read();
    if (!std.mem.eql(u8, journal_writer.written(), retained.journal_bytes))
        return error.RetainedIncrementalJournalMismatch;
    try observer.validateComplete();

    const final_bindings = try sealRawReceipts(
        allocator,
        &retained,
        &observer,
        options.retained_materialization_result,
        options.publication_root,
        stream_wall_ns,
        total_timer.read(),
    );
    try runPostprocess(
        allocator,
        &retained,
        options.publication_root,
        options.cold_workers,
        final_bindings,
    );
}

/// Authenticates a complete raw-only checkpoint before VM replay may be
/// skipped. Canonical receipt parsing and identity closure are followed by a
/// typed cold open of every STWEMT01/STWIPW04 pair against retained STWESG31.
/// A missing legacy receipt selects typed raw recovery; a malformed legacy
/// authority is terminal and is never treated as resumable.
fn authenticateCompleteRawResume(
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization_path: []const u8,
    root: []const u8,
    worker_count: usize,
) !?publication.FinalBindingsV4 {
    const profile_path = try childPath(
        allocator,
        root,
        profile_receipt_basename,
    );
    defer allocator.free(profile_path);
    const profile_bytes = artifact_io.readFileBounded(
        allocator,
        profile_path,
        guest_profile.max_receipt_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(profile_bytes);
    const compact_path = try childPath(
        allocator,
        root,
        compact_manifest_basename,
    );
    defer allocator.free(compact_path);
    const compact_bytes = artifact_io.readFileBounded(
        allocator,
        compact_path,
        compact_manifest.max_manifest_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(compact_bytes);

    var profile = try guest_profile.parseReceipt(allocator, profile_bytes);
    defer profile.deinit();
    var compact = try compact_manifest.parse(allocator, compact_bytes);
    defer compact.deinit();
    const materialization = evidence.identity(
        materialization_path,
        retained.materialization_bytes,
    );
    const profile_identity = evidence.identity(profile_path, profile_bytes);

    var authority = try authority_mod.AuthorityV4.init(allocator, retained, root);
    defer authority.deinit();
    try validateResumeReceiptBindings(
        retained,
        materialization,
        profile.value,
        profile_identity,
        compact.value,
        &authority,
    );

    const segment_count: usize = @intCast(authority.execution.segment_count);
    var start: usize = 0;
    while (start < segment_count) {
        const count = @min(worker_count, segment_count - start);
        var batch = try openInputBatch(allocator, &authority, start, count);
        defer batch.deinit();
        try validateOpenedBatchAgainstCompact(
            allocator,
            root,
            &batch,
            compact.value.artifacts,
        );
        start += count;
    }

    const result = publication.FinalBindingsV4{
        .compact_manifest = publication.ArtifactIdentityV4.fromBytes(
            compact_bytes,
        ),
        .materialization_result = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .execution_profile_receipt = publication.ArtifactIdentityV4.fromBytes(
            profile_bytes,
        ),
    };
    try result.validate();
    return result;
}

/// Recovers a complete raw-only checkpoint without executing the VM stream.
/// Every retained pair is first cold-opened against STWESG31 and then its
/// STWEMT01 tape is independently replayed. Per-segment profilers may execute
/// concurrently, but their counters and manifest records merge strictly in
/// segment order. The ordinary guest-PC receipt is therefore truthful; the
/// distinct binary manifest identifies it as cold-raw recovery evidence.
fn recoverCompleteRawResume(
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization_path: []const u8,
    root: []const u8,
    worker_count: usize,
) !publication.FinalBindingsV4 {
    var authority = try authority_mod.AuthorityV4.init(allocator, retained, root);
    defer authority.deinit();
    const execution = authority.execution;
    if (execution.segment_count != publication.CANONICAL_SEGMENT_COUNT)
        return error.CanonicalIncrementalSegmentCountRequired;

    const records = try allocator.alloc(
        raw_recovery.SegmentRecordV4,
        execution.segment_count,
    );
    defer allocator.free(records);
    var profiler = try guest_profile.Profiler.init(allocator, retained.elf_bytes);
    defer profiler.deinit();

    const recovery_workers = @min(worker_count, MAX_RECOVERY_REPLAY_WORKERS);
    var start: usize = 0;
    while (start < records.len) {
        const count = @min(recovery_workers, records.len - start);
        var batch = try openInputBatch(allocator, &authority, start, count);
        defer batch.deinit();
        try recoverOpenedBatch(
            allocator,
            &batch,
            execution,
            retained.elf_bytes,
            &profiler,
            records,
        );
        start += count;
    }

    const materialization = evidence.identity(
        materialization_path,
        retained.materialization_bytes,
    );
    const profile_path = try childPath(
        allocator,
        root,
        profile_receipt_basename,
    );
    defer allocator.free(profile_path);
    const profile_bytes = try profiler.encodeReceipt(allocator, .{
        .elf = retained.elfEvidence(),
        .execution_journal = retained.journalEvidence(),
        .materialization_result = materialization,
        .source_request = retained.sourceRequestEvidence(),
    });
    defer allocator.free(profile_bytes);
    try publishOrCompare(
        allocator,
        profile_path,
        profile_bytes,
        guest_profile.max_receipt_bytes,
    );
    const retained_profile_bytes = try artifact_io.readFileBounded(
        allocator,
        profile_path,
        guest_profile.max_receipt_bytes,
    );
    defer allocator.free(retained_profile_bytes);
    var parsed_profile = try guest_profile.parseReceipt(
        allocator,
        retained_profile_bytes,
    );
    defer parsed_profile.deinit();
    try validateRecoveredProfileBindings(
        retained,
        materialization,
        parsed_profile.value,
    );
    const profile_identity = publication.ArtifactIdentityV4.fromBytes(
        retained_profile_bytes,
    );

    const manifest = try raw_recovery.ManifestV4.seal(.{
        .execution = execution,
        .materialization_result = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .execution_profile_receipt = profile_identity,
        .program_identity_sha256 = authority.program_identity,
        .session_identity_sha256 = try execution.sessionIdentity(),
        .segment_count = execution.segment_count,
        .records = records,
        .content_sha256 = undefined,
    });
    const manifest_bytes = try raw_recovery.encodeManifestAlloc(
        allocator,
        &manifest,
    );
    defer allocator.free(manifest_bytes);
    const manifest_path = try childPath(
        allocator,
        root,
        raw_recovery.manifest_basename,
    );
    defer allocator.free(manifest_path);
    try publishOrCompare(
        allocator,
        manifest_path,
        manifest_bytes,
        raw_recovery.manifest_max_byte_count,
    );
    const retained_manifest_bytes = try artifact_io.readFileBounded(
        allocator,
        manifest_path,
        raw_recovery.manifest_max_byte_count,
    );
    defer allocator.free(retained_manifest_bytes);
    var retained_manifest = try raw_recovery.decodeManifestAlloc(
        allocator,
        retained_manifest_bytes,
    );
    defer retained_manifest.deinit();
    try requireRecoveredManifestEqual(&manifest, &retained_manifest.value);

    const result = publication.FinalBindingsV4{
        .compact_manifest = publication.ArtifactIdentityV4.fromBytes(
            retained_manifest_bytes,
        ),
        .materialization_result = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .execution_profile_receipt = profile_identity,
    };
    try result.validate();
    return result;
}

const RecoverySlotV4 = struct {
    input: *const authority_mod.OwnedMintInputV4,
    execution: publication.ExecutionAuthorityV4,
    elf_bytes: []const u8,
    result: ?raw_recovery.OwnedSegmentRecoveryV4 = null,
    failure: ?anyerror = null,

    fn run(self: *RecoverySlotV4) void {
        self.result = raw_recovery.replayAndAttribute(
            std.heap.smp_allocator,
            self.input,
            self.execution,
            self.elf_bytes,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn deinit(self: *RecoverySlotV4) void {
        if (self.result) |*result| result.deinit();
        self.* = undefined;
    }
};

fn recoverOpenedBatch(
    allocator: std.mem.Allocator,
    batch: *const OpenBatchV4,
    execution: publication.ExecutionAuthorityV4,
    elf_bytes: []const u8,
    profiler: *guest_profile.Profiler,
    records: []raw_recovery.SegmentRecordV4,
) !void {
    if (batch.slots.len == 0 or
        batch.slots.len > MAX_RECOVERY_REPLAY_WORKERS or
        batch.start + batch.slots.len > records.len)
    {
        return error.InvalidRecoveryWorkerCountV4;
    }
    const slots = try allocator.alloc(RecoverySlotV4, batch.slots.len);
    defer allocator.free(slots);
    var initialized: usize = 0;
    defer for (slots[0..initialized]) |*slot| slot.deinit();
    while (initialized < slots.len) : (initialized += 1) {
        const input = if (batch.slots[initialized].input.value) |*value|
            value
        else
            return error.IncompleteIncrementalOpenBatchV4;
        slots[initialized] = .{
            .input = input,
            .execution = execution,
            .elf_bytes = elf_bytes,
        };
    }

    const threads = try allocator.alloc(std.Thread, slots.len);
    defer allocator.free(threads);
    var spawned: usize = 0;
    var joined = false;
    defer if (!joined)
        for (threads[0..spawned]) |thread| thread.join();
    while (spawned < slots.len) : (spawned += 1)
        threads[spawned] = try std.Thread.spawn(
            .{},
            RecoverySlotV4.run,
            .{&slots[spawned]},
        );
    for (threads) |thread| thread.join();
    joined = true;
    for (slots, 0..) |*slot, offset| {
        if (slot.failure) |err| return err;
        const recovered = if (slot.result) |*value| value else return error.IncompleteIncrementalRawRecoveryV4;
        const ordinal = batch.start + offset;
        if (recovered.record.segment_index != ordinal)
            return error.IncrementalRawRecoveryOrderMismatchV4;
        try recovered.mergeInto(profiler);
        records[ordinal] = recovered.record;
    }
}

fn validateRecoveredProfileBindings(
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization: evidence.FileIdentity,
    profile: guest_profile.Receipt,
) !void {
    if (!identityMatches(profile.elf, retained.elfEvidence()) or
        !identityMatches(
            profile.execution_journal,
            retained.journalEvidence(),
        ) or !identityMatches(
        profile.materialization_result,
        materialization,
    ) or !identityMatches(
        profile.source_request,
        retained.sourceRequestEvidence(),
    )) return error.IncrementalRawRecoveryProfileMismatchV4;
}

fn requireRecoveredManifestEqual(
    expected: *const raw_recovery.ManifestV4,
    actual: *const raw_recovery.ManifestV4,
) !void {
    if (!std.meta.eql(expected.execution, actual.execution) or
        !std.meta.eql(
            expected.materialization_result,
            actual.materialization_result,
        ) or !std.meta.eql(expected.source_request, actual.source_request) or
        !std.meta.eql(expected.journal, actual.journal) or
        !std.meta.eql(
            expected.execution_profile_receipt,
            actual.execution_profile_receipt,
        ) or !std.mem.eql(
        u8,
        &expected.program_identity_sha256,
        &actual.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &expected.session_identity_sha256,
        &actual.session_identity_sha256,
    ) or expected.segment_count != actual.segment_count or
        expected.records.len != actual.records.len or !std.mem.eql(
        u8,
        &expected.content_sha256,
        &actual.content_sha256,
    )) return error.IncrementalRawRecoveryManifestMismatchV4;
    for (expected.records, actual.records) |expected_record, actual_record|
        if (!std.meta.eql(expected_record, actual_record))
            return error.IncrementalRawRecoveryManifestMismatchV4;
}

fn sealRawReceipts(
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    observer: *const raw_observer_mod.RawObserverV4,
    materialization_path: []const u8,
    root: []const u8,
    stream_wall_ns: u64,
    elapsed_before_receipts_ns: u64,
) !publication.FinalBindingsV4 {
    const materialization = evidence.identity(
        materialization_path,
        retained.materialization_bytes,
    );
    const profile_path = try childPath(
        allocator,
        root,
        profile_receipt_basename,
    );
    defer allocator.free(profile_path);
    const profile_bytes = try observer.profiler.encodeReceipt(allocator, .{
        .elf = retained.elfEvidence(),
        .execution_journal = retained.journalEvidence(),
        .materialization_result = materialization,
        .source_request = retained.sourceRequestEvidence(),
    });
    defer allocator.free(profile_bytes);
    try publishOrCompare(
        allocator,
        profile_path,
        profile_bytes,
        @import("ethereum_guest_pc_profile.zig").max_receipt_bytes,
    );
    const retained_profile_bytes = try artifact_io.readFileBounded(
        allocator,
        profile_path,
        @import("ethereum_guest_pc_profile.zig").max_receipt_bytes,
    );
    defer allocator.free(retained_profile_bytes);
    const profile_identity = evidence.identity(
        profile_path,
        retained_profile_bytes,
    );

    var post_timer = try std.time.Timer.start();
    const executable_sha256 = try artifact_io.executableSha256(allocator);
    const post_execution_authority_wall_ns = post_timer.read();
    const compact_path = try childPath(
        allocator,
        root,
        compact_manifest_basename,
    );
    defer allocator.free(compact_path);
    const execution = try retained.executionAuthority();
    const compact_bytes = try compact_manifest.encode(allocator, .{
        .artifacts = observer.compact_artifacts.items,
        .elf = retained.elfEvidence(),
        .execution_journal = retained.journalEvidence(),
        .execution_profile_abi_version = frontend.isa.execution_profile
            .ethereum_abi_version,
        .execution_profile_receipt = profile_identity,
        .execution_profile_semantic_sha256 = frontend.isa.execution_profile
            .ethereum_semantic_digest,
        .expected_output = retained.outputEvidence(),
        .input = retained.inputEvidence(),
        .materialization_result = materialization,
        .materializer_executable_sha256 = executable_sha256,
        .program_sha256 = try observer.programIdentity(),
        .segment_step_budget = execution.segment_step_budget,
        .session_sha256 = try execution.sessionIdentity(),
        .source_request = retained.sourceRequestEvidence(),
        .stage_timings = .{
            .capture_wall_ns = observer.capture_wall_ns,
            .encode_wall_ns = observer.encode_wall_ns,
            .observer_wall_ns = observer.observer_wall_ns,
            .pc_attribution_wall_ns = observer.pc_attribution_wall_ns,
            .post_execution_authority_wall_ns = post_execution_authority_wall_ns,
            .publish_wall_ns = observer.publish_wall_ns,
            .stream_observed_wall_ns = stream_wall_ns,
            .pre_manifest_materialization_wall_ns = std.math.add(
                u64,
                elapsed_before_receipts_ns,
                post_timer.read(),
            ) catch return error.ProfileTimingOverflow,
        },
    });
    defer allocator.free(compact_bytes);
    const retained_compact_bytes = try publishOrAdmitCompact(
        allocator,
        compact_path,
        compact_bytes,
        observer,
        retained,
        materialization,
    );
    defer allocator.free(retained_compact_bytes);
    const result = publication.FinalBindingsV4{
        .compact_manifest = publication.ArtifactIdentityV4.fromBytes(
            retained_compact_bytes,
        ),
        .materialization_result = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .execution_profile_receipt = publication.ArtifactIdentityV4.fromBytes(
            retained_profile_bytes,
        ),
    };
    try result.validate();
    return result;
}

fn runPostprocess(
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    root: []const u8,
    worker_count: usize,
    final_bindings: publication.FinalBindingsV4,
) !void {
    var authority = try authority_mod.AuthorityV4.init(allocator, retained, root);
    defer authority.deinit();
    const execution = try retained.executionAuthority();
    const segment_count: usize = @intCast(execution.segment_count);
    const first_count = @min(worker_count, segment_count);
    var first_batch = try openInputBatch(
        allocator,
        &authority,
        0,
        first_count,
    );
    defer first_batch.deinit();
    const first = if (first_batch.slots[0].input.value) |*input|
        input
    else
        return error.IncompleteIncrementalOpenBatchV4;
    var owner = try postprocess.SequentialMintOwnerV4.init(
        allocator,
        execution,
        first.initial_words,
        retained.sources[0].value.metadata.entry.continuation_root,
    );
    defer owner.deinit();
    const results = try allocator.alloc(
        postprocess.ColdResultV4,
        segment_count,
    );
    defer allocator.free(results);

    try processOpenedBatch(
        allocator,
        root,
        &first_batch,
        &owner,
        retained,
        results,
    );
    var start: usize = first_count;
    while (start < results.len) {
        const count = @min(worker_count, results.len - start);
        {
            var batch = try openInputBatch(
                allocator,
                &authority,
                start,
                count,
            );
            defer batch.deinit();
            try processOpenedBatch(
                allocator,
                root,
                &batch,
                &owner,
                retained,
                results,
            );
        }
        start += count;
    }
    var sealed = try owner.sealAfterCold(root, final_bindings, results);
    defer sealed.deinit();
    try sealed.transition.value.validateAgainst(execution, final_bindings);
    try sealed.public_wire.value.validateAgainst(
        execution,
        final_bindings,
        sealed.transition.file,
    );
}

const ColdSlotV4 = struct {
    root: []const u8,
    input: authority_mod.OwnedMintInputV4,
    job: postprocess.ColdJobV4,
    retained_metadata: *const frontend.recursion
        .segment_leaf_local_authority_v3.MetadataV3,
    result: ?postprocess.ColdResultV4 = null,
    failure: ?anyerror = null,

    fn run(self: *ColdSlotV4) void {
        self.result = postprocess.coldVerifyAndPublish(
            std.heap.smp_allocator,
            self.root,
            &self.job,
            &self.input.wire.data,
            self.input.publicAuthority(),
            self.retained_metadata,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn deinit(self: *ColdSlotV4) void {
        self.job.deinit();
        self.input.deinit();
        self.* = undefined;
    }
};

const OpenSlotV4 = struct {
    authority: *const authority_mod.AuthorityV4,
    segment_index: u32,
    input: OwnedOptionalV4(authority_mod.OwnedMintInputV4) = .{},
    failure: ?anyerror = null,
    completion_counter: ?*std.atomic.Value(usize) = null,
    completion_order: ?[]u32 = null,

    fn run(self: *OpenSlotV4) void {
        defer {
            const counter = self.completion_counter.?;
            const order = self.completion_order.?;
            const rank = counter.fetchAdd(1, .monotonic);
            order[rank] = self.segment_index;
        }
        self.input.value = self.authority.openSegmentWithAllocator(
            std.heap.smp_allocator,
            self.segment_index,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn deinit(self: *OpenSlotV4) void {
        self.input.deinit();
        self.* = undefined;
    }
};

const OpenBatchV4 = struct {
    allocator: std.mem.Allocator,
    start: usize,
    slots: []OpenSlotV4,
    completion_order: []u32,

    fn deinit(self: *OpenBatchV4) void {
        for (self.slots) |*slot| slot.deinit();
        self.allocator.free(self.completion_order);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
};

fn openInputBatch(
    allocator: std.mem.Allocator,
    authority: *const authority_mod.AuthorityV4,
    start: usize,
    count: usize,
) !OpenBatchV4 {
    if (count == 0 or count > MAX_COLD_WORKERS or
        start + count > @as(usize, @intCast(
            authority.execution.segment_count,
        )))
    {
        return error.InvalidColdWorkerCountV4;
    }
    const slots = try allocator.alloc(OpenSlotV4, count);
    errdefer allocator.free(slots);
    const completion_order = try allocator.alloc(u32, count);
    errdefer allocator.free(completion_order);
    var completion_counter = std.atomic.Value(usize).init(0);
    for (slots, 0..) |*slot, offset| slot.* = .{
        .authority = authority,
        .segment_index = @intCast(start + offset),
        .completion_counter = &completion_counter,
        .completion_order = completion_order,
    };
    errdefer for (slots) |*slot| slot.deinit();

    const threads = try allocator.alloc(std.Thread, count);
    defer allocator.free(threads);
    var spawned: usize = 0;
    var joined = false;
    defer if (!joined)
        for (threads[0..spawned]) |thread| thread.join();
    while (spawned < count) : (spawned += 1)
        threads[spawned] = try std.Thread.spawn(
            .{},
            OpenSlotV4.run,
            .{&slots[spawned]},
        );
    for (threads) |thread| thread.join();
    joined = true;
    try BatchOrderAuthorityV4.validateCompletionPermutation(
        start,
        completion_order,
    );
    for (slots) |slot| {
        if (slot.failure) |err| return err;
        if (slot.input.value == null)
            return error.IncompleteIncrementalOpenBatchV4;
    }
    for (slots) |*slot| {
        slot.completion_counter = null;
        slot.completion_order = null;
    }
    return .{
        .allocator = allocator,
        .start = start,
        .slots = slots,
        .completion_order = completion_order,
    };
}

fn processOpenedBatch(
    allocator: std.mem.Allocator,
    root: []const u8,
    batch: *OpenBatchV4,
    owner: *postprocess.SequentialMintOwnerV4,
    retained: *const retained_mod.RetainedAuthorityV4,
    results: []postprocess.ColdResultV4,
) !void {
    if (batch.slots.len == 0 or batch.slots.len > MAX_COLD_WORKERS or
        batch.start + batch.slots.len > results.len)
    {
        return error.InvalidColdWorkerCountV4;
    }
    const slots = try allocator.alloc(ColdSlotV4, batch.slots.len);
    defer allocator.free(slots);
    var initialized: usize = 0;
    defer for (slots[0..initialized]) |*slot| slot.deinit();
    while (initialized < batch.slots.len) : (initialized += 1) {
        const open_slot = &batch.slots[initialized];
        try BatchOrderAuthorityV4.requireMintOrdinal(
            batch.start,
            initialized,
            open_slot.segment_index,
        );
        const input = try open_slot.input.take();
        slots[initialized] = try mintColdSlot(
            root,
            owner,
            retained,
            input,
            open_slot.segment_index,
        );
    }

    const threads = try allocator.alloc(std.Thread, slots.len);
    defer allocator.free(threads);
    var spawned: usize = 0;
    var joined = false;
    defer if (!joined)
        for (threads[0..spawned]) |thread| thread.join();
    while (spawned < slots.len) : (spawned += 1)
        threads[spawned] = try std.Thread.spawn(
            .{},
            ColdSlotV4.run,
            .{&slots[spawned]},
        );
    for (threads) |thread| thread.join();
    joined = true;
    for (slots, 0..) |slot, offset| {
        if (slot.failure) |err| return err;
        results[batch.start + offset] = slot.result orelse
            return error.IncompleteIncrementalColdBatchV4;
    }
}

fn mintColdSlot(
    root: []const u8,
    owner: *postprocess.SequentialMintOwnerV4,
    retained: *const retained_mod.RetainedAuthorityV4,
    input_value: authority_mod.OwnedMintInputV4,
    segment_index: u32,
) !ColdSlotV4 {
    var input = input_value;
    errdefer input.deinit();
    var job = try owner.mint(input.input());
    errdefer job.deinit();
    return .{
        .root = root,
        .input = input,
        .job = job,
        .retained_metadata = &retained.sources[segment_index].value.metadata,
    };
}

fn validateResumeReceiptBindings(
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization: evidence.FileIdentity,
    profile: guest_profile.Receipt,
    profile_identity: evidence.FileIdentity,
    compact: compact_manifest.Receipt,
    authority: *const authority_mod.AuthorityV4,
) !void {
    const execution = authority.execution;
    if (!identityMatches(profile.elf, retained.elfEvidence()) or
        !identityMatches(
            profile.execution_journal,
            retained.journalEvidence(),
        ) or !identityMatches(
        profile.materialization_result,
        materialization,
    ) or !identityMatches(
        profile.source_request,
        retained.sourceRequestEvidence(),
    ) or !identityMatches(compact.elf, retained.elfEvidence()) or
        !identityMatches(
            compact.execution_journal,
            retained.journalEvidence(),
        ) or !identityMatches(
        compact.execution_profile_receipt,
        profile_identity,
    ) or !identityMatches(
        compact.expected_output,
        retained.outputEvidence(),
    ) or !identityMatches(compact.input, retained.inputEvidence()) or
        !identityMatches(compact.materialization_result, materialization) or
        !identityMatches(
            compact.source_request,
            retained.sourceRequestEvidence(),
        ) or compact.segment_count != execution.segment_count or
        compact.segment_step_budget != execution.segment_step_budget or
        compact.execution_profile_abi_version !=
            frontend.isa.execution_profile.ethereum_abi_version or
        !hexDigestMatches(
            compact.execution_profile_semantic_sha256,
            execution.execution_profile_semantic_sha256,
        ) or !hexDigestMatches(
        compact.program_sha256,
        authority.program_identity,
    ) or !hexDigestMatches(
        compact.session_sha256,
        try execution.sessionIdentity(),
    )) return error.IncrementalRawResumeReceiptMismatchV4;
}

fn validateOpenedBatchAgainstCompact(
    allocator: std.mem.Allocator,
    root: []const u8,
    batch: *const OpenBatchV4,
    artifacts: []const compact_manifest.Artifact,
) !void {
    if (batch.start + batch.slots.len > artifacts.len)
        return error.IncompleteIncrementalRawResumeV4;
    for (batch.slots, 0..) |slot, offset| {
        const ordinal = batch.start + offset;
        const input = slot.input.value orelse
            return error.IncompleteIncrementalOpenBatchV4;
        const expected = artifacts[ordinal];
        const path = try publication.compactTapePathAlloc(
            allocator,
            root,
            @intCast(ordinal),
        );
        defer allocator.free(path);
        const ordinal_u32: u32 = @intCast(ordinal);
        if (slot.segment_index != ordinal_u32 or
            input.segment_index != ordinal_u32 or
            expected.segment_index != ordinal_u32 or
            expected.artifact.bytes != input.compact_identity.byte_count or
            !std.mem.eql(u8, expected.artifact.path, path) or
            !hexDigestMatches(
                expected.artifact.sha256,
                input.compact_identity.sha256,
            )) return error.IncrementalRawResumeArtifactMismatchV4;
    }
}

fn hexDigestMatches(encoded: []const u8, expected: [32]u8) bool {
    const parsed = contract.parseSha256(encoded) catch return false;
    return std.mem.eql(u8, &parsed, &expected);
}

fn publishOrCompare(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    max_bytes: usize,
) !void {
    artifact_io.publishCreateOnlyDurable(path, expected) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try artifact_io.readFileBounded(
                allocator,
                path,
                max_bytes,
            );
            defer allocator.free(existing);
            if (!std.mem.eql(u8, existing, expected))
                return error.IncrementalCaptureResumeArtifactMismatchV4;
        },
        else => return err,
    };
}

fn publishOrAdmitCompact(
    allocator: std.mem.Allocator,
    path: []const u8,
    fresh: []const u8,
    observer: *const raw_observer_mod.RawObserverV4,
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization: evidence.FileIdentity,
) ![]u8 {
    artifact_io.publishCreateOnlyDurable(path, fresh) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const bytes = try artifact_io.readFileBounded(
                allocator,
                path,
                compact_manifest.max_manifest_bytes,
            );
            errdefer allocator.free(bytes);
            var parsed = try compact_manifest.parse(allocator, bytes);
            defer parsed.deinit();
            const value = parsed.value;
            if (value.segment_count != publication.CANONICAL_SEGMENT_COUNT or
                value.artifacts.len != observer.compact_artifacts.items.len or
                !identityMatches(value.elf, retained.elfEvidence()) or
                !identityMatches(
                    value.execution_journal,
                    retained.journalEvidence(),
                ) or !identityMatches(
                value.expected_output,
                retained.outputEvidence(),
            ) or !identityMatches(value.input, retained.inputEvidence()) or
                !identityMatches(value.materialization_result, materialization))
            {
                return error.IncrementalCaptureResumeCompactMismatchV4;
            }
            for (value.artifacts, observer.compact_artifacts.items) |
                actual,
                expected,
            | if (!identityMatches(actual.artifact, expected.artifact))
                return error.IncrementalCaptureResumeCompactMismatchV4;
            return bytes;
        },
        else => return err,
    };
    return allocator.dupe(u8, fresh);
}

fn identityMatches(
    actual: contract.Identity,
    expected: evidence.FileIdentity,
) bool {
    const digest = std.fmt.bytesToHex(expected.sha256, .lower);
    return actual.bytes == expected.bytes and
        std.mem.eql(u8, actual.path, expected.path) and
        std.mem.eql(u8, actual.sha256, &digest);
}

fn childPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    basename: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ root, basename });
}

fn requireDirectory(path: []const u8) !void {
    var directory = try std.fs.openDirAbsolute(path, .{});
    directory.close();
}
