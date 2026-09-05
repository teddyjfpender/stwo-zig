//! One-pass, proof-independent materialization of Ethereum leaf authorities.
//!
//! The exact execution that emits the canonical V3 journal is observed one
//! segment at a time. Only compact CPU/sparse-root/clock boundaries survive
//! each callback; traces and extension tapes remain segment-owned. After the
//! terminal output is known, those boundaries are lifted into one shared
//! `JobContext`, ordered `MetadataV3`, and fixed `STWESG31` source files.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const materialization = @import("ethereum_block_leaf_materialization_evidence.zig");
const materializer_options = @import("ethereum_block_leaf_materializer_options.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const snapshot_batch = @import("ethereum_block_snapshot_batch.zig");
const guest_pc_profile = @import("ethereum_guest_pc_profile.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const support = @import("ethereum_block_leaf_support.zig");

const public_data = frontend.air.public_data;
const execution_profile = frontend.isa.execution_profile;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const segment_v2 = frontend.recursion.segment_statement_v2;
const source_wire = support.source_wire;
const span = frontend.recursion.span_statement;
const minimal_trace = frontend.runner.minimal_trace;
const Options = materializer_options.Options;
const ProofProfileSelection = materializer_options.ProofProfileSelection;
const max_elf_bytes: usize = 64 * 1024 * 1024;
const max_input_bytes: usize = 64 * 1024 * 1024;
const max_output_bytes: usize = 16 * 1024 * 1024;
const max_journal_bytes: usize = 64 * 1024 * 1024;

const SourceAuthority = union(enum) {
    native: contract.SourceRequest,
    recursive: contract.RecursiveSourceRequestV2,

    fn encode(self: SourceAuthority, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .native => |value| materialization.encodeSourceRequest(
                allocator,
                value,
            ),
            .recursive => |value| materialization.encodeRecursiveSourceRequest(
                allocator,
                value,
            ),
        };
    }

    fn validateJournal(
        self: SourceAuthority,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) ![][32]u8 {
        return switch (self) {
            .native => |value| journal_authority.validate(
                allocator,
                bytes,
                value,
            ),
            .recursive => |value| journal_authority.validate(
                allocator,
                bytes,
                value,
            ),
        };
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var materializer_timer = try std.time.Timer.start();
    const parsed_options = try Options.parse(arguments);
    var options = try parsed_options.resolve(allocator);
    defer options.deinit(allocator);
    if (options.segment_count < 2 or options.segment_step_budget == 0 or
        options.segment_step_budget > global_v3.MAX_LEAF_CYCLES)
    {
        return error.InvalidSegmentGeometry;
    }
    try artifact_io.createDirectoryCreateOnly(options.source_root);
    if (options.compact_tape_root) |path|
        try artifact_io.createDirectoryCreateOnly(path);

    const elf = try artifact_io.readFileBounded(
        allocator,
        options.elf,
        max_elf_bytes,
    );
    defer allocator.free(elf);
    const input = try artifact_io.readFileBounded(
        allocator,
        options.input,
        max_input_bytes,
    );
    defer allocator.free(input);
    const expected_output = try artifact_io.readFileBounded(
        allocator,
        options.expected_output,
        max_output_bytes,
    );
    defer allocator.free(expected_output);
    if (try frontend.runner.elf_loader.requestedExecutionProfile(elf) !=
        .rv32im_zkvm_ethereum_v1)
    {
        return error.ExecutionProfileMismatch;
    }

    const elf_identity = evidence.identity(options.elf, elf);
    const input_identity = evidence.identity(options.input, input);
    const output_identity = evidence.identity(
        options.expected_output,
        expected_output,
    );
    const compact_session_identity = compact_manifest.sessionIdentity(
        elf_identity.sha256,
        input_identity.sha256,
        output_identity.sha256,
        execution_profile.ethereum_semantic_digest,
        options.segment_count,
        @intCast(options.segment_step_budget),
    );

    var pc_profiler: ?guest_pc_profile.Profiler =
        if (options.execution_profile_receipt != null)
            try guest_pc_profile.Profiler.init(allocator, elf)
        else
            null;
    defer if (pc_profiler) |*profile| profile.deinit();
    var observer = try Observer.init(
        allocator,
        input,
        expected_output,
        options.segment_count,
        if (pc_profiler) |*profile| profile else null,
        options.compact_tape_root,
        input_identity.sha256,
        compact_session_identity,
    );
    defer observer.deinit();
    try observer.initSnapshotBatch();
    var journal_writer = std.Io.Writer.Allocating.init(allocator);
    defer journal_writer.deinit();
    var stream_timer = try std.time.Timer.start();
    try frontend.diagnostics.segment_manifest.streamObserved(
        allocator,
        elf,
        input,
        options.segment_step_budget,
        true,
        .leaf_local,
        &journal_writer.writer,
        &observer,
    );
    const stream_observed_wall_ns = stream_timer.read();
    var post_execution_timer = try std.time.Timer.start();
    const journal_bytes = journal_writer.written();
    if (journal_bytes.len == 0 or journal_bytes.len > max_journal_bytes)
        return error.JournalResourceLimitExceeded;
    const built = try observer.finish(options.segment_step_budget);

    const journal_identity = evidence.identity(options.journal, journal_bytes);
    const pcs = pcsAuthority(options.proof_profile);
    const elf_sha = hex(elf_identity.sha256);
    const input_sha = hex(input_identity.sha256);
    const output_sha = hex(output_identity.sha256);
    const journal_sha = hex(journal_identity.sha256);
    const profile_sha = hex(execution_profile.ethereum_semantic_digest);
    const source_authority: SourceAuthority = switch (options.proof_profile) {
        .native_blake2s_v1 => .{ .native = .{
            .clock_frame = contract.clock_frame,
            .elf = identityForContract(elf_identity, &elf_sha),
            .execution_journal = identityForContract(journal_identity, &journal_sha),
            .execution_profile = contract.profile_name,
            .expected_output = identityForContract(output_identity, &output_sha),
            .input = identityForContract(input_identity, &input_sha),
            .pcs = pcs,
            .profile_abi_version = execution_profile.ethereum_abi_version,
            .profile_semantic_digest = &profile_sha,
            .profile_wire_id = @intFromEnum(
                execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
            ),
            .schema = contract.source_schema,
            .segment_authority_magic = contract.segment_magic,
            .segment_authority_version = source_wire.format_version,
            .segment_count = options.segment_count,
            .segment_step_budget = options.segment_step_budget,
            .strict_completion = true,
        } },
        .recursive_poseidon2_v2 => .{ .recursive = .{
            .clock_frame = contract.clock_frame,
            .elf = identityForContract(elf_identity, &elf_sha),
            .execution_journal = identityForContract(journal_identity, &journal_sha),
            .execution_profile = contract.profile_name,
            .expected_output = identityForContract(output_identity, &output_sha),
            .input = identityForContract(input_identity, &input_sha),
            .pcs = pcs,
            .profile_abi_version = execution_profile.ethereum_abi_version,
            .profile_semantic_digest = &profile_sha,
            .profile_wire_id = @intFromEnum(
                execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
            ),
            .proof_policy = recursiveProofPolicy(),
            .schema = contract.recursive_source_schema,
            .segment_authority_magic = contract.segment_magic,
            .segment_authority_version = source_wire.format_version,
            .segment_count = options.segment_count,
            .segment_step_budget = options.segment_step_budget,
            .strict_completion = true,
        } },
    };
    const source_request_bytes = try source_authority.encode(allocator);
    defer allocator.free(source_request_bytes);
    const source_request_identity = evidence.identity(
        options.source_request,
        source_request_bytes,
    );

    const admitted_records = try source_authority.validateJournal(
        allocator,
        journal_bytes,
    );
    defer allocator.free(admitted_records);
    if (admitted_records.len != built.records.len)
        return error.JournalSegmentCountMismatch;
    for (admitted_records, built.records) |admitted, record|
        if (!std.meta.eql(admitted, record.journal_record_sha256))
            return error.JournalRecordMismatch;

    const metadatas = try allocator.alloc(
        global_v3.MetadataV3,
        built.records.len,
    );
    defer allocator.free(metadatas);
    for (metadatas, built.records) |*metadata, record| {
        const statement = try statementForRecord(built.job, record);
        const words = try statement.canonicalWords();
        metadata.* = try metadataForRecord(
            &words,
            options.segment_count,
            record,
        );
    }
    if (metadatas[0].segment_index != 0 or
        metadatas[0].global_cycle_start != 0 or
        metadatas[metadatas.len - 1].segment_index + 1 !=
            options.segment_count or
        metadatas[metadatas.len - 1].completion == null)
    {
        return error.InvalidTerminalSegment;
    }
    for (metadatas[0 .. metadatas.len - 1], metadatas[1..]) |*left, *right|
        try global_v3.requireAdjacentMetadata(left, right);

    try publishIdentical(allocator, options.journal, journal_bytes);
    var leaves: std.ArrayList(materialization.LeafSource) = .empty;
    defer leaves.deinit(allocator);
    var retained_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (retained_paths.items) |path| allocator.free(path);
        retained_paths.deinit(allocator);
    }
    try leaves.ensureTotalCapacity(allocator, built.records.len);
    try retained_paths.ensureTotalCapacity(allocator, built.records.len);
    for (built.records, metadatas, 0..) |record, metadata, index| {
        const statement = try statementForRecord(built.job, record);
        const words = try statement.canonicalWords();
        const source = source_wire.Source{
            .journal_record_sha256 = record.journal_record_sha256,
            .metadata = metadata,
        };
        const encoded = try source_wire.encodeValue(&source);
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/segment-{d:0>6}.stwesg31",
            .{ options.source_root, index },
        );
        errdefer allocator.free(path);
        try publishIdentical(allocator, path, &encoded);
        try retained_paths.append(allocator, path);
        const authority = evidence.identity(path, &encoded);
        try leaves.append(allocator, .{
            .authority = authority,
            .metadata_id = try metadata.identity(),
            .segment_index = @intCast(index),
            .statement_id = statementId(&words),
            .statement_sha256 = try source.statementSha256(),
        });
    }
    try publishIdentical(
        allocator,
        options.source_request,
        source_request_bytes,
    );

    const first_words = try (try statementForRecord(
        built.job,
        built.records[0],
    )).canonicalWords();
    const manifest = try materialization.encodeManifest(allocator, .{
        .execution_journal = journal_identity,
        .expected_output = output_identity,
        .input = input_identity,
        .job = .{
            .final_state_sha256 = materialization.canonicalM31Sha256(
                materialization.machine_state_sha256_domain,
                first_words[span.canonical_layout.final_state_start..][0..span.MACHINE_STATE_CANONICAL_WORDS],
            ),
            .initial_state_sha256 = materialization.canonicalM31Sha256(
                materialization.machine_state_sha256_domain,
                first_words[span.canonical_layout.initial_state_start..][0..span.MACHINE_STATE_CANONICAL_WORDS],
            ),
            .job_sha256 = materialization.canonicalM31Sha256(
                materialization.job_sha256_domain,
                first_words[span.canonical_layout.job_start..span.canonical_layout.slot_start],
            ),
            .program = built.job.complete.program,
            .public_input = built.job.complete.public_input,
            .public_output = built.job.complete.public_output,
        },
        .leaf_sources = leaves.items,
        .pcs = pcs,
        .source_schema = switch (options.proof_profile) {
            .native_blake2s_v1 => contract.source_schema,
            .recursive_poseidon2_v2 => contract.recursive_source_schema,
        },
        .source_request = .{
            .bytes = source_request_identity.bytes,
            .path = source_request_identity.path,
            .sha256 = source_request_identity.sha256,
        },
        .total_cycles = built.job.complete.total_cycles,
    });
    defer allocator.free(manifest);
    const profile_bytes = if (options.execution_profile_receipt != null)
        try pc_profiler.?.encodeReceipt(allocator, .{
            .elf = elf_identity,
            .execution_journal = journal_identity,
            .materialization_result = evidence.identity(options.result, manifest),
            .source_request = source_request_identity,
        })
    else
        null;
    defer if (profile_bytes) |bytes| allocator.free(bytes);
    const materialization_result_identity = evidence.identity(
        options.result,
        manifest,
    );
    try artifact_io.publishCreateOnlyDurable(options.result, manifest);
    var profile_identity: ?evidence.FileIdentity = null;
    if (options.execution_profile_receipt) |path| {
        try artifact_io.publishCreateOnlyDurable(path, profile_bytes.?);
        profile_identity = evidence.identity(path, profile_bytes.?);
    }
    if (options.compact_tape_manifest) |path| {
        const compact = &observer.compact.?;
        const executable_sha256 = try artifact_io.executableSha256(allocator);
        const post_execution_authority_wall_ns = post_execution_timer.read();
        const compact_bytes = try compact_manifest.encode(allocator, .{
            .artifacts = compact.artifacts.items,
            .elf = elf_identity,
            .execution_journal = journal_identity,
            .execution_profile_abi_version = execution_profile.ethereum_abi_version,
            .execution_profile_receipt = profile_identity.?,
            .execution_profile_semantic_sha256 = execution_profile.ethereum_semantic_digest,
            .expected_output = output_identity,
            .input = input_identity,
            .materialization_result = materialization_result_identity,
            .materializer_executable_sha256 = executable_sha256,
            .program_sha256 = compact.program.?.identity,
            .segment_step_budget = options.segment_step_budget,
            .session_sha256 = compact_session_identity,
            .source_request = source_request_identity,
            .stage_timings = .{
                .capture_wall_ns = compact.capture_wall_ns,
                .encode_wall_ns = compact.encode_wall_ns,
                .observer_wall_ns = observer.observer_wall_ns,
                .pc_attribution_wall_ns = observer.pc_attribution_wall_ns,
                .post_execution_authority_wall_ns = post_execution_authority_wall_ns,
                .publish_wall_ns = compact.publish_wall_ns,
                .stream_observed_wall_ns = stream_observed_wall_ns,
                .pre_manifest_materialization_wall_ns = materializer_timer.read(),
            },
        });
        defer allocator.free(compact_bytes);
        try artifact_io.publishCreateOnlyDurable(path, compact_bytes);
    }
}

const Boundary = struct {
    machine: span.MachineState,
    authority: global_v3.BoundaryV3,
};

const Record = struct {
    segment_index: u32,
    global_cycle_start: u64,
    local_cycle_count: u32,
    entry: Boundary,
    exit: Boundary,
    completion: ?segment_v2.CompletionV2,
    journal_record_sha256: [32]u8,
};

const PendingBoundary = struct {
    cpu: frontend.runner.Cpu,
    register_clocks: [32]u32,
    memory_clock_id: segment_v2.Digest,
    memory_clock_count: u32,
    snapshot_slot: u32,
};

const PendingRecord = struct {
    segment_index: u32,
    global_cycle_start: u64,
    local_cycle_count: u32,
    entry: PendingBoundary,
    exit: PendingBoundary,
    completion: ?segment_v2.CompletionV2,
    journal_record_sha256: [32]u8,
};

const Built = struct {
    job: span.JobContext,
    records: []const Record,
};

const Observer = struct {
    const snapshot_worker_count: usize = 16;

    allocator: std.mem.Allocator,
    input: []const u8,
    expected_output: []const u8,
    expected_segment_count: u32,
    pc_profiler: ?*guest_pc_profile.Profiler,
    compact: ?CompactPublisher,
    observer_wall_ns: u64 = 0,
    pc_attribution_wall_ns: u64 = 0,
    pending_records: std.ArrayList(PendingRecord) = .empty,
    records: std.ArrayList(Record) = .empty,
    program_root: ?u32 = null,
    input_start: ?u32 = null,
    input_end: ?u32 = null,
    output_len: ?u32 = null,
    output_len_addr: ?u32 = null,
    output_data_addr: ?u32 = null,
    output_words: []frontend.recursion.vm_public_claim.PublicOutputValue = &.{},
    completion: ?public_data.Completion = null,
    job: ?span.JobContext = null,
    snapshots: snapshot_batch.Batch = .{},

    fn init(
        allocator: std.mem.Allocator,
        input: []const u8,
        expected_output: []const u8,
        expected_segment_count: u32,
        pc_profiler: ?*guest_pc_profile.Profiler,
        compact_tape_root: ?[]const u8,
        input_identity: [32]u8,
        session_identity: [32]u8,
    ) !Observer {
        if (expected_segment_count < 2) return error.InvalidSegmentCount;
        var result = Observer{
            .allocator = allocator,
            .input = input,
            .expected_output = expected_output,
            .expected_segment_count = expected_segment_count,
            .pc_profiler = pc_profiler,
            .compact = if (compact_tape_root) |root| CompactPublisher{
                .allocator = allocator,
                .input_identity = input_identity,
                .root = root,
                .semantic = minimal_trace.EthereumSemanticSegmentObservationV1
                    .init(allocator),
                .session_identity = session_identity,
            } else null,
        };
        try result.pending_records.ensureTotalCapacity(
            allocator,
            expected_segment_count,
        );
        errdefer result.pending_records.deinit(allocator);
        try result.records.ensureTotalCapacity(allocator, expected_segment_count);
        return result;
    }

    fn initSnapshotBatch(self: *Observer) !void {
        const snapshot_count = std.math.add(
            usize,
            @as(usize, @intCast(self.expected_segment_count)),
            1,
        ) catch return error.InvalidSegmentCount;
        try self.snapshots.initInPlace(
            self.allocator,
            snapshot_count,
            snapshot_worker_count,
        );
    }

    fn deinit(self: *Observer) void {
        self.snapshots.deinit();
        if (self.compact) |*compact| compact.deinit();
        self.pending_records.deinit(self.allocator);
        self.records.deinit(self.allocator);
        if (self.output_words.len != 0) self.allocator.free(self.output_words);
        self.* = undefined;
    }

    /// Installs the incremental compact observer only when tape publication is
    /// requested. Existing journal-only callers retain the exact session path.
    pub fn retirementObserver(
        self: *Observer,
    ) ?frontend.runner.RetirementObserverV1 {
        if (self.compact == null) return null;
        return .{
            .context = self,
            .begin_segment_fn = beginRetirementSegment,
            .core_row_fn = observeRetiredCoreRow,
        };
    }

    fn beginRetirementSegment(context: *anyopaque, segment_index: u32) !void {
        const self: *Observer = @ptrCast(@alignCast(context));
        if (self.compact) |*compact| return compact.semantic.begin(segment_index);
        return error.SemanticCaptureUnavailable;
    }

    fn observeRetiredCoreRow(
        context: *anyopaque,
        row: frontend.runner.trace.TraceRow,
    ) !void {
        const self: *Observer = @ptrCast(@alignCast(context));
        if (self.compact) |*compact| return compact.semantic.observeCoreRow(row);
        return error.SemanticCaptureUnavailable;
    }

    pub fn observe(
        self: *Observer,
        comptime profile: execution_profile.ExecutionProfile,
        configured: anytype,
        journal_record_sha256: [32]u8,
    ) !void {
        if (comptime profile != .rv32im_zkvm_ethereum_v1) {
            return error.ExecutionProfileMismatch;
        } else {
            var observer_timer = try std.time.Timer.start();
            if (self.pending_records.items.len >= self.expected_segment_count)
                return error.SegmentCountExceeded;
            const base = &configured.base;
            if (base.segment_index != self.pending_records.items.len or
                base.global_first_cycle == 0)
            {
                return error.ExecutionSegmentOrderMismatch;
            }
            if (self.pc_profiler) |profiler| {
                var pc_timer = try std.time.Timer.start();
                try profiler.observeCoreRows(base.execution_trace.rows.items);
                try profiler.observeExternalRecords(
                    .keccakf,
                    configured.keccakf_calls.records(),
                    configured.keccakf_execution_rows.rows().len,
                );
                try profiler.observeExternalRecords(
                    .secp256k1_recover,
                    configured.signer_recovery_calls.records(),
                    configured.signer_recovery_execution_rows.rows().len,
                );
                self.pc_attribution_wall_ns = try addTiming(
                    self.pc_attribution_wall_ns,
                    pc_timer.read(),
                );
            }
            if (self.program_root == null) {
                var program = try frontend.air.program.commitment
                    .buildDeclaredForProfileSources(
                    self.allocator,
                    .rv32im_zkvm_ethereum_v1,
                    .{},
                    base.rw_memory.program_words,
                    null,
                );
                defer program.deinit(self.allocator);
                try program.validate(self.allocator);
                self.program_root = program.tree.root;
                self.input_start = base.input_start;
                self.input_end = base.input_end;
                try requireInputFitsRegion(
                    base.input_start,
                    base.input_end,
                    self.input.len,
                );
            }

            const cycles = std.math.cast(u32, base.cycle_count) orelse
                return error.LocalCycleRangeOutOfBounds;
            const completion: ?segment_v2.CompletionV2 = if (base.completion_reason) |reason| try segment_v2.completionFromRunner(
                reason,
                base.completion_address,
                base.completion_value,
                base.completion_clock,
            ) else null;
            const is_final = self.pending_records.items.len + 1 ==
                self.expected_segment_count;
            if ((completion != null) != is_final)
                return error.InvalidTerminalSegment;
            const segment_index: usize = @intCast(base.segment_index);
            if (segment_index == 0) try self.snapshots.enqueue(
                0,
                base.rw_memory.words,
                .initial_word,
            );
            try self.snapshots.enqueue(
                segment_index + 1,
                base.rw_memory.words,
                .final_word,
            );
            const record = PendingRecord{
                .segment_index = base.segment_index,
                .global_cycle_start = base.global_first_cycle - 1,
                .local_cycle_count = cycles,
                .entry = try pendingBoundary(
                    base,
                    .initial_word,
                    @intCast(segment_index),
                ),
                .exit = try pendingBoundary(
                    base,
                    .final_word,
                    @intCast(segment_index + 1),
                ),
                .completion = completion,
                .journal_record_sha256 = journal_record_sha256,
            };
            if (self.pending_records.getLastOrNull()) |prior| {
                const expected_global_cycle_start = std.math.add(
                    u64,
                    prior.global_cycle_start,
                    prior.local_cycle_count,
                ) catch return error.ExecutionCycleCountOverflow;
                if (!std.meta.eql(prior.exit.cpu, record.entry.cpu) or
                    !pendingEntryClocksAreReset(record.entry) or
                    expected_global_cycle_start != record.global_cycle_start)
                {
                    return error.SegmentBoundaryMismatch;
                }
            }
            if (self.compact) |*compact|
                try compact.captureAndPublish(configured);
            self.pending_records.appendAssumeCapacity(record);

            if (base.isComplete()) {
                if (self.pending_records.items.len != self.expected_segment_count)
                    return error.SegmentCountMismatch;
                const output = base.output orelse return error.MissingOutput;
                if (!std.mem.eql(u8, output, self.expected_output))
                    return error.PublicOutputMismatch;
                self.output_len = base.output_len;
                self.output_len_addr = base.output_len_addr;
                self.output_data_addr = base.output_data_addr;
                self.output_words = try self.allocator.alloc(
                    frontend.recursion.vm_public_claim.PublicOutputValue,
                    base.output_words.len,
                );
                for (self.output_words, base.output_words) |*destination, word|
                    destination.* = .{
                        .addr = word.addr,
                        .value = word.value,
                    };
                const reason = base.completion_reason orelse
                    return error.MissingCompletion;
                self.completion = try public_data.completionFromRun(.{
                    .completion_reason = reason,
                    .completion_address = base.completion_address,
                    .completion_value = base.completion_value,
                    .completion_clock = base.completion_clock,
                });
            }
            self.observer_wall_ns = try addTiming(
                self.observer_wall_ns,
                observer_timer.read(),
            );
        }
    }

    fn finish(self: *Observer, segment_step_budget: usize) !Built {
        if (self.pending_records.items.len != self.expected_segment_count or
            self.pending_records.items.len < 2 or self.program_root == null or
            self.input_start == null or self.input_end == null or
            self.output_len == null or self.output_len_addr == null or
            self.output_data_addr == null or self.completion == null)
        {
            return error.IncompleteMaterialization;
        }
        if (segment_step_budget > global_v3.MAX_LEAF_CYCLES)
            return error.SegmentBudgetOutOfRange;
        try self.snapshots.finish();
        self.records.clearRetainingCapacity();
        for (self.pending_records.items) |pending| {
            const entry_snapshot = try self.snapshots.identityAt(
                @intCast(pending.entry.snapshot_slot),
            );
            const exit_snapshot = try self.snapshots.identityAt(
                @intCast(pending.exit.snapshot_slot),
            );
            const record = Record{
                .segment_index = pending.segment_index,
                .global_cycle_start = pending.global_cycle_start,
                .local_cycle_count = pending.local_cycle_count,
                .entry = try boundaryFromPending(pending.entry, entry_snapshot),
                .exit = try boundaryFromPending(pending.exit, exit_snapshot),
                .completion = pending.completion,
                .journal_record_sha256 = pending.journal_record_sha256,
            };
            if (self.records.getLastOrNull()) |prior| {
                const expected_global_cycle_start = std.math.add(
                    u64,
                    prior.global_cycle_start,
                    prior.local_cycle_count,
                ) catch return error.ExecutionCycleCountOverflow;
                if (!std.meta.eql(prior.exit.machine, record.entry.machine) or
                    !std.meta.eql(
                        prior.exit.authority.snapshot_id,
                        record.entry.authority.snapshot_id,
                    ) or
                    prior.exit.authority.snapshot_count !=
                        record.entry.authority.snapshot_count or
                    prior.exit.authority.continuation_root !=
                        record.entry.authority.continuation_root or
                    !entryClocksAreReset(record.entry.authority) or
                    expected_global_cycle_start != record.global_cycle_start)
                {
                    return error.SegmentBoundaryMismatch;
                }
            }
            self.records.appendAssumeCapacity(record);
        }
        const first = self.records.items[0];
        const last = self.records.items[self.records.items.len - 1];
        if (first.segment_index != 0 or first.global_cycle_start != 0 or
            last.segment_index + 1 != self.expected_segment_count or
            last.completion == null)
        {
            return error.InvalidTerminalSegment;
        }
        const total_cycles = std.math.add(
            u64,
            last.global_cycle_start,
            last.local_cycle_count,
        ) catch return error.ExecutionCycleCountOverflow;
        const input_words = try public_data.packInputWords(
            self.allocator,
            self.input,
        );
        defer self.allocator.free(input_words);
        const shape = try frontend.recursion.vm_public_claim.Shape.init(
            @intCast(input_words.len),
            @intCast(self.output_words.len),
        );
        const input_digest = try frontend.recursion.vm_public_claim
            .publicInputDigestFromProjection(.{
            .start = self.input_start.?,
            .len = @intCast(self.input.len),
            .words = input_words,
        }, shape);
        const output_digest = try frontend.recursion.vm_public_claim
            .publicOutputDigestFromProjection(.{
            .len_addr = self.output_len_addr.?,
            .data_addr = self.output_data_addr.?,
            .len = self.output_len.?,
            .words = self.output_words,
        }, shape);
        const complete = try span.CompleteExecution.init(
            frontend.recursion.protocol.protocolId(),
            try span.expandRoot(self.program_root.?),
            first.entry.machine,
            last.exit.machine,
            input_digest,
            output_digest,
            total_cycles,
        );
        self.job = try span.JobContext.init(
            complete,
            self.expected_segment_count,
        );
        return .{ .job = self.job.?, .records = self.records.items };
    }
};

const CompactPublisher = struct {
    allocator: std.mem.Allocator,
    input_identity: [32]u8,
    root: []const u8,
    semantic: minimal_trace.EthereumSemanticSegmentObservationV1,
    session_identity: [32]u8,
    program_words: []minimal_trace.ProgramWord = &.{},
    program: ?minimal_trace.SliceProgram = null,
    artifacts: std.ArrayList(compact_manifest.ArtifactInput) = .empty,
    paths: std.ArrayList([]u8) = .empty,
    capture_wall_ns: u64 = 0,
    encode_wall_ns: u64 = 0,
    publish_wall_ns: u64 = 0,

    fn deinit(self: *CompactPublisher) void {
        for (self.paths.items) |path| self.allocator.free(path);
        self.paths.deinit(self.allocator);
        self.artifacts.deinit(self.allocator);
        if (self.program_words.len != 0)
            self.allocator.free(self.program_words);
        self.semantic.deinit();
        self.* = undefined;
    }

    fn captureAndPublish(
        self: *CompactPublisher,
        segment: *const frontend.runner.EthereumSegmentResult,
    ) !void {
        try self.ensureProgram(&segment.base);
        var capture_timer = try std.time.Timer.start();
        var captured = try self.semantic.capture(
            self.allocator,
            .{
                .segment = segment,
                .program = self.program.?.source(),
                .input_identity = self.input_identity,
                .session_identity = self.session_identity,
            },
        );
        defer captured.deinit();
        const capture_wall_ns = capture_timer.read();
        self.capture_wall_ns = try addTiming(
            self.capture_wall_ns,
            capture_wall_ns,
        );

        var encode_timer = try std.time.Timer.start();
        const artifact = minimal_trace.EthereumMinimalArtifactV1{
            .leaf = captured.leaf,
            .boundary_words = captured.boundary_words,
            .allocator = self.allocator,
        };
        const encoded = try minimal_trace.encodeEthereumMinimalArtifactAlloc(
            self.allocator,
            &artifact,
        );
        defer self.allocator.free(encoded);
        const encode_wall_ns = encode_timer.read();
        self.encode_wall_ns = try addTiming(
            self.encode_wall_ns,
            encode_wall_ns,
        );

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/segment-{d:0>6}.stwemt01",
            .{ self.root, captured.leaf.segment_index },
        );
        errdefer self.allocator.free(path);
        var publish_timer = try std.time.Timer.start();
        try artifact_io.publishCreateOnlyDurable(path, encoded);
        const publish_wall_ns = publish_timer.read();
        self.publish_wall_ns = try addTiming(
            self.publish_wall_ns,
            publish_wall_ns,
        );
        try self.paths.append(self.allocator, path);
        errdefer _ = self.paths.pop();
        try self.artifacts.append(self.allocator, .{
            .artifact = evidence.identity(path, encoded),
            .capture_wall_ns = capture_wall_ns,
            // This value is copied from the live observer result before the
            // artifact is released. Replay never self-routes it from decoded
            // STWEMT01 bytes.
            .completion = captured.leaf.completion,
            .core_cycle_count = captured.leaf.core_cycle_count,
            .cycle_count = captured.leaf.cycle_count,
            .encode_wall_ns = encode_wall_ns,
            .entry_boundary = captured.leaf.entry_boundary,
            .entry_cpu = compact_manifest.cpuIdentity(segment.base.entry_cpu),
            .entry_memory = captured.leaf.source.entry_memory,
            .exit_boundary = captured.leaf.exit_boundary,
            .exit_cpu = compact_manifest.cpuIdentity(segment.base.exit_cpu),
            .exit_memory = captured.leaf.source.exit_memory,
            .global_first_cycle = captured.leaf.global_first_cycle,
            .keccak_calls = @intCast(captured.leaf.keccak_records.len),
            .leaf_seal = captured.leaf.seal,
            .publish_wall_ns = publish_wall_ns,
            .recovery_calls = @intCast(captured.leaf.recovery_records.len),
            .segment_index = captured.leaf.segment_index,
        });
    }

    fn ensureProgram(
        self: *CompactPublisher,
        base: *const frontend.runner.SegmentResult,
    ) !void {
        if (self.program != null) return;
        const words = try self.allocator.alloc(
            minimal_trace.ProgramWord,
            base.rw_memory.program_words.len,
        );
        errdefer self.allocator.free(words);
        for (words, base.rw_memory.program_words) |*destination, source|
            destination.* = .{
                .address = source.addr,
                .word = source.initial_word,
            };
        const program = try minimal_trace.SliceProgram.init(words);
        self.program_words = words;
        self.program = program;
    }
};

fn addTiming(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch error.ProfileTimingOverflow;
}

fn entryClocksAreReset(boundary_value: global_v3.BoundaryV3) bool {
    for (boundary_value.register_clocks) |clock| if (clock != 0) return false;
    return boundary_value.memory_clock_count == 0 and std.meta.eql(
        boundary_value.memory_clock_id,
        segment_v2.memoryClockIdentity(&.{}),
    );
}

fn pendingEntryClocksAreReset(boundary_value: PendingBoundary) bool {
    for (boundary_value.register_clocks) |clock| if (clock != 0) return false;
    return boundary_value.memory_clock_count == 0 and std.meta.eql(
        boundary_value.memory_clock_id,
        segment_v2.memoryClockIdentity(&.{}),
    );
}

fn pendingBoundary(
    base: anytype,
    comptime side: segment_v2.SnapshotSide,
    snapshot_slot: u32,
) !PendingBoundary {
    const clocks = switch (side) {
        .initial_word => base.entry_access_clocks,
        .final_word => base.exit_access_clocks,
    };
    const cpu = switch (side) {
        .initial_word => base.entry_cpu,
        .final_word => base.exit_cpu,
    };
    return .{
        .cpu = cpu,
        .register_clocks = clocks.register_clocks,
        .memory_clock_id = segment_v2.memoryClockIdentity(
            clocks.memory_clocks,
        ),
        .memory_clock_count = @intCast(clocks.memory_clocks.len),
        .snapshot_slot = snapshot_slot,
    };
}

fn boundaryFromPending(
    pending: PendingBoundary,
    snapshot: segment_v2.SnapshotIdentity,
) !Boundary {
    const zero = [_]u32{0} ** 8;
    return .{
        .machine = try span.MachineState.init(
            pending.cpu.pc,
            pending.cpu.regs,
            snapshot.id,
            zero,
        ),
        .authority = .{
            .snapshot_id = snapshot.id,
            .snapshot_count = snapshot.count,
            .continuation_root = snapshot.root,
            .register_clocks = pending.register_clocks,
            .memory_clock_id = pending.memory_clock_id,
            .memory_clock_count = pending.memory_clock_count,
        },
    };
}

fn statementForRecord(job: span.JobContext, record: Record) !span.SpanStatement {
    const input = if (record.segment_index == 0)
        try span.EdgeClaim.present(job.complete.public_input)
    else
        span.EdgeClaim.absent();
    const is_final = record.segment_index + 1 == job.segment_count;
    const output = if (is_final)
        try span.EdgeClaim.present(job.complete.public_output)
    else
        span.EdgeClaim.absent();
    const executed = try span.ExecutedSpan.init(
        record.segment_index,
        1,
        record.global_cycle_start,
        record.local_cycle_count,
        record.entry.machine,
        record.exit.machine,
        input,
        output,
    );
    return span.SpanStatement.segmentLeaf(job, record.segment_index, executed);
}

fn metadataForRecord(
    words: *const span.StatementWords,
    segment_count: u32,
    record: Record,
) !global_v3.MetadataV3 {
    const global_cycle_end = std.math.add(
        u64,
        record.global_cycle_start,
        record.local_cycle_count,
    ) catch return error.ExecutionCycleCountOverflow;
    const result = global_v3.MetadataV3{
        .base_statement_words = words.*,
        .segment_index = record.segment_index,
        .segment_count = segment_count,
        .global_cycle_start = record.global_cycle_start,
        .global_cycle_end = global_cycle_end,
        .local_cycle_count = record.local_cycle_count,
        .entry = record.entry.authority,
        .exit = record.exit.authority,
        .completion = record.completion,
    };
    try result.validate();
    return result;
}

fn statementId(words: *const span.StatementWords) span.Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return frontend.recursion.protocol.statementId(&canonical);
}

fn pcsAuthority(selection: ProofProfileSelection) contract.PcsAuthority {
    const config = switch (selection) {
        .native_blake2s_v1 => support.pcs_config,
        .recursive_poseidon2_v2 => frontend.recursion.protocol.PCS_CONFIG,
    };
    const hash = switch (selection) {
        .native_blake2s_v1 => "Blake2s",
        .recursive_poseidon2_v2 => contract.recursive_hash_suite,
    };
    return .{
        .commitment_hash = hash,
        .field = "M31",
        .fold_step = config.fri_config.fold_step,
        .lifting_log_size = config.lifting_log_size,
        .log_blowup_factor = config.fri_config.log_blowup_factor,
        .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
        .n_queries = config.fri_config.n_queries,
        .pow_bits = config.pow_bits,
        .transcript_hash = hash,
    };
}

fn recursiveProofPolicy() contract.RecursiveProofPolicyV1 {
    return .{
        .configured_pcs_bits = contract.recursive_configured_pcs_bits,
        .conjectured_security_bits = contract.recursive_conjectured_security_bits,
        .descriptor_authority = contract.recursive_descriptor_authority,
        .execution_semantics_authority = contract.recursive_execution_semantics_authority,
        .extension_component_count = contract.recursive_extension_component_count,
        .hash_suite = contract.recursive_hash_suite,
        .interaction_pow_bits = contract.recursive_interaction_pow_bits,
        .profile_name = contract.recursive_proof_profile_name,
        .proof_kind = contract.recursive_proof_kind,
        .recursive_ingress = contract.recursive_ingress,
        .security_identity_sha256 = contract.recursive_security_identity_sha256,
        .verifier_identity_authority = contract.recursive_verifier_identity_authority,
    };
}

fn identityForContract(
    value: evidence.FileIdentity,
    digest: *const [64]u8,
) contract.Identity {
    return .{
        .bytes = value.bytes,
        .path = value.path,
        .sha256 = digest,
    };
}

pub fn requireInputFitsRegion(start: u32, end: u32, input_bytes: usize) !void {
    const length = std.math.cast(u32, input_bytes) orelse
        return error.InputLayoutMismatch;
    const capacity = std.math.sub(u32, end, start) catch
        return error.InputLayoutMismatch;
    if (length > capacity) return error.InputLayoutMismatch;
}

fn publishIdentical(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
) !void {
    artifact_io.publishCreateOnlyDurable(path, bytes) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const retained = try artifact_io.readFileBounded(
                allocator,
                path,
                bytes.len,
            );
            defer allocator.free(retained);
            if (!std.mem.eql(u8, retained, bytes))
                return error.ConflictingPublication;
        },
        else => return err,
    };
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

comptime {
    if (support.pcs_config.pow_bits != 26 or
        support.pcs_config.fri_config.n_queries != 70 or
        support.pcs_config.fri_config.log_blowup_factor != 1 or
        source_wire.encoded_size != 2159 or
        global_v3.PRODUCTION_PROOF_ACTIVATION)
    {
        @compileError("pre-activation Ethereum materializer authority drifted");
    }
}
