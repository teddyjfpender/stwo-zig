//! Two-pass replay and exact first-call selection for retained memcpy evidence.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const journal = @import("bulk_memcpy_retained_journal_v1.zig");
const observation_mod = @import("bulk_memcpy_retained_observation_v1.zig");
const tape_artifact = @import("bulk_memcpy_tape_artifact_v1.zig");

const bulk_runner = frontend.runner.guest_precompile.bulk_memcpy_v1;
const call_buffer = frontend.runner.guest_precompile.bulk_memcpy_call_buffer_v1;
const tape_mod = frontend.runner.guest_precompile.bulk_memcpy_session_tape_v1;
const TraceRow = frontend.runner.trace.TraceRow;
const CompletionReason = frontend.runner.CompletionReason;

pub const family_count = frontend.witness_layout.canonical_families.len;

pub const Selection = struct {
    segment_index: u32,
    execution_ordinal: u64,
    trace_clock: u32,
    software_inst_word: u32,
    return_pc: u32,
    call: tape_mod.Call,
};

pub const Pass1Result = struct {
    selection: Selection,
    projection: OwnedSelectedBoundaryProjection,
    segment: CurrentSegment,
    stats: PassStats,

    pub fn deinit(self: *Pass1Result) void {
        self.projection.deinit();
        self.* = undefined;
    }
};

pub const CurrentBoundary = struct {
    pc: u32,
    cpu_sha256: [32]u8,
    memory_sha256: [32]u8,
    retained_words: u64,
    nonzero_words: u64,
    zero_words: u64,
    access_clocks_sha256: [32]u8,
    memory_clock_entries: u64,
};

pub const CurrentContinuation = struct {
    schema_version: u32,
    clock_frame: frontend.runner.result_mod.SegmentClockFrame,
    session_tag: u64,
    next_segment_index: u32,
    next_cycle: u64,
    cpu_sha256: [32]u8,
    rw_memory_word_count: u32,
    rw_memory_fingerprint: u64,
    access_clocks: u64,
    identity_sha256: [32]u8,
};

pub const CurrentSegment = struct {
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    is_first: bool,
    is_last: bool,
    entry: CurrentBoundary,
    exit: CurrentBoundary,
    core_trace_rows: u64,
    external_trace_rows: u64,
    external_calls: [2]u64,
    external_execution_rows: [2]u64,
    unclassified_core_rows: u64,
    opcode_family_rows: [family_count]u64,
    completion_reason: ?CompletionReason,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    exit_code: ?u32,
    output_bytes: ?u64,
    output_sha256: ?[32]u8,
    continuation: CurrentContinuation,
};

pub const SelectedBoundaryProjection = struct {
    boundary: CurrentBoundary,
    canonical_tape_bytes: []const u8,
    canonical_tape_sha256: [32]u8,
    tape_identity_sha256: [32]u8,
    external_step_origin: u64,
    call_count: u32,
    word_row_count: u32,
    execution_row_count: u32,

    pub fn validate(self: SelectedBoundaryProjection) !void {
        if (self.boundary.pc == 0 or self.canonical_tape_bytes.len == 0 or
            self.call_count != 1 or self.execution_row_count != 1 or
            self.word_row_count == 0 or
            !std.meta.eql(sha256(self.canonical_tape_bytes), self.canonical_tape_sha256) or
            !std.meta.eql(
                tape_artifact.identity(self.canonical_tape_bytes),
                self.tape_identity_sha256,
            ))
        {
            return error.InvalidSelectedBoundaryProjection;
        }
    }
};

pub const OwnedSelectedBoundaryProjection = struct {
    value: SelectedBoundaryProjection,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedSelectedBoundaryProjection) void {
        self.allocator.free(self.value.canonical_tape_bytes);
        self.* = undefined;
    }
};

pub const ReplayBoundary = CurrentBoundary;

pub const Pass2Result = struct {
    tape: tape_mod.Frozen,
    boundary: ReplayBoundary,
    stats: PassStats,
};

pub const PassStats = struct {
    segments: u32,
    cycles: u64,
    core_rows: u64,
    timing: evidence.Timing,
};

pub fn executePass1(
    allocator: std.mem.Allocator,
    elf: []const u8,
    input: []const u8,
    source: *const contract.RecursiveSourceRequestV2,
    memcpy_entry_pc: u32,
    max_word_rows: u32,
) !Pass1Result {
    var clock = try evidence.Clock.start();
    var capture = Capture.init(allocator, memcpy_entry_pc, max_word_rows);
    defer capture.deinit();
    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        elf,
        .{
            .input = input,
            .stop_on_halt_flag = true,
            .strict_completion = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .retirement_observer = capture.observer(),
            .pre_retirement_boundary_observer = capture.preObserver(),
        },
    );
    defer session.deinit();
    capture.registers = session.cpu.regs;

    var segment = try session.startSegment(source.segment_step_budget);
    defer segment.deinit();
    if (segment.base.segment_index != 0 or
        segment.base.global_first_cycle != 1 or
        !segment.base.segment_role.is_first or
        segment.base.segment_role.is_last or
        segment.base.isComplete() or
        segment.base.continuation == null or
        segment.base.cycle_count != source.segment_step_budget or
        capture.segment_count != 1 or
        capture.current_segment_index != 0 or
        capture.current_segment_rows != segment.base.execution_trace.rows.items.len)
    {
        return error.InvalidCurrentSegmentZeroExecution;
    }
    const selection = capture.selection orelse
        return error.NoBoundedBulkMemcpyCall;
    const projection = capture.takeProjection() orelse
        return error.MissingSelectedBoundaryProjection;
    errdefer {
        var owned = projection;
        owned.deinit();
    }
    if (capture.pending_entry != null or !capture.selected_completed or
        projection.value.boundary.pc != selection.call.pc)
    {
        return error.InvalidSelectedBoundaryProjection;
    }
    if (selection.segment_index != 0)
        return error.InvalidCurrentSegmentZeroSelection;
    const current_segment = try captureCurrentSegment(&segment);
    return .{
        .selection = selection,
        .projection = projection,
        .segment = current_segment,
        .stats = .{
            .segments = 1,
            .cycles = current_segment.cycle_count,
            .core_rows = current_segment.core_trace_rows,
            .timing = try clock.finish(),
        },
    };
}

pub fn executePass2(
    allocator: std.mem.Allocator,
    elf: []const u8,
    input: []const u8,
    segment: CurrentSegment,
    selection: Selection,
    expected_projection: SelectedBoundaryProjection,
) !Pass2Result {
    if (selection.segment_index != 0 or segment.segment_index != 0 or
        selection.trace_clock <= 1)
    {
        return error.InvalidReplayDerivedBoundary;
    }
    var clock = try evidence.Clock.start();
    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        elf,
        .{
            .input = input,
            .stop_on_halt_flag = true,
            .strict_completion = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        },
    );
    defer session.deinit();

    const prefix_budget: usize = selection.trace_clock - 1;
    var prefix = try session.startSegment(prefix_budget);
    defer prefix.deinit();
    const replay_boundary = try captureBoundary(
        prefix.base.exit_cpu,
        prefix.base.rw_memory,
        .final,
        prefix.base.exit_access_clocks,
    );
    try expected_projection.validate();
    if (!std.meta.eql(replay_boundary, expected_projection.boundary) or
        prefix.base.segment_index != segment.segment_index or
        prefix.base.global_first_cycle != segment.global_first_cycle or
        prefix.base.cycle_count != prefix_budget or prefix.base.isComplete() or
        prefix.base.continuation == null or
        prefix.base.exit_cpu.pc != selection.call.pc or
        !std.meta.eql(prefix.base.exit_cpu, session.cpu) or
        session.cpu.readReg(1) != selection.return_pc or
        session.cpu.readReg(10) != selection.call.destination or
        session.cpu.readReg(11) != selection.call.source or
        session.cpu.readReg(12) != selection.call.length or
        session.memory.readU32(selection.call.pc) != selection.software_inst_word)
    {
        return error.ReplayDerivedCallBoundaryMismatch;
    }
    var tape = try tape_mod.Builder.init(
        allocator,
        1,
        selection.call.expectedWordCount(),
        prefix.base.execution_trace.recordedExternalSteps(),
    );
    errdefer tape.deinit();
    try bulk_runner.projectIntoTape(
        selection.trace_clock,
        session.cpu,
        &session.memory,
        session.elf_info.memory_layout,
        &prefix.base.state_chain_tracker,
        &tape,
    );
    try tape.validate();
    if (tape.len() != 1 or
        tape.wordLen() != selection.call.expectedWordCount() or
        !std.meta.eql(tape.records()[0].caller.call(), selection.call) or
        tape.rows()[0].inst_word != tape_mod.fixed_inst_word)
    {
        return error.ReplayDerivedTapeMismatch;
    }
    var frozen = tape.freeze();
    errdefer frozen.deinit();
    const actual_tape_bytes = try tape_artifact.encodeAlloc(allocator, &frozen);
    defer allocator.free(actual_tape_bytes);
    if (!std.mem.eql(
        u8,
        actual_tape_bytes,
        expected_projection.canonical_tape_bytes,
    ) or !std.meta.eql(
        sha256(actual_tape_bytes),
        expected_projection.canonical_tape_sha256,
    ) or !std.meta.eql(
        tape_artifact.identity(actual_tape_bytes),
        expected_projection.tape_identity_sha256,
    ) or @as(u64, @intCast(frozen.externalStepOrigin())) !=
        expected_projection.external_step_origin or
        @as(u32, @intCast(frozen.records().len)) != expected_projection.call_count or
        @as(u32, @intCast(frozen.wordRows().len)) != expected_projection.word_row_count or
        @as(u32, @intCast(frozen.rows().len)) != expected_projection.execution_row_count)
    {
        return error.ReplayDerivedTapeByteMismatch;
    }
    return .{
        .tape = frozen,
        .boundary = replay_boundary,
        .stats = .{
            .segments = 1,
            .cycles = prefix.base.cycle_count,
            .core_rows = @intCast(prefix.base.execution_trace.rows.items.len),
            .timing = try clock.finish(),
        },
    };
}

fn captureCurrentSegment(
    segment: *const frontend.runner.EthereumSegmentResult,
) !CurrentSegment {
    const base = &segment.base;
    var family_rows: [family_count]u64 = .{0} ** family_count;
    var unclassified: u64 = 0;
    for (base.execution_trace.rows.items) |row| {
        const family = frontend.runner.trace.proofOpcodeFamily(row.opcode) catch {
            unclassified = try std.math.add(u64, unclassified, 1);
            continue;
        };
        family_rows[@intFromEnum(family)] = try std.math.add(
            u64,
            family_rows[@intFromEnum(family)],
            1,
        );
    }
    const external_calls = [2]u64{
        @intCast(segment.keccakf_calls.len()),
        @intCast(segment.signer_recovery_calls.len()),
    };
    const external_rows = [2]u64{
        @intCast(segment.keccakf_execution_rows.rows().len),
        @intCast(segment.signer_recovery_execution_rows.rows().len),
    };
    const external_total = try std.math.add(
        u64,
        external_rows[0],
        external_rows[1],
    );
    const core_rows: u64 = @intCast(base.execution_trace.rows.items.len);
    if (try std.math.add(u64, core_rows, external_total) != base.cycle_count)
        return error.InvalidCurrentSegmentZeroInventory;
    const continuation = base.continuation orelse
        return error.InvalidCurrentSegmentZeroExecution;
    return .{
        .segment_index = base.segment_index,
        .global_first_cycle = base.global_first_cycle,
        .cycle_count = base.cycle_count,
        .is_first = base.segment_role.is_first,
        .is_last = base.segment_role.is_last,
        .entry = try captureBoundary(
            base.entry_cpu,
            base.rw_memory,
            .initial,
            base.entry_access_clocks,
        ),
        .exit = try captureBoundary(
            base.exit_cpu,
            base.rw_memory,
            .final,
            base.exit_access_clocks,
        ),
        .core_trace_rows = core_rows,
        .external_trace_rows = external_total,
        .external_calls = external_calls,
        .external_execution_rows = external_rows,
        .unclassified_core_rows = unclassified,
        .opcode_family_rows = family_rows,
        .completion_reason = base.completion_reason,
        .completion_address = base.completion_address,
        .completion_value = base.completion_value,
        .completion_clock = base.completion_clock,
        .exit_code = base.exit_code,
        .output_bytes = if (base.output) |output| @intCast(output.len) else null,
        .output_sha256 = if (base.output) |output| sha256(output) else null,
        .continuation = .{
            .schema_version = continuation.schema_version,
            .clock_frame = continuation.clock_frame,
            .session_tag = continuation.session_tag,
            .next_segment_index = continuation.next_segment_index,
            .next_cycle = continuation.next_cycle,
            .cpu_sha256 = journal.cpuIdentity(continuation.cpu),
            .rw_memory_word_count = continuation.rw_memory.word_count,
            .rw_memory_fingerprint = continuation.rw_memory.fingerprint,
            .access_clocks = continuation.access_clocks,
            .identity_sha256 = journal.continuationIdentity(continuation),
        },
    };
}

fn captureBoundary(
    cpu: frontend.runner.Cpu,
    memory: frontend.runner.memory_state.Snapshot,
    comptime side: journal.MemorySide,
    clocks: frontend.runner.result_mod.AccessClockBoundary,
) !CurrentBoundary {
    const memory_identity = journal.memoryIdentity(memory, side);
    const retained_words: u64 = @intCast(memory.words.len);
    return .{
        .pc = cpu.pc,
        .cpu_sha256 = journal.cpuIdentity(cpu),
        .memory_sha256 = memory_identity.digest,
        .retained_words = retained_words,
        .nonzero_words = memory_identity.nonzero_words,
        .zero_words = try std.math.sub(
            u64,
            retained_words,
            memory_identity.nonzero_words,
        ),
        .access_clocks_sha256 = journal.accessClockIdentity(clocks),
        .memory_clock_entries = @intCast(clocks.memory_clocks.len),
    };
}

fn captureSelectedProjection(
    allocator: std.mem.Allocator,
    view: frontend.runner.PreRetirementBoundaryV1,
    external_step_origin: u64,
) !OwnedSelectedBoundaryProjection {
    const boundary = try captureReadOnlyBoundary(allocator, view);
    const external_origin = std.math.cast(usize, external_step_origin) orelse
        return error.InvalidPreRetirementClock;
    const projected_call = tape_mod.Call{
        .execution_clock = view.execution_clock,
        .call_index = 0,
        .pc = view.cpu.pc,
        .source = view.cpu.readReg(11),
        .destination = view.cpu.readReg(10),
        .length = view.cpu.readReg(12),
    };
    try call_buffer.validateRunnerCall(projected_call);
    var builder = try tape_mod.Builder.init(
        allocator,
        1,
        projected_call.expectedWordCount(),
        external_origin,
    );
    errdefer builder.deinit();
    try bulk_runner.projectIntoTape(
        view.execution_clock,
        view.cpu.*,
        view.memory,
        view.memory_layout,
        view.state_chain_tracker,
        &builder,
    );
    try builder.validate();
    var frozen = builder.freeze();
    defer frozen.deinit();
    const tape_bytes = try tape_artifact.encodeAlloc(allocator, &frozen);
    errdefer allocator.free(tape_bytes);
    const value = SelectedBoundaryProjection{
        .boundary = boundary,
        .canonical_tape_bytes = tape_bytes,
        .canonical_tape_sha256 = sha256(tape_bytes),
        .tape_identity_sha256 = tape_artifact.identity(tape_bytes),
        .external_step_origin = external_step_origin,
        .call_count = @intCast(frozen.records().len),
        .word_row_count = @intCast(frozen.wordRows().len),
        .execution_row_count = @intCast(frozen.rows().len),
    };
    try value.validate();
    return .{ .value = value, .allocator = allocator };
}

/// Read-only equivalent of the runner's yielded-boundary materialization.
/// It deliberately iterates the initialized-word inventory instead of calling
/// `canonicalAlignedWordAddresses`, whose cache compaction mutates host-owned
/// memory metadata even though architectural bytes remain unchanged.
fn captureReadOnlyBoundary(
    allocator: std.mem.Allocator,
    view: frontend.runner.PreRetirementBoundaryV1,
) !CurrentBoundary {
    var address_set = std.AutoHashMap(u32, void).init(allocator);
    defer address_set.deinit();
    try view.memory.addAlignedWordAddresses(&address_set);
    var accessed = view.state_chain_tracker.mem_last_clk.keyIterator();
    while (accessed.next()) |address|
        try address_set.put(address.* & ~@as(u32, 3), {});

    var addresses: std.ArrayList(u32) = .empty;
    defer addresses.deinit(allocator);
    try addresses.ensureTotalCapacity(allocator, address_set.count());
    var all_addresses = address_set.keyIterator();
    while (all_addresses.next()) |address| {
        if (view.memory_layout.isRwAddr(address.*))
            addresses.appendAssumeCapacity(address.*);
    }
    std.mem.sort(u32, addresses.items, {}, std.sort.asc(u32));

    const words = try allocator.alloc(
        frontend.runner.memory_state.WordState,
        addresses.items.len,
    );
    defer allocator.free(words);
    for (addresses.items, words) |address, *word| {
        const value = view.memory.readU32(address);
        word.* = .{
            .addr = address,
            .initial_word = view.state_chain_tracker.mem_initial.get(address) orelse
                value,
            .final_word = value,
            .final_clock = view.state_chain_tracker.mem_last_clk.get(address) orelse 0,
            .role = .{
                .is_public_input = view.memory_layout.isInputAddr(address),
            },
        };
    }
    const snapshot = frontend.runner.memory_state.Snapshot{
        .layout = view.memory_layout,
        .segment_role = .{ .is_first = true, .is_last = false },
        .words = words,
    };
    const memory_identity = journal.memoryIdentity(snapshot, .final);

    const clock_entries = try allocator.alloc(
        frontend.runner.result_mod.MemoryAccessClock,
        view.state_chain_tracker.mem_last_clk.count(),
    );
    defer allocator.free(clock_entries);
    var clock_iterator = view.state_chain_tracker.mem_last_clk.iterator();
    var clock_index: usize = 0;
    while (clock_iterator.next()) |entry| : (clock_index += 1) {
        clock_entries[clock_index] = .{
            .addr = entry.key_ptr.*,
            .clock = entry.value_ptr.*,
        };
    }
    std.mem.sort(
        frontend.runner.result_mod.MemoryAccessClock,
        clock_entries,
        {},
        lessMemoryAccessClock,
    );
    const clocks = frontend.runner.result_mod.AccessClockBoundary{
        .register_clocks = view.state_chain_tracker.reg_last_clk,
        .memory_clocks = clock_entries,
    };
    const retained_words: u64 = @intCast(words.len);
    return .{
        .pc = view.cpu.pc,
        .cpu_sha256 = journal.cpuIdentity(view.cpu.*),
        .memory_sha256 = memory_identity.digest,
        .retained_words = retained_words,
        .nonzero_words = memory_identity.nonzero_words,
        .zero_words = try std.math.sub(
            u64,
            retained_words,
            memory_identity.nonzero_words,
        ),
        .access_clocks_sha256 = journal.accessClockIdentity(clocks),
        .memory_clock_entries = @intCast(clock_entries.len),
    };
}

fn lessMemoryAccessClock(
    _: void,
    lhs: frontend.runner.result_mod.MemoryAccessClock,
    rhs: frontend.runner.result_mod.MemoryAccessClock,
) bool {
    return lhs.addr < rhs.addr;
}

pub fn projectionsEqual(
    lhs: SelectedBoundaryProjection,
    rhs: SelectedBoundaryProjection,
) bool {
    return std.meta.eql(lhs.boundary, rhs.boundary) and
        std.mem.eql(u8, lhs.canonical_tape_bytes, rhs.canonical_tape_bytes) and
        std.meta.eql(lhs.canonical_tape_sha256, rhs.canonical_tape_sha256) and
        std.meta.eql(lhs.tape_identity_sha256, rhs.tape_identity_sha256) and
        lhs.external_step_origin == rhs.external_step_origin and
        lhs.call_count == rhs.call_count and
        lhs.word_row_count == rhs.word_row_count and
        lhs.execution_row_count == rhs.execution_row_count;
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

const Classification = enum {
    admitted,
    too_short,
    alignment_mismatch,
    endpoint_invalid,
    byte_overlap,
    aligned_word_overlap,
};

const ActiveCall = struct {
    classification: Classification,
    length: u32,
    word_rows: u32,
    return_pc: u32,
    start_row: u64,
};

const PendingEntry = struct {
    active: ActiveCall,
    execution_clock: u32,
};

const Capture = struct {
    allocator: std.mem.Allocator,
    memcpy_entry_pc: u32,
    max_word_rows: u32,
    registers: [32]u32 = .{0} ** 32,
    current: ?ActiveCall = null,
    pending_entry: ?PendingEntry = null,
    selection: ?Selection = null,
    projection: ?OwnedSelectedBoundaryProjection = null,
    selected_start_row: ?u64 = null,
    selected_completed: bool = false,
    admitted: observation_mod.Bucket = zeroBucket(),
    too_short: observation_mod.Bucket = zeroBucket(),
    alignment_mismatch: observation_mod.Bucket = zeroBucket(),
    endpoint_invalid: observation_mod.Bucket = zeroBucket(),
    byte_overlap: observation_mod.Bucket = zeroBucket(),
    aligned_word_overlap: observation_mod.Bucket = zeroBucket(),
    current_segment_index: u32 = 0,
    current_segment_rows: usize = 0,
    completed_segment_rows: u64 = 0,
    rows_seen: u64 = 0,
    segment_count: u32 = 0,
    memcpy_entries: u64 = 0,
    validated_register_reads: u64 = 0,

    fn init(
        allocator: std.mem.Allocator,
        memcpy_entry_pc: u32,
        max_word_rows: u32,
    ) Capture {
        return .{
            .allocator = allocator,
            .memcpy_entry_pc = memcpy_entry_pc,
            .max_word_rows = max_word_rows,
        };
    }

    fn deinit(self: *Capture) void {
        if (self.projection) |*projection| projection.deinit();
        self.* = undefined;
    }

    fn takeProjection(self: *Capture) ?OwnedSelectedBoundaryProjection {
        const projection = self.projection orelse return null;
        self.projection = null;
        return projection;
    }

    fn observer(self: *Capture) frontend.runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginSegmentOpaque,
            .core_row_fn = observeRowOpaque,
        };
    }

    fn preObserver(
        self: *Capture,
    ) frontend.runner.PreRetirementBoundaryObserverV1 {
        return .{
            .context = self,
            .observe_fn = observePreRetirementOpaque,
        };
    }

    fn observePreRetirementOpaque(
        context: *anyopaque,
        boundary: frontend.runner.PreRetirementBoundaryV1,
    ) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        try self.observePreRetirement(boundary);
    }

    fn observePreRetirement(
        self: *Capture,
        boundary: frontend.runner.PreRetirementBoundaryV1,
    ) !void {
        if (!std.meta.eql(self.registers, boundary.cpu.regs))
            return error.PreRetirementRegisterStateMismatch;
        if (boundary.cpu.pc != self.memcpy_entry_pc) return;
        if (self.current != null or self.pending_entry != null)
            return error.RecursiveMemcpyUnavailable;

        const ordinal = self.memcpy_entries;
        self.memcpy_entries = try std.math.add(u64, self.memcpy_entries, 1);
        const active = classifyCall(
            boundary.cpu.readReg(10),
            boundary.cpu.readReg(11),
            boundary.cpu.readReg(12),
            boundary.cpu.readReg(1),
            self.rows_seen,
        );
        self.pending_entry = .{
            .active = active,
            .execution_clock = boundary.execution_clock,
        };
        if (self.selection != null or active.classification != .admitted or
            active.word_rows > self.max_word_rows)
        {
            return;
        }
        const previous_cycles = std.math.sub(
            u64,
            @as(u64, boundary.execution_clock),
            1,
        ) catch return error.InvalidPreRetirementClock;
        const external_step_origin = std.math.sub(
            u64,
            previous_cycles,
            self.rows_seen,
        ) catch return error.InvalidPreRetirementClock;
        const candidate = tape_mod.Call{
            .execution_clock = boundary.execution_clock,
            .call_index = 0,
            .pc = boundary.cpu.pc,
            .source = boundary.cpu.readReg(11),
            .destination = boundary.cpu.readReg(10),
            .length = boundary.cpu.readReg(12),
        };
        try call_buffer.validateRunnerCall(candidate);
        if (candidate.expectedWordCount() != active.word_rows)
            return error.RetainedCandidateClassificationMismatch;
        const selection = Selection{
            .segment_index = self.current_segment_index,
            .execution_ordinal = ordinal,
            .trace_clock = boundary.execution_clock,
            .software_inst_word = boundary.memory.readU32(boundary.cpu.pc),
            .return_pc = boundary.cpu.readReg(1),
            .call = candidate,
        };
        const projection = try captureSelectedProjection(
            self.allocator,
            boundary,
            external_step_origin,
        );
        if (!std.meta.eql(projection.value.boundary.pc, candidate.pc) or
            projection.value.word_row_count != candidate.expectedWordCount())
        {
            var invalid = projection;
            invalid.deinit();
            return error.InvalidSelectedBoundaryProjection;
        }
        self.selection = selection;
        self.projection = projection;
        self.selected_start_row = active.start_row;
    }

    fn beginSegmentOpaque(context: *anyopaque, segment_index: u32) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (segment_index != self.segment_count)
            return error.RetainedObserverSegmentOrderMismatch;
        self.completed_segment_rows = try std.math.add(
            u64,
            self.completed_segment_rows,
            @intCast(self.current_segment_rows),
        );
        self.current_segment_rows = 0;
        self.current_segment_index = segment_index;
        self.segment_count += 1;
    }

    fn observeRowOpaque(context: *anyopaque, row: TraceRow) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.current) |call| {
            if (row.pc == call.return_pc) {
                const software_rows = self.rows_seen - call.start_row;
                if (software_rows == 0) return error.InvalidMemcpyCallDuration;
                try self.finish(call, software_rows);
                self.current = null;
            }
        }
        const usage = frontend.isa.decode.operandUsage(row.opcode);
        if (usage.reads_rs1) {
            if (self.registers[row.rs1] != row.rs1_val)
                return error.RegisterReconstructionMismatch;
            self.validated_register_reads += 1;
        }
        if (usage.reads_rs2) {
            if (self.registers[row.rs2] != row.rs2_val)
                return error.RegisterReconstructionMismatch;
            self.validated_register_reads += 1;
        }
        if (row.pc == self.memcpy_entry_pc) {
            const pending = self.pending_entry orelse
                return error.MissingPreRetirementMemcpyEntry;
            if (pending.execution_clock != row.clk)
                return error.PreRetirementClockMismatch;
            if (self.selection) |selection| {
                if (selection.trace_clock == row.clk and
                    (selection.call.pc != row.pc or
                        selection.software_inst_word != row.inst_word))
                {
                    return error.PreRetirementInstructionMismatch;
                }
            }
            self.current = pending.active;
            self.pending_entry = null;
        }
        if (usage.writes_rd and row.rd != 0)
            self.registers[row.rd] = row.rd_val;
        self.registers[0] = 0;
        self.current_segment_rows = try std.math.add(
            usize,
            self.current_segment_rows,
            1,
        );
        self.rows_seen = try std.math.add(u64, self.rows_seen, 1);
    }

    fn finish(self: *Capture, call: ActiveCall, software_rows: u64) !void {
        if (self.selected_start_row != null and
            self.selected_start_row.? == call.start_row)
        {
            self.selected_completed = true;
        }
        switch (call.classification) {
            .admitted => try addBucket(&self.admitted, call, software_rows),
            .too_short => try addBucket(&self.too_short, call, software_rows),
            .alignment_mismatch => try addBucket(
                &self.alignment_mismatch,
                call,
                software_rows,
            ),
            .endpoint_invalid => try addBucket(
                &self.endpoint_invalid,
                call,
                software_rows,
            ),
            .byte_overlap => try addBucket(&self.byte_overlap, call, software_rows),
            .aligned_word_overlap => try addBucket(
                &self.aligned_word_overlap,
                call,
                software_rows,
            ),
        }
    }

    fn validateAgainst(
        self: Capture,
        expected: observation_mod.Observation,
    ) !void {
        const total_rows = try std.math.add(
            u64,
            self.completed_segment_rows,
            @intCast(self.current_segment_rows),
        );
        if (self.current != null or self.pending_entry != null or
            self.segment_count != expected.segment_count or
            total_rows != expected.retired_instructions or
            self.rows_seen != expected.retired_instructions or
            self.validated_register_reads != expected.validated_register_reads or
            !std.meta.eql(self.admitted, expected.admitted) or
            !std.meta.eql(self.too_short, expected.too_short) or
            !std.meta.eql(self.alignment_mismatch, expected.alignment_mismatch) or
            !std.meta.eql(self.endpoint_invalid, expected.endpoint_invalid) or
            !std.meta.eql(self.byte_overlap, expected.byte_overlap) or
            !std.meta.eql(
                self.aligned_word_overlap,
                expected.aligned_word_overlap,
            ))
        {
            return error.RetainedObservationReplayMismatch;
        }
        var completed_calls: u64 = 0;
        var total_software_rows: u64 = 0;
        inline for (.{
            self.admitted,
            self.too_short,
            self.alignment_mismatch,
            self.endpoint_invalid,
            self.byte_overlap,
            self.aligned_word_overlap,
        }) |bucket| {
            completed_calls = try std.math.add(u64, completed_calls, bucket.calls);
            total_software_rows = try std.math.add(
                u64,
                total_software_rows,
                bucket.software_rows,
            );
        }
        if (completed_calls != expected.completed_call_count or
            total_software_rows != expected.total_software_rows_in_memcpy or
            self.selection == null)
        {
            return error.RetainedObservationReplayMismatch;
        }
    }
};

fn zeroBucket() observation_mod.Bucket {
    return .{ .calls = 0, .requested_bytes = 0, .software_rows = 0, .word_rows = 0 };
}

fn addBucket(
    bucket: *observation_mod.Bucket,
    call: ActiveCall,
    software_rows: u64,
) !void {
    bucket.calls = try std.math.add(u64, bucket.calls, 1);
    bucket.requested_bytes = try std.math.add(
        u64,
        bucket.requested_bytes,
        call.length,
    );
    bucket.software_rows = try std.math.add(
        u64,
        bucket.software_rows,
        software_rows,
    );
    bucket.word_rows = try std.math.add(u64, bucket.word_rows, call.word_rows);
}

fn classifyCall(
    destination: u32,
    source: u32,
    length: u32,
    return_pc: u32,
    start_row: u64,
) ActiveCall {
    var result = ActiveCall{
        .classification = .admitted,
        .length = length,
        .word_rows = 0,
        .return_pc = return_pc,
        .start_row = start_row,
    };
    if (length < 32) {
        result.classification = .too_short;
        return result;
    }
    if ((destination ^ source) & 3 != 0) {
        result.classification = .alignment_mismatch;
        return result;
    }
    const destination_end = std.math.add(u32, destination, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const source_end = std.math.add(u32, source, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const address_limit: u32 = @as(u32, 1) << 30;
    if (destination_end > address_limit or source_end > address_limit) {
        result.classification = .endpoint_invalid;
        return result;
    }
    if (!(source_end <= destination or destination_end <= source)) {
        result.classification = .byte_overlap;
        return result;
    }
    result.word_rows = (length + (destination & 3) + 3) / 4;
    const source_word = source / 4;
    const destination_word = destination / 4;
    const source_word_end = std.math.add(
        u32,
        source_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const destination_word_end = std.math.add(
        u32,
        destination_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    if (!(source_word_end <= destination_word or
        destination_word_end <= source_word))
    {
        result.classification = .aligned_word_overlap;
    }
    return result;
}

const ObserverEvent = enum { begin, pre, post };

const ObserverAudit = struct {
    events: [8]ObserverEvent = undefined,
    event_len: usize = 0,
    pre_clocks: [2]u32 = undefined,
    pre_pcs: [2]u32 = undefined,
    pre_x1: [2]u32 = undefined,
    pre_x1_clocks: [2]u32 = undefined,
    pre_len: usize = 0,

    fn append(self: *ObserverAudit, event: ObserverEvent) !void {
        if (self.event_len == self.events.len) return error.ObserverAuditOverflow;
        self.events[self.event_len] = event;
        self.event_len += 1;
    }

    fn retirement(self: *ObserverAudit) frontend.runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginOpaque,
            .core_row_fn = postOpaque,
        };
    }

    fn pre(self: *ObserverAudit) frontend.runner.PreRetirementBoundaryObserverV1 {
        return .{ .context = self, .observe_fn = preOpaque };
    }

    fn beginOpaque(context: *anyopaque, segment_index: u32) !void {
        const self: *ObserverAudit = @ptrCast(@alignCast(context));
        if (segment_index != 0) return error.ObserverSegmentMismatch;
        try self.append(.begin);
    }

    fn preOpaque(
        context: *anyopaque,
        boundary: frontend.runner.PreRetirementBoundaryV1,
    ) !void {
        const self: *ObserverAudit = @ptrCast(@alignCast(context));
        if (self.pre_len == self.pre_clocks.len)
            return error.ObserverAuditOverflow;
        if (boundary.memory.readU32(boundary.cpu.pc) == 0) {
            return error.InvalidObservedPreRetirementBoundary;
        }
        try self.append(.pre);
        self.pre_clocks[self.pre_len] = boundary.execution_clock;
        self.pre_pcs[self.pre_len] = boundary.cpu.pc;
        self.pre_x1[self.pre_len] = boundary.cpu.readReg(1);
        self.pre_x1_clocks[self.pre_len] =
            boundary.state_chain_tracker.reg_last_clk[1];
        self.pre_len += 1;
    }

    fn postOpaque(context: *anyopaque, row: TraceRow) !void {
        const self: *ObserverAudit = @ptrCast(@alignCast(context));
        if (row.clk == 0) return error.InvalidObservedRetirement;
        try self.append(.post);
    }
};

const BoundaryOnlyAudit = struct {
    allocator: std.mem.Allocator,
    target_clock: u32,
    boundary: ?CurrentBoundary = null,

    fn observer(
        self: *BoundaryOnlyAudit,
    ) frontend.runner.PreRetirementBoundaryObserverV1 {
        return .{ .context = self, .observe_fn = observeOpaque };
    }

    fn observeOpaque(
        context: *anyopaque,
        view: frontend.runner.PreRetirementBoundaryV1,
    ) !void {
        const self: *BoundaryOnlyAudit = @ptrCast(@alignCast(context));
        if (view.execution_clock != self.target_clock) return;
        if (self.boundary != null) return error.DuplicateBoundaryProjection;
        self.boundary = try captureReadOnlyBoundary(self.allocator, view);
    }
};

test "pre-retirement observer sees exact const state before existing post observer" {
    const instructions = [_]u32{
        0x0050_0093, // ADDI x1, x0, 5.
        0x0010_8113, // ADDI x2, x1, 1.
        0x0000_0073, // ECALL (outside the bounded segment).
    };
    const elf = makeObserverTestElf(&instructions);
    var audit = ObserverAudit{};
    var session = try frontend.runner.BaseExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .retirement_observer = audit.retirement(),
            .pre_retirement_boundary_observer = audit.pre(),
        },
    );
    defer session.deinit();
    var segment = try session.startSegment(2);
    defer segment.deinit();

    try std.testing.expectEqualSlices(ObserverEvent, &.{
        .begin,
        .pre,
        .post,
        .pre,
        .post,
    }, audit.events[0..audit.event_len]);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, audit.pre_clocks[0..2]);
    try std.testing.expectEqualSlices(u32, &.{ 0x10000, 0x10004 }, audit.pre_pcs[0..2]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 5 }, audit.pre_x1[0..2]);
    try std.testing.expectEqual(@as(u32, 0), audit.pre_x1_clocks[0]);
    try std.testing.expect(audit.pre_x1_clocks[1] != 0);
    try std.testing.expectEqual(@as(u32, 6), segment.exit_cpu.readReg(2));
}

test "default-null pre-retirement observer preserves exact execution custody" {
    const instructions = [_]u32{
        0x0050_0093,
        0x0010_8113,
        0x0000_0073,
    };
    const elf = makeObserverTestElf(&instructions);
    var default_session = try frontend.runner.BaseExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer default_session.deinit();
    var explicit_session = try frontend.runner.BaseExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .pre_retirement_boundary_observer = null,
        },
    );
    defer explicit_session.deinit();
    var expected = try default_session.startSegment(2);
    defer expected.deinit();
    var actual = try explicit_session.startSegment(2);
    defer actual.deinit();

    try std.testing.expect(std.meta.eql(expected.entry_cpu, actual.entry_cpu));
    try std.testing.expect(std.meta.eql(expected.exit_cpu, actual.exit_cpu));
    try std.testing.expectEqualSlices(
        TraceRow,
        expected.execution_trace.rows.items,
        actual.execution_trace.rows.items,
    );
    try std.testing.expectEqualSlices(
        frontend.runner.memory_state.WordState,
        expected.rw_memory.words,
        actual.rw_memory.words,
    );
    try std.testing.expectEqualSlices(
        frontend.runner.state_chain.Access,
        expected.state_chain_tracker.accesses.items,
        actual.state_chain_tracker.accesses.items,
    );
    try std.testing.expectEqualDeep(
        expected.exit_access_clocks.register_clocks,
        actual.exit_access_clocks.register_clocks,
    );
    try std.testing.expectEqualSlices(
        frontend.runner.result_mod.MemoryAccessClock,
        expected.exit_access_clocks.memory_clocks,
        actual.exit_access_clocks.memory_clocks,
    );
}

test "in-run projection equals prefix exit and remains separate from full look-ahead" {
    const instructions = [_]u32{
        0x0010_0137, // LUI x2, 0x100 => default halt-flag address.
        0x0550_0093, // ADDI x1, x0, 0x55.
        0x0011_2023, // SW x1, 0(x2), first touching the word after projection.
        0x0000_0073,
    };
    const elf = makeObserverTestElf(&instructions);
    var audit = BoundaryOnlyAudit{
        .allocator = std.testing.allocator,
        .target_clock = 3,
    };
    var full_session = try frontend.runner.BaseExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .pre_retirement_boundary_observer = audit.observer(),
        },
    );
    defer full_session.deinit();
    var full = try full_session.startSegment(3);
    defer full.deinit();
    const projected = audit.boundary orelse return error.MissingBoundaryProjection;

    var prefix_session = try frontend.runner.BaseExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer prefix_session.deinit();
    var prefix = try prefix_session.startSegment(2);
    defer prefix.deinit();
    const prefix_boundary = try captureBoundary(
        prefix.exit_cpu,
        prefix.rw_memory,
        .final,
        prefix.exit_access_clocks,
    );
    try std.testing.expectEqualDeep(prefix_boundary, projected);
    try std.testing.expect(full.rw_memory.words.len > prefix.rw_memory.words.len);
    try std.testing.expect(!std.meta.eql(
        journal.memoryIdentity(full.rw_memory, .final).digest,
        projected.memory_sha256,
    ));
}

test "pre-retirement projection releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseCapturedProjectionAllocation,
        .{},
    );
}

fn exerciseCapturedProjectionAllocation(allocator: std.mem.Allocator) !void {
    var memory = try frontend.runner.Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    const layout = projectionTestLayout();
    memory.writeU32(0x3000, 0x0000_0013);
    for (0..8) |index| {
        memory.writeU32(0x4000 + @as(u32, @intCast(index * 4)), @intCast(index + 1));
        memory.writeU32(0x5000 + @as(u32, @intCast(index * 4)), 0);
    }
    var cpu = frontend.runner.Cpu.init(0x3000, 0x7ffc);
    cpu.writeReg(1, 0x3010);
    cpu.writeReg(10, 0x5000);
    cpu.writeReg(11, 0x4000);
    cpu.writeReg(12, 32);
    var tracker = frontend.runner.state_chain.StateChainTracker.init(
        std.testing.allocator,
    );
    defer tracker.deinit();
    var projection = try captureSelectedProjection(
        allocator,
        .{
            .execution_clock = 5,
            .cpu = &cpu,
            .memory = &memory,
            .memory_layout = layout,
            .state_chain_tracker = &tracker,
        },
        4,
    );
    defer projection.deinit();
    try projection.value.validate();
    try std.testing.expectEqual(@as(u32, 0x3000), projection.value.boundary.pc);
    try std.testing.expectEqual(@as(u32, 8), projection.value.word_row_count);
}

fn projectionTestLayout() frontend.runner.memory_state.MemoryLayout {
    return .{
        .program_base = 0x3000,
        .program_end = 0x4000,
        .data_base = 0x4000,
        .data_end = 0x6000,
        .stack_bottom = 0x7000,
        .stack_top = 0x8000,
        .io_base = 0x9000,
        .io_end = 0xa000,
        .input_base = 0x9000,
        .input_end = 0x9100,
        .output_len_addr = 0x9200,
        .output_data_addr = 0x9300,
        .output_base = 0x9300,
        .output_end = 0x9400,
    };
}

fn makeObserverTestElf(instructions: []const u32) [148]u8 {
    var bytes: [148]u8 = .{0} ** 148;
    @memcpy(bytes[0..7], &[_]u8{ 0x7f, 'E', 'L', 'F', 1, 1, 1 });
    bytes[16] = 2;
    bytes[18] = 0xf3;
    bytes[20] = 1;
    std.mem.writeInt(u32, bytes[24..28], 0x10000, .little);
    bytes[28] = 52;
    bytes[40] = 52;
    bytes[42] = 32;
    bytes[44] = 1;
    bytes[52] = 1;
    bytes[56] = 84;
    std.mem.writeInt(u32, bytes[60..64], 0x10000, .little);
    const code_bytes: u32 = @intCast(instructions.len * @sizeOf(u32));
    std.mem.writeInt(u32, bytes[68..72], code_bytes, .little);
    std.mem.writeInt(u32, bytes[72..76], code_bytes, .little);
    for (instructions, 0..) |instruction, index|
        std.mem.writeInt(
            u32,
            bytes[84 + index * 4 ..][0..4],
            instruction,
            .little,
        );
    return bytes;
}
