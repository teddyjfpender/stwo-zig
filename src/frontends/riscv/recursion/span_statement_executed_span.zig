//! Internal span statement authority shard; use span_statement.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const public_data_mod = @import("../air/public_data.zig");
pub const protocol = @import("protocol.zig");
pub const vm_claim = @import("vm_public_claim.zig");

pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;

pub const Digest = [8]u32;
pub const MACHINE_STATE_CANONICAL_WORDS: usize = 83;
pub const COMPLETE_EXECUTION_CANONICAL_WORDS: usize = 203;
pub const JOB_CONTEXT_CANONICAL_WORDS: usize = 207;
pub const SLOT_SPAN_CANONICAL_WORDS: usize = 6;
pub const EDGE_CLAIM_CANONICAL_WORDS: usize = 9;
pub const EXECUTED_SPAN_CANONICAL_WORDS: usize = 197;
pub const SPAN_BODY_CANONICAL_WORDS: usize = 198;
pub const SPAN_STATEMENT_CANONICAL_WORDS: usize = 412;
pub const StatementWords = [SPAN_STATEMENT_CANONICAL_WORDS]M31;
pub const MAX_SLOT_HEIGHT: u8 = 32;
pub const SLOT_BOUND: u64 = @as(u64, 1) << MAX_SLOT_HEIGHT;

pub const Tag = enum(u32) {
    span_statement = 60,
    job_context = 61,
    complete_execution = 62,
    machine_state = 63,
    slot_span = 64,
    empty_body = 65,
    executed_body = 66,
    executed_span = 67,
    absent_edge = 68,
    present_edge = 69,
};

pub const canonical_layout = struct {
    pub const span_tag: usize = 0;
    pub const job_start: usize = 1;
    pub const job_tag: usize = job_start;
    pub const complete_start: usize = job_tag + 1;
    pub const complete_tag: usize = complete_start;
    pub const protocol_start: usize = complete_tag + 1;
    pub const program_start: usize = protocol_start + 8;
    pub const initial_state_start: usize = program_start + 8;
    pub const final_state_start: usize = initial_state_start + MACHINE_STATE_CANONICAL_WORDS;
    pub const public_input_start: usize = final_state_start + MACHINE_STATE_CANONICAL_WORDS;
    pub const public_output_start: usize = public_input_start + 8;
    pub const total_cycles_start: usize = public_output_start + 8;
    pub const job_segment_count_start: usize = total_cycles_start + 4;
    pub const job_slot_height: usize = job_segment_count_start + 2;

    pub const slot_start: usize = job_start + JOB_CONTEXT_CANONICAL_WORDS;
    pub const slot_tag: usize = slot_start;
    pub const slot_node_index_start: usize = slot_tag + 1;
    pub const slot_height: usize = slot_node_index_start + 4;

    pub const body_start: usize = slot_start + SLOT_SPAN_CANONICAL_WORDS;
    pub const body_tag: usize = body_start;
    pub const executed_start: usize = body_tag + 1;
    pub const executed_tag: usize = executed_start;
    pub const first_segment_start: usize = executed_tag + 1;
    pub const executed_segment_count_start: usize = first_segment_start + 2;
    pub const first_cycle_start: usize = executed_segment_count_start + 2;
    pub const executed_cycle_count_start: usize = first_cycle_start + 4;
    pub const entry_state_start: usize = executed_cycle_count_start + 4;
    pub const exit_state_start: usize = entry_state_start + MACHINE_STATE_CANONICAL_WORDS;
    pub const input_edge_start: usize = exit_state_start + MACHINE_STATE_CANONICAL_WORDS;
    pub const input_edge_tag: usize = input_edge_start;
    pub const input_edge_digest_start: usize = input_edge_tag + 1;
    pub const output_edge_start: usize = input_edge_digest_start + 8;
    pub const output_edge_tag: usize = output_edge_start;
    pub const output_edge_digest_start: usize = output_edge_tag + 1;

    pub const machine_state_tag_offset: usize = 0;
    pub const machine_state_pc_start_offset: usize = 1;
    pub const machine_state_registers_start_offset: usize = 3;
    pub const machine_state_rw_digest_start_offset: usize = 67;
    pub const machine_state_io_digest_start_offset: usize = 75;
};

comptime {
    if (canonical_layout.output_edge_digest_start + 8 != SPAN_STATEMENT_CANONICAL_WORDS)
        @compileError("recursive statement V1 geometry drifted");
}

pub const Error = vm_claim.Error || error{
    CanonicalIntegerLimbOutOfRange,
    CanonicalPaddingNonZero,
    CanonicalTagMismatch,
    CanonicalWordNonCanonical,
    ChildHeightMismatch,
    CycleDiscontinuity,
    CycleRangeOverflow,
    DigestMismatch,
    EmptyBeforeExecuted,
    ExecutedCyclesOutsideJob,
    ExecutedPaddingSpan,
    ExecutedSlotCoverageMismatch,
    ExecutedSlotStartMismatch,
    FinalCycleMismatch,
    FinalRwRootMissing,
    FinalStateMismatch,
    InitialCycleMismatch,
    InitialRwRootMissing,
    InitialStateMismatch,
    InputMismatch,
    InteriorEmptySpan,
    JobMismatch,
    LeftOutputPresent,
    NonCanonicalDigest,
    OutputMismatch,
    RightInputPresent,
    RootCycleCountMismatch,
    RootCycleStartMismatch,
    RootFinalStateMismatch,
    RootHeightNotMinimal,
    RootInitialStateMismatch,
    RootInputMismatch,
    RootIsEmpty,
    RootOutputMismatch,
    RootSegmentCountMismatch,
    RootSegmentStartMismatch,
    RootSlotStartMismatch,
    SegmentDiscontinuity,
    SegmentRangeOverflow,
    SlotHeightOutOfRange,
    SlotRangeOverflow,
    SlotsMisaligned,
    SlotsNotAdjacent,
    SlotsOutsideJob,
    StateDiscontinuity,
    ZeroExecutedCycles,
    ZeroExecutedSegments,
    ZeroRegisterIsNonZero,
    ZeroSegmentCount,
    ZeroTotalCycles,
};

pub const MachineState = struct {
    pc: u32,
    registers: [32]u32,
    rw_memory: Digest,
    public_io_state: Digest,

    pub fn init(
        pc: u32,
        registers: [32]u32,
        rw_memory: Digest,
        public_io_state: Digest,
    ) Error!MachineState {
        const result = MachineState{
            .pc = pc,
            .registers = registers,
            .rw_memory = rw_memory,
            .public_io_state = public_io_state,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: MachineState) Error!void {
        if (self.registers[0] != 0) return error.ZeroRegisterIsNonZero;
        try validateDigest(self.rw_memory);
        try validateDigest(self.public_io_state);
    }
};

pub const CompleteExecution = struct {
    protocol_id: Digest,
    program: Digest,
    initial_state: MachineState,
    final_state: MachineState,
    public_input: Digest,
    public_output: Digest,
    total_cycles: u64,

    pub fn init(
        protocol_id: Digest,
        program: Digest,
        initial_state: MachineState,
        final_state: MachineState,
        public_input: Digest,
        public_output: Digest,
        total_cycles: u64,
    ) Error!CompleteExecution {
        const result = CompleteExecution{
            .protocol_id = protocol_id,
            .program = program,
            .initial_state = initial_state,
            .final_state = final_state,
            .public_input = public_input,
            .public_output = public_output,
            .total_cycles = total_cycles,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: CompleteExecution) Error!void {
        if (self.total_cycles == 0) return error.ZeroTotalCycles;
        try validateDigest(self.protocol_id);
        try validateDigest(self.program);
        try self.initial_state.validate();
        try self.final_state.validate();
        try validateDigest(self.public_input);
        try validateDigest(self.public_output);
    }
};

pub const JobContext = struct {
    complete: CompleteExecution,
    segment_count: u32,
    slot_height: u8,

    pub fn init(complete: CompleteExecution, segment_count: u32) Error!JobContext {
        if (segment_count == 0) return error.ZeroSegmentCount;
        const result = JobContext{
            .complete = complete,
            .segment_count = segment_count,
            .slot_height = ceilLog2(segment_count),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: JobContext) Error!void {
        try self.complete.validate();
        if (self.segment_count == 0) return error.ZeroSegmentCount;
        if (self.slot_height != ceilLog2(self.segment_count))
            return error.RootHeightNotMinimal;
    }

    pub fn slotCapacity(self: JobContext) u64 {
        return @as(u64, 1) << @as(u6, @intCast(self.slot_height));
    }
};

pub const SlotSpan = struct {
    first: u64,
    height: u8,

    pub fn init(first: u64, height: u8) Error!SlotSpan {
        const result = SlotSpan{ .first = first, .height = height };
        try result.validate();
        return result;
    }

    pub fn validate(self: SlotSpan) Error!void {
        if (self.height > MAX_SLOT_HEIGHT) return error.SlotHeightOutOfRange;
        const end = std.math.add(u64, self.first, self.capacity()) catch
            return error.SlotRangeOverflow;
        if (end > SLOT_BOUND) return error.SlotRangeOverflow;
    }

    pub fn capacity(self: SlotSpan) u64 {
        return @as(u64, 1) << @as(u6, @intCast(self.height));
    }

    pub fn endExclusive(self: SlotSpan) u64 {
        return self.first + self.capacity();
    }

    pub fn nodeIndex(self: SlotSpan) u64 {
        return self.first >> @as(u6, @intCast(self.height));
    }
};

pub const EdgeClaim = struct {
    digest: ?Digest,

    pub fn absent() EdgeClaim {
        return .{ .digest = null };
    }

    pub fn present(digest: Digest) Error!EdgeClaim {
        try validateDigest(digest);
        return .{ .digest = digest };
    }

    pub fn validate(self: EdgeClaim) Error!void {
        if (self.digest) |value| try validateDigest(value);
    }
};

pub const ExecutedSpan = struct {
    first_segment: u32,
    segment_count: u32,
    first_cycle: u64,
    cycle_count: u64,
    entry: MachineState,
    exit: MachineState,
    input: EdgeClaim,
    output: EdgeClaim,

    pub fn init(
        first_segment: u32,
        segment_count: u32,
        first_cycle: u64,
        cycle_count: u64,
        entry: MachineState,
        exit_state: MachineState,
        input: EdgeClaim,
        output: EdgeClaim,
    ) Error!ExecutedSpan {
        const result = ExecutedSpan{
            .first_segment = first_segment,
            .segment_count = segment_count,
            .first_cycle = first_cycle,
            .cycle_count = cycle_count,
            .entry = entry,
            .exit = exit_state,
            .input = input,
            .output = output,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ExecutedSpan) Error!void {
        if (self.segment_count == 0) return error.ZeroExecutedSegments;
        if (self.cycle_count == 0) return error.ZeroExecutedCycles;
        _ = std.math.add(u32, self.first_segment, self.segment_count) catch
            return error.SegmentRangeOverflow;
        _ = std.math.add(u64, self.first_cycle, self.cycle_count) catch
            return error.CycleRangeOverflow;
        try self.entry.validate();
        try self.exit.validate();
        try self.input.validate();
        try self.output.validate();
    }

    pub fn endSegment(self: ExecutedSpan) u32 {
        return self.first_segment + self.segment_count;
    }

    pub fn endCycle(self: ExecutedSpan) u64 {
        return self.first_cycle + self.cycle_count;
    }
};

pub const SpanBody = union(enum) {
    empty,
    executed: ExecutedSpan,
};

pub fn validateSlots(job: JobContext, slots: SlotSpan) Error!void {
    if (slots.first % slots.capacity() != 0) return error.SlotsMisaligned;
    if (slots.endExclusive() > job.slotCapacity()) return error.SlotsOutsideJob;
}

pub fn validateEmpty(job: JobContext, slots: SlotSpan) Error!void {
    if (slots.first < job.segment_count) return error.InteriorEmptySpan;
}

pub fn validateExecuted(job: JobContext, slots: SlotSpan, span: ExecutedSpan) Error!void {
    try span.validate();
    if (slots.first >= job.segment_count) return error.ExecutedPaddingSpan;
    if (span.first_segment != slots.first) return error.ExecutedSlotStartMismatch;
    const expected_end = @min(slots.endExclusive(), @as(u64, job.segment_count));
    if (span.endSegment() != expected_end) return error.ExecutedSlotCoverageMismatch;
    if (span.endCycle() > job.complete.total_cycles) return error.ExecutedCyclesOutsideJob;
    if (span.first_segment == 0) {
        if (span.first_cycle != 0) return error.InitialCycleMismatch;
        if (!std.meta.eql(span.entry, job.complete.initial_state))
            return error.InitialStateMismatch;
        if (!std.meta.eql(span.input.digest, @as(?Digest, job.complete.public_input)))
            return error.InputMismatch;
    } else if (span.input.digest != null) return error.InputMismatch;
    if (span.endSegment() == job.segment_count) {
        if (span.endCycle() != job.complete.total_cycles) return error.FinalCycleMismatch;
        if (!std.meta.eql(span.exit, job.complete.final_state))
            return error.FinalStateMismatch;
        if (!std.meta.eql(span.output.digest, @as(?Digest, job.complete.public_output)))
            return error.OutputMismatch;
    } else if (span.output.digest != null) return error.OutputMismatch;
}

pub fn foldExecuted(left: ExecutedSpan, right: ExecutedSpan) Error!ExecutedSpan {
    if (left.endSegment() != right.first_segment) return error.SegmentDiscontinuity;
    if (left.endCycle() != right.first_cycle) return error.CycleDiscontinuity;
    if (!std.meta.eql(left.exit, right.entry)) return error.StateDiscontinuity;
    if (left.output.digest != null) return error.LeftOutputPresent;
    if (right.input.digest != null) return error.RightInputPresent;
    const segments = std.math.add(u32, left.segment_count, right.segment_count) catch
        return error.SegmentRangeOverflow;
    const cycles = std.math.add(u64, left.cycle_count, right.cycle_count) catch
        return error.CycleRangeOverflow;
    return ExecutedSpan.init(
        left.first_segment,
        segments,
        left.first_cycle,
        cycles,
        left.entry,
        right.exit,
        left.input,
        right.output,
    );
}

pub fn validateDigest(digest: Digest) Error!void {
    for (digest) |word| if (word >= m31.Modulus) return error.NonCanonicalDigest;
}

pub fn ceilLog2(value: u32) u8 {
    std.debug.assert(value != 0);
    return @intCast(32 - @clz(value - 1));
}

pub const Writer = struct {
    words: *StatementWords,
    at: usize = 0,

    pub fn put(self: *Writer, value: u32) void {
        std.debug.assert(self.at < self.words.len and value < m31.Modulus);
        self.words[self.at] = M31.fromCanonical(value);
        self.at += 1;
    }

    pub fn tag(self: *Writer, value: Tag) void {
        self.put(@intFromEnum(value));
    }

    pub fn u32Value(self: *Writer, value: u32) void {
        self.put(value & 0xffff);
        self.put(value >> 16);
    }

    pub fn u64Value(self: *Writer, value: u64) void {
        inline for (0..4) |limb| self.put(@intCast((value >> (16 * limb)) & 0xffff));
    }

    pub fn digest(self: *Writer, value: Digest) void {
        for (value) |word| self.put(word);
    }

    pub fn zeroes(self: *Writer, count: usize) void {
        for (0..count) |_| self.put(0);
    }
};

pub const Reader = struct {
    words: *const StatementWords,
    at: usize = 0,

    fn word(self: *Reader) Error!u32 {
        std.debug.assert(self.at < self.words.len);
        const value = self.words[self.at].toU32();
        self.at += 1;
        if (value >= m31.Modulus) return error.CanonicalWordNonCanonical;
        return value;
    }

    pub fn tag(self: *Reader, expected: Tag) Error!void {
        if (try self.word() != @intFromEnum(expected))
            return error.CanonicalTagMismatch;
    }

    fn limb(self: *Reader) Error!u32 {
        const value = try self.word();
        if (value > std.math.maxInt(u16))
            return error.CanonicalIntegerLimbOutOfRange;
        return value;
    }

    fn u8Value(self: *Reader) Error!u8 {
        const value = try self.word();
        return std.math.cast(u8, value) orelse
            error.CanonicalIntegerLimbOutOfRange;
    }

    fn u32Value(self: *Reader) Error!u32 {
        const low = try self.limb();
        const high = try self.limb();
        return low | (high << 16);
    }

    fn u64Value(self: *Reader) Error!u64 {
        var value: u64 = 0;
        inline for (0..4) |limb_index|
            value |= @as(u64, try self.limb()) << (16 * limb_index);
        return value;
    }

    fn digest(self: *Reader) Error!Digest {
        var result: Digest = undefined;
        for (&result) |*value| value.* = try self.word();
        return result;
    }

    fn zeroes(self: *Reader, count: usize) Error!void {
        for (0..count) |_| if (try self.word() != 0)
            return error.CanonicalPaddingNonZero;
    }
};

pub fn readMachine(reader: *Reader) Error!MachineState {
    try reader.tag(.machine_state);
    const pc = try reader.u32Value();
    var registers: [32]u32 = undefined;
    for (&registers) |*value| value.* = try reader.u32Value();
    return MachineState.init(
        pc,
        registers,
        try reader.digest(),
        try reader.digest(),
    );
}

pub fn readComplete(reader: *Reader) Error!CompleteExecution {
    try reader.tag(.complete_execution);
    return CompleteExecution.init(
        try reader.digest(),
        try reader.digest(),
        try readMachine(reader),
        try readMachine(reader),
        try reader.digest(),
        try reader.digest(),
        try reader.u64Value(),
    );
}

pub fn readJob(reader: *Reader) Error!JobContext {
    try reader.tag(.job_context);
    const complete = try readComplete(reader);
    const segment_count = try reader.u32Value();
    const encoded_height = try reader.u8Value();
    const result = try JobContext.init(complete, segment_count);
    if (result.slot_height != encoded_height)
        return error.RootHeightNotMinimal;
    return result;
}

pub fn readSlot(reader: *Reader) Error!SlotSpan {
    try reader.tag(.slot_span);
    const node_index = try reader.u64Value();
    const height = try reader.u8Value();
    if (height > MAX_SLOT_HEIGHT or
        node_index > (@as(u64, std.math.maxInt(u64)) >> @as(u6, @intCast(height))))
    {
        return error.SlotRangeOverflow;
    }
    const result = try SlotSpan.init(
        node_index << @as(u6, @intCast(height)),
        height,
    );
    if (result.nodeIndex() != node_index) return error.SlotRangeOverflow;
    return result;
}

pub fn readEdge(reader: *Reader) Error!EdgeClaim {
    const tag_value = try reader.word();
    if (tag_value == @intFromEnum(Tag.absent_edge)) {
        try reader.zeroes(8);
        return EdgeClaim.absent();
    }
    if (tag_value == @intFromEnum(Tag.present_edge))
        return EdgeClaim.present(try reader.digest());
    return error.CanonicalTagMismatch;
}

pub fn readExecuted(reader: *Reader) Error!ExecutedSpan {
    try reader.tag(.executed_span);
    return ExecutedSpan.init(
        try reader.u32Value(),
        try reader.u32Value(),
        try reader.u64Value(),
        try reader.u64Value(),
        try readMachine(reader),
        try readMachine(reader),
        try readEdge(reader),
        try readEdge(reader),
    );
}

pub fn readBody(reader: *Reader) Error!SpanBody {
    const tag_value = try reader.word();
    if (tag_value == @intFromEnum(Tag.empty_body)) {
        try reader.zeroes(EXECUTED_SPAN_CANONICAL_WORDS);
        return .empty;
    }
    if (tag_value == @intFromEnum(Tag.executed_body))
        return .{ .executed = try readExecuted(reader) };
    return error.CanonicalTagMismatch;
}

pub fn m31WordsEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

pub fn appendMachine(writer: *Writer, state: MachineState) void {
    writer.tag(.machine_state);
    writer.u32Value(state.pc);
    for (state.registers) |value| writer.u32Value(value);
    writer.digest(state.rw_memory);
    writer.digest(state.public_io_state);
}

pub fn appendComplete(writer: *Writer, complete: CompleteExecution) void {
    writer.tag(.complete_execution);
    writer.digest(complete.protocol_id);
    writer.digest(complete.program);
    appendMachine(writer, complete.initial_state);
    appendMachine(writer, complete.final_state);
    writer.digest(complete.public_input);
    writer.digest(complete.public_output);
    writer.u64Value(complete.total_cycles);
}

pub fn appendJob(writer: *Writer, job: JobContext) void {
    writer.tag(.job_context);
    appendComplete(writer, job.complete);
    writer.u32Value(job.segment_count);
    writer.put(job.slot_height);
}
