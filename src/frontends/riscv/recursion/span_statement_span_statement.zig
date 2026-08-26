//! Internal span statement authority shard; use span_statement.zig publicly.

const dependency_0 = @import("span_statement_executed_span.zig");

const CompleteExecution = dependency_0.CompleteExecution;
const Digest = dependency_0.Digest;
const EXECUTED_SPAN_CANONICAL_WORDS = dependency_0.EXECUTED_SPAN_CANONICAL_WORDS;
const EdgeClaim = dependency_0.EdgeClaim;
const Error = dependency_0.Error;
const ExecutedSpan = dependency_0.ExecutedSpan;
const JobContext = dependency_0.JobContext;
const MachineState = dependency_0.MachineState;
const Reader = dependency_0.Reader;
const SlotSpan = dependency_0.SlotSpan;
const SpanBody = dependency_0.SpanBody;
const StatementWords = dependency_0.StatementWords;
const Writer = dependency_0.Writer;
const appendJob = dependency_0.appendJob;
const appendMachine = dependency_0.appendMachine;
const canonical_layout = dependency_0.canonical_layout;
const foldExecuted = dependency_0.foldExecuted;
const m31 = dependency_0.m31;
const m31WordsEql = dependency_0.m31WordsEql;
const protocol = dependency_0.protocol;
const public_data_mod = dependency_0.public_data_mod;
const readBody = dependency_0.readBody;
const readJob = dependency_0.readJob;
const readSlot = dependency_0.readSlot;
const std = dependency_0.std;
const validateEmpty = dependency_0.validateEmpty;
const validateExecuted = dependency_0.validateExecuted;
const validateSlots = dependency_0.validateSlots;
const vm_claim = dependency_0.vm_claim;

pub const SpanStatement = struct {
    job: JobContext,
    slots: SlotSpan,
    body: SpanBody,

    pub fn init(job: JobContext, slots: SlotSpan, body: SpanBody) Error!SpanStatement {
        const result = SpanStatement{ .job = job, .slots = slots, .body = body };
        try result.validate();
        return result;
    }

    pub fn segmentLeaf(job: JobContext, index: u32, span: ExecutedSpan) Error!SpanStatement {
        return init(job, try SlotSpan.init(index, 0), .{ .executed = span });
    }

    pub fn emptyLeaf(job: JobContext, index: u32) Error!SpanStatement {
        return init(job, try SlotSpan.init(index, 0), .empty);
    }

    pub fn validate(self: SpanStatement) Error!void {
        try self.job.validate();
        try self.slots.validate();
        try validateSlots(self.job, self.slots);
        switch (self.body) {
            .empty => try validateEmpty(self.job, self.slots),
            .executed => |span| try validateExecuted(self.job, self.slots, span),
        }
    }

    pub fn fold(left: SpanStatement, right: SpanStatement) Error!SpanStatement {
        try left.validate();
        try right.validate();
        if (!std.meta.eql(left.job, right.job)) return error.JobMismatch;
        if (left.slots.height != right.slots.height) return error.ChildHeightMismatch;
        if (left.slots.endExclusive() != right.slots.first) return error.SlotsNotAdjacent;
        const parent_height = std.math.add(u8, left.slots.height, 1) catch
            return error.SlotHeightOutOfRange;
        const parent_slots = try SlotSpan.init(left.slots.first, parent_height);
        if (parent_slots.first % parent_slots.capacity() != 0)
            return error.SlotsMisaligned;
        const body: SpanBody = switch (left.body) {
            .empty => switch (right.body) {
                .empty => .empty,
                .executed => return error.EmptyBeforeExecuted,
            },
            .executed => |left_span| switch (right.body) {
                .empty => .{ .executed = left_span },
                .executed => |right_span| .{
                    .executed = try foldExecuted(left_span, right_span),
                },
            },
        };
        return init(left.job, parent_slots, body);
    }

    pub fn canonicalWords(self: SpanStatement) Error!StatementWords {
        try self.validate();
        var words: StatementWords = undefined;
        var writer = Writer{ .words = &words };
        writer.tag(.span_statement);
        appendJob(&writer, self.job);
        appendSlot(&writer, self.slots);
        appendBody(&writer, self.body);
        std.debug.assert(writer.at == words.len);
        return words;
    }

    /// Decodes the pinned V1 word ABI without allocation. Every tag, reserved
    /// padding word, 16-bit integer limb, and field representative is checked
    /// before the normal semantic validators run. A final encode comparison
    /// makes this a strict inverse of `canonicalWords`, not a permissive parser.
    pub fn fromCanonicalWords(words: *const StatementWords) Error!SpanStatement {
        var reader = Reader{ .words = words };
        try reader.tag(.span_statement);
        const statement = try SpanStatement.init(
            try readJob(&reader),
            try readSlot(&reader),
            try readBody(&reader),
        );
        std.debug.assert(reader.at == words.len);
        const canonical = try statement.canonicalWords();
        if (!m31WordsEql(&canonical, words))
            return error.DigestMismatch;
        return statement;
    }
};

pub const RootStatement = struct {
    statement: SpanStatement,

    pub fn init(statement: SpanStatement) Error!RootStatement {
        try statement.validate();
        const job = statement.job;
        if (statement.slots.first != 0) return error.RootSlotStartMismatch;
        if (statement.slots.height != job.slot_height) return error.RootHeightNotMinimal;
        const span = switch (statement.body) {
            .empty => return error.RootIsEmpty,
            .executed => |value| value,
        };
        if (span.first_segment != 0) return error.RootSegmentStartMismatch;
        if (span.segment_count != job.segment_count) return error.RootSegmentCountMismatch;
        if (span.first_cycle != 0) return error.RootCycleStartMismatch;
        if (span.cycle_count != job.complete.total_cycles) return error.RootCycleCountMismatch;
        if (!std.meta.eql(span.entry, job.complete.initial_state))
            return error.RootInitialStateMismatch;
        if (!std.meta.eql(span.exit, job.complete.final_state))
            return error.RootFinalStateMismatch;
        if (!std.meta.eql(span.input.digest, @as(?Digest, job.complete.public_input)))
            return error.RootInputMismatch;
        if (!std.meta.eql(span.output.digest, @as(?Digest, job.complete.public_output)))
            return error.RootOutputMismatch;
        return .{ .statement = statement };
    }
};

/// Allocation-free production result for a complete one-segment VM proof.
pub const SegmentLeaf = struct {
    root: RootStatement,
    words: StatementWords,

    pub fn init(
        data: *const public_data_mod.PublicData,
        claim: *const vm_claim.Encoded,
        protocol_id: Digest,
    ) Error!SegmentLeaf {
        try claim.validateAgainst(data);
        if (!std.meta.eql(protocol_id, protocol.protocolId())) return error.DigestMismatch;
        const initial_rw = data.initial_rw_root orelse return error.InitialRwRootMissing;
        const final_rw = data.final_rw_root orelse return error.FinalRwRootMissing;
        const program = try expandRoot(data.program_root orelse unreachable);
        const zero = [_]u32{0} ** 8;
        const initial = try MachineState.init(
            data.initial_pc,
            data.initial_regs,
            try expandRoot(initial_rw),
            zero,
        );
        const final = try MachineState.init(
            data.final_pc,
            data.final_regs,
            try expandRoot(final_rw),
            zero,
        );
        const complete = try CompleteExecution.init(
            protocol_id,
            program,
            initial,
            final,
            claim.public_input_digest,
            claim.public_output_digest,
            data.clock,
        );
        const job = try JobContext.init(complete, 1);
        const executed = try ExecutedSpan.init(
            0,
            1,
            0,
            data.clock,
            initial,
            final,
            try EdgeClaim.present(claim.public_input_digest),
            try EdgeClaim.present(claim.public_output_digest),
        );
        const statement = try SpanStatement.segmentLeaf(job, 0, executed);
        const root = try RootStatement.init(statement);
        return .{ .root = root, .words = try statement.canonicalWords() };
    }

    pub fn validateAgainst(
        self: SegmentLeaf,
        data: *const public_data_mod.PublicData,
        claim: *const vm_claim.Encoded,
    ) Error!void {
        const expected = try SegmentLeaf.init(data, claim, protocol.protocolId());
        if (!std.meta.eql(expected, self)) return error.DigestMismatch;
    }
};

pub fn expandRoot(root: u32) Error!Digest {
    if (root >= m31.Modulus) return error.NonCanonicalDigest;
    var digest = [_]u32{0} ** 8;
    digest[0] = root;
    return digest;
}

pub fn isIntegerWord(index: usize) bool {
    const machine_starts = [_]usize{
        canonical_layout.initial_state_start,
        canonical_layout.final_state_start,
        canonical_layout.entry_state_start,
        canonical_layout.exit_state_start,
    };
    for (machine_starts) |start| {
        const first = start + canonical_layout.machine_state_pc_start_offset;
        const end = start + canonical_layout.machine_state_rw_digest_start_offset;
        if (index >= first and index < end) return true;
    }
    return inRange(index, canonical_layout.total_cycles_start, 4) or
        inRange(index, canonical_layout.job_segment_count_start, 2) or
        index == canonical_layout.job_slot_height or
        inRange(index, canonical_layout.slot_node_index_start, 4) or
        index == canonical_layout.slot_height or
        inRange(index, canonical_layout.first_segment_start, 2) or
        inRange(index, canonical_layout.executed_segment_count_start, 2) or
        inRange(index, canonical_layout.first_cycle_start, 4) or
        inRange(index, canonical_layout.executed_cycle_count_start, 4);
}

pub fn inRange(index: usize, start: usize, len: usize) bool {
    return index >= start and index < start + len;
}

pub fn appendSlot(writer: *Writer, slots: SlotSpan) void {
    writer.tag(.slot_span);
    writer.u64Value(slots.nodeIndex());
    writer.put(slots.height);
}

pub fn appendEdge(writer: *Writer, edge: EdgeClaim) void {
    if (edge.digest) |digest| {
        writer.tag(.present_edge);
        writer.digest(digest);
    } else {
        writer.tag(.absent_edge);
        writer.zeroes(8);
    }
}

pub fn appendExecuted(writer: *Writer, span: ExecutedSpan) void {
    writer.tag(.executed_span);
    writer.u32Value(span.first_segment);
    writer.u32Value(span.segment_count);
    writer.u64Value(span.first_cycle);
    writer.u64Value(span.cycle_count);
    appendMachine(writer, span.entry);
    appendMachine(writer, span.exit);
    appendEdge(writer, span.input);
    appendEdge(writer, span.output);
}

pub fn appendBody(writer: *Writer, body: SpanBody) void {
    switch (body) {
        .empty => {
            writer.tag(.empty_body);
            writer.zeroes(EXECUTED_SPAN_CANONICAL_WORDS);
        },
        .executed => |span| {
            writer.tag(.executed_body);
            appendExecuted(writer, span);
        },
    }
}
