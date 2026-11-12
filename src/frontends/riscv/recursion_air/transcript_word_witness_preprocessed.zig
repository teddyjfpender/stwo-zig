//! Internal transcript word witness authority shard; use transcript_word_witness.zig publicly.

const dependency_0 = @import("transcript_word_witness_binding.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const ConstructionError = dependency_0.ConstructionError;
const Error = dependency_0.Error;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const ProofKind = dependency_0.ProofKind;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Receipts = dependency_0.Receipts;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const Sink = dependency_0.Sink;
const Source = dependency_0.Source;
const TranscriptTrace = dependency_0.TranscriptTrace;
const batchDigest = dependency_0.batchDigest;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const emitLane = dependency_0.emitLane;
const laneRowCount = dependency_0.laneRowCount;
const logSizeFor = dependency_0.logSizeFor;
const m31 = dependency_0.m31;
const paddedWordCount = dependency_0.paddedWordCount;
const payloadWordCount = dependency_0.payloadWordCount;
const preprocessingDigest = dependency_0.preprocessingDigest;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const trace_mod = dependency_0.trace_mod;
const transcriptEffect = dependency_0.transcriptEffect;
const validateLanePlans = dependency_0.validateLanePlans;
const validateRow = dependency_0.validateRow;
const writePreprocessedRow = dependency_0.writePreprocessedRow;

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) ConstructionError!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(
                u8,
                &self.binding.source_authority_digest,
                &component.SOURCE_AUTHORITY_DIGEST,
            ))
        {
            return error.InvalidWitnessBinding;
        }
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        return preprocessing.generateInto(columns, self);
    }

    pub fn generateMainInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        batch: *const PreparedBatch,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        try batch.validateAgainstPreprocessing(preprocessing);
        try protectMainHeaders(columns, preprocessing, batch);
        return direct.generateMainInto(
            M31,
            M31,
            MAIN_COLUMN_COUNT,
            columns,
            batch.values,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainValue,
            writeMainValue,
        );
    }
};

/// Exactly one retained allocation owns all three verifier-lane layouts.
pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    vm_row_count: usize,
    recursion_row_count: usize,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!Preprocessed {
        try component.SourceAuthority.pinned().validate();
        try validateLanePlans(vm, recursion);
        const vm_rows = try laneRowCount(vm);
        const recursion_rows = try laneRowCount(recursion);
        const row_count = std.math.add(
            usize,
            vm_rows,
            std.math.mul(usize, recursion_rows, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const log_size = try logSizeFor(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var sink = Sink.write(rows);
        try emitLane(&sink, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try emitLane(&sink, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try emitLane(&sink, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (sink.at != row_count) return error.InvalidTranscriptLayout;
        for (rows) |row| try validateRow(row);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_row_count = vm_rows,
            .recursion_row_count = recursion_rows,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
            .authority_digest = preprocessingDigest(
                log_size,
                vm_rows,
                recursion_rows,
                vm.authority_digest,
                recursion.authority_digest,
                rows,
            ),
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Preprocessed) Error!void {
        try component.SourceAuthority.pinned().validate();
        const expected_len = std.math.add(
            usize,
            self.vm_row_count,
            std.math.mul(usize, self.recursion_row_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_len or
            self.log_size != try logSizeFor(expected_len))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows) |row| try validateRow(row);
        const actual = preprocessingDigest(
            self.log_size,
            self.vm_row_count,
            self.recursion_row_count,
            self.vm_schedule_digest,
            self.recursion_schedule_digest,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validate();
        try validateLanePlans(vm, recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_row_count != try laneRowCount(vm) or
            self.recursion_row_count != try laneRowCount(recursion))
        {
            return error.AuthorityMismatch;
        }
        var sink = Sink.compare(self.rows);
        try emitLane(&sink, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try emitLane(&sink, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try emitLane(&sink, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (sink.at != self.rows.len) return error.AuthorityMismatch;
    }

    pub fn activeWordCount(self: *const Preprocessed, kind: ProofKind) usize {
        return switch (kind) {
            .segment_leaf => self.vm_row_count,
            .binary_node => 2 * self.recursion_row_count,
            .empty_leaf => 0,
        };
    }

    pub fn activePayloadCount(self: *const Preprocessed, kind: ProofKind) usize {
        var result: usize = 0;
        for (self.rows) |row| {
            const active = switch (kind) {
                .segment_leaf => row.segment_mask == 1,
                .binary_node => row.binary_mask == 1,
                .empty_leaf => false,
            };
            result += @intFromBool(active and row.is_payload == 1);
        }
        return result;
    }

    fn generateInto(
        self: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        executor: *const Executor,
    ) Error!void {
        try self.validate();
        return direct.generateMainInto(
            M31,
            Row,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            executor,
            validateRow,
            writePreprocessedRow,
        );
    }
};

/// Compact immutable snapshot of the sole proof-supplied main value column.
pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    proof_kind: ProofKind,
    values: []M31,
    preprocessing_digest: digest.Digest,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    lane_count: u8,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
        source: Source,
    ) Error!PreparedBatch {
        try preprocessing.validateAgainst(vm, recursion);
        try validateSource(vm, recursion, source);
        const values = try allocator.alloc(M31, preprocessing.rows.len);
        errdefer allocator.free(values);
        fillValues(values, preprocessing.rows, source);
        var receipts = sourceReceipts(source);
        switch (source) {
            .segment_leaf => receipts.schedules[0] = vm.authority_digest,
            .binary_node => {
                receipts.schedules[0] = recursion.authority_digest;
                receipts.schedules[1] = recursion.authority_digest;
            },
            .empty_leaf => {},
        }
        return .{
            .allocator = allocator,
            .proof_kind = std.meta.activeTag(source),
            .values = values,
            .preprocessing_digest = preprocessing.authority_digest,
            .schedule_receipts = receipts.schedules,
            .transcript_receipts = receipts.transcripts,
            .lane_count = receipts.lane_count,
            .authority_digest = batchDigest(
                std.meta.activeTag(source),
                preprocessing.authority_digest,
                receipts,
                values,
            ),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try component.SourceAuthority.pinned().validate();
        const expected_lanes: u8 = switch (self.proof_kind) {
            .segment_leaf => 1,
            .binary_node => 2,
            .empty_leaf => 0,
        };
        if (self.lane_count != expected_lanes) return error.AuthorityMismatch;
        for (self.values) |value| if (value.v >= m31.Modulus)
            return error.InvalidFieldElement;
        const receipts = Receipts{
            .lane_count = self.lane_count,
            .schedules = self.schedule_receipts,
            .transcripts = self.transcript_receipts,
        };
        const actual = batchDigest(
            self.proof_kind,
            self.preprocessing_digest,
            receipts,
            self.values,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstPreprocessing(
        self: *const PreparedBatch,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        if (self.values.len != preprocessing.rows.len or
            !std.mem.eql(
                u8,
                &self.preprocessing_digest,
                &preprocessing.authority_digest,
            ))
        {
            return error.AuthorityMismatch;
        }
        for (self.values, preprocessing.rows) |value, row| {
            const active = rowActive(row, self.proof_kind);
            if ((!active or row.is_payload == 0) and !value.isZero())
                return error.AuthorityMismatch;
        }
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        preprocessing: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
        source: Source,
    ) Error!void {
        try self.validateAgainstPreprocessing(preprocessing);
        if (std.meta.activeTag(source) != self.proof_kind)
            return error.AuthorityMismatch;
        try preprocessing.validateAgainst(vm, recursion);
        try validateSource(vm, recursion, source);
        var receipts = sourceReceipts(source);
        switch (source) {
            .segment_leaf => receipts.schedules[0] = vm.authority_digest,
            .binary_node => {
                receipts.schedules[0] = recursion.authority_digest;
                receipts.schedules[1] = recursion.authority_digest;
            },
            .empty_leaf => {},
        }
        if (receipts.lane_count != self.lane_count or
            !std.meta.eql(receipts.schedules, self.schedule_receipts) or
            !std.meta.eql(receipts.transcripts, self.transcript_receipts))
        {
            return error.AuthorityMismatch;
        }
        for (self.values, preprocessing.rows) |value, row| {
            if (!value.eql(valueFor(row, source))) return error.AuthorityMismatch;
        }
    }
};

pub fn mainRow(value: M31) Error![MAIN_COLUMN_COUNT]M31 {
    if (value.v >= m31.Modulus) return error.InvalidFieldElement;
    return .{ M31.one(), value };
}

pub fn logicalRow(
    row: Row,
    value: M31,
    kind: ProofKind,
) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try validateRow(row);
    const main = try mainRow(value);
    const selectors = kind.selectors();
    return main ++ row.values() ++ .{ selectors[0], selectors[1] };
}

pub fn validateSource(
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
    source: Source,
) Error!void {
    switch (source) {
        .segment_leaf => |trace| try validateTraceAgainstPlan(vm, trace),
        .binary_node => |traces| {
            try validateTraceAgainstPlan(recursion, traces.left);
            try validateTraceAgainstPlan(recursion, traces.right);
        },
        .empty_leaf => {},
    }
}

pub fn validateTraceAgainstPlan(
    plan: *const schedule.Plan,
    trace: *const TranscriptTrace,
) Error!void {
    try plan.validate();
    try trace.validate();
    var frame_at: usize = 0;
    var call_at: usize = 0;
    var pow_at: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const payload_count = try payloadWordCount(plan.schema, step);
        const mix_frame = try validateExpectedFrame(
            trace,
            &frame_at,
            &call_at,
            .mix,
            sequence,
            step,
            payload_count,
        );
        if (effect != .mix) {
            const draw_frame = try validateExpectedFrame(
                trace,
                &frame_at,
                &call_at,
                .draw,
                sequence,
                step,
                0,
            );
            if (effect == .pow) {
                if (pow_at >= trace.pow_checks.len)
                    return error.InvalidTranscriptSource;
                const check = trace.pow_checks[pow_at];
                const bits = powBits(step) orelse
                    return error.InvalidTranscriptSource;
                if (draw_frame.finalCallId() != check.call_id or
                    check.bits != bits or
                    !draw_frame.output[0].eql(check.word))
                {
                    return error.InvalidTranscriptSource;
                }
                for (0..component.POW_NONCE_WORD_COUNT) |limb| {
                    const expected: u32 = @truncate(
                        (check.nonce >> @intCast(16 * limb)) & 0xffff,
                    );
                    if (mix_frame.words[2 * component.RATE + limb].v != expected)
                        return error.InvalidTranscriptSource;
                }
                pow_at += 1;
            }
        }
    }
    if (frame_at != trace.hash_frames.len or
        call_at != trace.poseidon_calls.len or
        pow_at != trace.pow_checks.len)
    {
        return error.InvalidTranscriptSource;
    }
}

pub fn validateExpectedFrame(
    trace: *const TranscriptTrace,
    frame_at: *usize,
    call_at: *usize,
    purpose: trace_mod.HashPurpose,
    sequence: usize,
    step: schedule.VerifierStep,
    payload_count: usize,
) Error!*const trace_mod.HashFrame {
    if (frame_at.* >= trace.hash_frames.len)
        return error.InvalidTranscriptSource;
    const frame = &trace.hash_frames[frame_at.*];
    const raw_count: usize = if (purpose == .mix)
        2 * component.RATE + payload_count
    else
        component.RATE + 2;
    const padded_count = try paddedWordCount(raw_count);
    const call_count = padded_count / component.RATE;
    if (frame.hash_id != @as(u32, @intCast(frame_at.*)) or
        frame.first_call_id != @as(u32, @intCast(call_at.*)) or
        frame.call_count != @as(u32, @intCast(call_count)) or
        frame.purpose != purpose or
        frame.words.len != raw_count)
    {
        return error.InvalidTranscriptSource;
    }
    if (purpose == .mix) {
        const encoded = step.encode();
        const header: [component.TRANSCRIPT_HEADER_WORD_COUNT]u32 = .{
            component.TRANSCRIPT_OPERATION_TAG,
            @as(u32, @intCast(sequence)),
            encoded.tag,
            @as(u32, encoded.arity),
        } ++ encoded.args;
        for (header, 0..) |expected, index| {
            if (frame.words[component.RATE + index].v != expected)
                return error.InvalidTranscriptSource;
        }
    } else if (frame.words[component.RATE].v != component.DRAW_COUNTER or
        frame.words[component.RATE + 1].v != component.DRAW_TAG)
    {
        return error.InvalidTranscriptSource;
    }
    frame_at.* += 1;
    call_at.* = std.math.add(usize, call_at.*, call_count) catch
        return error.ArithmeticOverflow;
    return frame;
}

pub fn powBits(step: schedule.VerifierStep) ?u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| item.bits,
        .verify_and_absorb_pcs_pow => |item| item.bits,
        else => null,
    };
}

pub fn fillValues(destination: []M31, rows: []const Row, source: Source) void {
    std.debug.assert(destination.len == rows.len);
    for (destination, rows) |*value, row| value.* = valueFor(row, source);
}

pub fn valueFor(row: Row, source: Source) M31 {
    if (row.is_payload == 0) return M31.zero();
    const trace: ?*const TranscriptTrace = switch (source) {
        .segment_leaf => |segment| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            segment
        else
            null,
        .binary_node => |binary| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => binary.left,
            RIGHT_RECURSION_VERIFIER_ID => binary.right,
            else => null,
        },
        .empty_leaf => null,
    };
    const selected = trace orelse return M31.zero();
    return selected.hash_frames[row.hash_id].words[row.word_index];
}

pub fn rowActive(row: Row, kind: ProofKind) bool {
    return switch (kind) {
        .segment_leaf => row.segment_mask == 1,
        .binary_node => row.binary_mask == 1,
        .empty_leaf => false,
    };
}

pub fn validateMainValue(value: M31) direct.Error!void {
    if (value.v >= m31.Modulus) return error.InvalidTraceRow;
}

pub fn writeMainValue(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    value: M31,
) void {
    columns[0][logical_row] = M31.one();
    columns[1][logical_row] = value;
}

pub fn sourceReceipts(source: Source) Receipts {
    var result = Receipts{
        .lane_count = 0,
        .schedules = .{.{0} ** 8} ** 2,
        .transcripts = .{.{0} ** 32} ** 2,
    };
    switch (source) {
        .segment_leaf => |trace| {
            result.lane_count = 1;
            result.transcripts[0] = trace.receiptDigest();
        },
        .binary_node => |traces| {
            result.lane_count = 2;
            result.transcripts[0] = traces.left.receiptDigest();
            result.transcripts[1] = traces.right.receiptDigest();
        },
        .empty_leaf => {},
    }
    return result;
}

pub fn protectMainHeaders(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    preprocessing: *const Preprocessed,
    batch: *const PreparedBatch,
) direct.Error!void {
    const descriptor = try objectRange(columns);
    const preprocessing_header = try objectRange(preprocessing);
    const batch_header = try objectRange(batch);
    const preprocessing_rows = try sliceRange(Row, preprocessing.rows);
    for (columns) |column| {
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(descriptor) or
            destination.overlaps(preprocessing_header) or
            destination.overlaps(batch_header))
        {
            return error.AliasedDestination;
        }
        if (destination.overlaps(preprocessing_rows))
            return error.AliasedInput;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.AddressOverflow,
    };
}

pub fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.AddressOverflow,
    };
}
