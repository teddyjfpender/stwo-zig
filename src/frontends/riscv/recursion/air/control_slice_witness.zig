//! Verifier-owned preprocessing for the two exact recursion control slices.
//!
//! The public-LogUp and AIR-composition slices both consume selected rows from
//! the authenticated full verifier schedule.  Selection is performed once on
//! the cold path.  The hot witness path writes the resulting nine columns
//! directly into caller-owned SoA storage without allocating or re-encoding
//! schedule steps.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const proof_kind_mod = @import("proof_kind.zig");
const schedule = @import("verifier_schedule.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const COLUMN_COUNT: usize = 9;
pub const LOGICAL_INPUT_COUNT: usize = 11;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const Error = direct.Error || schedule.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    CompositionAssertionMissing,
    CompositionAssertionNotAdjacent,
    DuplicateCompositionAssertion,
    DuplicateGlobalAssertion,
    GlobalAssertionMissing,
    InstructionAfterCompositionAssertion,
    InstructionCountMismatch,
    InstructionCountOverflow,
    InvalidControlRow,
    LogSizeOutOfRange,
    NonCanonicalInstructionIndex,
    NonCanonicalTermIndex,
    NonContiguousInstruction,
    SampledValueCountMismatch,
    ScheduleAuthorityMismatch,
    SchemaMismatch,
    SequenceOutOfRange,
    TermAfterGlobalAssertion,
    TermCountMismatch,
    TermCountOverflow,
};

pub const Row = struct {
    segment_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,

    /// Nine exact preprocessing values.  Every stored row is live; only padded
    /// rows receive a zero row-mask from the direct writer's zero fill.
    pub fn values(self: Row) [COLUMN_COUNT]M31 {
        return .{
            M31.one(),
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.sequence),
            M31.fromU64(self.tag),
            M31.fromU64(self.args[0]),
            M31.fromU64(self.args[1]),
            M31.fromU64(self.args[2]),
            M31.fromU64(self.args[3]),
        };
    }
};

pub const PublicLogupPreprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    vm_public_term_count: u32,
    recursion_public_term_count: u32,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        vm_public_term_count: u32,
        recursion: *const schedule.Plan,
        recursion_public_term_count: u32,
    ) Error!PublicLogupPreprocessed {
        try validatePlans(vm, recursion);
        if (vm.spec.public_logup_term_count != vm_public_term_count or
            recursion.spec.public_logup_term_count != recursion_public_term_count)
        {
            return error.TermCountMismatch;
        }
        const vm_count = try validatePublicLogupSteps(
            vm.steps,
            vm_public_term_count,
        );
        const recursion_count = try validatePublicLogupSteps(
            recursion.steps,
            recursion_public_term_count,
        );
        const row_count = try totalLaneRows(vm_count, recursion_count);
        const log_size = try logSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var at: usize = 0;
        try appendPublicRows(
            rows,
            &at,
            vm.steps,
            vm_public_term_count,
            SEGMENT_VERIFIER_ID,
        );
        try appendPublicRows(
            rows,
            &at,
            recursion.steps,
            recursion_public_term_count,
            LEFT_RECURSION_VERIFIER_ID,
        );
        try appendPublicRows(
            rows,
            &at,
            recursion.steps,
            recursion_public_term_count,
            RIGHT_RECURSION_VERIFIER_ID,
        );
        std.debug.assert(at == rows.len);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_public_term_count = vm_public_term_count,
            .recursion_public_term_count = recursion_public_term_count,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
        };
    }

    pub fn deinit(self: *PublicLogupPreprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PublicLogupPreprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try validatePlans(vm, recursion);
        try self.validateAgainstSealedPlans(vm, recursion);
    }

    /// Allocation-free continuation for a plan pair already admitted by
    /// `validateAgainst`. The retained rows depend only on the public-LogUp
    /// slices checked below; unrelated verifier steps never enter this
    /// witness. Schedule identities and the exact relevant steps are still
    /// compared, so this is not a detached fast-path authority.
    pub fn validateAgainstSealedPlans(
        self: *const PublicLogupPreprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        if (vm.schema != .vm or recursion.schema != .recursion)
            return error.SchemaMismatch;
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_public_term_count != vm.spec.public_logup_term_count or
            self.recursion_public_term_count != recursion.spec.public_logup_term_count)
        {
            return error.ScheduleAuthorityMismatch;
        }
        var at: usize = 0;
        try comparePublicRows(
            self.rows,
            &at,
            vm.steps,
            self.vm_public_term_count,
            SEGMENT_VERIFIER_ID,
        );
        try comparePublicRows(
            self.rows,
            &at,
            recursion.steps,
            self.recursion_public_term_count,
            LEFT_RECURSION_VERIFIER_ID,
        );
        try comparePublicRows(
            self.rows,
            &at,
            recursion.steps,
            self.recursion_public_term_count,
            RIGHT_RECURSION_VERIFIER_ID,
        );
        if (at != self.rows.len) return error.ScheduleAuthorityMismatch;
    }

    pub fn activeStepCount(self: *const PublicLogupPreprocessed, kind: ProofKind) usize {
        return activeCount(
            self.vm_public_term_count + 1,
            self.recursion_public_term_count + 1,
            kind,
        );
    }

    pub fn generateInto(
        self: *const PublicLogupPreprocessed,
        columns: *[COLUMN_COUNT][]M31,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(vm, recursion);
        return generateRows(self, columns, self.rows, self.log_size);
    }
};

pub const CompositionPreprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    vm_air_instruction_count: u32,
    vm_sampled_value_count: u32,
    recursion_air_instruction_count: u32,
    recursion_sampled_value_count: u32,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        vm_air_instruction_count: u32,
        vm_sampled_value_count: u32,
        recursion: *const schedule.Plan,
        recursion_air_instruction_count: u32,
        recursion_sampled_value_count: u32,
    ) Error!CompositionPreprocessed {
        try validatePlans(vm, recursion);
        if (vm.spec.air_instruction_count != vm_air_instruction_count or
            recursion.spec.air_instruction_count != recursion_air_instruction_count)
        {
            return error.InstructionCountMismatch;
        }
        const vm_count = try validateCompositionSteps(
            vm.steps,
            vm_air_instruction_count,
            vm_sampled_value_count,
        );
        const recursion_count = try validateCompositionSteps(
            recursion.steps,
            recursion_air_instruction_count,
            recursion_sampled_value_count,
        );
        const row_count = try totalLaneRows(vm_count, recursion_count);
        const log_size = try logSize(row_count);
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var at: usize = 0;
        try appendCompositionRows(
            rows,
            &at,
            vm.steps,
            vm_air_instruction_count,
            vm_sampled_value_count,
            SEGMENT_VERIFIER_ID,
        );
        try appendCompositionRows(
            rows,
            &at,
            recursion.steps,
            recursion_air_instruction_count,
            recursion_sampled_value_count,
            LEFT_RECURSION_VERIFIER_ID,
        );
        try appendCompositionRows(
            rows,
            &at,
            recursion.steps,
            recursion_air_instruction_count,
            recursion_sampled_value_count,
            RIGHT_RECURSION_VERIFIER_ID,
        );
        std.debug.assert(at == rows.len);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_air_instruction_count = vm_air_instruction_count,
            .vm_sampled_value_count = vm_sampled_value_count,
            .recursion_air_instruction_count = recursion_air_instruction_count,
            .recursion_sampled_value_count = recursion_sampled_value_count,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
        };
    }

    pub fn deinit(self: *CompositionPreprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const CompositionPreprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try validatePlans(vm, recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_air_instruction_count != vm.spec.air_instruction_count or
            self.recursion_air_instruction_count != recursion.spec.air_instruction_count)
        {
            return error.ScheduleAuthorityMismatch;
        }
        var at: usize = 0;
        try compareCompositionRows(
            self.rows,
            &at,
            vm.steps,
            self.vm_air_instruction_count,
            self.vm_sampled_value_count,
            SEGMENT_VERIFIER_ID,
        );
        try compareCompositionRows(
            self.rows,
            &at,
            recursion.steps,
            self.recursion_air_instruction_count,
            self.recursion_sampled_value_count,
            LEFT_RECURSION_VERIFIER_ID,
        );
        try compareCompositionRows(
            self.rows,
            &at,
            recursion.steps,
            self.recursion_air_instruction_count,
            self.recursion_sampled_value_count,
            RIGHT_RECURSION_VERIFIER_ID,
        );
        if (at != self.rows.len) return error.ScheduleAuthorityMismatch;
    }

    pub fn activeStepCount(self: *const CompositionPreprocessed, kind: ProofKind) usize {
        return activeCount(
            self.vm_air_instruction_count + 1,
            self.recursion_air_instruction_count + 1,
            kind,
        );
    }

    pub fn generateInto(
        self: *const CompositionPreprocessed,
        columns: *[COLUMN_COUNT][]M31,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(vm, recursion);
        return generateRows(self, columns, self.rows, self.log_size);
    }
};

/// Validates the exact public-LogUp schedule slice without allocating.
pub fn validatePublicLogupSteps(
    steps: []const schedule.VerifierStep,
    public_term_count: u32,
) Error!usize {
    var expected_term: u32 = 0;
    var assertion_seen = false;
    for (steps) |step| switch (step) {
        .accumulate_public_logup_term => |item| {
            if (assertion_seen) return error.TermAfterGlobalAssertion;
            if (item.term != expected_term) return error.NonCanonicalTermIndex;
            expected_term = std.math.add(u32, expected_term, 1) catch
                return error.TermCountOverflow;
        },
        .assert_global_logup_zero => {
            if (assertion_seen) return error.DuplicateGlobalAssertion;
            if (expected_term != public_term_count)
                return error.TermCountMismatch;
            assertion_seen = true;
        },
        else => {},
    };
    if (expected_term != public_term_count) return error.TermCountMismatch;
    if (!assertion_seen) return error.GlobalAssertionMissing;
    return std.math.add(usize, @as(usize, expected_term), 1) catch
        return error.ArithmeticOverflow;
}

/// Validates that AIR instructions are canonical and contiguous and that the
/// authenticated composition assertion immediately follows their slice.
pub fn validateCompositionSteps(
    steps: []const schedule.VerifierStep,
    air_instruction_count: u32,
    sampled_value_count: u32,
) Error!usize {
    var expected_instruction: u32 = 0;
    var previous_instruction_sequence: ?usize = null;
    var assertion_seen = false;
    for (steps, 0..) |step, sequence| switch (step) {
        .evaluate_air_instruction => |item| {
            if (assertion_seen) return error.InstructionAfterCompositionAssertion;
            if (item.instruction != expected_instruction)
                return error.NonCanonicalInstructionIndex;
            if (previous_instruction_sequence) |previous| {
                if (sequence != previous + 1)
                    return error.NonContiguousInstruction;
            }
            previous_instruction_sequence = sequence;
            expected_instruction = std.math.add(
                u32,
                expected_instruction,
                1,
            ) catch return error.InstructionCountOverflow;
        },
        .assert_composition => |item| {
            if (assertion_seen) return error.DuplicateCompositionAssertion;
            if (expected_instruction != air_instruction_count)
                return error.InstructionCountMismatch;
            if (item.sampled_value_count != sampled_value_count)
                return error.SampledValueCountMismatch;
            if (previous_instruction_sequence) |previous| {
                if (sequence != previous + 1)
                    return error.CompositionAssertionNotAdjacent;
            }
            assertion_seen = true;
        },
        else => {},
    };
    if (expected_instruction != air_instruction_count)
        return error.InstructionCountMismatch;
    if (!assertion_seen) return error.CompositionAssertionMissing;
    return std.math.add(usize, @as(usize, expected_instruction), 1) catch
        return error.ArithmeticOverflow;
}

pub fn logicalRow(row: Row, kind: ProofKind) [LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return row.values() ++ .{ selectors[0], selectors[1] };
}

fn validatePlans(
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) Error!void {
    try vm.validate();
    try recursion.validate();
    if (vm.schema != .vm or recursion.schema != .recursion)
        return error.SchemaMismatch;
}

fn totalLaneRows(vm_count: usize, recursion_count: usize) Error!usize {
    return std.math.add(
        usize,
        vm_count,
        std.math.mul(usize, recursion_count, 2) catch
            return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
}

fn logSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn appendPublicRows(
    destination: []Row,
    at: *usize,
    steps: []const schedule.VerifierStep,
    public_term_count: u32,
    verifier_id: u32,
) Error!void {
    _ = try validatePublicLogupSteps(steps, public_term_count);
    for (steps, 0..) |step, sequence| switch (step) {
        .accumulate_public_logup_term, .assert_global_logup_zero => {
            destination[at.*] = try rowFor(step, sequence, verifier_id);
            at.* += 1;
        },
        else => {},
    };
}

fn comparePublicRows(
    actual: []const Row,
    at: *usize,
    steps: []const schedule.VerifierStep,
    public_term_count: u32,
    verifier_id: u32,
) Error!void {
    _ = try validatePublicLogupSteps(steps, public_term_count);
    for (steps, 0..) |step, sequence| switch (step) {
        .accumulate_public_logup_term, .assert_global_logup_zero => {
            const expected = try rowFor(step, sequence, verifier_id);
            if (at.* >= actual.len or !std.meta.eql(actual[at.*], expected))
                return error.ScheduleAuthorityMismatch;
            at.* += 1;
        },
        else => {},
    };
}

fn appendCompositionRows(
    destination: []Row,
    at: *usize,
    steps: []const schedule.VerifierStep,
    air_instruction_count: u32,
    sampled_value_count: u32,
    verifier_id: u32,
) Error!void {
    _ = try validateCompositionSteps(
        steps,
        air_instruction_count,
        sampled_value_count,
    );
    for (steps, 0..) |step, sequence| switch (step) {
        .evaluate_air_instruction, .assert_composition => {
            destination[at.*] = try rowFor(step, sequence, verifier_id);
            at.* += 1;
        },
        else => {},
    };
}

fn compareCompositionRows(
    actual: []const Row,
    at: *usize,
    steps: []const schedule.VerifierStep,
    air_instruction_count: u32,
    sampled_value_count: u32,
    verifier_id: u32,
) Error!void {
    _ = try validateCompositionSteps(
        steps,
        air_instruction_count,
        sampled_value_count,
    );
    for (steps, 0..) |step, sequence| switch (step) {
        .evaluate_air_instruction, .assert_composition => {
            const expected = try rowFor(step, sequence, verifier_id);
            if (at.* >= actual.len or !std.meta.eql(actual[at.*], expected))
                return error.ScheduleAuthorityMismatch;
            at.* += 1;
        },
        else => {},
    };
}

fn rowFor(
    step: schedule.VerifierStep,
    sequence: usize,
    verifier_id: u32,
) Error!Row {
    const sequence_u32 = std.math.cast(u32, sequence) orelse
        return error.SequenceOutOfRange;
    const item = step.encode();
    const row = Row{
        .segment_mask = @intFromBool(verifier_id == SEGMENT_VERIFIER_ID),
        .verifier_id = verifier_id,
        .sequence = sequence_u32,
        .tag = item.tag,
        .args = item.args,
    };
    if (!canonicalRow(row)) return error.InvalidControlRow;
    return row;
}

fn activeCount(vm_count: u32, recursion_count: u32, kind: ProofKind) usize {
    return switch (kind) {
        .segment_leaf => vm_count,
        .binary_node => 2 * @as(usize, recursion_count),
        .empty_leaf => 0,
    };
}

fn canonicalRow(row: Row) bool {
    if (row.segment_mask > 1 or row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.verifier_id >= m31.Modulus or row.sequence >= m31.Modulus or
        row.tag >= m31.Modulus or
        row.segment_mask != @intFromBool(row.verifier_id == SEGMENT_VERIFIER_ID))
    {
        return false;
    }
    for (row.args) |arg| if (arg >= m31.Modulus) return false;
    return true;
}

fn validateRow(row: Row) direct.Error!void {
    if (!canonicalRow(row)) return error.InvalidTraceRow;
}

fn generateRows(
    protected: anytype,
    columns: *[COLUMN_COUNT][]M31,
    rows: []const Row,
    log_size: u32,
) direct.Error!void {
    return direct.generateMainInto(
        M31,
        Row,
        COLUMN_COUNT,
        columns,
        rows,
        log_size,
        M31.zero(),
        protected,
        validateRow,
        writeRow,
    );
}

fn writeRow(columns: *[COLUMN_COUNT][]M31, logical_row: usize, row: Row) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}
