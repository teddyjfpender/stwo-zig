//! Verifier-owned preprocessing and allocation-free SoA writer for row 0.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const control = @import("control.zig");
const proof_kind_mod = @import("proof_kind.zig");
const schedule = @import("verifier_schedule.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const COLUMN_COUNT = control.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const Error = direct.Error || schedule.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    InvalidControlRow,
    LogSizeOutOfRange,
    ScheduleAuthorityMismatch,
    SchemaMismatch,
};

pub const Row = struct {
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    terminal_mask: u32,

    pub fn values(self: Row) [COLUMN_COUNT]M31 {
        return .{
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.binary_mask),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.sequence),
            M31.fromU64(self.tag),
            M31.fromU64(self.args[0]),
            M31.fromU64(self.args[1]),
            M31.fromU64(self.args[2]),
            M31.fromU64(self.args[3]),
            M31.fromU64(self.terminal_mask),
        };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []Row,
    vm_step_count: usize,
    recursion_step_count: usize,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!Preprocessed {
        try validateLanePlans(vm, recursion);
        const recursion_rows = std.math.mul(
            usize,
            recursion.steps.len,
            2,
        ) catch return error.ArithmeticOverflow;
        const row_count = std.math.add(
            usize,
            vm.steps.len,
            recursion_rows,
        ) catch return error.ArithmeticOverflow;
        const log_size: u32 = @max(
            MIN_LOG_SIZE,
            @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
        );
        if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;

        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        var at: usize = 0;
        appendPlanRows(rows, &at, vm, SEGMENT_VERIFIER_ID, 1, 0);
        appendPlanRows(rows, &at, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        appendPlanRows(rows, &at, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        std.debug.assert(at == rows.len);
        for (rows) |row| try validateRow(row);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_step_count = vm.steps.len,
            .recursion_step_count = recursion.steps.len,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try validateLanePlans(vm, recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_step_count != vm.steps.len or
            self.recursion_step_count != recursion.steps.len)
        {
            return error.ScheduleAuthorityMismatch;
        }
        const expected_len = std.math.add(
            usize,
            vm.steps.len,
            std.math.mul(usize, recursion.steps.len, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_len) return error.ScheduleAuthorityMismatch;
        var at: usize = 0;
        try comparePlanRows(self.rows, &at, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try comparePlanRows(self.rows, &at, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try comparePlanRows(self.rows, &at, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (at != self.rows.len) return error.ScheduleAuthorityMismatch;
    }

    pub fn activeStepCount(self: *const Preprocessed, kind: ProofKind) usize {
        return switch (kind) {
            .segment_leaf => self.vm_step_count,
            .binary_node => 2 * self.recursion_step_count,
            .empty_leaf => 0,
        };
    }

    pub fn generateInto(
        self: *const Preprocessed,
        columns: *[COLUMN_COUNT][]M31,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(vm, recursion);
        return direct.generateMainInto(
            M31,
            Row,
            COLUMN_COUNT,
            columns,
            self.rows,
            self.log_size,
            M31.zero(),
            self,
            validateRow,
            writeRow,
        );
    }
};

pub fn logicalRow(row: Row, kind: ProofKind) [control.LOGICAL_INPUT_COUNT]M31 {
    const values = row.values();
    const selectors = kind.selectors();
    return values ++ .{ selectors[0], selectors[1] };
}

fn validateLanePlans(
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) Error!void {
    try vm.validate();
    try recursion.validate();
    if (vm.schema != .vm or recursion.schema != .recursion)
        return error.SchemaMismatch;
}

fn appendPlanRows(
    destination: []Row,
    at: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) void {
    for (plan.steps, 0..) |step, sequence| {
        destination[at.*] = rowFor(
            step,
            @intCast(sequence),
            verifier_id,
            segment_mask,
            binary_mask,
        );
        at.* += 1;
    }
}

fn comparePlanRows(
    actual: []const Row,
    at: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    for (plan.steps, 0..) |step, sequence| {
        const expected = rowFor(
            step,
            @intCast(sequence),
            verifier_id,
            segment_mask,
            binary_mask,
        );
        if (at.* >= actual.len or !std.meta.eql(actual[at.*], expected))
            return error.ScheduleAuthorityMismatch;
        at.* += 1;
    }
}

fn rowFor(
    step: schedule.VerifierStep,
    sequence: u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Row {
    const item = step.encode();
    return .{
        .segment_mask = segment_mask,
        .binary_mask = binary_mask,
        .verifier_id = verifier_id,
        .sequence = sequence,
        .tag = item.tag,
        .args = item.args,
        .terminal_mask = @intFromBool(step.terminal()),
    };
}

fn validateRow(row: Row) direct.Error!void {
    if ((row.segment_mask > 1 or row.binary_mask > 1 or row.terminal_mask > 1) or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id >= m31.Modulus or row.sequence >= m31.Modulus or
        row.tag >= m31.Modulus)
    {
        return error.InvalidTraceRow;
    }
    for (row.args) |arg| if (arg >= m31.Modulus)
        return error.InvalidTraceRow;
}

fn writeRow(columns: *[COLUMN_COUNT][]M31, logical_row: usize, row: Row) void {
    const values = row.values();
    for (columns, values) |column, value| column[logical_row] = value;
}

test "R-012 control preprocessing is verifier-owned across all three lanes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(&fixture.vm, &fixture.recursion);
    try std.testing.expectEqual(fixture.vm.steps.len, preprocessing.activeStepCount(.segment_leaf));
    try std.testing.expectEqual(2 * fixture.recursion.steps.len, preprocessing.activeStepCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 0), preprocessing.activeStepCount(.empty_leaf));
    try std.testing.expectEqual(SEGMENT_VERIFIER_ID, preprocessing.rows[0].verifier_id);
    try std.testing.expectEqual(
        LEFT_RECURSION_VERIFIER_ID,
        preprocessing.rows[fixture.vm.steps.len].verifier_id,
    );
    try std.testing.expect(preprocessing.rows[fixture.vm.steps.len - 1].terminal_mask == 1);
}

test "R-012 control preprocessing mutation and swapped lane reject" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    preprocessing.rows[0].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        preprocessing.validateAgainst(&fixture.vm, &fixture.recursion),
    );
    try std.testing.expectError(
        error.SchemaMismatch,
        Preprocessed.init(std.testing.allocator, &fixture.vm, &fixture.vm),
    );
}

test "R-012 control preprocessing direct writer is atomic and zero pads" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var preprocessing = try Preprocessed.init(
        std.testing.allocator,
        &fixture.vm,
        &fixture.recursion,
    );
    defer preprocessing.deinit();
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const storage = try std.testing.allocator.alloc(M31, COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    @memset(storage, M31.fromU64(99));
    var columns: [COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try preprocessing.generateInto(&columns, &fixture.vm, &fixture.recursion);
    for (preprocessing.rows, 0..) |row, index| {
        for (columns, row.values()) |column, expected|
            try std.testing.expect(column[index].eql(expected));
    }
    for (columns) |column| for (column[preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    const snapshot = try std.testing.allocator.dupe(M31, storage);
    defer std.testing.allocator.free(snapshot);
    columns[1] = columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        preprocessing.generateInto(&columns, &fixture.vm, &fixture.recursion),
    );
    try std.testing.expectEqualSlices(M31, snapshot, storage);
}

test "R-012 control preprocessing releases every allocation failure" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{ &fixture.vm, &fixture.recursion },
    );
}

const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
                shape,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) !void {
    var preprocessing = try Preprocessed.init(allocator, vm, recursion);
    defer preprocessing.deinit();
}

fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("control-air", 0x5450),
        .preprocessing_id = channel.hashBytes("control-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("control-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
    };
}
