//! Lane-specific verifier-owned preprocessing for universal row 0.
//!
//! V1 duplicates one recursion schedule across both child lanes. This
//! append-only compiler retains the exact VM, left, and right schedules and
//! reconstructs every encoded verifier step before publication or emission.

const std = @import("std");
const stwo_core = @import("stwo_core");
const base = @import("control_witness.zig");
const schedule = @import("verifier_schedule.zig");

const M31 = stwo_core.fields.m31.M31;
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/control-witness-heterogeneous/v2\x00";

pub const Error = base.Error || error{
    InvalidHeterogeneousControlAuthority,
};

pub const LaneV2 = struct {
    verifier_id: u32,
    schema: schedule.Schema,
    step_count: usize,
    schedule_digest: [8]u32,

    fn init(plan: *const schedule.Plan, verifier_id: u32) Error!LaneV2 {
        try plan.validate();
        if (verifier_id > base.RIGHT_RECURSION_VERIFIER_ID or
            (verifier_id == base.SEGMENT_VERIFIER_ID and plan.schema != .vm))
        {
            return error.SchemaMismatch;
        }
        return .{
            .verifier_id = verifier_id,
            .schema = plan.schema,
            .step_count = plan.steps.len,
            .schedule_digest = plan.authority_digest,
        };
    }
};

pub const PreprocessedV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    log_size: u32,
    rows: []base.Row,
    lanes: [LANE_COUNT]LaneV2,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!PreprocessedV2 {
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        const lanes = [LANE_COUNT]LaneV2{
            try LaneV2.init(vm, base.SEGMENT_VERIFIER_ID),
            try LaneV2.init(left, base.LEFT_RECURSION_VERIFIER_ID),
            try LaneV2.init(right, base.RIGHT_RECURSION_VERIFIER_ID),
        };
        var row_count: usize = 0;
        for (lanes) |lane| row_count = std.math.add(
            usize,
            row_count,
            lane.step_count,
        ) catch return error.ArithmeticOverflow;
        const rows = try allocator.alloc(base.Row, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (plans, lanes) |plan, lane| appendLane(rows, &cursor, plan, lane);
        if (cursor != rows.len)
            return error.InvalidHeterogeneousControlAuthority;
        var result = PreprocessedV2{
            .allocator = allocator,
            .log_size = try base.logSizeForRowCount(row_count),
            .rows = rows,
            .lanes = lanes,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = authorityIdentity(&result);
        try result.validateAgainst(vm, left, right);
        return result;
    }

    pub fn deinit(self: *PreprocessedV2) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        const verifier_ids = [LANE_COUNT]u32{
            base.SEGMENT_VERIFIER_ID,
            base.LEFT_RECURSION_VERIFIER_ID,
            base.RIGHT_RECURSION_VERIFIER_ID,
        };
        var row_count: usize = 0;
        for (plans, self.lanes, verifier_ids) |plan, lane, verifier_id| {
            if (!std.meta.eql(lane, try LaneV2.init(plan, verifier_id)))
                return error.ScheduleAuthorityMismatch;
            row_count = std.math.add(
                usize,
                row_count,
                lane.step_count,
            ) catch return error.ArithmeticOverflow;
        }
        if (self.rows.len != row_count or
            self.log_size != try base.logSizeForRowCount(row_count))
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
        var cursor: usize = 0;
        for (plans, self.lanes) |plan, lane|
            try compareLane(self.rows, &cursor, plan, lane);
        if (cursor != self.rows.len or !std.mem.eql(
            u8,
            &self.authority_sha256,
            &authorityIdentity(self),
        )) return error.InvalidHeterogeneousControlAuthority;
    }

    pub fn activeStepCount(
        self: *const PreprocessedV2,
        kind: base.ProofKind,
    ) usize {
        return switch (kind) {
            .segment_leaf => self.lanes[0].step_count,
            .binary_node => self.lanes[1].step_count + self.lanes[2].step_count,
            .empty_leaf => 0,
        };
    }

    pub fn generateInto(
        self: *const PreprocessedV2,
        columns: *[base.COLUMN_COUNT][]M31,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        try self.validateAgainst(vm, left, right);
        return base.generateValidatedRows(
            self,
            columns,
            self.rows,
            self.log_size,
        );
    }
};

fn appendLane(
    rows: []base.Row,
    cursor: *usize,
    plan: *const schedule.Plan,
    lane: LaneV2,
) void {
    for (plan.steps, 0..) |step, sequence| {
        rows[cursor.*] = base.rowForVerifierStep(
            step,
            @intCast(sequence),
            lane.verifier_id,
            @intFromBool(lane.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(lane.verifier_id != base.SEGMENT_VERIFIER_ID),
        );
        cursor.* += 1;
    }
}

fn compareLane(
    rows: []const base.Row,
    cursor: *usize,
    plan: *const schedule.Plan,
    lane: LaneV2,
) Error!void {
    for (plan.steps, 0..) |step, sequence| {
        const expected = base.rowForVerifierStep(
            step,
            @intCast(sequence),
            lane.verifier_id,
            @intFromBool(lane.verifier_id == base.SEGMENT_VERIFIER_ID),
            @intFromBool(lane.verifier_id != base.SEGMENT_VERIFIER_ID),
        );
        if (cursor.* >= rows.len or !std.meta.eql(rows[cursor.*], expected))
            return error.ScheduleAuthorityMismatch;
        cursor.* += 1;
    }
}

fn authorityIdentity(value: *const PreprocessedV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.log_size);
    for (value.lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u16, @intFromEnum(lane.schema));
        hashInt(&hash, u64, lane.step_count);
        for (lane.schedule_digest) |word| hashInt(&hash, u32, word);
    }
    hashInt(&hash, u64, value.rows.len);
    for (value.rows) |row| for (row.values()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("heterogeneous control row contract drifted");
}
