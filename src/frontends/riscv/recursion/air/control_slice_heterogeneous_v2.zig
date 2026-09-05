//! Lane-specific verifier-owned preprocessing for recursive composition.
//!
//! V1 deliberately applied one recursive verifier plan and one sampled-value
//! count to both child lanes.  That is correct for its fixed homogeneous
//! proof profile, but it cannot authenticate two transparent-STARK children
//! with distinct proof geometry.  This append-only V2 retains the exact VM,
//! left-child, and right-child schedules independently.  Child schedules may
//! describe native VM leaves or recursive nodes; their authenticated schema
//! remains part of the schedule digest.  It changes no V1 rows or identities.

const std = @import("std");
const stwo_core = @import("stwo_core");
const base = @import("control_slice_witness.zig");
const schedule = @import("verifier_schedule.zig");

const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/control-slice-heterogeneous/v2\x00";
const PUBLIC_LOGUP_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/public-logup-control-heterogeneous/v2\x00";

pub const Error = base.Error || error{
    InvalidHeterogeneousControlAuthority,
};

pub const LaneV2 = struct {
    verifier_id: u32,
    air_instruction_count: u32,
    sampled_value_count: u32,
    schedule_digest: [8]u32,

    fn init(
        plan: *const schedule.Plan,
        verifier_id: u32,
        air_instruction_count: u32,
        sampled_value_count: u32,
    ) Error!LaneV2 {
        try plan.validate();
        if (verifier_id > base.RIGHT_RECURSION_VERIFIER_ID or
            (verifier_id == base.SEGMENT_VERIFIER_ID and plan.schema != .vm) or
            plan.spec.air_instruction_count != air_instruction_count)
        {
            return error.SchemaMismatch;
        }
        _ = try base.validateCompositionSteps(
            plan.steps,
            air_instruction_count,
            sampled_value_count,
        );
        return .{
            .verifier_id = verifier_id,
            .air_instruction_count = air_instruction_count,
            .sampled_value_count = sampled_value_count,
            .schedule_digest = plan.authority_digest,
        };
    }

    fn activeRowCount(self: LaneV2) Error!usize {
        return std.math.add(
            usize,
            @as(usize, self.air_instruction_count),
            1,
        ) catch error.ArithmeticOverflow;
    }
};

pub const PublicLogupLaneV2 = struct {
    verifier_id: u32,
    schema: schedule.Schema,
    public_term_count: u32,
    schedule_digest: [8]u32,

    fn init(
        plan: *const schedule.Plan,
        verifier_id: u32,
    ) Error!PublicLogupLaneV2 {
        try plan.validate();
        if (verifier_id > base.RIGHT_RECURSION_VERIFIER_ID or
            (verifier_id == base.SEGMENT_VERIFIER_ID and plan.schema != .vm))
        {
            return error.SchemaMismatch;
        }
        _ = try base.validatePublicLogupSteps(
            plan.steps,
            plan.spec.public_logup_term_count,
        );
        return .{
            .verifier_id = verifier_id,
            .schema = plan.schema,
            .public_term_count = plan.spec.public_logup_term_count,
            .schedule_digest = plan.authority_digest,
        };
    }

    fn activeRowCount(self: PublicLogupLaneV2) Error!usize {
        return std.math.add(
            usize,
            @as(usize, self.public_term_count),
            1,
        ) catch error.ArithmeticOverflow;
    }
};

/// Exact row-17 schedule for one VM capacity lane and two independently
/// compiled children. Unlike V1, neither child inherits the other's public
/// LogUp term count or schema. Generation always reconstructs the retained
/// rows from all three trusted plans, so a resealed mutable row is rejected.
pub const PublicLogupPreprocessedV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    log_size: u32,
    rows: []base.Row,
    lanes: [LANE_COUNT]PublicLogupLaneV2,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!PublicLogupPreprocessedV2 {
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        const lanes = [LANE_COUNT]PublicLogupLaneV2{
            try PublicLogupLaneV2.init(vm, base.SEGMENT_VERIFIER_ID),
            try PublicLogupLaneV2.init(left, base.LEFT_RECURSION_VERIFIER_ID),
            try PublicLogupLaneV2.init(right, base.RIGHT_RECURSION_VERIFIER_ID),
        };
        var row_count: usize = 0;
        for (lanes) |lane| row_count = std.math.add(
            usize,
            row_count,
            try lane.activeRowCount(),
        ) catch return error.ArithmeticOverflow;
        const rows = try allocator.alloc(base.Row, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (plans, lanes) |plan, lane|
            try appendPublicLane(rows, &cursor, plan, lane);
        if (cursor != rows.len)
            return error.InvalidHeterogeneousControlAuthority;
        var result = PublicLogupPreprocessedV2{
            .allocator = allocator,
            .log_size = try base.logSizeForRowCount(row_count),
            .rows = rows,
            .lanes = lanes,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = publicLogupIdentity(&result);
        try result.validateAgainst(vm, left, right);
        return result;
    }

    pub fn deinit(self: *PublicLogupPreprocessedV2) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PublicLogupPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
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
        for (plans, self.lanes, verifier_ids) |plan, retained, verifier_id| {
            const expected = try PublicLogupLaneV2.init(plan, verifier_id);
            if (!std.meta.eql(expected, retained))
                return error.ScheduleAuthorityMismatch;
            row_count = std.math.add(
                usize,
                row_count,
                try expected.activeRowCount(),
            ) catch return error.ArithmeticOverflow;
        }
        if (self.rows.len != row_count or
            self.log_size != try base.logSizeForRowCount(row_count))
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
        var cursor: usize = 0;
        for (plans, self.lanes) |plan, lane|
            try comparePublicLane(self.rows, &cursor, plan, lane);
        if (cursor != self.rows.len or !std.mem.eql(
            u8,
            &self.authority_sha256,
            &publicLogupIdentity(self),
        )) return error.InvalidHeterogeneousControlAuthority;
    }

    pub fn activeStepCount(
        self: *const PublicLogupPreprocessedV2,
        kind: base.ProofKind,
    ) Error!usize {
        return switch (kind) {
            .segment_leaf => self.lanes[0].activeRowCount(),
            .binary_node => std.math.add(
                usize,
                try self.lanes[1].activeRowCount(),
                try self.lanes[2].activeRowCount(),
            ) catch error.ArithmeticOverflow,
            .empty_leaf => 0,
        };
    }

    pub fn generateInto(
        self: *const PublicLogupPreprocessedV2,
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

/// Exact rows for one VM capacity lane and two independently shaped recursive
/// child lanes.  All arrays are owned, and validation reconstructs every row
/// from the retained schedule authorities before any witness generation.
pub const CompositionPreprocessedV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    log_size: u32,
    rows: []base.Row,
    lanes: [LANE_COUNT]LaneV2,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        vm_air_instruction_count: u32,
        vm_sampled_value_count: u32,
        left: *const schedule.Plan,
        left_air_instruction_count: u32,
        left_sampled_value_count: u32,
        right: *const schedule.Plan,
        right_air_instruction_count: u32,
        right_sampled_value_count: u32,
    ) Error!CompositionPreprocessedV2 {
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        const lanes = [LANE_COUNT]LaneV2{
            try LaneV2.init(
                vm,
                base.SEGMENT_VERIFIER_ID,
                vm_air_instruction_count,
                vm_sampled_value_count,
            ),
            try LaneV2.init(
                left,
                base.LEFT_RECURSION_VERIFIER_ID,
                left_air_instruction_count,
                left_sampled_value_count,
            ),
            try LaneV2.init(
                right,
                base.RIGHT_RECURSION_VERIFIER_ID,
                right_air_instruction_count,
                right_sampled_value_count,
            ),
        };
        var row_count: usize = 0;
        for (lanes) |lane| {
            row_count = std.math.add(
                usize,
                row_count,
                try lane.activeRowCount(),
            ) catch return error.ArithmeticOverflow;
        }
        const log_size = try base.logSizeForRowCount(row_count);
        const rows = try allocator.alloc(base.Row, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (plans, lanes) |plan, lane|
            try appendLane(rows, &cursor, plan, lane);
        if (cursor != rows.len)
            return error.InvalidHeterogeneousControlAuthority;

        var result = CompositionPreprocessedV2{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .lanes = lanes,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = authorityIdentity(&result);
        try result.validateAgainst(vm, left, right);
        return result;
    }

    pub fn deinit(self: *CompositionPreprocessedV2) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const CompositionPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        const verifier_ids = [LANE_COUNT]u32{
            base.SEGMENT_VERIFIER_ID,
            base.LEFT_RECURSION_VERIFIER_ID,
            base.RIGHT_RECURSION_VERIFIER_ID,
        };
        var expected_row_count: usize = 0;
        for (plans, self.lanes, verifier_ids) |plan, retained, verifier_id| {
            const expected = try LaneV2.init(
                plan,
                verifier_id,
                retained.air_instruction_count,
                retained.sampled_value_count,
            );
            if (!std.meta.eql(expected, retained))
                return error.ScheduleAuthorityMismatch;
            expected_row_count = std.math.add(
                usize,
                expected_row_count,
                try retained.activeRowCount(),
            ) catch return error.ArithmeticOverflow;
        }
        if (self.rows.len != expected_row_count or
            self.log_size != try base.logSizeForRowCount(expected_row_count))
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
        var cursor: usize = 0;
        for (plans, self.lanes) |plan, lane|
            try compareLane(self.rows, &cursor, plan, lane);
        if (cursor != self.rows.len or
            !std.mem.eql(
                u8,
                &self.authority_sha256,
                &authorityIdentity(self),
            ))
        {
            return error.InvalidHeterogeneousControlAuthority;
        }
    }

    pub fn activeStepCount(
        self: *const CompositionPreprocessedV2,
        kind: base.ProofKind,
    ) Error!usize {
        return switch (kind) {
            .segment_leaf => self.lanes[0].activeRowCount(),
            .binary_node => std.math.add(
                usize,
                try self.lanes[1].activeRowCount(),
                try self.lanes[2].activeRowCount(),
            ) catch error.ArithmeticOverflow,
            .empty_leaf => 0,
        };
    }

    pub fn generateInto(
        self: *const CompositionPreprocessedV2,
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
) Error!void {
    _ = try base.validateCompositionSteps(
        plan.steps,
        lane.air_instruction_count,
        lane.sampled_value_count,
    );
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .evaluate_air_instruction, .assert_composition => {
            if (cursor.* >= rows.len)
                return error.InvalidHeterogeneousControlAuthority;
            rows[cursor.*] = try base.rowForVerifierStep(
                step,
                sequence,
                lane.verifier_id,
            );
            cursor.* += 1;
        },
        else => {},
    };
}

fn compareLane(
    rows: []const base.Row,
    cursor: *usize,
    plan: *const schedule.Plan,
    lane: LaneV2,
) Error!void {
    _ = try base.validateCompositionSteps(
        plan.steps,
        lane.air_instruction_count,
        lane.sampled_value_count,
    );
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .evaluate_air_instruction, .assert_composition => {
            const expected = try base.rowForVerifierStep(
                step,
                sequence,
                lane.verifier_id,
            );
            if (cursor.* >= rows.len or
                !std.meta.eql(rows[cursor.*], expected))
            {
                return error.ScheduleAuthorityMismatch;
            }
            cursor.* += 1;
        },
        else => {},
    };
}

fn appendPublicLane(
    rows: []base.Row,
    cursor: *usize,
    plan: *const schedule.Plan,
    lane: PublicLogupLaneV2,
) Error!void {
    _ = try base.validatePublicLogupSteps(
        plan.steps,
        lane.public_term_count,
    );
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .accumulate_public_logup_term, .assert_global_logup_zero => {
            if (cursor.* >= rows.len)
                return error.InvalidHeterogeneousControlAuthority;
            rows[cursor.*] = try base.rowForVerifierStep(
                step,
                sequence,
                lane.verifier_id,
            );
            cursor.* += 1;
        },
        else => {},
    };
}

fn comparePublicLane(
    rows: []const base.Row,
    cursor: *usize,
    plan: *const schedule.Plan,
    lane: PublicLogupLaneV2,
) Error!void {
    _ = try base.validatePublicLogupSteps(
        plan.steps,
        lane.public_term_count,
    );
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .accumulate_public_logup_term, .assert_global_logup_zero => {
            const expected = try base.rowForVerifierStep(
                step,
                sequence,
                lane.verifier_id,
            );
            if (cursor.* >= rows.len or
                !std.meta.eql(rows[cursor.*], expected))
            {
                return error.ScheduleAuthorityMismatch;
            }
            cursor.* += 1;
        },
        else => {},
    };
}

fn authorityIdentity(value: *const CompositionPreprocessedV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.log_size);
    for (value.lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u32, lane.air_instruction_count);
        hashInt(&hash, u32, lane.sampled_value_count);
        for (lane.schedule_digest) |word| hashInt(&hash, u32, word);
    }
    hashInt(&hash, u64, @intCast(value.rows.len));
    for (value.rows) |row| {
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.sequence);
        hashInt(&hash, u32, row.tag);
        for (row.args) |arg| hashInt(&hash, u32, arg);
    }
    return hash.finalResult();
}

fn publicLogupIdentity(value: *const PublicLogupPreprocessedV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PUBLIC_LOGUP_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.log_size);
    for (value.lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u16, @intFromEnum(lane.schema));
        hashInt(&hash, u32, lane.public_term_count);
        for (lane.schedule_digest) |word| hashInt(&hash, u32, word);
    }
    hashInt(&hash, u64, value.rows.len);
    for (value.rows) |row| {
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.sequence);
        hashInt(&hash, u32, row.tag);
        for (row.args) |arg| hashInt(&hash, u32, arg);
    }
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("heterogeneous control slice contract drifted");
}
