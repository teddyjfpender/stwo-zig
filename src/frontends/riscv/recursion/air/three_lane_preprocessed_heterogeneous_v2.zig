//! Shared cold owner for exact VM/left/right schedule-row preprocessing.

const std = @import("std");
const schedule = @import("verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;

pub fn Type(comptime Context: type) type {
    const Base = Context.Base;
    const Row = Base.PreprocessedRow;
    const Error = Base.Error || error{
        InvalidHeterogeneousScheduleAuthority,
    };
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        log_size: u32,
        rows: []Row,
        counts: [LANE_COUNT]usize,
        schemas: [LANE_COUNT]schedule.Schema,
        schedule_digests: [LANE_COUNT][8]u32,
        authority_sha256: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            vm: *const schedule.Plan,
            left: *const schedule.Plan,
            right: *const schedule.Plan,
        ) Error!Self {
            const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
            try validatePlans(plans);
            var counts: [LANE_COUNT]usize = undefined;
            var row_count: usize = 0;
            for (plans, &counts) |plan, *count| {
                count.* = try Context.count(plan);
                row_count = std.math.add(
                    usize,
                    row_count,
                    count.*,
                ) catch return error.ArithmeticOverflow;
            }
            const rows = try allocator.alloc(Row, row_count);
            errdefer allocator.free(rows);
            var cursor: usize = 0;
            inline for (plans, 0..) |plan, lane|
                try Context.append(
                    rows,
                    &cursor,
                    plan,
                    @intCast(lane),
                    @intFromBool(lane == 0),
                    @intFromBool(lane != 0),
                );
            if (cursor != rows.len)
                return error.InvalidHeterogeneousScheduleAuthority;
            var result = Self{
                .allocator = allocator,
                .log_size = try Context.logSize(row_count),
                .rows = rows,
                .counts = counts,
                .schemas = .{ vm.schema, left.schema, right.schema },
                .schedule_digests = .{
                    vm.authority_digest,
                    left.authority_digest,
                    right.authority_digest,
                },
                .authority_sha256 = undefined,
            };
            result.authority_sha256 = identity(&result);
            try result.validateAgainst(vm, left, right);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.rows);
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const Self,
            vm: *const schedule.Plan,
            left: *const schedule.Plan,
            right: *const schedule.Plan,
        ) Error!void {
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION)
            {
                return error.InvalidHeterogeneousScheduleAuthority;
            }
            const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
            try validatePlans(plans);
            var row_count: usize = 0;
            for (plans, self.counts, self.schemas, self.schedule_digests) |
                plan,
                count,
                schema,
                schedule_digest,
            | {
                if (count != try Context.count(plan) or
                    schema != plan.schema or
                    !std.meta.eql(schedule_digest, plan.authority_digest))
                {
                    return error.InvalidHeterogeneousScheduleAuthority;
                }
                row_count = std.math.add(
                    usize,
                    row_count,
                    count,
                ) catch return error.ArithmeticOverflow;
            }
            if (self.rows.len != row_count or
                self.log_size != try Context.logSize(row_count))
            {
                return error.InvalidHeterogeneousScheduleAuthority;
            }
            var cursor: usize = 0;
            inline for (plans, 0..) |plan, lane|
                try Context.compare(
                    self.rows,
                    &cursor,
                    plan,
                    @intCast(lane),
                    @intFromBool(lane == 0),
                    @intFromBool(lane != 0),
                );
            if (cursor != self.rows.len or !std.mem.eql(
                u8,
                &self.authority_sha256,
                &identity(self),
            )) return error.InvalidHeterogeneousScheduleAuthority;
        }

        fn validatePlans(plans: [LANE_COUNT]*const schedule.Plan) Error!void {
            for (plans) |plan| try plan.validate();
            if (plans[0].schema != .vm)
                return error.SchemaMismatch;
        }

        fn identity(self: *const Self) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(Context.AUTHORITY_DOMAIN);
            hashInt(&hash, u16, self.format_version);
            hashInt(&hash, u16, self.schema_version);
            hashInt(&hash, u32, self.log_size);
            for (self.counts, self.schemas, self.schedule_digests) |
                count,
                schema,
                schedule_digest,
            | {
                hashInt(&hash, u64, count);
                hashInt(&hash, u16, @intFromEnum(schema));
                for (schedule_digest) |word| hashInt(&hash, u32, word);
            }
            hashInt(&hash, u64, self.rows.len);
            for (self.rows) |row| for (row.values()) |word|
                hashInt(&hash, u32, word.toU32());
            return hash.finalResult();
        }
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("three-lane heterogeneous schedule contract drifted");
}
