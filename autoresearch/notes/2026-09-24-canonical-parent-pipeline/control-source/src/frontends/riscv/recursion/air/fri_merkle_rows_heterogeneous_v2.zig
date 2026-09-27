//! Reconstructed row custody for heterogeneous FRI leaf/node/anchor stages.
//!
//! All three AIRs already namespace rows by verifier id. This module supplies
//! append-only V2 preprocessing that compiles VM, left, and right profiles
//! independently. Anchor rows additionally bind the exact lane-local verifier
//! schedule. Every validation reconstructs rows from those trusted inputs;
//! resealing a mutated public row array is never sufficient for admission.

const std = @import("std");
const reference_v2 = @import("fri_merkle_reference_heterogeneous_v2.zig");
const leaf = @import("fri_merkle_leaf_witness.zig");
const leaf_contract = @import("fri_merkle_leaf_witness_contract.zig");
const leaf_impl = @import("fri_merkle_leaf_witness_preprocessed.zig");
const node = @import("fri_merkle_node_witness.zig");
const anchor = @import("fri_merkle_anchor_witness.zig");
const schedule = @import("verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-merkle-rows/v2\x00";

pub const Kind = enum(u8) { leaf = 0, node = 1, anchor = 2 };

pub const Plans = union(enum) {
    none,
    anchor: [3]*const schedule.Plan,
};

pub const Error = reference_v2.Error || leaf.Error || node.Error || anchor.Error || error{
    InvalidHeterogeneousFriRows,
};

pub fn Preprocessed(comptime kind: Kind) type {
    const Row = RowType(kind);
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        log_size: u32,
        rows: []Row,
        reference_sha256: [32]u8,
        schedule_digests: [3][8]u32,
        authority_sha256: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            reference: *const reference_v2.Reference,
            plans: Plans,
        ) Error!Self {
            try reference.validate();
            const schedule_digests = try validatePlans(kind, reference, plans);
            const rows = try allocator.alloc(Row, try totalRows(kind, reference));
            errdefer allocator.free(rows);
            var cursor: usize = 0;
            for (reference.lanes, 0..) |lane, lane_index| try fillLane(
                kind,
                rows,
                &cursor,
                lane,
                planAt(plans, lane_index),
            );
            if (cursor != rows.len) return error.InvalidHeterogeneousFriRows;
            var result = Self{
                .allocator = allocator,
                .log_size = try logSize(kind, rows.len),
                .rows = rows,
                .reference_sha256 = reference.authority_sha256,
                .schedule_digests = schedule_digests,
                .authority_sha256 = undefined,
            };
            result.authority_sha256 = rowsIdentity(kind, &result);
            try result.validateAgainstAuthority(reference, plans);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.rows);
            self.* = undefined;
        }

        pub fn validateAgainstAuthority(
            self: *const Self,
            reference: *const reference_v2.Reference,
            plans: Plans,
        ) Error!void {
            try reference.validate();
            const expected_schedules = try validatePlans(kind, reference, plans);
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.rows.len != try totalRows(kind, reference) or
                self.log_size != try logSize(kind, self.rows.len) or
                !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
                !std.meta.eql(self.schedule_digests, expected_schedules) or
                !std.mem.eql(u8, &self.authority_sha256, &rowsIdentity(kind, self)))
            {
                return error.InvalidHeterogeneousFriRows;
            }
            var cursor: usize = 0;
            for (reference.lanes, 0..) |lane, lane_index| try validateLane(
                kind,
                self.rows,
                &cursor,
                lane,
                planAt(plans, lane_index),
            );
            if (cursor != self.rows.len) return error.InvalidHeterogeneousFriRows;
        }

        pub fn computedAuthoritySha256(self: *const Self) [32]u8 {
            return rowsIdentity(kind, self);
        }
    };
}

fn RowType(comptime kind: Kind) type {
    return switch (kind) {
        .leaf => leaf.Row,
        .node => node.Row,
        .anchor => anchor.Row,
    };
}

fn validatePlans(
    comptime kind: Kind,
    reference: *const reference_v2.Reference,
    plans: Plans,
) Error![3][8]u32 {
    var digests = [_][8]u32{[_]u32{0} ** 8} ** 3;
    switch (kind) {
        .leaf, .node => if (plans != .none)
            return error.InvalidHeterogeneousFriRows,
        .anchor => switch (plans) {
            .none => return error.InvalidHeterogeneousFriRows,
            .anchor => |retained| for (retained, reference.lanes, 0..) |
                plan,
                lane,
                lane_index,
            | {
                try plan.validate();
                const expected_schema: schedule.Schema = if (lane_index == 0)
                    .vm
                else
                    plan.schema;
                if (plan.schema != expected_schema)
                    return error.ScheduleAuthorityMismatch;
                try anchor.validatePlanGeometry(lane.profile, plan);
                digests[lane_index] = plan.authority_digest;
            },
        },
    }
    return digests;
}

fn planAt(plans: Plans, lane: usize) ?*const schedule.Plan {
    return switch (plans) {
        .none => null,
        .anchor => |values| values[lane],
    };
}

fn totalRows(comptime kind: Kind, reference: *const reference_v2.Reference) Error!usize {
    var count: usize = 0;
    for (reference.lanes) |lane| count = std.math.add(
        usize,
        count,
        try laneRows(kind, lane.profile),
    ) catch return error.ArithmeticOverflow;
    return count;
}

fn laneRows(comptime kind: Kind, profile: leaf.LaneProfile) Error!usize {
    return switch (kind) {
        .leaf => leaf_contract.rowsForLane(profile),
        .node => node.rowsForLane(profile),
        .anchor => std.math.mul(usize, profile.query_count, profile.layers.len) catch
            error.ArithmeticOverflow,
    };
}

fn fillLane(
    comptime kind: Kind,
    rows: []RowType(kind),
    cursor: *usize,
    lane: reference_v2.Lane,
    plan: ?*const schedule.Plan,
) Error!void {
    const segment = @intFromBool(lane.verifier_id == leaf.SEGMENT_VERIFIER_ID);
    const binary = @intFromBool(lane.verifier_id != leaf.SEGMENT_VERIFIER_ID);
    return switch (kind) {
        .leaf => leaf_contract.fillLaneRows(
            rows,
            cursor,
            lane.profile,
            lane.verifier_id,
            segment,
            binary,
        ),
        .node => node.fillLaneRows(
            rows,
            cursor,
            lane.profile,
            lane.verifier_id,
            segment,
            binary,
        ),
        .anchor => anchor.fillLaneRows(
            rows,
            cursor,
            lane.profile,
            plan orelse return error.InvalidHeterogeneousFriRows,
            lane.verifier_id,
            segment,
            binary,
        ),
    };
}

fn validateLane(
    comptime kind: Kind,
    rows: []const RowType(kind),
    cursor: *usize,
    lane: reference_v2.Lane,
    plan: ?*const schedule.Plan,
) Error!void {
    const segment = @intFromBool(lane.verifier_id == leaf.SEGMENT_VERIFIER_ID);
    const binary = @intFromBool(lane.verifier_id != leaf.SEGMENT_VERIFIER_ID);
    return switch (kind) {
        .leaf => leaf_impl.validateLaneRows(
            rows,
            cursor,
            lane.profile,
            lane.verifier_id,
            segment,
            binary,
        ),
        .node => node.validateLaneRows(
            rows,
            cursor,
            lane.profile,
            lane.verifier_id,
            segment,
            binary,
        ),
        .anchor => anchor.validateLaneRows(
            rows,
            cursor,
            lane.profile,
            plan orelse return error.InvalidHeterogeneousFriRows,
            lane.verifier_id,
            segment,
            binary,
        ),
    };
}

fn logSize(comptime kind: Kind, row_count: usize) Error!u32 {
    return switch (kind) {
        .leaf => leaf_impl.traceLogSize(row_count),
        .node => node.traceLogSize(row_count),
        .anchor => anchor.traceLogSize(row_count),
    };
}

fn baseRowsDigest(comptime kind: Kind, rows: []const RowType(kind)) [32]u8 {
    return switch (kind) {
        .leaf => leaf_impl.rowsDigest(rows),
        .node => node.rowsDigest(rows),
        .anchor => anchor.rowsDigest(rows),
    };
}

fn rowsIdentity(comptime kind: Kind, value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u32, value.log_size);
    hash.update(&value.reference_sha256);
    for (value.schedule_digests) |words| for (words) |word|
        hashInt(&hash, u32, word);
    hash.update(&baseRowsDigest(kind, value.rows));
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
