//! Lane-specific FRI verifier-control schedule for row 28.
//!
//! V1 binds one recursive plan to both child lanes. V2 retains three plans
//! and three mapping profiles, reconstructing every route row before use.

const std = @import("std");
const base = @import("fri_verifier_control_witness.zig");
const mapping_v2 = @import("query_mapping_witness_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-control-reference/v2\x00";
const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-control-rows/v2\x00";

pub const Error = base.Error || mapping_v2.Error || error{
    InvalidHeterogeneousFriControl,
};

pub const Reference = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lanes: [3]base.Lane,
    schedule_digests: [3][8]u32,
    authority_sha256: [32]u8,

    pub fn seal(
        vm: base.Lane,
        left: base.Lane,
        right: base.Lane,
    ) Error!Reference {
        try base.validateLaneAuthority(vm, .vm);
        try base.validateLaneAuthority(left, left.plan.schema);
        try base.validateLaneAuthority(right, right.plan.schema);
        var result = Reference{
            .lanes = .{ vm, left, right },
            .schedule_digests = .{
                vm.plan.authority_digest,
                left.plan.authority_digest,
                right.plan.authority_digest,
            },
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = referenceIdentity(&result);
        try result.validateAuthority();
        return result;
    }

    pub fn validateAuthority(self: *const Reference) Error!void {
        if (self.format_version != FORMAT_VERSION or self.schema_version != SCHEMA_VERSION)
            return error.InvalidHeterogeneousFriControl;
        if (self.lanes[0].plan.schema != .vm)
            return error.InvalidHeterogeneousFriControl;
        for (self.lanes, self.schedule_digests) |lane, retained| {
            try base.validateLaneAuthority(lane, lane.plan.schema);
            if (!std.meta.eql(lane.plan.authority_digest, retained))
                return error.InvalidHeterogeneousFriControl;
        }
        if (!std.mem.eql(u8, &self.authority_sha256, &referenceIdentity(self)))
            return error.InvalidHeterogeneousFriControl;
    }

    pub fn validateMapping(
        self: *const Reference,
        mapping: *const mapping_v2.Reference,
    ) Error!void {
        try self.validateAuthority();
        try mapping.validate();
        for (self.lanes, mapping.lanes) |control, route| {
            if (!std.meta.eql(control.mapping, route.profile))
                return error.InvalidHeterogeneousFriControl;
        }
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    log_size: u32,
    rows: []base.Row,
    reference_sha256: [32]u8,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: *const Reference,
    ) Error!Preprocessed {
        try reference.validateAuthority();
        const rows = try allocator.alloc(base.Row, try totalRows(reference));
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| try base.fillLaneRows(
            rows,
            &cursor,
            lane,
            @intCast(lane_index),
            @intFromBool(lane_index == 0),
            @intFromBool(lane_index != 0),
        );
        if (cursor != rows.len) return error.InvalidHeterogeneousFriControl;
        var result = Preprocessed{
            .allocator = allocator,
            .log_size = try base.traceLogSize(rows.len),
            .rows = rows,
            .reference_sha256 = reference.authority_sha256,
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = rowsIdentity(&result);
        try result.validateAgainstAuthority(reference);
        return result;
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainstAuthority(
        self: *const Preprocessed,
        reference: *const Reference,
    ) Error!void {
        try reference.validateAuthority();
        if (self.format_version != FORMAT_VERSION or self.schema_version != SCHEMA_VERSION or
            self.rows.len != try totalRows(reference) or
            self.log_size != try base.traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &rowsIdentity(self)))
        {
            return error.InvalidHeterogeneousFriControl;
        }
        var cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| try base.validateLaneRows(
            self.rows,
            &cursor,
            lane,
            @intCast(lane_index),
            @intFromBool(lane_index == 0),
            @intFromBool(lane_index != 0),
        );
        if (cursor != self.rows.len) return error.InvalidHeterogeneousFriControl;
    }

    pub fn computedAuthoritySha256(self: *const Preprocessed) [32]u8 {
        return rowsIdentity(self);
    }
};

fn totalRows(reference: *const Reference) Error!usize {
    var count: usize = 0;
    for (reference.lanes) |lane| count = std.math.add(
        usize,
        count,
        try base.rowsForLane(lane.mapping),
    ) catch return error.ArithmeticOverflow;
    return count;
}

fn referenceIdentity(reference: *const Reference) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, reference.format_version);
    hashInt(&hash, u16, reference.schema_version);
    for (reference.lanes, reference.schedule_digests, 0..) |lane, words, lane_index| {
        hashInt(&hash, u32, lane_index);
        for (words) |word| hashInt(&hash, u32, word);
        hashMapping(&hash, lane.mapping);
    }
    return hash.finalResult();
}

fn rowsIdentity(value: *const Preprocessed) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.log_size);
    hash.update(&value.reference_sha256);
    hash.update(&base.rowsDigest(value.rows));
    return hash.finalResult();
}

fn hashMapping(hash: anytype, profile: @import("query_mapping_witness.zig").LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.tree_heights.len);
    for (profile.tree_heights) |height| hashInt(hash, u32, height);
    hashInt(hash, u32, profile.fri_fold_widths.len);
    for (profile.fri_fold_widths) |width| hashInt(hash, u32, width);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
