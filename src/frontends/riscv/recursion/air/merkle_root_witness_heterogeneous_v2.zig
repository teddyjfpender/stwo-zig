//! Three-lane Merkle-root schedule authority for heterogeneous child proofs.
//!
//! The row-22 AIR already namespaces every root by verifier id. V2 therefore
//! changes only the cold compiler authority: left and right retain independent
//! trace-tree and FRI-layer counts, while the V1 row/AIR encoding is reused.

const std = @import("std");
const base = @import("merkle_root_witness.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-merkle-root-reference/v2\x00";
const ROWS_DOMAIN =
    "stwo-zig/typed-air/recursion-merkle-root-rows/v2\x00";

pub const Error = base.Error || error{
    InvalidHeterogeneousMerkleRootAuthority,
};

pub const Lane = struct {
    verifier_id: u32,
    profile: base.LaneProfile,
};

pub const Reference = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lanes: [LANE_COUNT]Lane,
    authority_sha256: [32]u8,

    pub fn seal(
        vm: base.LaneProfile,
        left: base.LaneProfile,
        right: base.LaneProfile,
    ) Error!Reference {
        // Reuse the V1 profile validator without inheriting its equal-child
        // identity or row duplication.
        _ = try base.Reference.seal(vm, left);
        _ = try base.Reference.seal(vm, right);
        var result = Reference{
            .lanes = .{
                .{ .verifier_id = base.SEGMENT_VERIFIER_ID, .profile = vm },
                .{ .verifier_id = base.LEFT_RECURSION_VERIFIER_ID, .profile = left },
                .{ .verifier_id = base.RIGHT_RECURSION_VERIFIER_ID, .profile = right },
            },
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = referenceIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Reference) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.lanes[0].verifier_id != base.SEGMENT_VERIFIER_ID or
            self.lanes[1].verifier_id != base.LEFT_RECURSION_VERIFIER_ID or
            self.lanes[2].verifier_id != base.RIGHT_RECURSION_VERIFIER_ID)
        {
            return error.InvalidHeterogeneousMerkleRootAuthority;
        }
        _ = try base.Reference.seal(self.lanes[0].profile, self.lanes[1].profile);
        _ = try base.Reference.seal(self.lanes[0].profile, self.lanes[2].profile);
        if (!std.mem.eql(u8, &self.authority_sha256, &referenceIdentity(self)))
            return error.InvalidHeterogeneousMerkleRootAuthority;
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
        try reference.validate();
        const rows = try allocator.alloc(base.Row, try totalRows(reference));
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        for (reference.lanes) |lane| appendLane(rows, &cursor, lane);
        if (cursor != rows.len)
            return error.InvalidHeterogeneousMerkleRootAuthority;
        var result = Preprocessed{
            .allocator = allocator,
            .log_size = try traceLogSize(rows.len),
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
        try reference.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.rows.len != try totalRows(reference) or
            self.log_size != try traceLogSize(self.rows.len) or
            !std.mem.eql(u8, &self.reference_sha256, &reference.authority_sha256) or
            !std.mem.eql(u8, &self.authority_sha256, &rowsIdentity(self)))
        {
            return error.InvalidHeterogeneousMerkleRootAuthority;
        }
        var cursor: usize = 0;
        for (reference.lanes) |lane| {
            for (0..laneRows(lane.profile)) |index| {
                if (cursor >= self.rows.len or
                    !std.meta.eql(self.rows[cursor], laneRow(lane, index)))
                {
                    return error.InvalidHeterogeneousMerkleRootAuthority;
                }
                cursor += 1;
            }
        }
        if (cursor != self.rows.len)
            return error.InvalidHeterogeneousMerkleRootAuthority;
    }

    pub fn computedAuthoritySha256(self: *const Preprocessed) [32]u8 {
        return rowsIdentity(self);
    }
};

pub fn logicalRow(
    preprocessing: *const Preprocessed,
    reference: *const Reference,
    row_index: usize,
    roots: base.RootWitness,
) Error![@import("merkle_root.zig").LOGICAL_INPUT_COUNT]@import("stwo_core").fields.m31.M31 {
    try preprocessing.validateAgainstAuthority(reference);
    try validateWitness(reference, roots);
    if (row_index >= preprocessing.rows.len)
        return error.InvalidHeterogeneousMerkleRootAuthority;
    return base.logicalRow(preprocessing.rows[row_index], roots);
}

fn validateWitness(reference: *const Reference, roots: base.RootWitness) Error!void {
    switch (roots) {
        .segment_leaf => |values| try validateRootSet(reference.lanes[0].profile, values),
        .binary_node => |values| {
            try validateRootSet(reference.lanes[1].profile, values.left);
            try validateRootSet(reference.lanes[2].profile, values.right);
        },
        .empty_leaf => {},
    }
}

fn validateRootSet(profile: base.LaneProfile, roots: base.RootSet) Error!void {
    if (roots.trace.len != profile.trace_tree_count or
        roots.fri.len != profile.fri_layer_count)
    {
        return error.InvalidWitness;
    }
    for (roots.trace) |value| for (value) |word| if (word >= 0x7fff_ffff)
        return error.InvalidWitness;
    for (roots.fri) |value| for (value) |word| if (word >= 0x7fff_ffff)
        return error.InvalidWitness;
}

fn totalRows(reference: *const Reference) Error!usize {
    var count: usize = 0;
    for (reference.lanes) |lane| count = std.math.add(
        usize,
        count,
        laneRows(lane.profile),
    ) catch return error.ArithmeticOverflow;
    return count;
}

fn laneRows(profile: base.LaneProfile) usize {
    return @as(usize, profile.trace_tree_count) + profile.fri_layer_count;
}

fn appendLane(rows: []base.Row, cursor: *usize, lane: Lane) void {
    for (0..laneRows(lane.profile)) |index| {
        rows[cursor.*] = laneRow(lane, index);
        cursor.* += 1;
    }
}

fn laneRow(lane: Lane, index: usize) base.Row {
    const is_fri = index >= lane.profile.trace_tree_count;
    const item: u32 = @intCast(if (is_fri)
        index - lane.profile.trace_tree_count
    else
        index);
    return .{
        .row_mask = 1,
        .segment_mask = @intFromBool(lane.verifier_id == base.SEGMENT_VERIFIER_ID),
        .binary_mask = @intFromBool(lane.verifier_id != base.SEGMENT_VERIFIER_ID),
        .verifier_id = lane.verifier_id,
        .source = if (is_fri) .fri else .trace,
        .item = item,
        .tree_id = if (is_fri)
            base.friTreeId(lane.verifier_id, item) catch unreachable
        else
            base.traceTreeId(lane.verifier_id, item) catch unreachable,
        .path_count = lane.profile.query_count,
    };
}

fn traceLogSize(row_count: usize) Error!u32 {
    const result: u32 = @max(
        base.MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > base.MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return result;
}

fn referenceIdentity(reference: *const Reference) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, reference.format_version);
    hashInt(&hash, u16, reference.schema_version);
    for (reference.lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        hashProfile(&hash, lane.profile);
    }
    return hash.finalResult();
}

fn rowsIdentity(preprocessing: *const Preprocessed) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROWS_DOMAIN);
    hashInt(&hash, u16, preprocessing.format_version);
    hashInt(&hash, u16, preprocessing.schema_version);
    hashInt(&hash, u32, preprocessing.log_size);
    hash.update(&preprocessing.reference_sha256);
    for (preprocessing.rows) |row| {
        hashInt(&hash, u32, row.row_mask);
        hashInt(&hash, u32, row.segment_mask);
        hashInt(&hash, u32, row.binary_mask);
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u8, @intFromEnum(row.source));
        hashInt(&hash, u32, row.item);
        hashInt(&hash, u32, row.tree_id);
        hashInt(&hash, u32, row.path_count);
    }
    return hash.finalResult();
}

fn hashProfile(hash: anytype, profile: base.LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.trace_tree_count);
    hashInt(hash, u32, profile.fri_layer_count);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
