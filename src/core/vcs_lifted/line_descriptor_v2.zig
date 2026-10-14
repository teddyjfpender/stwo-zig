//! Candidate line-tree descriptor and statement binding for S31NAT9F.
//!
//! This validates bytes and the proposed event plan. A selected verifier must
//! derive these descriptors from a sealed key, privately own the transcript,
//! and pass the root actually absorbed at the named event. No selector exists.
const std = @import("std");
const framed = @import("../channel/framed_bcs_v2.zig");
const line = @import("blake2s_personalized_line_v2.zig");

pub const Digest32 = framed.Digest32;
pub const tree_magic = "S31LTDV2";
pub const manifest_magic = "S31LTMV2";
pub const row_parent_encoding = "M31LE32|P64";
pub const max_fold_heights: usize = 64;
pub const max_columns: usize = 256;
pub const max_manifest_bytes: usize = 1 << 19;

pub const Error = error{
    InvalidFoldHeightRoster,
    InvalidTreeCount,
    InvalidTreeDescriptor,
    InvalidColumnRoster,
    DuplicateColumnIdentity,
    InvalidTreeIndex,
    StatementMismatch,
    RootEventMismatch,
    LengthOverflow,
} || std.mem.Allocator.Error || framed.Error || line.Error;

pub const Track = enum(u8) { original = 1, own_quotient = 2 };

fn addLength(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.LengthOverflow;
}

fn writeBytes(out: []u8, offset: *usize, bytes: []const u8) void {
    @memcpy(out[offset.*..][0..bytes.len], bytes);
    offset.* += bytes.len;
}

fn writeU32(out: []u8, offset: *usize, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    writeBytes(out, offset, &bytes);
}

fn writeU64(out: []u8, offset: *usize, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    writeBytes(out, offset, &bytes);
}

pub fn lineHashProfileDigest() Digest32 {
    return framed.hashFrameParts(.tree_context, 0, &.{
        line.profile_id,
        &line.leaf_context,
        &line.parent_context,
        row_parent_encoding,
    }) catch unreachable;
}

pub const LineTreeDescriptorV2 = struct {
    key_digest: Digest32,
    profile_digest: Digest32,
    track: Track,
    fold_height: u32,
    tree_log_size: u32,
    root_event: u64,
    column_descriptors: []const Digest32,

    const Self = @This();
    const fixed_len: usize = 8 + 1 + 4 + 4 + 8 + 32 + 32 + 4;

    pub fn encodedLen(self: Self) Error!usize {
        if (self.tree_log_size >= 64) return error.InvalidTreeDescriptor;
        if (self.column_descriptors.len == 0 or self.column_descriptors.len > max_columns)
            return error.InvalidColumnRoster;
        for (self.column_descriptors, 0..) |descriptor, i| {
            for (self.column_descriptors[0..i]) |earlier| {
                if (std.mem.eql(u8, &descriptor, &earlier)) return error.DuplicateColumnIdentity;
            }
        }
        const columns_len = std.math.mul(usize, self.column_descriptors.len, 32) catch
            return error.LengthOverflow;
        return addLength(fixed_len, columns_len);
    }

    fn writeTo(self: Self, out: []u8, offset: *usize) void {
        writeBytes(out, offset, tree_magic);
        writeBytes(out, offset, &.{@intFromEnum(self.track)});
        writeU32(out, offset, self.fold_height);
        writeU32(out, offset, self.tree_log_size);
        writeU64(out, offset, self.root_event);
        writeBytes(out, offset, &self.key_digest);
        writeBytes(out, offset, &self.profile_digest);
        writeU32(out, offset, @intCast(self.column_descriptors.len));
        for (self.column_descriptors) |descriptor| writeBytes(out, offset, &descriptor);
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) Error![]u8 {
        const len = try self.encodedLen();
        const out = try allocator.alloc(u8, len);
        var offset: usize = 0;
        self.writeTo(out, &offset);
        std.debug.assert(offset == len);
        return out;
    }
};

pub const LineTreeManifestV2 = struct {
    key_digest: Digest32,
    fold_heights: []const u32,
    trees: []const LineTreeDescriptorV2,

    const Self = @This();
    const fixed_len: usize = 8 + 32 + 32 + 4 + 4;

    pub fn validate(self: Self) Error!void {
        if (self.fold_heights.len == 0 or self.fold_heights.len > max_fold_heights)
            return error.InvalidFoldHeightRoster;
        for (self.fold_heights[1..], 1..) |height, i| {
            if (self.fold_heights[i - 1] <= height) return error.InvalidFoldHeightRoster;
        }
        if (self.trees.len != 2 * (self.fold_heights.len - 1)) return error.InvalidTreeCount;
        const profile = lineHashProfileDigest();
        for (self.trees, 0..) |tree, i| {
            _ = try tree.encodedLen();
            const pair = i / 2;
            const expected_track: Track = if (i % 2 == 0) .original else .own_quotient;
            const expected_event: u64 = 17 + 3 * @as(u64, @intCast(pair)) + @as(u64, @intCast(i % 2));
            if (tree.track != expected_track or tree.fold_height != self.fold_heights[pair] or
                tree.root_event != expected_event or
                !std.mem.eql(u8, &tree.key_digest, &self.key_digest) or
                !std.mem.eql(u8, &tree.profile_digest, &profile))
                return error.InvalidTreeDescriptor;
        }
    }

    pub fn encodedLen(self: Self) Error!usize {
        try self.validate();
        const heights_len = std.math.mul(usize, self.fold_heights.len, 4) catch
            return error.LengthOverflow;
        var total = try addLength(fixed_len, heights_len);
        for (self.trees) |tree| total = try addLength(total, try addLength(4, try tree.encodedLen()));
        if (total > max_manifest_bytes) return error.LengthOverflow;
        return total;
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) Error![]u8 {
        const len = try self.encodedLen();
        const out = try allocator.alloc(u8, len);
        var offset: usize = 0;
        writeBytes(out, &offset, manifest_magic);
        writeBytes(out, &offset, &self.key_digest);
        const profile = lineHashProfileDigest();
        writeBytes(out, &offset, &profile);
        writeU32(out, &offset, @intCast(self.fold_heights.len));
        for (self.fold_heights) |height| writeU32(out, &offset, height);
        writeU32(out, &offset, @intCast(self.trees.len));
        for (self.trees) |tree| {
            writeU32(out, &offset, @intCast(try tree.encodedLen()));
            tree.writeTo(out, &offset);
        }
        std.debug.assert(offset == len);
        return out;
    }

    pub fn digest(self: Self, allocator: std.mem.Allocator) Error!Digest32 {
        const payload = try self.encode(allocator);
        defer allocator.free(payload);
        return framed.hashFrameParts(.tree_context, 0, &.{payload});
    }

    /// Both statement and manifest must originate from one sealed key. This
    /// equality check cannot establish that external custody premise.
    pub fn matchesStatement(self: Self, allocator: std.mem.Allocator, statement: framed.StatementBinding) Error!bool {
        if (!std.mem.eql(u8, &self.key_digest, &statement.key_digest)) return false;
        const manifest_digest = try self.digest(allocator);
        return std.mem.eql(u8, &manifest_digest, &statement.line_profile_digest);
    }
};

/// `authenticated_root` must be the root the verifier absorbed at the named
/// event. The caller must enforce this identity and retain the manifest from
/// its sealed key; this helper checks the remaining statement/path equality.
pub fn verifyBoundOpening(
    allocator: std.mem.Allocator,
    manifest: LineTreeManifestV2,
    statement: framed.StatementBinding,
    tree_index: usize,
    event: u64,
    authenticated_root: Digest32,
    row: []const u32,
    leaf_index: u64,
    siblings: []const Digest32,
) Error!bool {
    if (!try manifest.matchesStatement(allocator, statement)) return error.StatementMismatch;
    if (tree_index >= manifest.trees.len) return error.InvalidTreeIndex;
    const tree = manifest.trees[tree_index];
    if (event != tree.root_event) return error.RootEventMismatch;
    return line.verifyPath(authenticated_root, row, leaf_index, tree.tree_log_size, siblings);
}

test "line descriptor exact Python bytes and statement digest" {
    const allocator = std.testing.allocator;
    var key: Digest32 = undefined;
    for (&key, 0..) |*byte, i| byte.* = @intCast(i);
    const profile = lineHashProfileDigest();
    const one = [_]Digest32{ [_]u8{0x11} ** 32, [_]u8{0x12} ** 32 };
    const two = [_]Digest32{[_]u8{0x21} ** 32};
    const trees = [_]LineTreeDescriptorV2{
        .{ .key_digest = key, .profile_digest = profile, .track = .original, .fold_height = 17, .tree_log_size = 17, .root_event = 17, .column_descriptors = &one },
        .{ .key_digest = key, .profile_digest = profile, .track = .own_quotient, .fold_height = 17, .tree_log_size = 17, .root_event = 18, .column_descriptors = &two },
    };
    const manifest = LineTreeManifestV2{ .key_digest = key, .fold_heights = &.{ 17, 16 }, .trees = &trees };
    const first = try trees[0].encode(allocator);
    defer allocator.free(first);
    try std.testing.expectEqual(@as(usize, 157), first.len);
    try std.testing.expectEqualSlices(u8, "S31LTDV2", first[0..8]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 17, 0, 0, 0, 17, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0 }, first[8..25]);
    try std.testing.expectEqualSlices(u8, &key, first[25..57]);
    try std.testing.expectEqualSlices(u8, &profile, first[57..89]);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0 }, first[89..93]);
    try std.testing.expectEqualSlices(u8, &one[0], first[93..125]);
    try std.testing.expectEqualSlices(u8, &one[1], first[125..157]);
    const bytes = try manifest.encode(allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 378), bytes.len);
    try std.testing.expectEqualSlices(u8, "S31LTMV2", bytes[0..8]);
    try std.testing.expectEqualSlices(u8, &key, bytes[8..40]);
    try std.testing.expectEqualSlices(u8, &profile, bytes[40..72]);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 17, 0, 0, 0, 16, 0, 0, 0, 2, 0, 0, 0, 157, 0, 0, 0 }, bytes[72..92]);
    try std.testing.expectEqualSlices(u8, first, bytes[92..249]);
    try std.testing.expectEqualSlices(u8, &.{ 125, 0, 0, 0 }, bytes[249..253]);
    const second = try trees[1].encode(allocator);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(u8, second, bytes[253..378]);
    var expected: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "cfe6fd8b3c4b3996d878f9234c61945263c6403fd16fb1e9db6d63af55718fac");
    try std.testing.expectEqualDeep(expected, profile);
    _ = try std.fmt.hexToBytes(&expected, "ee5d374d300ab5aaf8f01794f9c9c67f4f6f3ffd20e0433c8ae74496bfecab2c");
    try std.testing.expectEqualDeep(expected, try manifest.digest(allocator));
    const zero = [_]u8{0} ** 32;
    const statement = framed.StatementBinding{ .key_digest = key, .circuit_digest = zero, .fri_config_digest = zero, .source_tree_descriptors = [_]Digest32{zero} ** 4, .line_profile_digest = expected };
    try std.testing.expect(try manifest.matchesStatement(allocator, statement));
    const bad_event = verifyBoundOpening(allocator, manifest, statement, 0, 18, zero, &.{0}, 0, &.{});
    try std.testing.expectError(error.RootEventMismatch, bad_event);
}

test "line descriptor rejects reordering, duplicated roles and wrong roster" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    const original = LineTreeDescriptorV2{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 17, .tree_log_size = 1, .root_event = 17, .column_descriptors = &columns };
    const own = LineTreeDescriptorV2{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 17, .tree_log_size = 1, .root_event = 18, .column_descriptors = &columns };
    const wrong_order = [_]LineTreeDescriptorV2{ own, original };
    try std.testing.expectError(error.InvalidTreeDescriptor, (LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &wrong_order,
    }).digest(allocator));
    const duplicate = [_]LineTreeDescriptorV2{ original, original };
    try std.testing.expectError(error.InvalidTreeDescriptor, (LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &duplicate,
    }).digest(allocator));
    const wrong_event = [_]LineTreeDescriptorV2{ original, blk: {
        var changed = own;
        changed.root_event = 19;
        break :blk changed;
    } };
    try std.testing.expectError(error.InvalidTreeDescriptor, (LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &wrong_event,
    }).digest(allocator));
    const valid = [_]LineTreeDescriptorV2{ original, own };
    const manifest = LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &valid,
    };
    try std.testing.expectError(error.InvalidFoldHeightRoster, (LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 16, 17 },
        .trees = &valid,
    }).digest(allocator));
    var invalid_log = original;
    invalid_log.tree_log_size = 64;
    try std.testing.expectError(error.InvalidTreeDescriptor, invalid_log.encode(allocator));
    const repeated_columns = [_]Digest32{ zero, zero };
    var duplicate_column = original;
    duplicate_column.column_descriptors = &repeated_columns;
    try std.testing.expectError(error.DuplicateColumnIdentity, duplicate_column.encode(allocator));
    var changed_log = original;
    changed_log.tree_log_size = 2;
    const changed_trees = [_]LineTreeDescriptorV2{ changed_log, own };
    const changed_manifest = LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &changed_trees,
    };
    const original_digest = try manifest.digest(allocator);
    const changed_digest = try changed_manifest.digest(allocator);
    try std.testing.expect(!std.mem.eql(u8, &original_digest, &changed_digest));

    const statement = framed.StatementBinding{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = try manifest.digest(allocator),
    };
    const leaf0 = try line.hashCanonicalRow(&.{0});
    const leaf1 = try line.hashCanonicalRow(&.{1});
    const root = line.LineMerkleHasherV2.hashChildren(.{ .left = leaf0, .right = leaf1 });
    try std.testing.expect(try verifyBoundOpening(
        allocator,
        manifest,
        statement,
        0,
        17,
        root,
        &.{0},
        0,
        &.{leaf1},
    ));
    try std.testing.expect(!(try verifyBoundOpening(
        allocator,
        manifest,
        statement,
        0,
        17,
        root,
        &.{1},
        0,
        &.{leaf1},
    )));
    try std.testing.expectError(error.InvalidTreeIndex, verifyBoundOpening(
        allocator,
        manifest,
        statement,
        2,
        17,
        root,
        &.{0},
        0,
        &.{leaf1},
    ));
    try std.testing.expectError(error.InvalidPathShape, verifyBoundOpening(
        allocator,
        manifest,
        statement,
        0,
        17,
        root,
        &.{0},
        0,
        &.{},
    ));
    var wrong_statement = statement;
    wrong_statement.line_profile_digest = zero;
    try std.testing.expectError(error.StatementMismatch, verifyBoundOpening(
        allocator,
        manifest,
        wrong_statement,
        0,
        17,
        root,
        &.{0},
        0,
        &.{leaf1},
    ));
}

test "line descriptor manifest cap rejects before allocation" {
    const zero = [_]u8{0} ** 32;
    const profile = lineHashProfileDigest();
    var columns: [129]Digest32 = undefined;
    for (&columns, 0..) |*column, i| @memset(column, @intCast(i));
    var heights: [64]u32 = undefined;
    for (&heights, 0..) |*height, i| height.* = @intCast(64 - i);
    var trees: [126]LineTreeDescriptorV2 = undefined;
    for (0..63) |i| {
        for (0..2) |track_index| {
            const index = 2 * i + track_index;
            trees[index] = .{
                .key_digest = zero,
                .profile_digest = profile,
                .track = if (track_index == 0) .original else .own_quotient,
                .fold_height = heights[i],
                .tree_log_size = @min(heights[i], 63),
                .root_event = 17 + 3 * @as(u64, @intCast(i)) + @as(u64, @intCast(track_index)),
                .column_descriptors = &columns,
            };
        }
    }
    const manifest = LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &heights,
        .trees = &trees,
    };
    try std.testing.expectError(error.LengthOverflow, manifest.encode(std.testing.allocator));
}
