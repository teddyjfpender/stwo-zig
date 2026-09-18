//! Bend QM31 butterfly folds with host domain preparation. Every result is
//! compared with core FRI before it leaves this experimental boundary.
const std = @import("std");
const core = @import("stwo_core");
const abi = @import("abi.zig");
const runtime = @import("runtime.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub fn request(allocator: std.mem.Allocator, values: []const QM31, coset: core.circle.Coset, alpha: QM31, comptime y_coordinate: bool) ![]u8 {
    if (values.len < 2 or !std.math.isPowerOfTwo(values.len) or values.len > 1 << (abi.max_log_size - 2)) return error.InvalidEvaluationLength;
    const log: u32 = @intCast(std.math.log2_int(usize, values.len));
    if (coset.size() < values.len / 2) return error.InvalidDomain;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for ([_]u32{ abi.request_magic, abi.version, 4, log + 2, 1 }) |v| try abi.word(&out, allocator, v);
    for (values) |q| for (q.toM31Array()) |x| {
        if (x.v >= 2147483647) return error.NonCanonicalInput;
        try abi.word(&out, allocator, x.v);
    };
    const inverses = try allocator.alloc(M31, values.len / 2);
    defer allocator.free(inverses);
    var points = coset.iter();
    for (0..inverses.len) |i| {
        const point = points.next() orelse return error.InvalidDomain;
        inverses[core.utils.bitReverseIndex(i, log - 1)] = try (if (y_coordinate) point.y else point.x).inv();
    }
    for (inverses) |x| try abi.word(&out, allocator, x.v);
    for (alpha.toM31Array()) |x| {
        if (x.v >= 2147483647) return error.NonCanonicalInput;
        try abi.word(&out, allocator, x.v);
    }
    return out.toOwnedSlice(allocator);
}

fn fold(allocator: std.mem.Allocator, config: runtime.Config, values: []const QM31, coset: core.circle.Coset, alpha: QM31, comptime y: bool) ![]QM31 {
    const bytes = try request(allocator, values, coset, alpha, y);
    defer allocator.free(bytes);
    const flat = try runtime.execute(allocator, config, bytes, values.len * 2);
    defer allocator.free(flat);
    const result = try allocator.alloc(QM31, values.len / 2);
    for (result, 0..) |*q, i| q.* = QM31.fromM31Array(flat[4 * i ..][0..4].*);
    return result;
}

pub fn line(allocator: std.mem.Allocator, config: runtime.Config, values: []QM31, domain: core.poly.line.LineDomain, alpha: QM31, workspace: *core.fri.FoldLineWorkspace, count: u32) !core.fri.FoldLineResult {
    if (values.len != domain.size() or count == 0 or count > domain.logSize()) return error.InvalidEvaluationLength;
    var current = try allocator.dupe(QM31, values);
    errdefer allocator.free(current);
    var d = domain;
    var challenge = alpha;
    for (0..count) |_| {
        const next = try fold(allocator, config, current, d.coset(), challenge, false);
        allocator.free(current);
        current = next;
        d = d.double();
        challenge = challenge.square();
    }
    const expected = try core.fri.foldLineNWithWorkspace(allocator, values, domain, alpha, workspace, count);
    defer allocator.free(expected.values);
    if (!equal(expected.values, current)) return error.BendParityMismatch;
    return .{ .domain = d, .values = current };
}

pub fn circle(allocator: std.mem.Allocator, config: runtime.Config, dst: []QM31, src: [4][]const M31, domain: core.poly.circle.domain.CircleDomain, alpha: QM31, workspace: *core.fri.FoldCircleWorkspace) !void {
    if (src[0].len != domain.size() or dst.len != src[0].len / 2) return error.ShapeMismatch;
    for (src) |c| if (c.len != src[0].len) return error.ShapeMismatch;
    const values = try allocator.alloc(QM31, src[0].len);
    defer allocator.free(values);
    for (values, 0..) |*q, i| q.* = QM31.fromM31(src[0][i], src[1][i], src[2][i], src[3][i]);
    const result = try fold(allocator, config, values, domain.half_coset, alpha, true);
    defer allocator.free(result);
    const alpha_sq = alpha.square();
    for (result, dst) |*q, previous| q.* = previous.mul(alpha_sq).add(q.*);
    const expected = try allocator.dupe(QM31, dst);
    defer allocator.free(expected);
    try core.fri.foldCircleColumnsIntoLineWithWorkspace(allocator, expected, src, domain, alpha, workspace);
    if (!equal(expected, result)) return error.BendParityMismatch;
    @memcpy(dst, result);
}

fn equal(a: []const QM31, b: []const QM31) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!x.eql(y)) return false;
    return true;
}
