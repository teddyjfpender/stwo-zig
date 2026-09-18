//! Circle transform transport; numerical oracle stays in the prover package.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const abi = @import("abi.zig");
const runtime = @import("runtime.zig");
const M31 = core.fields.m31.M31;
const Domain = core.poly.circle.domain.CircleDomain;

pub fn writePlan(out: *std.ArrayList(u8), a: std.mem.Allocator, tree: anytype, domain: Domain, depth: u32, group: usize, inverse: bool) !void {
    const ts = if (inverse) tree.itwiddles else tree.twiddles;
    var w: M31 = undefined;
    if (domain.logSize() == 1) {
        w = domain.half_coset.initial.y;
        if (inverse) w = try w.inv();
    } else if (depth == 1) {
        if (domain.logSize() == 2) {
            w = domain.half_coset.initial.y;
            if (inverse) w = try w.inv();
            if (group == 1) w = w.neg();
        } else {
            const k = (group / 4) * 2;
            w = switch (group % 4) {
                0 => ts[k + 1],
                1 => ts[k + 1].neg(),
                2 => ts[k].neg(),
                3 => ts[k],
                else => unreachable,
            };
        }
    } else {
        const count = @as(usize, 1) << @intCast(domain.logSize() - depth);
        w = ts[ts.len - 2 * count + group];
    }
    try abi.word(out, a, w.v);
    if (depth > 1) {
        try writePlan(out, a, tree, domain, depth - 1, group * 2, inverse);
        try writePlan(out, a, tree, domain, depth - 1, group * 2 + 1, inverse);
    }
}

pub fn transform(allocator: std.mem.Allocator, config: runtime.Config, values: []const []M31, domain: Domain, tree: anytype, inverse: bool) !void {
    const log = domain.logSize();
    if (log < 1 or log > abi.max_log_size or values.len == 0) return error.InvalidColumns;
    if (tree.root_coset.logSize() != domain.half_coset.logSize() or
        !tree.root_coset.initial_index.eql(domain.half_coset.initial_index) or
        tree.twiddles.len != domain.size() / 2 or tree.itwiddles.len != domain.size() / 2) return error.InvalidTwiddles;
    for (values) |v| {
        if (v.len != domain.size()) return error.InvalidColumns;
        for (v) |x| if (x.v >= 2147483647) return error.NonCanonicalInput;
    }
    for (tree.twiddles) |x| if (x.v >= 2147483647) return error.NonCanonicalInput;
    for (tree.itwiddles) |x| if (x.v >= 2147483647) return error.NonCanonicalInput;
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    const norm = try M31.fromCanonical(@intCast(domain.size())).inv();
    for (values) |v| {
        request.clearRetainingCapacity();
        for ([_]u32{ abi.request_magic, abi.version, if (inverse) 1 else 0, log, norm.v }) |x| try abi.word(&request, allocator, x);
        for (v) |x| try abi.word(&request, allocator, x.v);
        try writePlan(&request, allocator, tree, domain, log, 0, inverse);
        const actual = try runtime.execute(allocator, config, request.items, v.len);
        defer allocator.free(actual);
        // This experimental backend remains parity-checked on every call.
        const expected = try allocator.dupe(M31, v);
        defer allocator.free(expected);
        var batch = [_][]M31{expected};
        if (inverse) try prover.poly.circle.poly.interpolateBuffersWithTwiddles(&batch, domain, tree) else try prover.poly.circle.poly.evaluateBuffersWithTwiddles(&batch, domain, tree);
        for (expected, actual) |x, y| if (!x.eql(y)) return error.BendParityMismatch;
        @memcpy(v, actual);
    }
}
