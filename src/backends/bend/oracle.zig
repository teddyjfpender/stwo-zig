//! Fixture producer using the existing Zig field/FFT code, never a Python FFT.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const abi = @import("stwo_bend_backend").abi;
const M31 = core.fields.m31.M31;
const tw = prover.poly.twiddles;
const Poly = prover.poly.circle.poly;
const Domain = core.poly.circle.domain.CircleDomain;

pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 6) return error.UsageExpectedOperationLogSeedRequestExpected;
    const op = try std.fmt.parseInt(u32, args[1], 10);
    const log = try std.fmt.parseInt(u32, args[2], 10);
    const seed = try std.fmt.parseInt(u64, args[3], 10);
    if (op > 5 or log < 1 or log > abi.max_log_size) return error.InvalidInput;
    const n = @as(usize, 1) << @intCast(log);
    const values = try a.alloc(M31, n);
    defer a.free(values);
    var rng = std.Random.DefaultPrng.init(seed);
    for (values) |*x| x.* = M31.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
    // A deterministic cross-product of limb/carry boundaries precedes random data.
    if (op == 2) {
        const edges = [_]u32{ 0, 1, 2, 32767, 32768, 65535, 65536, 65537, 1073741823, 1073741824, 2147483645, 2147483646 };
        for (0..@min(n / 2, edges.len * edges.len)) |i| {
            values[i] = M31.fromCanonical(edges[i / edges.len]);
            values[n / 2 + i] = M31.fromCanonical(edges[i % edges.len]);
        }
    }
    if (op >= 4) {
        if (log < 3) return error.InvalidInput;
        const QM31 = core.fields.qm31.QM31;
        const qs = try a.alloc(QM31, n / 4);
        defer a.free(qs);
        for (qs, 0..) |*q, i| q.* = QM31.fromM31(values[4 * i], values[4 * i + 1], values[4 * i + 2], values[4 * i + 3]);
        const alpha = QM31.fromU32Unchecked(17, 2147483646, 65535, 12345);
        const circle_domain = core.poly.circle.canonic.CanonicCoset.new(log - 2).circleDomain();
        const line_domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(log - 2));
        const is_circle = op == 5;
        const req = if (is_circle)
            try @import("stwo_bend_backend").fri.request(a, qs, circle_domain.half_coset, alpha, true)
        else
            try @import("stwo_bend_backend").fri.request(a, qs, line_domain.coset(), alpha, false);
        defer a.free(req);
        try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = req });
        var timer = try std.time.Timer.start();
        const result = try a.alloc(QM31, qs.len / 2);
        defer a.free(result);
        @memset(result, QM31.zero());
        if (is_circle) {
            var workspace = try core.fri.FoldCircleWorkspace.init(a, result.len);
            defer workspace.deinit(a);
            try @call(.never_inline, core.fri.foldCircleIntoLineWithWorkspace, .{ a, result, qs, circle_domain, alpha, &workspace });
        } else {
            var workspace = try core.fri.FoldLineWorkspace.init(a, result.len);
            defer workspace.deinit(a);
            const folded = try @call(.never_inline, core.fri.foldLineNWithWorkspace, .{ a, qs, line_domain, alpha, &workspace, @as(u32, 1) });
            defer a.free(folded.values);
            @memcpy(result, folded.values);
        }
        const ns = timer.read();
        var expected: std.ArrayList(u8) = .empty;
        defer expected.deinit(a);
        for ([_]u32{ abi.response_magic, abi.version, @intCast(result.len * 4) }) |v| try abi.word(&expected, a, v);
        for (result) |q| for (q.toM31Array()) |v| try abi.word(&expected, a, v.v);
        try std.fs.cwd().writeFile(.{ .sub_path = args[5], .data = expected.items });
        std.debug.print("{{\"compute_ns\":{d},\"pack_width\":{d},\"lane\":\"zig-existing\"}}\n", .{ ns, core.fields.m31.PACK_WIDTH });
        return;
    }
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var tree = try tw.precomputeM31(a, domain.half_coset);
    defer tw.deinitM31(a, &tree);
    const norm = try M31.fromCanonical(@intCast(n)).inv();
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(a);
    for ([_]u32{ abi.request_magic, abi.version, op, log, norm.v }) |v| try abi.word(&request, a, v);
    for (values) |v| try abi.word(&request, a, v.v);
    if (op < 2) try @import("stwo_bend_backend").circle.writePlan(&request, a, tree, domain, log, 0, op == 1);
    try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = request.items });
    var timer = try std.time.Timer.start();
    const view = tw.TwiddleTree([]const M31).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    var batch = [_][]M31{values};
    var result: []M31 = values;
    switch (op) {
        0 => try Poly.evaluateBuffersWithTwiddles(&batch, domain, view),
        1 => try Poly.interpolateBuffersWithTwiddles(&batch, domain, view),
        2 => {
            for (values[0 .. n / 2], values[n / 2 ..]) |*x, y| x.* = x.mul(y);
            result = values[0 .. n / 2];
        },
        3 => {
            var acc = M31.zero();
            for (values) |*x| {
                acc = acc.add(x.*);
                x.* = acc;
            }
        },
        else => unreachable,
    }
    const ns = timer.read();
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(a);
    for ([_]u32{ abi.response_magic, abi.version, @intCast(result.len) }) |v| try abi.word(&expected, a, v);
    for (result) |v| try abi.word(&expected, a, v.v);
    try std.fs.cwd().writeFile(.{ .sub_path = args[5], .data = expected.items });
    std.debug.print("{{\"compute_ns\":{d},\"pack_width\":{d},\"lane\":\"zig-existing\"}}\n", .{ ns, core.fields.m31.PACK_WIDTH });
}
