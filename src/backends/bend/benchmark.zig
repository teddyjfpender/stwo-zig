//! End-to-end backend-operation timing, including serialization and Zig parity.
//! This is not full-proof throughput. Setup and the final external check are untimed.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const bend = @import("stwo_bend_backend");
const M31 = core.fields.m31.M31;
const tw = prover.poly.twiddles;
const poly = prover.poly.circle.poly;
const B = bend.BendBackend(.{ .executable = @import("config").executable, .threads = 8 });
fn view(tree: tw.TwiddleTree([]M31)) tw.TwiddleTree([]const M31) {
    return .init(tree.root_coset, tree.twiddles, tree.itwiddles);
}
pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedOperationLogSeed;
    const op = try std.fmt.parseInt(u32, args[1], 10);
    const log = try std.fmt.parseInt(u32, args[2], 10);
    const seed = try std.fmt.parseInt(u64, args[3], 10);
    if (op > 2 or log < 1 or log > bend.abi.max_log_size - @as(u32, if (op == 2) 1 else 0)) return error.InvalidInput;
    const d = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    const ed = core.poly.circle.canonic.CanonicCoset.new(log + @as(u32, if (op == 2) 1 else 0)).circleDomain();
    var tree = try tw.precomputeM31(a, d.half_coset);
    defer tw.deinitM31(a, &tree);
    var etree = try tw.precomputeM31(a, ed.half_coset);
    defer tw.deinitM31(a, &etree);
    const input = try a.alloc(M31, d.size());
    defer a.free(input);
    var rng = std.Random.DefaultPrng.init(seed);
    for (input) |*x| x.* = M31.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
    const native = try a.dupe(M31, input);
    defer a.free(native);
    const zig = try a.dupe(M31, input);
    defer a.free(zig);
    const ne = try a.alloc(M31, ed.size());
    defer a.free(ne);
    const ze = try a.alloc(M31, ed.size());
    defer a.free(ze);
    var timer = try std.time.Timer.start();
    switch (op) {
        0 => {
            _ = try B.evaluateCircleBuffers(a, &.{native}, d, view(tree));
        },
        1 => {
            _ = try B.interpolateCircleBuffers(a, &.{native}, d, view(tree));
        },
        2 => {
            _ = try B.interpolateAndEvaluateCircleBuffers(a, &.{input}, &.{native}, &.{ne}, ne, 0, ne.len, d, view(tree), ed, view(etree));
        },
        else => unreachable,
    }
    const bend_ns = timer.lap();
    var zb = [_][]M31{zig};
    switch (op) {
        0 => try poly.evaluateBuffersWithTwiddles(&zb, d, view(tree)),
        1 => try poly.interpolateBuffersWithTwiddles(&zb, d, view(tree)),
        2 => {
            try poly.interpolateBuffersWithTwiddles(&zb, d, view(tree));
            @memcpy(ze[0..zig.len], zig);
            var eb = [_][]M31{ze};
            // Same specialized 2x path used by CpuBackend's combined LDE.
            try poly.evaluateExtensionBuffersWithTwiddles(&eb, ed, view(etree));
        },
        else => unreachable,
    }
    const zig_ns = timer.read();
    for (native, zig) |x, y| if (!x.eql(y)) return error.ExternalParityMismatch;
    if (op == 2) {
        for (ne, ze) |x, y| if (!x.eql(y)) return error.ExternalLdeParityMismatch;
    }
    std.debug.print("{{\"compute_ns\":{d},\"bend_backend_ns\":{d},\"zig_operation_ns\":{d},\"lane\":\"bend-cpu-verified-backend\",\"equal\":true}}\n", .{ bend_ns, bend_ns, zig_ns });
}
