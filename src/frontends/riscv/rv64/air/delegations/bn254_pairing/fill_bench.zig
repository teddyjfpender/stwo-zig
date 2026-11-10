//! Explicit bounded full four-role carry/column witness benchmark. No GP/STARK.
const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const L = @import("lowering.zig");
const NW = @import("normalized_witness.zig");
const C = @import("fixture.zig");
const V = @import("../bn254_miller/vectors.zig");
const R = @import("../bn254_residue/vectors.zig");
const ORDER = [_]C.Role{ .frontier, .arithmetic, .hints, .table };
const Columns = struct { fixed: []C.M, main: []C.M };
const physical = @import("../../memory/closed_ram/trace.zig").physical;
fn pass(reference: bool, plan: *const L.Program, actual: *const NW.Witness, initial: *const [S.INITIAL]u256, columns: *[4]Columns, deadline: *std.time.Timer) !struct { ns: u64, hash: [32]u8 } {
    var timer = try std.time.Timer.start();
    var model = if (reference) try C.Model.initReferenceForTesting(plan, actual, initial) else try C.Model.init(plan, actual, initial);
    inline for (ORDER, 0..) |role, index| {
        const rows = @as(usize, 1) << @intCast(C.logSize(role));
        for (0..rows) |logical| {
            if (logical % 512 == 0 and deadline.read() > 120 * std.time.ns_per_s) return error.BoundedWitnessFillDeadline;
            const position = physical(logical, C.logSize(role));
            const view = try model.materialize(role, logical);
            for (0..C.fixedWidth(role)) |col| columns[index].fixed[col * rows + position] = view.fixed(col).toM31Array()[0];
            for (0..C.mainWidth(role)) |col| columns[index].main[col * rows + position] = view.main(col).toM31Array()[0];
        }
        try model.installColumns(role, columns[index].main);
    }
    const ns = timer.read();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |part| {
        h.update(std.mem.sliceAsBytes(part.fixed));
        h.update(std.mem.sliceAsBytes(part.main));
    }
    return .{ .ns = ns, .hash = h.finalResult() };
}
test "MAC12 whole witness encoding interleaved bounded benchmark" {
    const marker = std.process.getEnvVarOwned(std.testing.allocator, "STWO_MAC12_FILL_BENCH") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return error.SkipZigTest;
        return err;
    };
    defer std.testing.allocator.free(marker);
    const backing = try std.testing.allocator.alloc(u8, 256 << 20);
    defer std.testing.allocator.free(backing);
    var fixed = std.heap.FixedBufferAllocator.init(backing);
    const a = fixed.allocator();
    var source = try W.Witness.init(a, V.INPUT, .{ .seed = R.POSITIVE.seed, .scale = R.POSITIVE.c[0..6].*, .inverse2 = R.POSITIVE.inverse2 });
    defer source.deinit();
    var plan = try L.Program.init(a);
    defer plan.deinit();
    var actual = try NW.Witness.init(a, &plan, &source);
    defer actual.deinit();
    const initial = try S.initialValues(V.INPUT);
    var columns: [4]Columns = undefined;
    inline for (ORDER, 0..) |role, i| {
        const rows = @as(usize, 1) << @intCast(C.logSize(role));
        columns[i] = .{ .fixed = try a.alloc(C.M, C.fixedWidth(role) * rows), .main = try a.alloc(C.M, C.mainWidth(role) * rows) };
    }
    var deadline = try std.time.Timer.start();
    const warm = try pass(true, &plan, &actual, &initial, &columns, &deadline);
    var times: [4]u64 = undefined;
    for ([_]bool{ true, false, false, true }, 0..) |reference, i| {
        const result = try pass(reference, &plan, &actual, &initial, &columns, &deadline);
        try std.testing.expectEqualSlices(u8, &warm.hash, &result.hash);
        times[i] = result.ns;
        std.debug.print("OP_MAC12_FILL_BENCH index={d} mode={s} seconds={d:.6} fixed_main_sha256={s}\n", .{ i, if (reference) "reference" else "known_zero_skip", @as(f64, @floatFromInt(result.ns)) / 1e9, std.fmt.bytesToHex(result.hash, .lower) });
    }
    const reference = @as(f64, @floatFromInt(times[0] + times[3])) / 2e9;
    const candidate = @as(f64, @floatFromInt(times[1] + times[2])) / 2e9;
    std.debug.print("OP_MAC12_FILL_SUMMARY reference_seconds={d:.6} candidate_seconds={d:.6} speedup={d:.3} requested_arena_bytes={d} cap_bytes={d} rows={d}\n", .{ reference, candidate, reference / candidate, fixed.end_index, backing.len, plan.stages.len });
}
