const std = @import("std");
const core = @import("stwo_core");
const R = @import("record.zig");
const Catalog = @import("catalog.zig");
const C = @import("emit_c.zig");
const a = std.testing.allocator;
const Q = R.Q;
const M = R.M;

const QuotientFn = *const fn ([*]const u32, [*]const u32, [*]const u32, u32, [*]u32) callconv(.c) void;

test "generated C for the CPU row (fused tail) is bit-identical to the IR and the native evaluator" {
    var prng = std.Random.DefaultPrng.init(0xC0DE);
    const rng = prng.random();
    var case = try Catalog.cpu(a, rng, 6, true, false);
    defer case.deinit(a);
    const program = &case.exported.program;
    const shape = case.exported.shape;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var source: std.ArrayList(u8) = .empty;
        defer source.deinit(a);
        try C.emit(a, source.writer(a), program, "cpu_fused_tail");
        try tmp.dir.writeFile(.{ .sub_path = "cpu.c", .data = source.items });
    }
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);
    const lib = try std.fs.path.join(a, &.{ dir, "libcir.dylib" });
    defer a.free(lib);
    var child = std.process.Child.init(&.{ "cc", "-O1", "-std=c11", "-Wall", "-Werror", "-Wno-unused-variable", "-Wno-unused-function", "-shared", "-fPIC", "-o", lib, "cpu.c" }, a);
    child.cwd = dir;
    const term = try child.spawnAndWait();
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 0 }, term);
    var dl = try std.DynLib.open(lib);
    defer dl.close();
    const quotient = dl.lookup(QuotientFn, "cpu_fused_tail_quotient") orelse return error.MissingGeneratedSymbol;

    var trace = try R.RandomTrace.init(a, rng, shape, null);
    defer trace.deinit(a);
    const alpha = R.randomQ(rng);
    // IR == native first (the established parity), then generated C == IR.
    _ = try R.checkDomain(a, &case.exported, case.prover, &trace, alpha);
    const n = @as(usize, 1) << @intCast(shape.eval_log);
    const powers = try @import("stwo_prover_engine").air.accumulation.generateSecurePowers(a, alpha, program.roots.len);
    defer a.free(powers);
    const expected = try a.alloc(Q, n);
    defer a.free(expected);
    const columns = trace.local(shape);
    try R.evaluateDomain(a, program, shape, columns, powers, expected);
    // Residual j carries power[n-1-j]; flatten parameters and reversed powers.
    const params = try a.alloc(u32, 4 * program.parameters.len);
    defer a.free(params);
    for (program.parameters, 0..) |p, i| for (p.toM31Array(), 0..) |c, k| {
        params[4 * i + k] = c.toU32();
    };
    const flat_powers = try a.alloc(u32, 4 * powers.len);
    defer a.free(flat_powers);
    for (0..powers.len) |j| for (powers[powers.len - 1 - j].toM31Array(), 0..) |c, k| {
        flat_powers[4 * j + k] = c.toU32();
    };
    const inverses = try @import("stwo_riscv_frontend").rv64_air.geometry.denominatorInverses(a, shape.log_size, shape.eval_log);
    defer a.free(inverses);
    const inputs = try a.alloc(u32, program.inputs.len);
    defer a.free(inputs);
    for (0..n) |row| {
        for (program.inputs, inputs) |input, *v| v.* = R.rowInput(input, shape, columns, row).toU32();
        var out: [4]u32 = undefined;
        quotient(inputs.ptr, params.ptr, flat_powers.ptr, inverses[row >> @intCast(shape.log_size)].toU32(), &out);
        const got = Q.fromU32Unchecked(out[0], out[1], out[2], out[3]);
        if (!got.eql(expected[row])) {
            std.debug.print("generated C mismatch at row {d}\n", .{row});
            return error.GeneratedCMismatch;
        }
    }
}
