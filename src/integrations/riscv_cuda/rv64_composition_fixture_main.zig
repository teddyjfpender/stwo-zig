//! Cold numerical qualification: exports actual MAIN-only RV64 AIR equations.
//! This tool is not a production proof generator or an admitted role catalog.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const CG = @import("rv64/composition_codegen.zig");
const Main = A.main_only.authority;
const O = CG.O;
const M = core.fields.m31.M31;
const Lane = A.evaluation.symbolic.SymbolicLane(O);
const a = std.heap.page_allocator;
fn random(rng: std.Random) O {
    var coords: [8]M = undefined;
    for (&coords) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, 2147483647));
    return O.fromM31Array(coords);
}
const words = @import("rv64/fixture_io.zig").words;
const felts = @import("rv64/fixture_io.zig").felts;
fn public(role: Main.Role) Main.PublicFor(O) {
    return switch (role) {
        .cpu => .{ .cpu = .{ .steps = 3, .initial_pc = .{ 4096, 0, 0, 0 }, .final_pc = .{ 4108, 0, 0, 0 }, .epoch = 1 } },
        .cpu_compact => .{ .cpu_compact = .{ .steps = 3, .initial_pc = .{ 4096, 0, 0, 0 }, .final_pc = .{ 4108, 0, 0, 0 }, .epoch = 1 } },
        .alu => .{ .alu = {} },
        .binary => .{ .binary = {} },
        .shift => .{ .shift = {} },
        .ls => .{ .ls = .{ .count = 3 } },
        .jalr => .{ .jalr = {} },
        .mul => .{ .mul = .{ .count = 3 } },
        .div => .{ .div = .{ .count = 3 } },
    };
}
fn fixedValue(seed: u32) O {
    var coords: [8]M = undefined;
    for (&coords, 0..) |*v, i| v.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 17);
    return O.fromM31Array(coords);
}
fn synthetic() !CG.Program {
    var b = CG.ir.BuilderFor(O).init(a);
    defer b.deinit();
    const x = b.input(.{ .tree = 0, .column = 0, .offset = -2 });
    const y = b.input(.{ .tree = 0, .column = 1, .offset = 2 });
    const z = b.input(.{ .tree = 1, .column = 0, .offset = -1 });
    const t = b.input(.{ .tree = 1, .column = 1, .offset = 1 });
    const u = b.input(.{ .tree = 2, .column = 0 });
    const v = b.input(.{ .tree = 2, .column = 1, .offset = -2 });
    const parameter = b.parameter(fixedValue(103));
    const constant = b.constant(fixedValue(17));
    const r0 = b.add(b.mul(b.sub(x, y), parameter), constant);
    const r1 = b.add(b.neg(b.mul(z, t)), b.mul(u, v));
    const r2 = b.add(x, y);
    return b.finish(@splat(73), &.{ r0, r1, r0, r2 });
}
fn valueAt(trees: [3][]M, tree: usize, column: usize, row: usize, offset: isize, trace_log: u32, eval_log: u32) O {
    const n = @as(usize, 1) << @intCast(eval_log);
    return O.fromBase(trees[tree][column * n + core.utils.offsetBitReversedCircleDomainIndex(row, trace_log, eval_log, offset)]);
}
fn record(role: Main.Role) !CG.Program {
    const shape = Main.shape(role);
    var recording = A.evaluation.symbolic.Recording(O).init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const fixed = try a.alloc(Lane, shape.fixed);
    defer a.free(fixed);
    const current = try a.alloc(Lane, shape.main);
    defer a.free(current);
    const previous = try a.alloc(Lane, shape.main);
    defer a.free(previous);
    for (fixed, 0..) |*v, i| v.* = Lane.input(0, i, 0);
    for (current, previous, 0..) |*v, *p, i| {
        v.* = Lane.input(1, i, 0);
        p.* = if (Main.previousMain(role, i)) Lane.input(1, i, -1) else Lane.zero();
    }
    const residuals = try a.alloc(Lane, shape.constraints);
    defer a.free(residuals);
    var sink = A.evaluation.SinkFor(Lane){ .values = residuals };
    try Main.emitFor(Lane, public(role), fixed, current, previous, &sink);
    if (sink.count != residuals.len) return error.WrongNativeConstraintCount;
    const roots = try a.alloc(u32, residuals.len);
    defer a.free(roots);
    for (residuals, roots) |v, *id| id.* = v.id;
    var authority: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64/main-only/" ++ "composition-device-fixture", &authority, .{});
    // The actual ordered DAG, including every input offset, also enters identity.
    return recording.builder.finish(authority, roots);
}
fn fixture(dir: std.fs.Dir, source: anytype, role: ?Main.Role, index: u32, trace_log: u32, eval_log: u32) !void {
    const shape = if (role) |r| Main.shape(r) else Main.Shape{ .fixed = 2, .main = 2, .constraints = 4 };
    var program = if (role) |r| try record(r) else try synthetic();
    defer program.deinit();
    const name = try std.fmt.allocPrint(a, "rv64_composition_fixture_{}", .{index});
    defer a.free(name);
    try CG.emit(a, source, &program, name);
    const n = @as(usize, 1) << @intCast(eval_log);
    const widths = [3]usize{ shape.fixed, shape.main, if (role == null) 2 else 0 };
    var rng = std.Random.DefaultPrng.init(17 + index);
    var trees: [3][]M = undefined;
    for (&trees, widths) |*tree, width| {
        tree.* = try a.alloc(M, width * n);
        for (tree.*) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
    }
    defer for (trees) |tree| a.free(tree);
    const initial = try a.alloc(O, n);
    defer a.free(initial);
    const expected = try a.alloc(O, n);
    defer a.free(expected);
    const powers = try a.alloc(O, shape.constraints);
    defer a.free(powers);
    var power = O.one();
    const alpha = random(rng.random());
    for (powers) |*p| {
        p.* = power;
        power = power.mul(alpha);
    }
    const denoms = try A.geometry.denominatorInverses(a, trace_log, eval_log);
    defer a.free(denoms);
    const fixed = try a.alloc(O, shape.fixed);
    defer a.free(fixed);
    const current = try a.alloc(O, shape.main);
    defer a.free(current);
    const previous = try a.alloc(O, shape.main);
    defer a.free(previous);
    const residuals = try a.alloc(O, shape.constraints);
    defer a.free(residuals);
    const ir_inputs = try a.alloc(O, program.inputs.len);
    defer a.free(ir_inputs);
    const ir_values = try a.alloc(O, program.nodes.len);
    defer a.free(ir_values);
    const ir_residuals = try a.alloc(O, program.roots.len);
    defer a.free(ir_residuals);
    for (0..n) |row| {
        for (fixed, 0..) |*v, c| v.* = O.fromBase(trees[0][c * n + row]);
        for (current, previous, 0..) |*v, *p, c| {
            v.* = O.fromBase(trees[1][c * n + row]);
            p.* = if (if (role) |r| Main.previousMain(r, c) else false) O.fromBase(trees[1][c * n + core.utils.offsetBitReversedCircleDomainIndex(row, trace_log, eval_log, -1)]) else O.zero();
        }
        var sink = A.evaluation.SinkFor(O){ .values = residuals };
        if (role) |r| {
            try Main.emitFor(O, public(r), fixed, current, previous, &sink);
        } else {
            const x = valueAt(trees, 0, 0, row, -2, trace_log, eval_log);
            const y = valueAt(trees, 0, 1, row, 2, trace_log, eval_log);
            const z = valueAt(trees, 1, 0, row, -1, trace_log, eval_log);
            const t = valueAt(trees, 1, 1, row, 1, trace_log, eval_log);
            const u = valueAt(trees, 2, 0, row, 0, trace_log, eval_log);
            const v = valueAt(trees, 2, 1, row, -2, trace_log, eval_log);
            residuals[0] = x.sub(y).mul(fixedValue(103)).add(fixedValue(17));
            residuals[1] = z.mul(t).neg().add(u.mul(v));
            residuals[2] = residuals[0];
            residuals[3] = x.add(y);
        }
        for (program.inputs, ir_inputs) |input, *v| v.* = O.fromBase(trees[input.tree][input.column * n + core.utils.offsetBitReversedCircleDomainIndex(row, trace_log, eval_log, input.offset)]);
        program.evaluateRow(ir_values, ir_inputs, ir_residuals);
        var folded = O.zero();
        for (residuals, ir_residuals, 0..) |native, ir_value, j| {
            if (!native.eql(ir_value)) return error.NativeIrResidualMismatch;
            folded = folded.add(native.mul(powers[shape.constraints - 1 - j]));
        }
        initial[row] = random(rng.random());
        expected[row] = initial[row].add(folded.mulM31(denoms[row >> @intCast(trace_log)]));
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try words(w, &.{ 0x52564350, 1, trace_log, eval_log, @intCast(widths[0]), @intCast(widths[1]), @intCast(widths[2]), @intCast(program.inputs.len), @intCast(program.parameters.len), @intCast(program.roots.len), @intCast(program.nodes.len), index });
    for (trees) |tree| for (tree) |v| try words(w, &.{v.v});
    for (program.inputs) |input| {
        const offset: u64 = @as(u64, input.column) * n;
        try words(w, &.{ @truncate(offset), @truncate(offset >> 32) });
    }
    try felts(w, program.parameters);
    try felts(w, powers);
    for (denoms) |v| try words(w, &.{v.v});
    // Secure matrices are serialized SoA, as the real device allocation.
    for (0..8) |c| for (initial) |v| try words(w, &.{v.toM31Array()[c].v});
    for (0..8) |c| for (expected) |v| try words(w, &.{v.toM31Array()[c].v});
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{index});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
    std.debug.print("role={s} roots={} nodes={} inputs={} rows={} identity={s}\n", .{ if (role) |r| @tagName(r) else "mixed_secure_masks", program.roots.len, program.nodes.len, program.inputs.len, n, std.fmt.bytesToHex(try CG.identity(&program), .lower) });
}
fn writeMasks(dir: std.fs.Dir) !void {
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(a);
    const w = data.writer(a);
    for (1..8) |t| for (t..t + 3) |e| {
        const trace_log: u32 = @intCast(t);
        const eval_log: u32 = @intCast(e);
        const n = @as(usize, 1) << @intCast(eval_log);
        for (0..n) |row| for ([_]i32{ -128, -2, -1, 0, 1, 2, 127 }) |offset| {
            try words(w, &.{ @intCast(row), trace_log, eval_log, @bitCast(offset), @intCast(core.utils.offsetBitReversedCircleDomainIndex(row, trace_log, eval_log, offset)) });
        };
    };
    try dir.writeFile(.{ .sub_path = "mask-positions.bin", .data = data.items });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    for (std.enums.values(Main.Role), 0..) |role, i| try fixture(dir, source.writer(a), role, @intCast(i), 5, 7);
    try fixture(dir, source.writer(a), null, @intCast(std.enums.values(Main.Role).len), 5, 7);
    try dir.writeFile(.{ .sub_path = "generated.cu", .data = source.items });
    var declarations: std.ArrayList(u8) = .empty;
    defer declarations.deinit(a);
    const count = std.enums.values(Main.Role).len + 1;
    try declarations.writer(a).writeAll("#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n");
    for (0..count) |id| try declarations.writer(a).print("extern \"C\" __global__ void rv64_composition_fixture_{}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n", .{id});
    try declarations.writer(a).print("constexpr uint32_t composition_case_count={};\nstatic const void *kernels[]={{{s}", .{ count, "" });
    for (0..count) |id| try declarations.writer(a).print("{s}(void*)rv64_composition_fixture_{}", .{ if (id == 0) "" else ",", id });
    try declarations.writer(a).writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "composition_launches.h", .data = declarations.items });
    try writeMasks(dir);
}
