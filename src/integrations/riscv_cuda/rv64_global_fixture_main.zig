//! Native tuple -> paired fraction -> native classic witness CUDA oracle.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("rv64/global_codegen.zig");
const Oracle = @import("rv64/joined_fixture_support.zig");
const IO = @import("rv64/fixture_io.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Classic = G.Authority.GlobalWitness;
const a = std.heap.page_allocator;
const Sink = struct {
    params: *const [G.P.count]O,
    n: [108]O = undefined,
    d: [108]O = undefined,
    ram: usize = 0,
    other: usize = 0,
    pub fn emit(self: *@This(), relation: G.Authority.Global.Relation, tuple: anytype, weight: O) void {
        const slot: usize = switch (relation) {
            .ram => G.P.ram,
            .kio => G.P.kio,
            .wire => G.P.wire,
        };
        var den = self.params[slot];
        for (tuple, 0..) |v, i| den = den.sub(self.params[slot + 1 + i].mul(v));
        const idx = if (relation == .ram) self.ram else 58 + self.other;
        self.n[idx] = weight;
        self.d[idx] = den;
        if (relation == .ram) self.ram += 1 else self.other += 1;
    }
};
const Provider = struct {
    d: []const O,
    n: []const O,
    rows: usize,
    pairs: usize,
    log: u32,
    pub fn fill(self: @This(), logical: usize, ds: []O, ns: []Classic.Numerator) !void {
        const row = A.witness.physical(logical, self.log);
        for (ds, ns, 0..) |*d, *n, pair| {
            d.* = self.d[row * self.pairs + pair];
            n.* = .{ .secure = self.n[row * self.pairs + pair] };
        }
    }
};
fn fixture(dir: std.fs.Dir, descriptor: G.Source.Descriptor, id: u32) !void {
    var artifact = try G.record(a, descriptor);
    defer artifact.deinit();
    const shape = try G.Authority.shape(descriptor);
    const log: u32 = if (id == 0) 14 else 5;
    const rows = @as(usize, 1) << @intCast(log);
    const pairs = artifact.ram_pairs + artifact.other_pairs;
    const width = 8 * (pairs + @as(u32, if (artifact.other_pairs > 0) 2 else 1));
    const stride = rows + 3;
    const fixed = try a.alloc(O, shape.fixed);
    defer a.free(fixed);
    const main_row = try a.alloc(O, shape.main);
    defer a.free(main_row);
    const tree0 = try a.alloc(M, shape.fixed * rows);
    defer a.free(tree0);
    const tree1 = try a.alloc(M, shape.main * rows);
    defer a.free(tree1);
    const ns = try a.alloc(O, rows * pairs);
    defer a.free(ns);
    const ds = try a.alloc(O, rows * pairs);
    defer a.free(ds);
    var rng = std.Random.DefaultPrng.init(0x914720 + id);
    const random = rng.random();
    const params = Oracle.metadata(random, 0);
    for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
    const inputs = try a.alloc(O, artifact.program.inputs.len);
    defer a.free(inputs);
    for (0..rows) |row| {
        for (fixed, 0..) |*v, c| {
            const x = M.fromCanonical(random.uintLessThan(u32, 65536));
            v.* = O.fromBase(x);
            tree0[c * rows + row] = x;
        }
        for (main_row, 0..) |*v, c| {
            const x = M.fromCanonical(random.uintLessThan(u32, 65536));
            v.* = O.fromBase(x);
            tree1[c * rows + row] = x;
        }
        var sink = Sink{ .params = &params };
        try G.Authority.emitGlobalQueries(descriptor, O, fixed, main_row, params[G.P.source_public + G.Source.Public.sponge_first_id], &sink);
        var pair: usize = 0;
        const counts = [2]usize{ sink.ram, sink.other };
        for (counts, 0..) |count, group| {
            const base = if (group == 0) @as(usize, 0) else 58;
            var q: usize = 0;
            while (q < count) : (q += 2) {
                const ni = base + q;
                ns[row * pairs + pair] = if (q + 1 < count) sink.n[ni].mul(sink.d[ni + 1]).add(sink.n[ni + 1].mul(sink.d[ni])) else sink.n[ni];
                ds[row * pairs + pair] = if (q + 1 < count) sink.d[ni].mul(sink.d[ni + 1]) else sink.d[ni];
                pair += 1;
            }
        }
        for (artifact.program.inputs, inputs) |input, *v| v.* = if (input.tree == 0) fixed[input.column] else main_row[input.column];
        const actual = try artifact.program.evaluate(a, inputs);
        defer a.free(actual);
        for (0..pairs) |p| if (!actual[2 * p].eql(ns[row * pairs + p]) or !actual[2 * p + 1].eql(ds[row * pairs + p])) return error.NativeGlobalProjectionMismatch;
    }
    const groups = [2]Classic.Group{ .{ .inverses = @intCast(artifact.ram_pairs) }, .{ .inverses = @intCast(artifact.other_pairs) } };
    var witness = try Classic.Witness.initTruth(a, log, groups[0..if (artifact.other_pairs > 0) @as(usize, 2) else 1], Provider{ .d = ds, .n = ns, .rows = rows, .pairs = pairs, .log = log }, 1 << 30);
    defer witness.deinit();
    if (witness.width() != width) return error.InvalidGlobalFixtureWidth;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564750, 1, id, log, @intCast(shape.fixed), @intCast(shape.main), @intCast(artifact.program.inputs.len), @intCast(artifact.parameter_slots.len), artifact.ram_pairs, artifact.other_pairs, width, @intCast(stride) });
    for (artifact.program.inputs) |input| {
        const offset = @as(u64, input.column) * rows;
        try IO.words(w, &.{ @truncate(offset), @truncate(offset >> 32) });
    }
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    const name = try std.fmt.allocPrint(a, "rv64_global_projection_{}", .{id});
    defer a.free(name);
    try G.emit(a, source.writer(a), &artifact, name);
    const cu = try std.fmt.allocPrint(a, "case-{}.cu", .{id});
    defer a.free(cu);
    try dir.writeFile(.{ .sub_path = cu, .data = source.items });
    // Data follows the cold column offsets; all values are canonical M31 words.
    for (tree0) |v| try IO.words(w, &.{v.v});
    for (tree1) |v| try IO.words(w, &.{v.v});
    for (artifact.program.parameters) |v| try IO.felts(w, &.{v});
    for (witness.data) |v| try IO.words(w, &.{v.v});
    try IO.felts(w, witness.claimSlice());
    const bin = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(bin);
    try dir.writeFile(.{ .sub_path = bin, .data = bytes.items });
    std.debug.print("global case={} ram_pairs={} other_pairs={} nodes={} identity={s}\n", .{ id, artifact.ram_pairs, artifact.other_pairs, artifact.program.nodes.len, std.fmt.bytesToHex(try artifact.identity(), .lower) });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    var header: std.ArrayList(u8) = .empty;
    defer header.deinit(a);
    const w = header.writer(a);
    try w.writeAll("#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n");
    var count: u32 = 0;
    for (Oracle.descriptors()) |d| {
        if (G.Authority.Global.layout(d.origin).ram_queries == 0) continue;
        try fixture(dir, d, count);
        try w.print("extern \"C\" __global__ void rv64_global_projection_{}(const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,uint32_t*,uint32_t*,uint64_t,uint32_t,uint32_t*);\n", .{count});
        count += 1;
    }
    try w.print("constexpr uint32_t global_case_count={};\nstatic const void *global_kernels[]={{", .{count});
    for (0..count) |i| try w.print("{s}(void*)rv64_global_projection_{}", .{ if (i == 0) "" else ",", i });
    try w.writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "global_launches.h", .data = header.items });
}
