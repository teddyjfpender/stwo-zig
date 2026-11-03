//! Cold native joined AIR oracle and AOT kernels. Never a proof producer.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("rv64/joined_codegen.zig");
const C = @import("rv64/composition_codegen.zig");
const Oracle = @import("rv64/joined_fixture_support.zig");
const IO = @import("rv64/fixture_io.zig");
const O = Oracle.O;
const a = std.heap.page_allocator;
fn fixture(dir: std.fs.Dir, descriptor: G.Source.Descriptor, id: u32) !void {
    var artifact = try G.record(a, descriptor);
    defer artifact.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    const oods_name = try std.fmt.allocPrint(a, "rv64_joined_oods_{}", .{id});
    defer a.free(oods_name);
    try C.emitOods(a, source.writer(a), &artifact.program, oods_name);
    const oods_file = try std.fmt.allocPrint(a, "case-{}-oods.cu", .{id});
    defer a.free(oods_file);
    try dir.writeFile(.{ .sub_path = oods_file, .data = source.items });
    source.clearRetainingCapacity();
    const domain_name = try std.fmt.allocPrint(a, "rv64_joined_domain_{}", .{id});
    defer a.free(domain_name);
    if (id == 41) try C.emitGrouped(a, source.writer(a), &artifact.program, domain_name, 32) else try C.emit(a, source.writer(a), &artifact.program, domain_name);
    const domain_file = try std.fmt.allocPrint(a, "case-{}-domain.cu", .{id});
    defer a.free(domain_file);
    try dir.writeFile(.{ .sub_path = domain_file, .data = source.items });
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564a50, 1, id, @intCast(artifact.program.inputs.len), @intCast(artifact.parameter_slots.len), @intCast(artifact.program.roots.len), 3, G.Parameters.count });
    for (artifact.parameter_slots) |slot| {
        const address = try G.Parameters.address(slot);
        try IO.words(w, &.{ @intFromEnum(address.namespace), address.index });
    }
    var rng = std.Random.DefaultPrng.init(0xb401aa + id);
    for (0..3) |mode| {
        var row = try Oracle.Row.init(a, descriptor, rng.random(), mode != 0);
        defer row.deinit();
        const params = Oracle.metadata(rng.random(), @intCast(mode));
        const inputs = try row.inputs(&artifact.program);
        defer a.free(inputs);
        const expected = try Oracle.nativeResiduals(a, descriptor, &params, row.fixed, row.main, row.previous, row.inter, row.shifted, row.aux);
        defer a.free(expected);
        // Re-prove the recorder's exact native emission order before exporting.
        for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
        const actual = try artifact.program.evaluate(a, inputs);
        defer a.free(actual);
        for (actual, expected) |x, y| if (!x.eql(y)) return error.NativeJoinedResidualMismatch;
        const powers = try a.alloc(O, expected.len);
        defer a.free(powers);
        var power = O.one();
        const alpha = Oracle.random(rng.random());
        for (powers) |*v| {
            v.* = power;
            power = power.mul(alpha);
        }
        var folded = O.zero();
        for (expected, 0..) |value, j| folded = folded.add(value.mul(powers[powers.len - 1 - j]));
        const inverse = Oracle.random(rng.random());
        const initial = Oracle.random(rng.random());
        const result = initial.add(folded.mul(inverse));
        try IO.words(w, &.{@intCast(mode)});
        try IO.felts(w, inputs);
        // Public input is the only base-valued namespace; gathering zero-lifts
        // its limbs on the GPU. Other reservoirs are explicit OM31 AoS words.
        for (params[0..G.Parameters.local]) |value| {
            const coordinates = value.toM31Array();
            for (coordinates[1..]) |x| if (!x.isZero()) return error.NonBaseJoinedFixturePublic;
            try IO.words(w, &.{coordinates[0].v});
        }
        try IO.felts(w, params[G.Parameters.local..]);
        try IO.felts(w, powers);
        try IO.felts(w, &.{ inverse, initial, result });
    }
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
    const tags = G.Source.Frame.originWords(descriptor.origin);
    std.debug.print("id={} origin={}/{} roots={} masks={} params={} identity={s}\n", .{ id, tags[0], tags[1], artifact.program.roots.len, artifact.program.inputs.len, artifact.parameter_slots.len, std.fmt.bytesToHex(try artifact.identity(), .lower) });
}
fn domainFixture(dir: std.fs.Dir, descriptor: G.Source.Descriptor, id: u32) !void {
    const M = core.fields.m31.M31;
    const trace_log: u32 = 4;
    const eval_log: u32 = 6;
    const rows: usize = 1 << eval_log;
    var artifact = try G.record(a, descriptor);
    defer artifact.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    const name = try std.fmt.allocPrint(a, "rv64_joined_domain_{}", .{id});
    defer a.free(name);
    if (id == 41) try C.emitGrouped(a, source.writer(a), &artifact.program, name, 32) else try C.emit(a, source.writer(a), &artifact.program, name);
    const source_file = try std.fmt.allocPrint(a, "case-{}-domain.cu", .{id});
    defer a.free(source_file);
    try dir.writeFile(.{ .sub_path = source_file, .data = source.items });
    var rng = std.Random.DefaultPrng.init(0x25dda9 + id);
    var row = try Oracle.Row.init(a, descriptor, rng.random(), false);
    defer row.deinit();
    const params = Oracle.metadata(rng.random(), 0);
    for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
    const widths = [3]usize{ row.fixed.len, row.main.len, row.inter.len + row.aux.len };
    var trees: [3][]M = undefined;
    var allocated: usize = 0;
    defer for (trees[0..allocated]) |tree| a.free(tree);
    for (&trees, widths) |*tree, width| {
        tree.* = try a.alloc(M, width * rows);
        allocated += 1;
        for (tree.*) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
    }
    const powers = try a.alloc(O, artifact.program.roots.len);
    defer a.free(powers);
    var power = O.one();
    const alpha = Oracle.random(rng.random());
    for (powers) |*v| {
        v.* = power;
        power = power.mul(alpha);
    }
    const denoms = try @import("stwo_riscv_frontend").rv64_air.geometry.denominatorInverses(a, trace_log, eval_log);
    defer a.free(denoms);
    var initial_values: [rows]O = undefined;
    var expected: [rows]O = undefined;
    for (0..rows) |r| {
        const previous = core.utils.offsetBitReversedCircleDomainIndex(r, trace_log, eval_log, -1);
        const next2 = core.utils.offsetBitReversedCircleDomainIndex(r, trace_log, eval_log, 2);
        for (row.fixed, 0..) |*v, c| v.* = O.fromBase(trees[0][c * rows + r]);
        for (row.main, row.previous, 0..) |*v, *p, c| {
            v.* = O.fromBase(trees[1][c * rows + r]);
            p.* = O.fromBase(trees[1][c * rows + previous]);
        }
        for (row.inter, row.shifted, 0..) |*v, *s, c| {
            v.* = O.fromBase(trees[2][c * rows + r]);
            s.* = O.fromBase(trees[2][c * rows + if (G.Authority.hasLocal(descriptor) and c < 8) next2 else previous]);
        }
        for (row.aux, 0..) |*v, c| v.* = O.fromBase(trees[2][(row.inter.len + c) * rows + r]);
        const residuals = try Oracle.nativeResiduals(a, descriptor, &params, row.fixed, row.main, row.previous, row.inter, row.shifted, row.aux);
        defer a.free(residuals);
        const inputs = try row.inputs(&artifact.program);
        defer a.free(inputs);
        const actual = try artifact.program.evaluate(a, inputs);
        defer a.free(actual);
        var folded = O.zero();
        for (residuals, actual, 0..) |v, ir_value, j| {
            if (!v.eql(ir_value)) return error.NativeJoinedDomainResidualMismatch;
            folded = folded.add(v.mul(powers[powers.len - 1 - j]));
        }
        initial_values[r] = Oracle.random(rng.random());
        expected[r] = initial_values[r].add(folded.mulM31(denoms[r >> trace_log]));
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564350, 1, trace_log, eval_log, @intCast(widths[0]), @intCast(widths[1]), @intCast(widths[2]), @intCast(artifact.program.inputs.len), @intCast(artifact.program.parameters.len), @intCast(powers.len), @intCast(artifact.program.nodes.len), id });
    for (trees) |tree| for (tree) |v| try IO.words(w, &.{v.v});
    for (artifact.program.inputs) |input| {
        const column_offset: u64 = @as(u64, input.column) * rows;
        try IO.words(w, &.{ @truncate(column_offset), @truncate(column_offset >> 32) });
    }
    try IO.felts(w, artifact.program.parameters);
    try IO.felts(w, powers);
    for (denoms) |v| try IO.words(w, &.{v.v});
    for (0..8) |coordinate| for (initial_values) |v| try IO.words(w, &.{v.toM31Array()[coordinate].v});
    for (0..8) |coordinate| for (expected) |v| try IO.words(w, &.{v.toM31Array()[coordinate].v});
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
    std.debug.print("DOMAIN id={} rows={} roots={}\n", .{ id, rows, powers.len });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--outer-control")) return @import("rv64/outer_proof_fixture.zig").run(a, .control, "", args[2]);
    if (args.len == 4 and std.mem.eql(u8, args[1], "--outer-proof")) return @import("rv64/outer_proof_fixture.zig").run(a, .gpu, args[2], args[3]);
    if (args.len == 4 and std.mem.eql(u8, args[1], "--outer-check")) return @import("rv64/outer_proof_fixture.zig").run(a, .verify, args[2], args[3]);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--outer-native-om31")) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        return @import("rv64/outer_aot.zig").write(a, directory);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--curve-witness-layout")) {
        try std.fs.cwd().makePath(args[2]);
        var d = try std.fs.cwd().openDir(args[2], .{});
        defer d.close();
        return @import("rv64/curve_witness_codegen.zig").writeExtended(a, d);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--secp-witness-layout")) {
        try std.fs.cwd().makePath(args[2]);
        var d = try std.fs.cwd().openDir(args[2], .{});
        defer d.close();
        return @import("rv64/curve_witness_codegen.zig").write(a, d);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--truth-interaction-fixtures")) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        return @import("rv64/truth_rational_fixtures.zig").write(a, directory);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--truth-interactions")) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        return @import("rv64/truth_interaction_codegen.zig").writeAot(a, directory);
    }
    const truth = args.len == 3 and std.mem.eql(u8, args[1], "--truth-domain");
    if (truth) return truthFixtures(args[2]);
    const domain = args.len == 3 and std.mem.eql(u8, args[1], "--domain");
    if (args.len != 2 and !domain) return error.ExpectedOutputDirectory;
    const directory = args[if (domain) @as(usize, 2) else 1];
    try std.fs.cwd().makePath(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    for (Oracle.descriptors(), 0..) |descriptor, id| {
        if (domain) try domainFixture(dir, descriptor, @intCast(id)) else try fixture(dir, descriptor, @intCast(id));
    }
    var declarations: std.ArrayList(u8) = .empty;
    defer declarations.deinit(a);
    const w = declarations.writer(a);
    try w.writeAll("#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n");
    if (domain) {
        for (0..Oracle.count) |id| try w.print("extern \"C\" __global__ void rv64_joined_domain_{}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n", .{id});
        try w.print("constexpr uint32_t composition_case_count={};\nstatic const void *kernels[]={{", .{Oracle.count});
        for (0..Oracle.count) |id| try w.print("{s}(void*)rv64_joined_domain_{}", .{ if (id == 0) "" else ",", id });
        try w.writeAll("};\nstatic const uint32_t composition_groups[]={");
        for (0..Oracle.count) |id| {
            var count: usize = 1;
            if (id == 41) {
                var grouped = try G.record(a, Oracle.descriptors()[id]);
                defer grouped.deinit();
                count = (grouped.program.roots.len + 31) / 32;
            }
            try w.print("{s}{}u", .{ if (id == 0) "" else ",", count });
        }
        try w.writeAll("};\n");
        return dir.writeFile(.{ .sub_path = "composition_launches.h", .data = declarations.items });
    }
    for (0..Oracle.count) |id| try w.print("extern \"C\" __global__ void rv64_joined_oods_{}(const uint32_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*);\n", .{id});
    try w.print("constexpr uint32_t joined_case_count={};\nstatic const void *joined_kernels[]={{", .{Oracle.count});
    for (0..Oracle.count) |id| try w.print("{s}(void*)rv64_joined_oods_{}", .{ if (id == 0) "" else ",", id });
    try w.writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "joined_launches.h", .data = declarations.items });
}

fn truthFixtures(directory: []const u8) !void {
    const T = @import("rv64/truth_domain_fixtures.zig");
    try std.fs.cwd().makePath(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    var header: std.ArrayList(u8) = .empty;
    defer header.deinit(a);
    const w = header.writer(a);
    try w.writeAll("#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n");
    for (0..T.count) |i| {
        try T.write(a, dir, @intCast(i));
        try w.print("extern \"C\" __global__ void rv64_truth_domain_{}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n", .{i});
    }
    try w.print("constexpr uint32_t composition_case_count={};\nstatic const void *kernels[]={{", .{T.count});
    for (0..T.count) |i| try w.print("{s}(void*)rv64_truth_domain_{}", .{ if (i == 0) "" else ",", i });
    try w.writeAll("};\nstatic const uint32_t composition_groups[]={");
    for (0..T.count) |i| {
        var item = try T.record(a, @intCast(i));
        defer item.artifact.deinit();
        try w.print("{s}{}u", .{ if (i == 0) "" else ",", (item.artifact.program.roots.len + 31) / 32 });
    }
    try w.writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "composition_launches.h", .data = header.items });
}
