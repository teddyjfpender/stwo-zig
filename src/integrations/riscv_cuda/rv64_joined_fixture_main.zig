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
    try C.emit(a, source.writer(a), &artifact.program, domain_name);
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
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    for (Oracle.descriptors(), 0..) |descriptor, id| try fixture(dir, descriptor, @intCast(id));
    var declarations: std.ArrayList(u8) = .empty;
    defer declarations.deinit(a);
    const w = declarations.writer(a);
    try w.writeAll("#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n");
    for (0..Oracle.count) |id| try w.print("extern \"C\" __global__ void rv64_joined_oods_{}(const uint32_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*);\n", .{id});
    try w.print("constexpr uint32_t joined_case_count={};\nstatic const void *joined_kernels[]={{", .{Oracle.count});
    for (0..Oracle.count) |id| try w.print("{s}(void*)rv64_joined_oods_{}", .{ if (id == 0) "" else ",", id });
    try w.writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "joined_launches.h", .data = declarations.items });
}
