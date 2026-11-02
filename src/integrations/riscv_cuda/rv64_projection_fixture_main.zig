//! Cold scalar-authority fixtures for source projection and real OM draw flow.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("rv64/projection_codegen.zig");
const Fixtures = @import("rv64/projection_fixture_support.zig");
const IO = @import("rv64/fixture_io.zig");
const Source = G.Source;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.heap.page_allocator;
fn checkpoint(w: anytype, ch: anytype) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, ch.inner.digest[i * 4 ..][0..4], .little)});
    try IO.words(w, &.{ch.inner.n_draws});
}
fn fixture(dir: std.fs.Dir, descriptor: Source.Descriptor, id: usize) !void {
    var artifact = try G.record(a, descriptor);
    defer artifact.deinit();
    const shape = try descriptor.shape();
    const log: u32 = 5;
    const rows: usize = 1 << log;
    const facts = rows * artifact.lanes;
    var rng = std.Random.DefaultPrng.init(172813 + id);
    const fixed = try a.alloc(M, rows * shape.fixed);
    defer a.free(fixed);
    const main_values = try a.alloc(M, rows * shape.main);
    defer a.free(main_values);
    var public: [Source.Public.count]M = undefined;
    for (fixed) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
    for (main_values) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
    for (&public) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    ch.mixU32s(&.{ 0x50524f4a, @intCast(id) });
    const seed = ch;
    const challenges = Source.Challenges.For(O).drawV3(&ch);
    const ns = try a.alloc(M, facts);
    defer a.free(ns);
    @memset(ns, M.zero());
    const ds = try a.alloc(O, facts);
    defer a.free(ds);
    @memset(ds, O.one());
    const f = try a.alloc(M, shape.fixed);
    defer a.free(f);
    const m = try a.alloc(M, shape.main);
    defer a.free(m);
    const pm = try a.alloc(M, shape.main);
    defer a.free(pm);
    for (0..rows) |row| {
        for (f, 0..) |*v, c| v.* = fixed[c * rows + row];
        const previous = core.utils.offsetBitReversedCircleDomainIndex(row, log, log, -1);
        for (m, pm, 0..) |*v, *p, c| {
            v.* = main_values[c * rows + row];
            p.* = if (descriptor.previous(c)) main_values[c * rows + previous] else M.zero();
        }
        var sink = Source.RowSink{ .challenges = &challenges, .numerator = ns[row * artifact.lanes ..][0..artifact.terms], .denominator = ds[row * artifact.lanes ..][0..artifact.terms] };
        var base = Source.BaseSink{ .row = &sink };
        try descriptor.emit(M, f, m, pm, &public, &base);
        if (sink.invalid or sink.count != artifact.terms) return error.NativeProjectionShape;
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x5256504a, 1, @intCast(id), log, @intCast(shape.fixed), @intCast(shape.main), artifact.terms, artifact.lanes, @intCast(artifact.program.inputs.len), @intCast(artifact.source_slots.len) });
    try checkpoint(w, seed);
    try checkpoint(w, ch);
    for (fixed) |v| try IO.words(w, &.{v.v});
    for (main_values) |v| try IO.words(w, &.{v.v});
    for (public) |v| try IO.words(w, &.{v.v});
    for (artifact.program.inputs) |input| {
        const offset: u64 = if (input.tree == 2) 0 else @as(u64, input.column) * rows;
        var out: [8]u8 = undefined;
        std.mem.writeInt(u64, &out, offset, .little);
        try w.writeAll(&out);
    }
    try IO.words(w, artifact.source_slots);
    for (ns) |v| try IO.words(w, &.{v.v});
    try IO.soa(w, ds);
    const bin = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(bin);
    try dir.writeFile(.{ .sub_path = bin, .data = bytes.items });
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    const name = try std.fmt.allocPrint(a, "rv64_projection_case_{}", .{id});
    defer a.free(name);
    try G.emit(a, source.writer(a), &artifact, name);
    try source.writer(a).writeAll("#include \"projection_fixture.h\"\n");
    try source.writer(a).print("extern \"C\" int launch_{}(void *stream,const Rv64ProjectionFixture *p) {{ {s}<<<(p->rows+127)/128,128,0,reinterpret_cast<cudaStream_t>(stream)>>>(p->fixed,p->main,p->public_values,p->offsets,p->parameters,p->n,p->d,p->log,p->first,p->rows,p->status);return int(cudaPeekAtLastError()); }}\n", .{ id, name });
    const cu = try std.fmt.allocPrint(a, "case-{}.cu", .{id});
    defer a.free(cu);
    try dir.writeFile(.{ .sub_path = cu, .data = source.items });
    std.debug.print("SOURCE_PROJECTION case={} origin={any} terms={} lanes={} nodes={} params={} PASS\n", .{ id, descriptor.origin, artifact.terms, artifact.lanes, artifact.program.nodes.len, artifact.source_slots.len });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    var declarations: std.ArrayList(u8) = .empty;
    defer declarations.deinit(a);
    try declarations.writer(a).writeAll("#pragma once\n#include \"projection_fixture.h\"\n");
    for (Fixtures.descriptors(), 0..) |d, id| {
        try fixture(dir, d, id);
        try declarations.writer(a).print("extern \"C\" int launch_{}(void *,const Rv64ProjectionFixture *);\n", .{id});
    }
    try declarations.writer(a).print("constexpr uint32_t projection_case_count={};\nstatic const Rv64ProjectionLaunch projection_launches[]={{{s}", .{ Fixtures.count, "" });
    for (0..Fixtures.count) |id| try declarations.writer(a).print("{s}launch_{}", .{ if (id == 0) "" else ",", id });
    try declarations.writer(a).writeAll("};\n");
    try dir.writeFile(.{ .sub_path = "launches.h", .data = declarations.items });
}
