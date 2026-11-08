//! Export one joined RV64 AIR to the settlement DAG and compare with native residuals.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("rv64/joined_codegen.zig");
const Oracle = @import("rv64/joined_fixture_support.zig");
const IO = @import("rv64/fixture_io.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = Oracle.O;
const a = std.heap.page_allocator;

pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputPath;
    const descriptor: G.Source.Descriptor = .{ .origin = .{ .core = .initial } };
    var artifact = try G.record(a, descriptor);
    defer artifact.deinit();
    const p = &artifact.program;
    try p.validate();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try w.writeAll("AIR1");
    try IO.words(w, &.{ @intCast(p.nodes.len), @intCast(p.roots.len), @intCast(p.constants.len), @intCast(p.inputs.len), @intCast(p.parameters.len) });
    for (p.nodes) |node| {
        try w.writeByte(@intFromEnum(node.op));
        try IO.words(w, &.{ node.lhs, node.rhs, node.value });
    }
    for (p.constants) |words| try IO.words(w, &words);
    try IO.words(w, p.roots);
    const code_end = bytes.items.len;

    var rng = std.Random.DefaultPrng.init(0x09f72546);
    var row = try Oracle.Row.init(a, descriptor, rng.random(), true);
    defer row.deinit();
    const params = Oracle.metadata(rng.random(), 0);
    const inputs = try row.inputs(p);
    defer a.free(inputs);
    const expected = try Oracle.nativeResiduals(a, descriptor, &params, row.fixed, row.main, row.previous, row.inter, row.shifted, row.aux);
    defer a.free(expected);
    for (p.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
    const actual = try p.evaluate(a, inputs);
    defer a.free(actual);
    if (actual.len != expected.len) return error.NativeResidualCountMismatch;
    for (actual, expected) |x, y| if (!x.eql(y)) return error.NativeResidualMismatch;
    const alpha = Oracle.random(rng.random());
    const point = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, Oracle.random(rng.random()));
    const mask_log = 11;
    const local_log = 7;
    const inverse = try A.geometry.denominatorInverseFor(O, point, mask_log, local_log);
    var acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator.init(alpha);
    for (expected) |value| acc.accumulate(value.mul(inverse));
    try IO.felts(w, inputs);
    try IO.felts(w, p.parameters);
    try IO.felts(w, &.{ alpha, point.x, point.y, inverse, acc.finalize() });
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try out.print(a,
        \\{{"schema":"stwo.rv64.settlement-air-fixture.v1","role":"initial","sourceIdentity":"{x}",
        \\ "maskLog":{},"localLog":{},"codeBytes":{},"wire":"0x{x}"}}
        \\
    , .{ &p.identity, mask_log, local_log, code_end, bytes.items });
    try std.fs.cwd().writeFile(.{ .sub_path = args[1], .data = out.items });
}
