//! Small numerical lowering oracle for an actual source-derived CPU role.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("native_gkr_codegen.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const IO = @import("fixture_io.zig");
pub fn write(a: std.mem.Allocator, artifact: *G.Artifact, path: []const u8) !void {
    const rows = 32;
    const log = 5;
    const shape = try G.Authority.shape(artifact.descriptor);
    var random = std.Random.DefaultPrng.init(0xB121093);
    var full: [G.P.count]O = undefined;
    for (&full, 0..) |*value, i| value.* = if (i < G.P.local) O.fromBase(M.fromCanonical(random.random().uintLessThan(u32, 65536))) else @import("joined_fixture_support.zig").random(random.random());
    var p = artifact.program;
    p.parameters = try a.alloc(O, artifact.parameter_slots.len);
    defer a.free(p.parameters);
    for (p.parameters, artifact.parameter_slots) |*value, slot| value.* = full[slot];
    var trees: [2][]M = undefined;
    var made: usize = 0;
    defer for (trees[0..made]) |tree| a.free(tree);
    for (&trees, [2]usize{ shape.fixed, shape.main }) |*tree, width| {
        tree.* = try a.alloc(M, width * rows);
        made += 1;
        for (tree.*) |*value| value.* = M.fromCanonical(random.random().uintLessThan(u32, 65536));
    }
    var facts: u32 = 0;
    for (artifact.terms) |terms| if (terms != 0) {
        facts += rows * (@as(u32, 1) << @intCast(std.math.log2_int_ceil(u32, terms)));
    };
    const numerators = try a.alloc(u32, facts);
    defer a.free(numerators);
    @memset(numerators, 0);
    const denominators = try a.alloc(O, facts);
    defer a.free(denominators);
    @memset(denominators, O.one());
    const inputs = try a.alloc(O, p.inputs.len);
    defer a.free(inputs);
    for (0..rows) |row| {
        for (inputs, p.inputs) |*value, input| {
            const at = core.utils.offsetBitReversedCircleDomainIndex(row, log, log, input.offset);
            value.* = O.fromBase(trees[input.tree][input.column * rows + at]);
        }
        const out = try p.evaluate(a, inputs);
        defer a.free(out);
        var first: usize = 0;
        var group_base: usize = 0;
        for (artifact.terms) |terms| {
            if (terms == 0) continue;
            const lanes = @as(usize, 1) << @intCast(std.math.log2_int_ceil(u32, terms));
            for (0..terms) |lane| {
                const n = out[2 * (first + lane)].toM31Array();
                for (n[1..]) |word| if (!word.isZero()) return error.NativeGkrNumeratorNotBase;
                numerators[group_base + lane * rows + row] = n[0].v;
                denominators[group_base + lane * rows + row] = out[2 * (first + lane) + 1];
            }
            first += terms;
            group_base += lanes * rows;
        }
    }
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(a);
    const w = output.writer(a);
    try IO.words(w, &.{ 0x4e475232, 1, log, @intCast(shape.fixed), @intCast(shape.main), @intCast(p.parameters.len) });
    try IO.words(w, &artifact.terms);
    for (trees) |tree| try w.writeAll(std.mem.sliceAsBytes(tree));
    try IO.felts(w, p.parameters);
    try IO.words(w, numerators);
    try IO.felts(w, denominators);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = output.items });
}
