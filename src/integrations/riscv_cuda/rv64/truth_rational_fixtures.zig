//! Cold raw-projection numerical oracle. CPU IR evaluation checks native CUDA
//! lowering; policy-specific native fraction authority is tested separately.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("truth_interaction_codegen.zig");
const Meta = @import("truth_codegen.zig");
const Oracle = @import("joined_fixture_support.zig");
const IO = @import("fixture_io.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    for (7..15) |id| {
        var artifact = try T.record(a, @intCast(id));
        defer artifact.deinit();
        const sizes = try T.roleWidths(@intCast(id));
        const widths: [2]u32 = .{ @intCast(sizes[0]), @intCast(sizes[1]) };
        const log: u32 = 5;
        const n = 32;
        var rng = std.Random.DefaultPrng.init(0x617572 + id);
        var trees: [2][]M = undefined;
        var made: usize = 0;
        defer for (trees[0..made]) |tree| a.free(tree);
        for (&trees, widths) |*tree, width| {
            tree.* = try a.alloc(M, width * n);
            made += 1;
            for (tree.*) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
        }
        var parameters: [Meta.slots.count]O = undefined;
        for (&parameters) |*v| v.* = Oracle.random(rng.random());
        parameters[0] = O.fromBase(M.fromCanonical(3));
        parameters[1] = O.fromBase(M.fromCanonical(2));
        parameters[2] = O.one();
        for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = parameters[slot];
        const pairs = artifact.groups[0] + artifact.groups[1];
        const numerator = try a.alloc(u32, pairs * 8 * n);
        defer a.free(numerator);
        const denominator = try a.alloc(u32, numerator.len);
        defer a.free(denominator);
        const inputs = try a.alloc(O, artifact.program.inputs.len);
        defer a.free(inputs);
        for (0..n) |row| {
            for (inputs, artifact.program.inputs) |*v, input| {
                const at = core.utils.offsetBitReversedCircleDomainIndex(row, log, log, input.offset);
                v.* = O.fromBase(trees[input.tree][input.column * n + at]);
            }
            const values = try artifact.program.evaluate(a, inputs);
            defer a.free(values);
            for (0..pairs) |pair| {
                for (values[2 * pair].toM31Array(), 0..) |word, coordinate| numerator[(8 * pair + coordinate) * n + row] = word.v;
                for (values[2 * pair + 1].toM31Array(), 0..) |word, coordinate| denominator[(8 * pair + coordinate) * n + row] = word.v;
            }
        }
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(a);
        const w = output.writer(a);
        try IO.words(w, &.{ 0x52565452, 1, @intCast(id), log, widths[0], widths[1], @intCast(artifact.program.parameters.len), artifact.groups[0], artifact.groups[1] });
        for (trees) |tree| try w.writeAll(std.mem.sliceAsBytes(tree));
        try IO.felts(w, artifact.program.parameters);
        try IO.words(w, numerator);
        try IO.words(w, denominator);
        const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
        defer a.free(name);
        try dir.writeFile(.{ .sub_path = name, .data = output.items });
    }
}
