//! Bounded, reproducible STWZPPC export using canonical frontend columns.
const std = @import("std");
const stwo = @import("stwo");
const preprocessed = stwo.frontends.cairo.preprocessed;

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2 and args.len != 3) return error.ExpectedOutputPathAndOptionalVariant;
    const variant = if (args.len == 3)
        std.meta.stringToEnum(preprocessed.trace.Variant, args[2]) orelse return error.InvalidPreprocessedVariant
    else
        preprocessed.trace.Variant.canonical_small;
    var pool: stwo.prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try stwo.prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var spec = try preprocessed.trace.Spec.init(a, variant);
    defer spec.deinit();
    var table = try preprocessed.pedersen_table.Table.init(a, if (variant == .canonical_small) .small else .standard);
    defer table.deinit();
    const canonic = stwo.core.poly.circle.canonic.CanonicCoset;
    const tree = try stwo.prover.poly.twiddles.precomputeM31(a, canonic.new(spec.variant.maxLogSize()).circleDomain().half_coset);
    defer a.free(tree.twiddles);
    defer a.free(tree.itwiddles);
    const borrowed = stwo.prover.poly.twiddles.TwiddleTree([]const stwo.core.fields.m31.M31).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    var buffer: [1024 * 1024]u8 = undefined;
    var output = try std.fs.cwd().atomicFile(args[1], .{ .write_buffer = &buffer });
    defer output.deinit();
    const writer = &output.file_writer.interface;
    try writer.writeAll("STWZPPC\x00");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u32, @intCast(spec.columns.len), .little);
    for (spec.columns, 0..) |column, i| {
        const evaluations = try spec.materializeColumnRangeWithPedersen(a, &table, i, i + 1);
        defer a.free(evaluations);
        const values = @constCast(evaluations[0].values);
        defer a.free(values);
        var batch = [_][]stwo.core.fields.m31.M31{values};
        try stwo.prover.poly.circle.poly.interpolateBuffersWithTwiddlesWithPool(&batch, canonic.new(column.log_size).circleDomain(), try borrowed.subtree(column.log_size - 1), &pool);
        const words: []u32 = @ptrCast(values);
        if (column.log_size > 16) preprocessed.coefficient_order.transposeSimdBlocks(words, column.log_size);
        try writer.writeInt(u16, @intCast(column.identity.len), .little);
        try writer.writeInt(u16, 0, .little);
        try writer.writeInt(u32, column.log_size, .little);
        try writer.writeInt(u64, @intCast(values.len), .little);
        try writer.writeAll(column.identity);
        try writer.writeAll(std.mem.sliceAsBytes(values));
    }
    try writer.flush();
    try output.finish();
}
