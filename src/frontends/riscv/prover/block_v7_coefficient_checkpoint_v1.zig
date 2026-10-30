//! Explicit native-coefficient checkpoint payload. The original Merkle layers
//! are retained; bytes remain untrusted until fresh ordinary proof verification.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const IO = @import("block_v6_cpu_checkpoint_codec_v1.zig");
const M = core.fields.m31.M31;
const Hash = core.proof_suites.Blake3.Hasher.Hash;
const Poly = E.poly.circle.CircleCoefficients;
const Column = E.pcs.ColumnEvaluation;
pub fn inspect(tree: *const IO.Tree, width: usize, raw_log: u32, extended: u32, root: Hash) !u64 {
    if (raw_log < 1 or extended < raw_log or extended > 30 or tree.columns.len != width or !tree.compact_polynomials or tree.commitment.layers.len != extended + 1) return error.InvalidCoefficientCheckpoint;
    const coefficients = tree.coefficients orelse return error.InvalidCoefficientCheckpoint;
    if (coefficients.len != width) return error.InvalidCoefficientCheckpoint;
    for (tree.columns, coefficients) |column, coefficient| {
        try column.validateRetained();
        if (column.log_size != extended or column.values.len != 0 or coefficient.logSize() != raw_log) return error.InvalidCoefficientCheckpoint;
        if (column.coefficient_values.?.ptr != coefficient.coefficients().ptr) return error.InvalidCoefficientCheckpoint;
    }
    var bytes: u64 = 0;
    var pruned = false;
    for (tree.commitment.layers, 0..) |layer, depth| {
        if (layer.len == 0) {
            if (depth == 0) return error.InvalidNativeCheckpointLayers;
            pruned = true;
        } else if (pruned or layer.len != @as(usize, 1) << @intCast(depth)) return error.InvalidNativeCheckpointLayers;
        bytes = try std.math.add(u64, bytes, try std.math.mul(u64, layer.len, @sizeOf(Hash)));
    }
    if (!std.meta.eql(tree.root(), root)) return error.ChangedNativeCheckpointRoot;
    return bytes;
}
pub fn write(file: std.fs.File, tree: *const IO.Tree) !void {
    try IO.integer(u32, file, @intCast(tree.columns.len));
    try IO.integer(u32, file, @intCast(tree.commitment.layers.len));
    for (tree.columns, tree.coefficients.?) |column, coefficient| {
        try IO.integer(u32, file, column.log_size);
        try IO.writeValues(file, coefficient.coefficients());
    }
    for (tree.commitment.layers) |layer| {
        try IO.integer(u64, file, layer.len);
        try file.writeAll(std.mem.sliceAsBytes(layer));
    }
}
pub fn load(a: std.mem.Allocator, file: std.fs.File, width: usize, raw_log: u32, extended: u32, used: *u64, cap: u64) !IO.Tree {
    if (raw_log < 1 or raw_log > extended or extended > 30 or width == 0 or width > 65536 or used.* > cap) return error.InvalidCoefficientCheckpoint;
    const n_layers = extended + 1;
    if (try IO.readInteger(u32, file) != width or try IO.readInteger(u32, file) != n_layers) return error.ChangedNativeCheckpointGeometry;
    const columns = try a.alloc(Column, width);
    errdefer a.free(columns);
    const coefficients = try a.alloc(Poly, width);
    var made: usize = 0;
    errdefer {
        for (coefficients[0..made]) |*p| p.deinit(a);
        a.free(coefficients);
    }
    for (columns, coefficients) |*column, *coefficient| {
        if (try IO.readInteger(u32, file) != extended) return error.ChangedNativeCheckpointGeometry;
        const values = try a.alloc(M, @as(usize, 1) << @intCast(raw_log));
        coefficient.* = Poly.initOwned(values) catch |err| {
            a.free(values);
            return err;
        };
        made += 1;
        try IO.readValues(file, values);
        column.* = .{ .log_size = extended, .values = &.{}, .coefficient_values = values };
    }
    const layers = try a.alloc([]Hash, n_layers);
    var initialized: usize = 0;
    errdefer {
        for (layers[0..initialized]) |layer| a.free(layer);
        a.free(layers);
    }
    var pruned = false;
    for (layers, 0..) |*layer, depth| {
        const count = try IO.readInteger(u64, file);
        if (count == 0) {
            if (depth == 0) return error.InvalidNativeCheckpointLayers;
            pruned = true;
        } else if (pruned or count != @as(u64, 1) << @intCast(depth)) return error.InvalidNativeCheckpointLayers;
        const next = try std.math.add(u64, used.*, try std.math.mul(u64, count, @sizeOf(Hash)));
        if (next > cap) return error.InvalidNativeCheckpointLength;
        layer.* = try a.alloc(Hash, @intCast(count));
        initialized += 1;
        try IO.readExact(file, std.mem.sliceAsBytes(layer.*));
        used.* = next;
    }
    var result = IO.Tree.initPrecommitted(columns, coefficients, null, null, .{ .layers = layers, .layer_allocator = a });
    result.compact_polynomials = true;
    return result;
}
