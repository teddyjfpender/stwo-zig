//! Shared bounded CPU committed-tree encoding. Typed stores supply independent
//! geometry/root identity and enforce whole-file and total-allocation budgets.
//! Structural decoding grants no proof acceptance or authentication authority.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
pub const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
pub const Tree = Scheme.CommittedTree;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const Hash = suite.Hasher.Hash;
pub fn requireName(name: []const u8) !void {
    if (name.len == 0 or name.len > 200 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or std.mem.indexOfAny(u8, name, "/\\\x00") != null) return error.InvalidNativeCheckpointName;
}
pub fn integer(comptime T: type, file: std.fs.File, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try file.writeAll(&bytes);
}
pub fn readExact(file: std.fs.File, bytes: []u8) !void {
    if (try file.readAll(bytes) != bytes.len) return error.TruncatedNativeCheckpoint;
}
pub fn readInteger(comptime T: type, file: std.fs.File) !T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    try readExact(file, &bytes);
    return std.mem.readInt(T, &bytes, .little);
}
pub fn writeValues(file: std.fs.File, values: []const M) !void {
    if (builtin.cpu.arch.endian() == .little) return file.writeAll(std.mem.sliceAsBytes(values));
    for (values) |value| try integer(u32, file, value.toU32());
}
pub fn readValues(file: std.fs.File, values: []M) !void {
    try readExact(file, std.mem.sliceAsBytes(values));
    var invalid: u32 = 0;
    for (values) |*value| {
        if (builtin.cpu.arch.endian() != .little) value.v = @byteSwap(value.v);
        invalid |= @intFromBool(value.v >= core.fields.m31.Modulus);
    }
    if (invalid != 0) return error.NonCanonicalNativeCheckpointM31;
}

pub fn writeTree(file: std.fs.File, tree: *const Tree) !void {
    try integer(u32, file, @intCast(tree.columns.len));
    try integer(u32, file, @intCast(tree.commitment.layers.len));
    for (tree.columns) |column| {
        try integer(u32, file, column.log_size);
        try writeValues(file, column.values);
    }
    for (tree.commitment.layers) |layer| {
        try integer(u64, file, layer.len);
        try file.writeAll(std.mem.sliceAsBytes(layer));
    }
}

/// Validate materialized storage and exact independently derived extended
/// column geometry. Returns actual retained Merkle bytes, including pruning.
pub fn inspectTree(tree: *const Tree, logs: []const u32, layer_count: usize, root: Hash) !u64 {
    if (tree.columns.len != logs.len or tree.coefficients != null or tree.compact_polynomials or tree.commitment.layers.len != layer_count) return error.UnsupportedNativeCheckpointStorage;
    for (tree.columns, logs) |column, log| {
        if (log > 30 or column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.ChangedNativeCheckpointGeometry;
    }
    var count: u64 = 0;
    var pruned = false;
    for (tree.commitment.layers, 0..) |layer, depth| {
        if (layer.len == 0) {
            if (depth == 0) return error.InvalidNativeCheckpointLayers;
            pruned = true;
        } else if (pruned or depth > 30 or layer.len != @as(usize, 1) << @intCast(depth)) return error.InvalidNativeCheckpointLayers;
        count = try std.math.add(u64, count, try std.math.mul(u64, layer.len, @sizeOf(Hash)));
    }
    if (!std.meta.eql(tree.commitment.root(), root)) return error.ChangedNativeCheckpointRoot;
    return count;
}

pub fn loadTree(a: std.mem.Allocator, file: std.fs.File, logs: []const u32, n_layers: usize, used: *u64, cap: u64) !Tree {
    if (n_layers == 0 or n_layers > 31 or used.* > cap) return error.ChangedNativeCheckpointGeometry;
    var maximum: u32 = 0;
    for (logs) |log| {
        if (log > 30) return error.ChangedNativeCheckpointGeometry;
        maximum = @max(maximum, log);
    }
    if (n_layers != maximum + 1) return error.ChangedNativeCheckpointGeometry;
    if (try readInteger(u32, file) != logs.len or try readInteger(u32, file) != n_layers) return error.ChangedNativeCheckpointGeometry;
    const columns = try a.alloc(Column, logs.len);
    var made: usize = 0;
    errdefer {
        for (columns[0..made]) |column| a.free(column.values);
        a.free(columns);
    }
    for (logs, columns) |log, *column| {
        if (try readInteger(u32, file) != log) return error.ChangedNativeCheckpointGeometry;
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        column.* = .{ .log_size = log, .values = values };
        made += 1;
        try readValues(file, values);
    }
    const layers = try a.alloc([]Hash, n_layers);
    var initialized: usize = 0;
    errdefer {
        for (layers[0..initialized]) |layer| a.free(layer);
        a.free(layers);
    }
    var pruned = false;
    for (layers, 0..) |*layer, depth| {
        const count = try readInteger(u64, file);
        if (count == 0) {
            if (depth == 0) return error.InvalidNativeCheckpointLayers;
            pruned = true;
        } else if (pruned or count != @as(u64, 1) << @intCast(depth)) return error.InvalidNativeCheckpointLayers;
        const next = try std.math.add(u64, used.*, try std.math.mul(u64, count, @sizeOf(Hash)));
        if (next > cap) return error.InvalidNativeCheckpointLength;
        layer.* = try a.alloc(Hash, @intCast(count));
        initialized += 1;
        try readExact(file, std.mem.sliceAsBytes(layer.*));
        used.* = next;
    }
    // All allocations use the explicit caller/budget allocator. Do not pass
    // these layers to fromLayers(), whose ordinary allocator may be mmap.
    return Tree.initPrecommitted(columns, null, null, null, .{ .layers = layers, .layer_allocator = a });
}
