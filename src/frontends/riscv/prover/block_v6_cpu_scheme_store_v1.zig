//! Bounded first-round CPU PCS transport shared by typed provider adapters.
//! Admission must be derived independently by each protocol; a checkpoint is
//! untrusted prover material and never replaces fresh verification.
const std = @import("std");
const core = @import("stwo_core");
const codec = @import("block_v6_cpu_checkpoint_codec_v1.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Hash = [32]u8;
const Coefficients = @import("stwo_prover_engine").poly.circle.CircleCoefficients;
const M = core.fields.m31.M31;
pub const Limits = @import("block_v6_native_commitment_store_v1.zig").Limits;
pub const Admission = struct {
    identity: Hash,
    config: core.pcs.PcsConfig,
    roots: []const Hash,
    /// Exact raw logs derived from the protocol/plan, before FRI blowup.
    logs: []const []const u32,
    retain_coefficients: bool = false,
};
pub const Pin = struct { bytes: u64, column_bytes: u64, merkle_bytes: u64, coefficient_bytes: u64 = 0, loaded_bytes: usize };
const Shape = struct {
    a: std.mem.Allocator,
    logs: [][]u32,
    layers: []usize,
    columns: u64,
    coefficient_bytes: u64,
    descriptors: u64,
    framing: u64,
    maximum_merkle: u64,
    header: [48]u8,
    fn init(a: std.mem.Allocator, admission: Admission, limits: Limits) !Shape {
        try @import("blake3_execution_protocol.zig").validateConfig(admission.config);
        if (admission.config.lifting_log_size != null) return error.UnsupportedProviderCheckpointLifting;
        if (admission.logs.len == 0 or admission.logs.len > 8 or admission.logs.len != admission.roots.len) return error.InvalidProviderCheckpointScope;
        const logs = try a.alloc([]u32, admission.logs.len);
        errdefer a.free(logs);
        const layers = try a.alloc(usize, logs.len);
        errdefer a.free(layers);
        var result = Shape{ .a = a, .logs = logs, .layers = layers, .columns = 0, .coefficient_bytes = 0, .descriptors = logs.len * @sizeOf(codec.Tree), .framing = 48 + logs.len * 8, .maximum_merkle = 0, .header = @splat(0) };
        var made: usize = 0;
        errdefer for (logs[0..made]) |values| a.free(values);
        var total_columns: usize = 0;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42365043, 2, @intCast(logs.len), @intFromBool(admission.retain_coefficients) });
        channel.mixRoot(admission.identity);
        admission.config.mixInto(&channel);
        for (admission.logs, logs, layers, admission.roots) |raw, *out, *layer_count, root| {
            total_columns = try std.math.add(usize, total_columns, raw.len);
            if (total_columns > limits.max_columns or raw.len > std.math.maxInt(u32)) return error.ProviderCheckpointResourceLimit;
            out.* = try a.alloc(u32, raw.len);
            made += 1;
            channel.mixRoot(root);
            channel.mixU32s(&.{@intCast(raw.len)});
            var maximum: u32 = 0;
            for (raw, out.*) |log, *extended| {
                extended.* = try std.math.add(u32, log, admission.config.fri_config.log_blowup_factor);
                if (extended.* > 30 or extended.* > limits.max_log_size) return error.ProviderCheckpointResourceLimit;
                maximum = @max(maximum, extended.*);
                result.columns = try std.math.add(u64, result.columns, @as(u64, 4) << @intCast(extended.*));
                if (admission.retain_coefficients) result.coefficient_bytes = try std.math.add(u64, result.coefficient_bytes, @as(u64, 4) << @intCast(log));
                channel.mixU32s(&.{log});
            }
            layer_count.* = maximum + 1;
            result.descriptors = try std.math.add(u64, result.descriptors, raw.len * @sizeOf(Column) + layer_count.* * @sizeOf([]Hash));
            if (admission.retain_coefficients) result.descriptors = try std.math.add(u64, result.descriptors, raw.len * @sizeOf(Coefficients));
            result.framing = try std.math.add(u64, result.framing, raw.len * 4 + layer_count.* * 8);
            result.maximum_merkle = try std.math.add(u64, result.maximum_merkle, ((@as(u64, 1) << @intCast(maximum + 1)) - 1) * @sizeOf(Hash));
        }
        @memcpy(result.header[0..8], "B6PRV002");
        std.mem.writeInt(u32, result.header[8..12], 2, .little);
        std.mem.writeInt(u32, result.header[12..16], @intCast(logs.len), .little);
        @memcpy(result.header[16..48], &channel.digestBytes());
        _ = try result.pin(logs.len * @sizeOf(Hash), limits);
        return result;
    }
    fn deinit(self: *Shape) void {
        for (self.logs) |logs| self.a.free(logs);
        self.a.free(self.logs);
        self.a.free(self.layers);
    }
    fn pin(self: Shape, merkle: u64, limits: Limits) !Pin {
        if (merkle < self.logs.len * @sizeOf(Hash) or merkle > self.maximum_merkle) return error.InvalidProviderCheckpointLayers;
        const payload = try std.math.add(u64, try std.math.add(u64, self.columns, merkle), self.coefficient_bytes);
        const bytes = try std.math.add(u64, self.framing, payload);
        const loaded = try std.math.add(u64, self.descriptors, payload);
        if (bytes > limits.max_file_bytes or loaded > limits.max_loaded_bytes) return error.ProviderCheckpointResourceLimit;
        return .{ .bytes = bytes, .column_bytes = self.columns, .merkle_bytes = merkle, .coefficient_bytes = self.coefficient_bytes, .loaded_bytes = @intCast(loaded) };
    }
};
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admission: Admission, scheme: *const codec.Scheme, limits: Limits) !Pin {
    try codec.requireName(name);
    var shape = try Shape.init(a, admission, limits);
    defer shape.deinit();
    if (scheme.pending_commit != null or scheme.trees.items.len != shape.logs.len or !std.meta.eql(scheme.config, admission.config)) return error.InvalidProviderCheckpointScope;
    var merkle: u64 = 0;
    for (scheme.trees.items, shape.logs, shape.layers, admission.roots, admission.logs) |*tree, logs, layers, root, raw_logs| {
        // Borrow-only view lets the existing tree codec validate materialized
        // LDEs while coefficients receive independent exact-degree checks.
        var view = tree.*;
        if (admission.retain_coefficients) {
            const coefficients = tree.coefficients orelse return error.MissingProviderCheckpointCoefficients;
            if (coefficients.len != raw_logs.len) return error.ChangedProviderCheckpointCoefficients;
            for (coefficients, raw_logs) |polynomial, log| if (polynomial.logSize() != log or polynomial.coefficients().len != @as(usize, 1) << @intCast(log)) return error.ChangedProviderCheckpointCoefficients;
            view.coefficients = null;
        }
        merkle = try std.math.add(u64, merkle, try codec.inspectTree(&view, logs, layers, root));
    }
    const pin = try shape.pin(merkle, limits);
    const temporary = try std.fmt.allocPrint(a, ".{s}.partial", .{name});
    defer a.free(temporary);
    const file = try dir.createFile(temporary, .{ .exclusive = true });
    defer file.close();
    var published = false;
    defer if (!published) dir.deleteFile(temporary) catch {};
    try file.writeAll(&shape.header);
    for (scheme.trees.items) |*tree| {
        try codec.writeTree(file, tree);
        if (admission.retain_coefficients) for (tree.coefficients.?) |polynomial| try codec.writeValues(file, polynomial.coefficients());
    }
    if ((try file.stat()).size != pin.bytes) return error.InvalidProviderCheckpointLength;
    try file.sync();
    if (dir.openFile(name, .{})) |existing| {
        existing.close();
        return error.ProviderCheckpointAlreadyExists;
    } else |err| if (err != error.FileNotFound) return err;
    try dir.rename(temporary, name);
    published = true;
    return pin;
}
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admission: Admission, pin: Pin, limits: Limits) !codec.Scheme {
    try codec.requireName(name);
    var shape = try Shape.init(a, admission, limits);
    defer shape.deinit();
    if (!std.meta.eql(pin, try shape.pin(pin.merkle_bytes, limits))) return error.InvalidProviderCheckpointLength;
    const file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.bytes) return error.InvalidProviderCheckpointLength;
    var header: [48]u8 = undefined;
    try codec.readExact(file, &header);
    if (!std.mem.eql(u8, &header, &shape.header)) return error.InvalidProviderCheckpointScope;
    var scheme = try codec.Scheme.init(a, admission.config);
    errdefer scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.never);
    try scheme.trees.ensureTotalCapacityPrecise(a, shape.logs.len);
    var used: u64 = 0;
    for (shape.logs, shape.layers, admission.roots, admission.logs) |logs, layers, root, raw_logs| {
        var tree = try codec.loadTree(a, file, logs, layers, &used, pin.merkle_bytes);
        errdefer tree.deinit(a);
        if (!std.meta.eql(tree.commitment.root(), root)) return error.InvalidProviderCheckpointRoot;
        if (admission.retain_coefficients) tree.coefficients = try loadCoefficients(a, file, raw_logs);
        scheme.trees.appendAssumeCapacity(tree);
    }
    if (used != pin.merkle_bytes) return error.InvalidProviderCheckpointLength;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.InvalidProviderCheckpointLength;
    return scheme;
}

fn loadCoefficients(a: std.mem.Allocator, file: std.fs.File, logs: []const u32) ![]Coefficients {
    const polynomials = try a.alloc(Coefficients, logs.len);
    var initialized: usize = 0;
    errdefer {
        for (polynomials[0..initialized]) |*polynomial| polynomial.deinit(a);
        a.free(polynomials);
    }
    for (logs, polynomials) |log, *polynomial| {
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        polynomial.* = Coefficients.initOwned(values) catch |err| {
            a.free(values);
            return err;
        };
        initialized += 1;
        try codec.readValues(file, values);
    }
    return polynomials;
}
