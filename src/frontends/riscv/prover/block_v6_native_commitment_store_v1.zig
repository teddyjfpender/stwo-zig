//! Bounded CPU PCS checkpoints. No FFT or Merkle rebuild on restore.
//! Cache bytes are untrusted prover material, never a verification receipt.
//! The original independent roots and ordinary fresh proof verifier remain
//! authoritative; geometry checks are not a substitute for proof verification.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Root = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Physical = Root.ForBackend(Cpu).PhysicalFirstRound;
const Scheme = @FieldType(Physical, "scheme");
const Tree = Scheme.CommittedTree;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Hash = core.proof_suites.Blake3.Hasher.Hash;
const codec = @import("block_v6_cpu_checkpoint_codec_v1.zig");
const HEADER_BYTES = 160;
const MAGIC = "B6PCS001";
pub const Limits = struct {
    max_columns: usize = 2048,
    max_log_size: u32 = 26,
    max_file_bytes: u64 = 64 << 30,
    max_loaded_bytes: usize = 32 << 30,
};
pub const Pin = struct {
    bytes: u64,
    column_bytes: u64,
    merkle_bytes: u64,
    /// Restored column/layer storage plus exact outer descriptor allocation;
    /// subsequent prover scratch and raw native owner are outside this count.
    loaded_bytes: usize,
};

const Geometry = struct {
    a: std.mem.Allocator,
    logs: [2][]u32,
    layers: [2]usize,
    column_bytes: u64,
    descriptors: u64,
    framing: u64,
    max_merkle_bytes: u64,
    fn init(a: std.mem.Allocator, proposal: *const Root.Proposal, limits: Limits) !Geometry {
        try proposal.template.admit(&proposal.shape, proposal.template_id);
        if (!std.meta.eql(Public.publicDigest(&proposal.shape.public_data), proposal.public_digest) or
            proposal.first_cycle == 0 or proposal.shape.total_steps == 0 or proposal.last_cycle != try std.math.add(u64, proposal.first_cycle, proposal.shape.total_steps - 1) or
            !std.meta.eql(proposal.roots[0], proposal.template.fixed_root)) return error.ChangedNativeCheckpointScope;
        var result = Geometry{ .a = a, .logs = undefined, .layers = undefined, .column_bytes = 0, .descriptors = 2 * @sizeOf(Tree), .framing = HEADER_BYTES + 16, .max_merkle_bytes = 0 };
        var initialized: usize = 0;
        errdefer for (result.logs[0..initialized]) |logs| a.free(logs);
        inline for (.{ Template.ColumnTree.fixed, .main }, 0..) |kind, tree| {
            const logs = try Template.columnLogs(a, &proposal.shape, proposal.template.external_retirements, kind);
            result.logs[tree] = logs;
            initialized += 1;
            if (logs.len > limits.max_columns or logs.len > std.math.maxInt(u32)) return error.NativeCheckpointResourceLimit;
            var maximum: u32 = 0;
            for (logs) |*log| {
                log.* = try std.math.add(u32, log.*, proposal.template.config.fri_config.log_blowup_factor);
                if (log.* > limits.max_log_size or log.* > 30) return error.NativeCheckpointResourceLimit;
                maximum = @max(maximum, log.*);
                result.column_bytes = try std.math.add(u64, result.column_bytes, @as(u64, 4) << @intCast(log.*));
            }
            result.layers[tree] = maximum + 1;
            result.descriptors = try std.math.add(u64, result.descriptors, logs.len * @sizeOf(Column) + result.layers[tree] * @sizeOf([]Hash));
            result.framing = try std.math.add(u64, result.framing, logs.len * 4 + result.layers[tree] * 8);
            result.max_merkle_bytes = try std.math.add(u64, result.max_merkle_bytes, ((@as(u64, 1) << @intCast(maximum + 1)) - 1) * @sizeOf(Hash));
        }
        _ = try result.pin(2 * @sizeOf(Hash), limits);
        return result;
    }
    fn deinit(self: *Geometry) void {
        for (self.logs) |logs| self.a.free(logs);
    }
    fn pin(self: Geometry, merkle_bytes: u64, limits: Limits) !Pin {
        if (merkle_bytes < 2 * @sizeOf(Hash) or merkle_bytes > self.max_merkle_bytes) return error.InvalidNativeCheckpointLayers;
        const payload = try std.math.add(u64, self.column_bytes, merkle_bytes);
        const bytes = try std.math.add(u64, self.framing, payload);
        const loaded = try std.math.add(u64, self.descriptors, payload);
        if (bytes > limits.max_file_bytes or loaded > limits.max_loaded_bytes) return error.NativeCheckpointResourceLimit;
        return .{ .bytes = bytes, .column_bytes = self.column_bytes, .merkle_bytes = merkle_bytes, .loaded_bytes = @intCast(loaded) };
    }
};

fn header(proposal: *const Root.Proposal) [HEADER_BYTES]u8 {
    var bytes: [HEADER_BYTES]u8 = @splat(0);
    @memcpy(bytes[0..8], MAGIC);
    std.mem.writeInt(u32, bytes[8..12], 1, .little);
    std.mem.writeInt(u32, bytes[12..16], proposal.index, .little);
    std.mem.writeInt(u64, bytes[16..24], proposal.first_cycle, .little);
    std.mem.writeInt(u32, bytes[24..28], proposal.shape.total_steps, .little);
    @memcpy(bytes[32..64], &proposal.template_id);
    @memcpy(bytes[64..96], &proposal.public_digest);
    @memcpy(bytes[96..128], &proposal.roots[0]);
    @memcpy(bytes[128..160], &proposal.roots[1]);
    return bytes;
}
/// Bounds and validates the complete source before opening a file. Ownership
/// stays with the caller; no wide allocation is duplicated for serialization.
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, first: *const Physical, limits: Limits) !Pin {
    try codec.requireName(name);
    var shape = try Geometry.init(a, proposal, limits);
    defer shape.deinit();
    if (!std.meta.eql(first.roots, proposal.roots) or !std.meta.eql(first.template, proposal.template) or
        !std.meta.eql(first.template_id, proposal.template_id) or !std.meta.eql(first.scheme.config, proposal.template.config) or
        first.scheme.trees.items.len != 2 or first.scheme.pending_commit != null) return error.ChangedNativeCheckpointScope;
    var merkle_bytes: u64 = 0;
    for (first.scheme.trees.items, 0..) |*tree, i| {
        merkle_bytes = try std.math.add(u64, merkle_bytes, try codec.inspectTree(tree, shape.logs[i], shape.layers[i], proposal.roots[i]));
    }
    const pin = try shape.pin(merkle_bytes, limits);
    const temporary = try std.fmt.allocPrint(a, ".{s}.partial", .{name});
    defer a.free(temporary);
    const file = try dir.createFile(temporary, .{ .exclusive = true });
    defer file.close();
    var published = false;
    defer if (!published) dir.deleteFile(temporary) catch {};
    try file.writeAll(&header(proposal));
    for (first.scheme.trees.items) |*tree| try codec.writeTree(file, tree);
    if ((try file.stat()).size != pin.bytes) return error.InvalidNativeCheckpointLength;
    try file.sync();
    if (dir.openFile(name, .{})) |existing| {
        existing.close();
        return error.NativeCheckpointAlreadyExists;
    } else |err| if (err != error.FileNotFound) return err;
    try dir.rename(temporary, name);
    published = true;
    return pin;
}

/// Restores bounded proving state only. Caller must use ordinary verification
/// before granting any receipt: canonical but changed cache cells are not
/// authenticated by this structural loader and cannot authorize a statement.
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits) !Physical {
    try codec.requireName(name);
    var shape = try Geometry.init(a, proposal, limits);
    defer shape.deinit();
    if (!std.meta.eql(pin, try shape.pin(pin.merkle_bytes, limits))) return error.InvalidNativeCheckpointLength;
    const file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.bytes) return error.InvalidNativeCheckpointLength;
    var actual: [HEADER_BYTES]u8 = undefined;
    try codec.readExact(file, &actual);
    if (!std.mem.eql(u8, &actual, &header(proposal))) return error.ChangedNativeCheckpointScope;
    var scheme = try Scheme.init(a, proposal.template.config);
    errdefer scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.never);
    try scheme.trees.ensureTotalCapacityPrecise(a, 2);
    var merkle_bytes: u64 = 0;
    for (shape.logs, 0..) |logs, i| {
        var tree = try codec.loadTree(a, file, logs, shape.layers[i], &merkle_bytes, pin.merkle_bytes);
        errdefer tree.deinit(a);
        if (!std.meta.eql(tree.commitment.root(), proposal.roots[i])) return error.ChangedNativeCheckpointRoot;
        scheme.trees.appendAssumeCapacity(tree);
    }
    if (merkle_bytes != pin.merkle_bytes) return error.InvalidNativeCheckpointLength;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.InvalidNativeCheckpointLength;
    return .{ .scheme = scheme, .roots = proposal.roots, .template = proposal.template, .template_id = proposal.template_id };
}
