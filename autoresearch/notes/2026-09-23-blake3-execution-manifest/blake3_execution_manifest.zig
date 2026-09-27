//! Caller-pinned base execution admission metadata. Authenticate the complete
//! envelope and policy before allocating decoded schedules or deriving a key.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("../air/statement.zig");
const plans = @import("blake3_commitment_plan.zig");
const plan_wire = @import("blake3_commitment_plan_codec.zig");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const MAGIC = "B3EXADM1";
pub const HEADER_BYTES: usize = 184;
pub const Source = struct { elf_sha256: [32]u8, input_sha256: [32]u8 };
pub const Limits = struct {
    max_bytes: usize = 96 * 1024 * 1024,
    statement: wire.Limits = .{},
    plan: plan_wire.Limits = .{},
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    statement: wire.OwnedBlake3Statement,
    plan: plans.Plan,
    plan_id: [32]u8,
    config: core.pcs.PcsConfig,
    source: Source,
    pub fn admission(self: *const Owned) !plans.Admission {
        return plans.Admission.init(&self.plan, self.plan_id);
    }
    pub fn deinit(self: *Owned) void {
        self.statement.deinit(self.allocator);
        self.plan.deinit();
        self.* = undefined;
    }
};
pub fn identity(raw: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(raw, &digest, .{});
    return digest;
}
pub fn encode(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, pin: plans.Admission, config: core.pcs.PcsConfig, source: Source, limits: Limits) ![]u8 {
    try shape.validateBlake3Execution();
    try pin.validatePublic(&shape.public_data);
    try protocol.validateConfig(config);
    var metadata: std.ArrayList(u8) = .empty;
    defer metadata.deinit(a);
    try wire.encodeBlake3Statement(metadata.writer(a), shape, limits.statement);
    const plan = try plan_wire.encode(a, pin.plan, pin.expected_id, limits.plan);
    defer a.free(plan);
    const count = try std.math.add(usize, HEADER_BYTES, try std.math.add(usize, metadata.items.len, plan.len));
    if (count > limits.max_bytes) return error.ExecutionManifestResourceLimit;
    const raw = try a.alloc(u8, count);
    errdefer a.free(raw);
    var stream = std.io.fixedBufferStream(raw);
    const writer = stream.writer();
    try writer.writeAll(MAGIC);
    try wire.writeInt(writer, u32, 1);
    try writer.writeAll(&source.elf_sha256);
    try writer.writeAll(&source.input_sha256);
    for ([_]u32{ config.pow_bits, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound, @intCast(config.fri_config.n_queries), config.fri_config.fold_step, @intFromBool(config.lifting_log_size != null), config.lifting_log_size orelse 0 }) |value| try wire.writeInt(writer, u32, value);
    try wire.writeInt(writer, u64, metadata.items.len);
    try wire.writeInt(writer, u64, plan.len);
    try writer.writeAll(&pin.expected_id);
    var context = core.channel.blake3.Channel{};
    try protocol.mix(&context, config, shape, pin);
    try writer.writeAll(&context.digestBytes());
    std.debug.assert(stream.pos == HEADER_BYTES);
    try writer.writeAll(metadata.items);
    try writer.writeAll(plan);
    return raw;
}
/// Expected identity, source digests and PCS policy must come from the caller,
/// not fields extracted from the received manifest or proof artifact.
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, source: Source, config: core.pcs.PcsConfig, limits: Limits) !Owned {
    if (raw.len > limits.max_bytes) return error.ExecutionManifestResourceLimit;
    if (raw.len < HEADER_BYTES) return error.TruncatedExecutionManifest;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidExecutionManifestVersion;
    if (!std.mem.eql(u8, &identity(raw), &expected)) return error.UntrustedExecutionManifest;
    try protocol.validateConfig(config);
    var cursor = wire.Cursor.init(raw[12..HEADER_BYTES]);
    var received_source: Source = undefined;
    try cursor.readExact(&received_source.elf_sha256);
    try cursor.readExact(&received_source.input_sha256);
    if (!std.meta.eql(received_source, source)) return error.ExecutionSourceMismatch;
    var received_config: core.pcs.PcsConfig = .{
        .pow_bits = try cursor.readInt(u32),
        .fri_config = .{
            .log_blowup_factor = try cursor.readInt(u32),
            .log_last_layer_degree_bound = try cursor.readInt(u32),
            .n_queries = try cursor.readInt(u32),
            .fold_step = try cursor.readInt(u32),
        },
    };
    const lifting_present = try cursor.readInt(u32);
    const lifting_log = try cursor.readInt(u32);
    received_config.lifting_log_size = switch (lifting_present) {
        0 => if (lifting_log == 0) null else return error.InvalidExecutionConfig,
        1 => lifting_log,
        else => return error.InvalidExecutionConfig,
    };
    if (!std.meta.eql(received_config, config)) return error.InvalidExecutionConfig;
    const statement_size = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.ExecutionManifestResourceLimit;
    const plan_size = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.ExecutionManifestResourceLimit;
    var plan_id: [32]u8 = undefined;
    try cursor.readExact(&plan_id);
    var context_id: [32]u8 = undefined;
    try cursor.readExact(&context_id);
    try cursor.requireDone();
    const plan_start = try std.math.add(usize, HEADER_BYTES, statement_size);
    if (try std.math.add(usize, plan_start, plan_size) != raw.len) return error.InvalidExecutionManifestLength;
    var decoded_statement = try wire.decodeBlake3Statement(a, raw[HEADER_BYTES..plan_start], limits.statement);
    errdefer decoded_statement.deinit(a);
    try decoded_statement.value.validateBlake3Execution();
    var plan = try plan_wire.decode(a, raw[plan_start..], plan_id, limits.plan);
    errdefer plan.deinit();
    const pin = try plans.Admission.init(&plan, plan_id);
    try pin.validatePublic(&decoded_statement.value.public_data);
    var context = core.channel.blake3.Channel{};
    try protocol.mix(&context, config, &decoded_statement.value, pin);
    if (!std.mem.eql(u8, &context_id, &context.digestBytes())) return error.ExecutionManifestAuthorityMismatch;
    return .{ .allocator = a, .statement = decoded_statement, .plan = plan, .plan_id = plan_id, .config = config, .source = source };
}
