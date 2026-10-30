//! Original caller fixed/main PCS transport. A cached tree is producer material;
//! family11 and fused proofs must still pass independent verification.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Store = @import("block_v6_cpu_scheme_store_v1.zig");
const Stage = @import("block_v5_caller_columns_stage_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Physical = @import("block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).PhysicalFirstRound;
pub const Limits = Store.Limits;
// Arithmetic caller AIRs include thousands of columns even at small row logs.
pub const DEFAULT_LIMITS: Limits = .{ .max_columns = 1 << 16 };
pub const Pin = Store.Pin;
pub const Staging = struct { name: []const u8, limits: Limits, pin_out: *Pin, statistics: ?*@import("block_v6_provider_commitment_staging_v1.zig").Statistics = null };
pub const Input = struct { name: []const u8, limits: Limits, pin: Pin, statistics: ?*@import("block_v6_provider_commitment_staging_v1.zig").Statistics = null };
fn identity(a: std.mem.Allocator, descriptor: *const Stage.Descriptor) ![32]u8 {
    try descriptor.require(a);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42364343, 1, descriptor.index, descriptor.total_steps, descriptor.frame.cycle_count, @intFromEnum(descriptor.frame.clock_frame) });
    channel.mixU64(descriptor.frame.global_first_cycle);
    channel.mixRoot(descriptor.key_id);
    return channel.digestBytes();
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, descriptor: *const Stage.Descriptor, first: *const Physical, limits: Limits) !Pin {
    if (!first.owns_scheme or !std.meta.eql(first.roots, descriptor.roots) or !std.meta.eql(first.key_id, descriptor.key_id) or first.total_steps != descriptor.total_steps or !std.meta.eql(first.config, descriptor.config) or !std.meta.eql(first.witness.statement, descriptor.statement)) return error.InvalidCallerCheckpointScope;
    const fixed = try Protocol.columnLogs(a, &descriptor.statement, .fixed);
    defer a.free(fixed);
    const main = try Protocol.columnLogs(a, &descriptor.statement, .main);
    defer a.free(main);
    return Store.write(a, dir, name, .{ .identity = try identity(a, descriptor), .config = descriptor.config, .roots = &descriptor.roots, .logs = &.{ fixed, main } }, &first.scheme, limits);
}
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, descriptor: *const Stage.Descriptor, witness: *const Witness, pin: Pin, limits: Limits) !Physical {
    if (witness.total_steps != descriptor.total_steps or !std.meta.eql(witness.statement, descriptor.statement)) return error.InvalidCallerCheckpointScope;
    const fixed = try Protocol.columnLogs(a, &descriptor.statement, .fixed);
    defer a.free(fixed);
    const main = try Protocol.columnLogs(a, &descriptor.statement, .main);
    defer a.free(main);
    return .{ .scheme = try Store.load(a, dir, name, .{ .identity = try identity(a, descriptor), .config = descriptor.config, .roots = &descriptor.roots, .logs = &.{ fixed, main } }, pin, limits), .roots = descriptor.roots, .key_id = descriptor.key_id, .total_steps = descriptor.total_steps, .config = descriptor.config, .witness = witness };
}
