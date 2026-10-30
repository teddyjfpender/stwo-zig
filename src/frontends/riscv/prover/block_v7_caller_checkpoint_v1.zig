//! V7 caller handoff: original arithmetic and access witnesses are constructed
//! and committed once, then restored under the new epoch. No legacy seal or
//! successful-proof receipt is manufactured by these transport codecs.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Raw = @import("block_v5_caller_columns_stage_v1.zig");
const PCS = @import("block_v6_caller_commitment_store_v1.zig");
const Access = @import("block_v6_external_commitment_store_v1.zig");
const External = @import("block_v5_caller_external_stage_v1.zig").ForBackend(Cpu);
const Family = @import("block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu);
const Native = @import("block_v7_native_source_v1.zig");
const Caller = @import("block_v7_caller_joint_proof_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Counter = @import("../air/lookups/tables/counter.zig");
pub const Names = struct { raw: []const u8, pcs: []const u8, access_raw: []const u8, access_pcs: []const u8 };
pub const Limits = struct { raw: Raw.Limits = .{}, pcs: PCS.Limits = PCS.DEFAULT_LIMITS, access: Access.Limits = .{}, max_total_bytes: u64 = 8 << 30 };
fn bytesWithin(limit: u64, parts: []const u64) !u64 {
    var total: u64 = 0;
    for (parts) |part| {
        total = try std.math.add(u64, total, part);
        if (total > limit) return error.V7CallerCheckpointBudget;
    }
    return total;
}
pub const Record = struct {
    descriptor: Raw.Descriptor,
    execution_index: u32,
    execution_identity: [32]u8,
    raw: Raw.Pin,
    pcs: PCS.Pin,
    access: Access.Pin,
    access_root: [32]u8,
    byte_snapshot: [32]u8,
    event_count: u64,
    written_bytes: u64,
    pub fn pin(self: *const Record) Caller.Pin {
        return .{ .index = self.descriptor.index, .execution_index = self.execution_index, .execution_identity = self.execution_identity, .statement = &self.descriptor.statement, .total_steps = self.descriptor.total_steps, .frame = self.descriptor.frame, .roots = self.descriptor.roots, .access_root = self.access_root, .config = self.descriptor.config };
    }
};
fn validateNames(names: Names) !void {
    const all = [_][]const u8{ names.raw, names.pcs, names.access_raw, names.access_pcs };
    for (all, 0..) |name, i| {
        try @import("block_v6_cpu_checkpoint_codec_v1.zig").requireName(name);
        for (all[0..i]) |previous| if (std.mem.eql(u8, previous, name)) return error.DuplicateV7CheckpointName;
    }
}
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, witness: *const Witness, native: Native.Pin, index: u32, counters: *Counter.Set, sink: @import("block_v7_native_checkpoint_v1.zig").EventSink, limits: Limits) !Record {
    try validateNames(names);
    if (limits.max_total_bytes == 0 or witness.total_steps != native.frame.cycle_count) return error.InvalidV7CallerCheckpoint;
    var first = try Family.commitPhysicalFirstRound(a, witness, witness.total_steps, native.template.config);
    defer first.deinit(a);
    var local = try Counter.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    var external = try External.Prepared.initForMode(a, &first, &witness.statement, native.frame, index, &local, 1);
    defer external.deinit(a);
    const descriptor = Raw.Descriptor{ .statement = witness.statement, .total_steps = witness.total_steps, .index = index, .frame = native.frame, .config = native.template.config, .key_id = first.key_id, .roots = first.roots };
    var raw_limits = limits.raw;
    raw_limits.columns.max_file_bytes = @min(raw_limits.columns.max_file_bytes, limits.max_total_bytes);
    const raw = try Raw.write(a, dir, names.raw, witness, &descriptor, raw_limits);
    errdefer dir.deleteFile(names.raw) catch {};
    var pcs_limits = limits.pcs;
    pcs_limits.max_file_bytes = @min(pcs_limits.max_file_bytes, limits.max_total_bytes - raw.bytes);
    const pcs = try PCS.write(a, dir, names.pcs, &descriptor, &first, pcs_limits);
    errdefer dir.deleteFile(names.pcs) catch {};
    var access_limits = limits.access;
    access_limits.storage.max_file_bytes = @min(access_limits.storage.max_file_bytes, limits.max_total_bytes - raw.bytes - pcs.bytes);
    var access: Access.Pin = undefined;
    try Access.write(a, dir, .{ .raw_name = names.access_raw, .pcs_name = names.access_pcs, .limits = access_limits, .pin_out = &access }, &descriptor, 1, &external);
    errdefer {
        dir.deleteFile(names.access_raw) catch {};
        dir.deleteFile(names.access_pcs) catch {};
    }
    const written_bytes = try bytesWithin(limits.max_total_bytes, &.{ raw.bytes, pcs.bytes, access.raw.bytes, access.pcs.bytes });
    for (external.inputs) |input| for (0..input.trace.domainSize()) |row| {
        const value = try input.trace.row(row);
        if (value.active) try sink.put(sink.context, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(value.tuple));
    };
    for (counters.get(.range_check_8_8).values, local.values) |*value, addend| value.* = value.add(addend);
    return .{ .descriptor = descriptor, .execution_index = native.index, .execution_identity = (try native.entry(a)).identity, .raw = raw, .pcs = pcs, .access = access, .access_root = external.first.roots[2], .byte_snapshot = external.byte_snapshot, .event_count = external.byte_demand.event_count, .written_bytes = written_bytes };
}
pub fn proveOne(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: Epoch.Epoch, roster: []const Epoch.Entry, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !Caller.Proof {
    return proveOneWithExecutor(a, dir, names, record, limits, epoch, roster, pool, null);
}
pub fn proveOneWithExecutor(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: Epoch.Epoch, roster: []const Epoch.Entry, pool: *@import("stwo_prover_engine").work_pool.WorkPool, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !Caller.Proof {
    try validateNames(names);
    const size = try bytesWithin(limits.max_total_bytes, &.{ record.raw.bytes, record.pcs.bytes, record.access.raw.bytes, record.access.pcs.bytes });
    if (record.written_bytes != size or size > limits.max_total_bytes) return error.InvalidV7CallerCheckpoint;
    _ = try record.pin().require(a, epoch, roster);
    var loaded = try Raw.ForBackend(Cpu).loadWithCommitment(a, dir, names.raw, &record.descriptor, record.raw, limits.raw, .{ .name = names.pcs, .limits = limits.pcs, .pin = record.pcs });
    defer loaded.deinit(a);
    var local = try Counter.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    var external = try External.Prepared.initForModeWithCheckpoint(a, &loaded.first, &record.descriptor.statement, record.descriptor.frame, record.descriptor.index, &local, 1, .{ .dir = dir, .raw_name = names.access_raw, .pcs_name = names.access_pcs, .limits = limits.access, .pin = record.access }, record.access_root);
    defer external.deinit(a);
    if (!std.meta.eql(external.byte_snapshot, record.byte_snapshot) or external.byte_demand.event_count != record.event_count) return error.InvalidV7CallerCheckpoint;
    external.first.scheme.quotient_executor = executor;
    return Caller.ForBackend(Cpu).prove(a, &external.first, &loaded.first, external.inputs, record.pin(), epoch, roster, pool);
}
test "v7 caller checkpoint budget counts all four files without wrap" {
    try std.testing.expectEqual(@as(u64, 100), try bytesWithin(100, &.{ 10, 20, 30, 40 }));
    try std.testing.expectError(error.V7CallerCheckpointBudget, bytesWithin(99, &.{ 10, 20, 30, 40 }));
    try std.testing.expectError(error.Overflow, bytesWithin(std.math.maxInt(u64), &.{ std.math.maxInt(u64), 1 }));
}
