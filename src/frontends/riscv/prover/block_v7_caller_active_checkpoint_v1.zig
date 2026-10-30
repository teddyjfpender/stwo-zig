//! Bounded active-family handoff. Raw arithmetic cells and all three original
//! compact PCS trees are staged once. The legacy raw-cell descriptor is only
//! transport framing; active entry identity and fresh STARK verification remain
//! the sole proof authority. No old seal or original-family proof is created.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Raw = @import("block_v5_caller_columns_stage_v1.zig");
const Store = @import("block_v6_cpu_scheme_store_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Stage = @import("block_v7_caller_active_stage_v1.zig").For(Cpu);
const Source = @import("block_v7_caller_active_source_v1.zig");
const Schedule = @import("block_v7_caller_active_schedule_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const Proof = @import("block_v7_caller_active_proof_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Counter = @import("../air/lookups/tables/counter.zig");
pub const Names = @import("block_v7_caller_checkpoint_v1.zig").Names;
pub const Limits = @import("block_v7_caller_checkpoint_v1.zig").Limits;
pub const Record = struct {
    descriptor: Raw.Descriptor,
    execution_index: u32,
    execution_identity: [32]u8,
    raw: Raw.Pin,
    pcs: Store.Pin,
    access_root: [32]u8,
    event_count: u64,
    written_bytes: u64,
    pub fn pin(self: *const Record) Source.Pin {
        return .{ .index = self.descriptor.index, .execution_index = self.execution_index, .execution_identity = self.execution_identity, .statement = &self.descriptor.statement, .total_steps = self.descriptor.total_steps, .frame = self.descriptor.frame, .roots = self.descriptor.roots, .access_root = self.access_root, .config = self.descriptor.config };
    }
};
fn namesValid(names: Names) !void {
    try @import("block_v6_cpu_checkpoint_codec_v1.zig").requireName(names.raw);
    try @import("block_v6_cpu_checkpoint_codec_v1.zig").requireName(names.pcs);
    if (std.mem.eql(u8, names.raw, names.pcs)) return error.DuplicateV7CheckpointName;
}
fn bytesWithin(limit: u64, raw: u64, pcs: u64) !u64 {
    const total = try std.math.add(u64, raw, pcs);
    if (total > limit) return error.V7CallerCheckpointBudget;
    return total;
}
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, witness: *const @import("block_v5_precompile_witness_v1.zig").Witness, native: Native.Pin, index: u32, counters: *Counter.Set, sink: @import("block_v7_native_checkpoint_v1.zig").EventSink, limits: Limits) !Record {
    try namesValid(names);
    if (limits.max_total_bytes == 0 or witness.total_steps != native.frame.cycle_count) return error.InvalidV7CallerCheckpoint;
    var local = try Counter.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    const stage = try Stage.init(a, witness, native.frame, index, native.template.config, &local);
    defer stage.deinit();
    const pin = stage.pin(native.index, (try native.entry(a)).identity);
    const entry = try pin.entry(a);
    const descriptor = Raw.Descriptor{ .statement = witness.statement, .total_steps = witness.total_steps, .index = index, .frame = native.frame, .config = pin.config, .key_id = try Protocol.keyId(pin.statement, pin.total_steps, pin.config, pin.roots[0]), .roots = pin.roots };
    var raw_limits = limits.raw;
    raw_limits.columns.max_file_bytes = @min(raw_limits.columns.max_file_bytes, limits.max_total_bytes);
    const raw = try Raw.write(a, dir, names.raw, witness, &descriptor, raw_limits);
    errdefer dir.deleteFile(names.raw) catch {};
    _ = try bytesWithin(limits.max_total_bytes, raw.bytes, 0);
    var pcs_limits = limits.pcs;
    pcs_limits.max_file_bytes = @min(pcs_limits.max_file_bytes, limits.max_total_bytes - raw.bytes);
    const access_logs = try stage.schedule.witnessLogs();
    defer a.free(access_logs);
    const pcs = try Store.write(a, dir, names.pcs, .{ .identity = entry.identity, .config = pin.config, .retain_coefficients = true, .roots = &stage.first.roots, .logs = &.{ stage.schedule.fixed, stage.schedule.main, access_logs } }, &stage.first.scheme, pcs_limits);
    errdefer dir.deleteFile(names.pcs) catch {};
    const written = try bytesWithin(limits.max_total_bytes, raw.bytes, pcs.bytes);
    var events: u64 = 0;
    for (stage.inputs) |input| for (0..input.trace.domainSize()) |row| {
        const value = try input.trace.row(row);
        if (value.active) {
            try sink.put(sink.context, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(value.tuple));
            events = try std.math.add(u64, events, 1);
        }
    };
    const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(pin.statement, stage.schedule.memory, 1);
    if (events != demand.event_count) return error.InvalidActiveCallerCensus;
    for (counters.get(.range_check_8_8).values, local.values) |*value, addend| value.* = value.add(addend);
    return .{ .descriptor = descriptor, .execution_index = native.index, .execution_identity = pin.execution_identity, .raw = raw, .pcs = pcs, .access_root = pin.access_root, .event_count = events, .written_bytes = written };
}
pub fn proveOne(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: Epoch.Epoch, roster: []const Epoch.Entry, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !Proof.Proof {
    return proveOneWithExecutor(a, dir, names, record, limits, epoch, roster, pool, null);
}
pub const Loaded = struct {
    owner: *Raw.Owner,
    stage: *Proof.ForBackend(Cpu).Stage,
    pub fn deinit(self: *Loaded) void {
        self.stage.deinit();
        self.owner.deinit();
        self.* = undefined;
    }
};
/// Restore proving material only. Root checks do not grant a proof receipt.
/// A union must independently admit its complete epoch before publication.
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits) !Loaded {
    try namesValid(names);
    if (record.written_bytes != try bytesWithin(limits.max_total_bytes, record.raw.bytes, record.pcs.bytes)) return error.InvalidV7CallerCheckpoint;
    const pin = record.pin();
    const entry = try pin.entry(a);
    var schedule = try Schedule.derive(a, pin.statement, pin.total_steps, pin.frame);
    defer schedule.deinit();
    const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(pin.statement, schedule.memory, 1);
    if (record.event_count != demand.event_count) return error.InvalidActiveCallerCensus;
    const access_logs = try schedule.witnessLogs();
    defer a.free(access_logs);
    const owner = try Raw.reconstruct(a, dir, names.raw, &record.descriptor, record.raw, limits.raw);
    errdefer owner.deinit();
    var scheme = try Store.load(a, dir, names.pcs, .{ .identity = entry.identity, .config = pin.config, .retain_coefficients = true, .roots = &(pin.roots ++ .{pin.access_root}), .logs = &.{ schedule.fixed, schedule.main, access_logs } }, record.pcs, limits.pcs);
    var scheme_live = true;
    defer if (scheme_live) scheme.deinit(a);
    const stage = try Stage.fromRestored(a, &owner.witness, pin.frame, pin.index, pin.roots ++ .{pin.access_root}, &scheme);
    scheme_live = false;
    return .{ .owner = owner, .stage = stage };
}
pub fn proveOneWithExecutor(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: Epoch.Epoch, roster: []const Epoch.Entry, pool: *@import("stwo_prover_engine").work_pool.WorkPool, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !Proof.Proof {
    _ = try record.pin().require(a, epoch, roster);
    var loaded = try load(a, dir, names, record, limits);
    defer loaded.deinit();
    loaded.stage.first.scheme.quotient_executor = executor;
    return Proof.ForBackend(Cpu).prove(a, loaded.stage, record.pin(), epoch, roster, pool);
}
test "active caller staged bytes are aggregate bounded and overflow checked" {
    try std.testing.expectEqual(@as(u64, 100), try bytesWithin(100, 40, 60));
    try std.testing.expectError(error.V7CallerCheckpointBudget, bytesWithin(99, 40, 60));
    try std.testing.expectError(error.Overflow, bytesWithin(std.math.maxInt(u64), std.math.maxInt(u64), 1));
}
