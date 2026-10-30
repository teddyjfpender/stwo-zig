//! Exact external-access witness and original third-tree transport. No cache
//! grants authentication: original caller roots and fresh fused proof checks
//! still bind all cells, counters and global relations.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Store = @import("block_v6_cpu_scheme_store_v1.zig");
const Raw = @import("block_v5_witness_columns_store_v1.zig");
const Caller = @import("block_v5_caller_columns_stage_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Source = @import("block_execution_external_trace_v2.zig");
const Old = @import("block_execution_external_batch_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Scheme = @import("block_v6_cpu_checkpoint_codec_v1.zig").Scheme;
const M = core.fields.m31.M31;
pub const Limits = struct { storage: Store.Limits = .{ .max_columns = 1 << 16 }, max_raw_bytes: usize = 16 << 30, max_slots: usize = 1024 };
pub const Pin = struct {
    raw: Raw.Pin,
    pcs: Store.Pin,
    /// Persistent external source storage, selected raw caller views and their
    /// descriptors. Excludes shared caller PCS and transient transform scratch.
    raw_loaded_bytes: usize,
};
pub const Staging = struct { raw_name: []const u8, pcs_name: []const u8, limits: Limits, pin_out: *Pin, statistics: ?*@import("block_v6_caller_commitment_staging_v1.zig").ExternalStatistics = null };
pub const Input = struct { dir: std.fs.Dir, raw_name: []const u8, pcs_name: []const u8, limits: Limits, pin: Pin, statistics: ?*@import("block_v6_caller_commitment_staging_v1.zig").ExternalStatistics = null };
const Shape = struct {
    a: std.mem.Allocator,
    slots: []Source.Descriptor,
    logs: []u32,
    scope: Raw.Scope,
    raw_limits: Raw.Limits,
    raw_loaded_bytes: usize,
    identity: [32]u8,
    fn init(a: std.mem.Allocator, descriptor: *const Caller.Descriptor, mode: u32, witness_root: [32]u8, limits: Limits) !Shape {
        try descriptor.require(a);
        const fixed = try Protocol.columnLogs(a, &descriptor.statement, .fixed);
        defer a.free(fixed);
        const main = try Protocol.columnLogs(a, &descriptor.statement, .main);
        defer a.free(main);
        const slots = try Source.descriptorsFromStatementForMode(a, &descriptor.statement, fixed, main, descriptor.frame, mode);
        errdefer a.free(slots);
        if (slots.len == 0 or slots.len > limits.max_slots) return error.ExternalCheckpointResourceLimit;
        const logs = try a.alloc(u32, try std.math.mul(usize, slots.len, Integer.COLUMN_COUNT));
        errdefer a.free(logs);
        if (logs.len > limits.storage.max_columns) return error.ExternalCheckpointResourceLimit;
        var bytes: usize = 0;
        for (slots, 0..) |slot, i| {
            if (slot.log_size > 24 or slot.log_size > limits.storage.max_log_size) return error.ExternalCheckpointResourceLimit;
            @memset(logs[i * Integer.COLUMN_COUNT ..][0..Integer.COLUMN_COUNT], slot.log_size);
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, Integer.COLUMN_COUNT, @as(usize, 4) << @intCast(slot.log_size)));
        }
        if (bytes > limits.max_raw_bytes) return error.ExternalCheckpointResourceLimit;
        // Exact surviving selected-column and source owners; fixed/main PCS
        // leases are borrowed and charged to the independent caller policy.
        const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
        const metadata = try std.math.add(usize, try std.math.mul(usize, slots.len, @sizeOf(Source.Trace) + @sizeOf(Source.Descriptor) + @sizeOf(Old.Input) + @sizeOf(Range.SNAPSHOT)), try std.math.mul(usize, fixed.len + main.len, @sizeOf(Column) + @sizeOf(u32)));
        var owned = try std.math.add(usize, bytes, metadata);
        var masks = try Old.masks(a, slots, fixed.len, main.len);
        defer masks.deinit(a);
        for (masks.fixed, fixed) |selected, log| if (selected) {
            owned = try std.math.add(usize, owned, @as(usize, 4) << @intCast(log));
        };
        if (masks.state_offset) |offset| @memset(masks.main[offset..][0..@import("../air/guest_precompile/keccakf_witness.zig").state_cell_count], true);
        for (masks.main, main) |selected, log| if (selected) {
            owned = try std.math.add(usize, owned, @as(usize, 4) << @intCast(log));
        };
        if (owned >= limits.storage.max_loaded_bytes) return error.ExternalCheckpointResourceLimit;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42364543, 1, mode });
        Old.mixRoster(&channel, descriptor.index, descriptor.key_id, slots);
        for (descriptor.roots) |root| channel.mixRoot(root);
        channel.mixRoot(witness_root);
        const identity = channel.digestBytes();
        return .{ .a = a, .slots = slots, .logs = logs, .identity = identity, .raw_loaded_bytes = owned, .scope = .{ .kind = .caller_external, .execution_index = descriptor.index, .first_cycle = descriptor.frame.global_first_cycle, .cycle_count = descriptor.total_steps, .descriptor_digest = identity, .first_roots = descriptor.roots }, .raw_limits = .{ .max_columns = logs.len, .max_log_size = limits.storage.max_log_size, .max_file_bytes = limits.storage.max_file_bytes, .max_loaded_bytes = try std.math.add(usize, limits.max_raw_bytes, logs.len * @sizeOf(@import("stwo_prover_engine").pcs.ColumnEvaluation)) } };
    }
    fn deinit(self: *Shape) void {
        self.a.free(self.slots);
        self.a.free(self.logs);
    }
    fn requireTraces(self: *const Shape, traces: []const Source.Trace) !void {
        if (traces.len != self.slots.len) return error.ChangedExternalCheckpointScope;
        for (traces, self.slots) |trace, slot| {
            const size = @as(usize, 1) << @intCast(slot.log_size);
            if (!std.meta.eql(trace.descriptor, slot) or trace.storage.len != size * Integer.COLUMN_COUNT) return error.ChangedExternalCheckpointScope;
            for (trace.witness, 0..) |column, i| if (column.len != size or column.ptr != trace.storage[i * size ..].ptr) return error.ChangedExternalCheckpointScope;
        }
    }
};
const Mapping = struct {
    traces: []Source.Trace,
    fn get(raw: *const anyopaque, column: usize, offset: usize, out: []M) !void {
        const self: *const Mapping = @ptrCast(@alignCast(raw));
        const values = try self.valuesAt(column, offset, out.len);
        @memcpy(out, values);
    }
    fn put(raw: *anyopaque, column: usize, offset: usize, values: []const M) !void {
        const self: *Mapping = @ptrCast(@alignCast(raw));
        @memcpy(try self.valuesAt(column, offset, values.len), values);
    }
    fn valuesAt(self: *const Mapping, index: usize, offset: usize, count: usize) ![]M {
        if (index / Integer.COLUMN_COUNT >= self.traces.len) return error.ChangedExternalCheckpointScope;
        const values = self.traces[index / Integer.COLUMN_COUNT].witness[index % Integer.COLUMN_COUNT];
        if (offset > values.len or count > values.len - offset) return error.ChangedExternalCheckpointScope;
        return values[offset..][0..count];
    }
};
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, output: Staging, descriptor: *const Caller.Descriptor, mode: u32, prepared: anytype) !void {
    var timer = try std.time.Timer.start();
    const root = prepared.first.roots[2];
    var shape = try Shape.init(a, descriptor, mode, root, output.limits);
    defer shape.deinit();
    try shape.requireTraces(prepared.traces);
    if (!prepared.first.owns_scheme or prepared.first.scheme.trees.items.len != 3 or !std.meta.eql(prepared.first.roots[0..2].*, descriptor.roots)) return error.ChangedExternalCheckpointScope;
    const map = Mapping{ .traces = prepared.traces };
    const raw = try Raw.writeMapped(a, dir, output.raw_name, shape.scope, shape.logs, shape.raw_limits, .{ .context = &map, .get = Mapping.get });
    errdefer dir.deleteFile(output.raw_name) catch {};
    var limits = output.limits.storage;
    if (raw.bytes >= limits.max_file_bytes) return error.ExternalCheckpointResourceLimit;
    limits.max_file_bytes -= raw.bytes;
    limits.max_loaded_bytes -= shape.raw_loaded_bytes;
    // Serialization view only; source owns all three trees and is never consumed.
    var view = prepared.first.scheme;
    view.trees.items = view.trees.items[2..3];
    view.trees.capacity = 1;
    const pcs = try Store.write(a, dir, output.pcs_name, .{ .identity = shape.identity, .config = descriptor.config, .roots = &.{root}, .logs = &.{shape.logs} }, &view, limits);
    output.pin_out.* = .{ .raw = raw, .pcs = pcs, .raw_loaded_bytes = shape.raw_loaded_bytes };
    if (output.statistics) |statistics| try statistics.wrote(output.pin_out.*, timer.read());
}
pub fn preflight(a: std.mem.Allocator, input: Input, descriptor: *const Caller.Descriptor, mode: u32, witness_root: [32]u8) !void {
    var shape = try Shape.init(a, descriptor, mode, witness_root, input.limits);
    defer shape.deinit();
    if (shape.raw_loaded_bytes != input.pin.raw_loaded_bytes or try std.math.add(usize, shape.raw_loaded_bytes, input.pin.pcs.loaded_bytes) > input.limits.storage.max_loaded_bytes or try std.math.add(u64, input.pin.raw.bytes, input.pin.pcs.bytes) > input.limits.storage.max_file_bytes) return error.ExternalCheckpointResourceLimit;
}
pub fn loadRaw(a: std.mem.Allocator, input: Input, descriptor: *const Caller.Descriptor, mode: u32, witness_root: [32]u8, traces: []Source.Trace) !void {
    var timer = try std.time.Timer.start();
    var shape = try Shape.init(a, descriptor, mode, witness_root, input.limits);
    defer shape.deinit();
    try shape.requireTraces(traces);
    if (shape.raw_loaded_bytes != input.pin.raw_loaded_bytes or try std.math.add(usize, shape.raw_loaded_bytes, input.pin.pcs.loaded_bytes) > input.limits.storage.max_loaded_bytes or try std.math.add(u64, input.pin.raw.bytes, input.pin.pcs.bytes) > input.limits.storage.max_file_bytes) return error.ExternalCheckpointResourceLimit;
    var map = Mapping{ .traces = traces };
    try Raw.readMapped(input.dir, input.raw_name, shape.scope, shape.logs, input.pin.raw, shape.raw_limits, .{ .context = &map, .put = Mapping.put });
    if (input.statistics) |statistics| {
        statistics.raw_read_bytes = try std.math.add(u64, statistics.raw_read_bytes, input.pin.raw.bytes);
        statistics.pcs.restore_ns = try std.math.add(u64, statistics.pcs.restore_ns, timer.read());
    }
}
pub fn loadFirst(a: std.mem.Allocator, input: Input, descriptor: *const Caller.Descriptor, mode: u32, witness_root: [32]u8, prefix: *Scheme, traces: []const Source.Trace, counter: *@import("../air/lookups/tables/counter.zig").Counter) !Old.ForBackend(Cpu).FirstRound {
    try preflight(a, input, descriptor, mode, witness_root);
    var shape = try Shape.init(a, descriptor, mode, witness_root, input.limits);
    defer shape.deinit();
    try shape.requireTraces(traces);
    var timer = try std.time.Timer.start();
    var loaded = try Store.load(a, input.dir, input.pcs_name, .{ .identity = shape.identity, .config = descriptor.config, .roots = &.{witness_root}, .logs = &.{shape.logs} }, input.pin.pcs, input.limits.storage);
    defer loaded.deinit(a);
    const fixed = try Protocol.columnLogs(a, &descriptor.statement, .fixed);
    errdefer a.free(fixed);
    const main = try Protocol.columnLogs(a, &descriptor.statement, .main);
    errdefer a.free(main);
    const snapshots = try a.alloc(Range.SNAPSHOT, traces.len);
    errdefer a.free(snapshots);
    for (traces, snapshots) |*trace, *snapshot| snapshot.* = try Range.collectCounter(a, trace, counter);
    var channel = core.proof_suites.Blake3.Channel{};
    Old.mixRoster(&channel, descriptor.index, descriptor.key_id, shape.slots);
    var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Cpu, a, prefix, &channel);
    errdefer scheme.deinit(a);
    if (!std.meta.eql(scheme.trees.items[0].commitment.root(), descriptor.roots[0]) or !std.meta.eql(scheme.trees.items[1].commitment.root(), descriptor.roots[1])) return error.ChangedExternalCheckpointScope;
    try scheme.appendCommittedTree(a, loaded.trees.items[0], &channel);
    loaded.trees.items.len = 0;
    if (input.statistics) |statistics| try statistics.pcs.restored(input.pin.pcs, timer.read());
    return .{ .scheme = scheme, .roots = .{ descriptor.roots[0], descriptor.roots[1], witness_root }, .fixed_logs = fixed, .main_logs = main, .snapshots = snapshots };
}
