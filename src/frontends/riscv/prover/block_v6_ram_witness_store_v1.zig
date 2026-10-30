//! Exact raw RAM matrix transport, without a second temporary column matrix.
const std = @import("std");
const core = @import("stwo_core");
const Raw = @import("block_v5_witness_columns_store_v1.zig");
const TraceModule = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Trace = TraceModule.Trace;
const Ram = @import("block_v5_ram_lanes_proof_v1.zig");
const Spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
pub const Pin = Raw.Pin;
pub const Limits = struct { max_row_log: u32 = 24, max_owned_bytes: usize = 4 << 30, max_file_bytes: u64 = 8 << 30 };
fn scope(pin: Ram.Pin) !Raw.Scope {
    try pin.validate();
    // For ram_lane these two scalar fields encode event ordinals, not clocks.
    return .{ .kind = .ram_lane, .execution_index = pin.index, .first_cycle = try std.math.add(u64, pin.claim.first_event, 1), .cycle_count = pin.claim.events, .descriptor_digest = try pin.identity(), .first_roots = pin.roots };
}
fn rawLimits(limits: Limits) !Raw.Limits {
    return .{ .max_columns = Spec.FIXED_COUNT + Spec.MAIN_COUNT, .max_log_size = limits.max_row_log, .max_file_bytes = limits.max_file_bytes, .max_loaded_bytes = try std.math.add(usize, limits.max_owned_bytes, (Spec.FIXED_COUNT + Spec.MAIN_COUNT) * @sizeOf(Column)) };
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, trace: *const Trace, expected: Ram.Pin, limits: Limits) !Pin {
    if (!trace.sealed or trace.written != expected.claim.events or !std.meta.eql(trace.claim, expected.claim) or try Trace.ownedBytes(trace.claim) > limits.max_owned_bytes) return error.InvalidRamCheckpointWitness;
    var columns: [Spec.FIXED_COUNT + Spec.MAIN_COUNT]Column = undefined;
    for (columns[0..Spec.FIXED_COUNT], 0..) |*column, i| column.* = .{ .log_size = expected.claim.row_log, .values = trace.fixedColumn(i) };
    for (columns[Spec.FIXED_COUNT..], 0..) |*column, i| column.* = .{ .log_size = expected.claim.row_log, .values = trace.mainColumn(i) };
    return Raw.write(a, dir, name, try scope(expected), &columns, try rawLimits(limits));
}
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, expected: Ram.Pin, pin: Pin, limits: Limits) !Trace {
    const identity = try scope(expected);
    var trace = try Trace.allocateForCheckpoint(a, expected.claim, .{ .max_row_log = limits.max_row_log, .max_events = expected.claim.events, .max_owned_bytes = limits.max_owned_bytes });
    errdefer trace.deinit();
    const Destination = struct {
        trace: *Trace,
        fn put(raw: *anyopaque, column: usize, offset: usize, values: []const M) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const size = self.trace.domainSize();
            if (column >= Spec.FIXED_COUNT + Spec.MAIN_COUNT or offset > size or values.len > size - offset) return error.InvalidRamCheckpointWitness;
            const target = if (column < Spec.FIXED_COUNT) self.trace.fixed[column * size ..][0..size] else self.trace.main[(column - Spec.FIXED_COUNT) * size ..][0..size];
            @memcpy(target[offset..][0..values.len], values);
        }
    };
    var destination = Destination{ .trace = &trace };
    const logs = [_]u32{expected.claim.row_log} ** (Spec.FIXED_COUNT + Spec.MAIN_COUNT);
    try Raw.readMapped(dir, name, identity, &logs, pin, try rawLimits(limits), .{ .context = &destination, .put = Destination.put });
    trace.previous = expected.claim.last;
    trace.written = expected.claim.events;
    trace.sealed = true;
    return trace;
}
