//! Shared coefficient bounds for native execution and full-width BLAKE3 providers.
const std = @import("std");
const core = @import("stwo_core");
const native_mod = @import("../air/statement.zig");
const bounds = @import("../air/guest_precompile/statement.zig");
const plans = @import("blake3_commitment_plan.zig");
const roster = @import("blake3_commitment_components.zig");
pub const HashLogs = [roster.Airs.len]u32;
pub fn fixedTables(native: *const native_mod.Blake3ExecutionStatement, logs: HashLogs) ![bounds.fixed_table_count]u64 {
    var base = try bounds.deriveBaseFixedTableBounds(native.*);
    // Every physical LogUp batch has at most two relation events. Bounding
    // each fixed table by the entire provider roster is conservative, and
    // includes padding rather than relying on witness-dependent activity.
    var provider_events: u64 = 0;
    inline for (roster.Airs, 0..) |Air, i| {
        if (logs[i] == 0 or logs[i] > 24) return error.InvalidTraceShape;
        provider_events = try add(provider_events, try mul(@as(u64, 1) << @intCast(logs[i]), Air.INTERACTION_COLUMN_COUNT / 2));
    }
    for (&base) |*value| value.* = try bounded(try add(value.*, provider_events));
    return base;
}
pub fn memoryTerms(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, extra: u64) !u64 {
    var memory = try add(try mul(native.total_steps, 3), extra);
    for (native.infra_descs[0..native.n_infra]) |descriptor| {
        if (descriptor.kind == .clock_update) memory = try add(memory, descriptor.n_rows);
    }
    memory = try add(memory, pin.plan.memories.len);
    memory = try add(memory, 64); // Initial/final register memory tuples.
    memory = try add(memory, native.public_data.io_entries.input_words.len);
    memory = try add(memory, native.public_data.io_entries.output_words.len);
    if (native.public_data.completion) |completion| {
        if (completion.kind == .halt_flag) memory = try add(memory, 1);
    }
    return bounded(memory);
}
pub fn bounded(value: u64) !u64 {
    if (value >= core.fields.m31.Modulus) return error.CoefficientBoundExceeded;
    return value;
}
pub fn add(a: anytype, b: anytype) !u64 {
    return std.math.add(u64, @intCast(a), @intCast(b));
}
pub fn mul(a: anytype, b: anytype) !u64 {
    return std.math.mul(u64, @intCast(a), @intCast(b));
}
