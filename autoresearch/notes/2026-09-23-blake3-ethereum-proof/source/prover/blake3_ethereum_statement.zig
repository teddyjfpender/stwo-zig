//! Ethereum coefficient admission for full-width BLAKE3 execution providers.
//! Hash geometry is verifier-derived from the admitted commitment schedules.
const std = @import("std");
const core = @import("stwo_core");
const native_mod = @import("../air/statement.zig");
const ethereum = @import("../air/guest_precompile/ethereum_statement.zig");
const bounds = @import("../air/guest_precompile/statement.zig");
const plans = @import("blake3_commitment_plan.zig");
const roster = @import("blake3_commitment_components.zig");
const tables = @import("../air/lookups/tables/schema.zig");
pub const Statement = ethereum.Statement;
pub const HashLogs = [roster.Airs.len]u32;

pub fn canonical(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, keccak: u32, signer: u32, shapes: ethereum.SecpShapes) !Statement {
    const certificate = try admission(native, pin, logs, keccak, signer);
    const result = try Statement.canonicalWithAdmission(keccak, signer, shapes, certificate);
    try validate(&result, native, pin, logs);
    return result;
}
pub fn validate(extension: *const Statement, native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs) !void {
    try extension.validateGeometry(native.total_steps);
    const maximum = @import("../air/guest_precompile/keccakf_trace.zig").maximum_log_size;
    const rows = extension.components[0].n_rows;
    const min_log = @import("../air/guest_precompile/keccakf_trace.zig").minimum_log_size;
    const log = if (rows == 0) min_log else @max(min_log, std.math.log2_int_ceil(u32, rows));
    if (log > maximum or extension.components[0].log_size != log) return error.InvalidComponentGeometry;
    const expected = try admission(native, pin, logs, extension.counts.keccak_calls, extension.counts.signer_calls);
    if (!std.meta.eql(extension.admission, expected)) return error.AdmissionCertificateMismatch;
}
fn admission(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, keccak: u32, signer: u32) !ethereum.Admission {
    const external = try std.math.add(u32, keccak, signer);
    try native.validateBlake3ExecutionWithExternal(external);
    try pin.validatePublic(&native.public_data);
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
    var extended = base;
    try demand(&extended, .range_check_20, keccak, 51);
    try demand(&extended, .range_check_8_8, keccak, 1);
    try demand(&extended, .range_check_8_8_4, keccak, 1);
    try demand(&extended, .range_check_20, signer, 43);
    try demand(&extended, .range_check_8_8, signer, 1);
    try demand(&extended, .range_check_8_8_4, signer, 1);
    const extra = try add(try mul(keccak, 48), try mul(signer, 40));
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
    return .{ .extra_memory_terms = extra, .memory_relation_terms = try bounded(memory), .base_fixed_table_bounds = base, .extended_fixed_table_bounds = extended };
}
fn demand(values: *[ethereum.fixed_table_count]u64, kind: tables.Kind, count: u32, per_row: u32) !void {
    const value = &values[@intFromEnum(kind)];
    value.* = try bounded(try add(value.*, try mul(count, per_row)));
}
fn bounded(value: u64) !u64 {
    if (value >= core.fields.m31.Modulus) return error.CoefficientBoundExceeded;
    return value;
}
fn add(a: anytype, b: anytype) !u64 {
    return std.math.add(u64, @intCast(a), @intCast(b));
}
fn mul(a: anytype, b: anytype) !u64 {
    return std.math.mul(u64, @intCast(a), @intCast(b));
}
