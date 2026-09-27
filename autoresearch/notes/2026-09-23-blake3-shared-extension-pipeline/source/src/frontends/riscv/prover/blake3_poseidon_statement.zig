//! Guest Poseidon semantics over full-width BLAKE3 execution commitments.
//! This authenticates extension geometry; the enclosing proof protocol must
//! additionally bind the native statement, commitment plan and PCS parameters.
const std = @import("std");
const native_mod = @import("../air/statement.zig");
const guest = @import("../air/guest_precompile/statement.zig");
const plans = @import("blake3_commitment_plan.zig");
const common = @import("blake3_extension_bounds.zig");
pub const Statement = guest.ExtensionStatement;
pub const HashLogs = common.HashLogs;

pub fn canonical(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, calls: u32) !Statement {
    return Statement.canonicalWithAdmission(calls, try admission(native, pin, logs, calls));
}
pub fn validate(extension: *const Statement, native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs) !void {
    try extension.validateGeometry();
    try extension.validateWithAdmission(try admission(native, pin, logs, extension.counts.n_guest));
}
fn admission(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, calls: u32) !guest.AdmissionCertificate {
    try native.validateBlake3ExecutionWithExternal(calls);
    try pin.validatePublic(&native.public_data);
    const base = try common.fixedTables(native, logs);
    var clock_rows: u64 = 0;
    for (native.infra_descs[0..native.n_infra]) |descriptor| {
        if (descriptor.kind == .clock_update) clock_rows = try common.add(clock_rows, descriptor.n_rows);
    }
    return .{
        .n_base = try std.math.sub(u64, native.total_steps, calls),
        .total_steps = native.total_steps,
        .n_guest = calls,
        .clock_update_rows = clock_rows,
        .memory_rows = pin.plan.memories.len,
        .memory_relation_terms = try common.memoryTerms(native, pin, try common.mul(calls, 14)),
        .base_fixed_table_bounds = base,
        .extended_fixed_table_bounds = try guest.checkedExtendedFixedTableBounds(base, calls),
    };
}
