//! Ethereum coefficient admission for full-width BLAKE3 execution providers.
//! Hash geometry is verifier-derived from the admitted commitment schedules.
const std = @import("std");
const native_mod = @import("../air/statement.zig");
const ethereum = @import("../air/guest_precompile/ethereum_statement.zig");
const common = @import("blake3_extension_bounds.zig");
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
    try validateExtensionGeometry(extension, native.total_steps);
    const expected = try admission(native, pin, logs, extension.counts.keccak_calls, extension.counts.signer_calls);
    if (!std.meta.eql(extension.admission, expected)) return error.AdmissionCertificateMismatch;
}

pub fn validateExtensionGeometry(extension: *const Statement, total_steps: u32) !void {
    try extension.validateGeometry(total_steps);
    const maximum = @import("../air/guest_precompile/keccakf_trace.zig").maximum_log_size;
    const rows = extension.components[0].n_rows;
    const min_log = @import("../air/guest_precompile/keccakf_trace.zig").minimum_log_size;
    const log = if (rows == 0) min_log else @max(min_log, std.math.log2_int_ceil(u32, rows));
    if (log > maximum or extension.components[0].log_size != log) return error.InvalidComponentGeometry;
}
fn admission(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, keccak: u32, signer: u32) !ethereum.Admission {
    return admissionExtended(native, pin, logs, keccak, signer, 0, .{});
}

/// Combined-profile verifier admission. SHA's fixed padding contributes even
/// for zero calls; the old Ethereum profile continues to use `admission` above.
pub fn admissionWithSha(a: std.mem.Allocator, native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, keccak: u32, signer: u32, sha: u32) !ethereum.Admission {
    return admissionExtended(native, pin, logs, keccak, signer, sha, try @import("../air/guest_precompile/sha256_coefficient_bounds.zig").derive(a, sha));
}

fn admissionExtended(native: *const native_mod.Blake3ExecutionStatement, pin: plans.Admission, logs: HashLogs, keccak: u32, signer: u32, sha: u32, sha_bounds: @import("../air/guest_precompile/sha256_coefficient_bounds.zig").Bounds) !ethereum.Admission {
    const external = try std.math.add(u32, try std.math.add(u32, keccak, signer), sha);
    try native.validateBlake3ExecutionWithExternal(external);
    try pin.validatePublic(&native.public_data);
    const base = try common.fixedTables(native, logs);
    var extended = base;
    try demand(&extended, .range_check_20, keccak, 51);
    try demand(&extended, .range_check_8_8, keccak, 1);
    try demand(&extended, .range_check_8_8_4, keccak, 1);
    try demand(&extended, .range_check_20, signer, 43);
    try demand(&extended, .range_check_8_8, signer, 1);
    try demand(&extended, .range_check_8_8_4, signer, 1);
    for (&extended, sha_bounds.tables) |*value, sha_terms| value.* = try bounded(try add(value.*, sha_terms));
    const extra = try add(try add(try mul(keccak, 48), try mul(signer, 40)), sha_bounds.extra_memory_terms);
    const memory = try common.memoryTerms(native, pin, extra);
    return .{ .extra_memory_terms = extra, .memory_relation_terms = try bounded(memory), .base_fixed_table_bounds = base, .extended_fixed_table_bounds = extended };
}
fn demand(values: *[ethereum.fixed_table_count]u64, kind: tables.Kind, count: u32, per_row: u32) !void {
    const value = &values[@intFromEnum(kind)];
    value.* = try bounded(try add(value.*, try mul(count, per_row)));
}
const bounded = common.bounded;
const add = common.add;
const mul = common.mul;
