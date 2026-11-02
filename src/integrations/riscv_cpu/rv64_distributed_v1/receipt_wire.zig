//! Worker -> coordinator ROOT-ONLY message with canonical binding metadata.
//! It carries no trace columns, native RAM image, coefficients or alpha.
const std = @import("std");
const M = @import("manifest.zig");
const T = M.T;
const W = @import("wire.zig");
const IO = @import("../rv64_work_packet_io.zig");
pub const MAGIC = "RV64SR01";
pub fn write(file: std.fs.File, context: T.Context, spec: T.Spec, receipt: T.Receipt) !void {
    try validate(context, spec, receipt);
    var writer = IO.Writer{ .file = file };
    try writer.bytes(MAGIC);
    try writer.int(u32, 1);
    try writer.int(u32, @intCast(spec.column_logs.len));
    try writer.int(u64, 548 + 4 * spec.column_logs.len);
    try writer.bytes(&W.contextBytes(context));
    try writer.bytes(&W.specBytes(spec));
    for (spec.column_logs) |log| try writer.int(u32, log);
    try writer.int(u32, receipt.ordinal);
    try writer.bytes(&receipt.spec_digest);
    try writer.bytes(&receipt.fixed.value);
    try writer.bytes(&receipt.shared.value);
    try writer.flush();
}
/// Expected request/program/job/schema/fixed root and dimensions are checked
/// without allocating. The returned root message is not a verified proof.
pub fn read(file: std.fs.File, context: T.Context, spec: T.Spec) !T.Receipt {
    try M.validateContext(context);
    try T.validateSpec(spec);
    var header: [24]u8 = undefined;
    try IO.exact(file, &header);
    const bytes = 548 + 4 * spec.column_logs.len;
    if (!std.mem.eql(u8, header[0..8], MAGIC) or std.mem.readInt(u32, header[8..12], .little) != 1 or std.mem.readInt(u32, header[12..16], .little) != spec.column_logs.len or std.mem.readInt(u64, header[16..24], .little) != bytes) return error.InvalidStage1ReceiptWire;
    var reader = IO.Reader{ .file = file, .remaining = bytes - 24 };
    var raw_context: [256]u8 = undefined;
    var raw_spec: [168]u8 = undefined;
    try reader.bytes(&raw_context);
    try reader.bytes(&raw_spec);
    if (!std.mem.eql(u8, &raw_context, &W.contextBytes(context)) or !std.mem.eql(u8, &raw_spec, &W.specBytes(spec))) return error.DistributedInventoryMismatch;
    for (spec.column_logs) |log| if (try reader.int(u32) != log) return error.DistributedInventoryMismatch;
    var receipt: T.Receipt = undefined;
    receipt.ordinal = try reader.int(u32);
    try reader.bytes(&receipt.spec_digest);
    try reader.bytes(&receipt.fixed.value);
    try reader.bytes(&receipt.shared.value);
    try reader.finish();
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.TrailingStage1ReceiptWire;
    try validate(context, spec, receipt);
    return receipt;
}
fn validate(context: T.Context, spec: T.Spec, receipt: T.Receipt) !void {
    try M.validateContext(context);
    try T.validateSpec(spec);
    if (receipt.ordinal != spec.ordinal or !std.mem.eql(u8, &receipt.spec_digest, &T.specDigest(spec)) or !std.mem.eql(u8, &receipt.fixed.value, &spec.expected_fixed.value)) return error.DistributedInventoryMismatch;
}
