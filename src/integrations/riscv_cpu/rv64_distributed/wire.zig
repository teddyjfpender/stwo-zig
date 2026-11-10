//! Canonical complete manifest exchange, not a proof/alpha acceptance channel.
//! Expected descriptors are supplied independently; no shape is allocated from
//! incoming untrusted counts. All u64 identities/spans remain exact LE bytes.
const std = @import("std");
const M = @import("manifest.zig");
const T = M.T;
const IO = @import("../rv64_work_packet_io.zig");
pub const MAGIC = "RV64DM01";
pub const HEADER_BYTES = 312;
pub fn encodedBytes(expected: M.Expected) !usize {
    _ = try M.validateInventory(expected);
    var total: usize = HEADER_BYTES;
    for (expected.specs) |spec| total = try std.math.add(usize, total, 268 + try std.math.mul(usize, spec.column_logs.len, 4));
    if (total > T.MAX_MANIFEST_BYTES) return error.DistributedResourceLimit;
    return total;
}
pub fn write(file: std.fs.File, manifest: *const M.Manifest) !void {
    try manifest.validateUnchanged();
    const expected = M.Expected{ .context = manifest.context, .specs = manifest.specs };
    var writer = IO.Writer{ .file = file };
    try writer.bytes(MAGIC);
    try writer.int(u32, 1);
    try writer.int(u32, @intCast(manifest.specs.len));
    try writer.int(u64, try encodedBytes(expected));
    try writer.bytes(&contextBytes(manifest.context));
    try writer.bytes(&manifest.digest);
    for (manifest.specs, manifest.receipts) |spec, receipt| {
        try writer.bytes(&specBytes(spec));
        for (spec.column_logs) |log| try writer.int(u32, log);
        try writer.int(u32, receipt.ordinal);
        try writer.bytes(&receipt.spec_digest);
        try writer.bytes(&receipt.fixed.value);
        try writer.bytes(&receipt.shared.value);
    }
    try writer.flush();
}
pub fn read(a: std.mem.Allocator, file: std.fs.File, expected: M.Expected) !M.Manifest {
    const bytes = try encodedBytes(expected);
    var header: [HEADER_BYTES]u8 = undefined;
    try IO.exact(file, &header);
    if (!std.mem.eql(u8, header[0..8], MAGIC) or std.mem.readInt(u32, header[8..12], .little) != 1 or std.mem.readInt(u32, header[12..16], .little) != expected.specs.len or std.mem.readInt(u64, header[16..24], .little) != bytes or !std.mem.eql(u8, header[24..280], &contextBytes(expected.context))) return error.InvalidDistributedManifestWire;
    const receipts = try a.alloc(T.Receipt, expected.specs.len);
    defer a.free(receipts);
    var reader = IO.Reader{ .file = file, .remaining = bytes - HEADER_BYTES };
    for (expected.specs, receipts) |spec, *receipt| {
        var raw: [168]u8 = undefined;
        try reader.bytes(&raw);
        if (!std.mem.eql(u8, &raw, &specBytes(spec))) return error.DistributedInventoryMismatch;
        for (spec.column_logs) |log| if (try reader.int(u32) != log) return error.DistributedInventoryMismatch;
        receipt.ordinal = try reader.int(u32);
        try reader.bytes(&receipt.spec_digest);
        try reader.bytes(&receipt.fixed.value);
        try reader.bytes(&receipt.shared.value);
    }
    try reader.finish();
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.TrailingDistributedManifestWire;
    var result = try M.Manifest.init(a, expected, receipts);
    errdefer result.deinit();
    if (!std.mem.eql(u8, &result.digest, header[280..312])) return error.DistributedManifestChanged;
    return result;
}
pub fn contextBytes(context: T.Context) [256]u8 {
    var result: [256]u8 = undefined;
    put(u32, result[0..4], @intFromEnum(context.protocol));
    put(u32, result[4..8], context.local_register_clock_bits);
    put(u64, result[8..16], context.request_id);
    put(u64, result[16..24], context.relation_epoch);
    put(u64, result[24..32], context.positive_limit);
    for ([_]T.Digest{ context.request_digest, context.instance, context.program_key, context.input, context.policy, context.terminal, context.opcode_map }, 0..) |digest, i| @memcpy(result[32 + 32 * i ..][0..32], &digest);
    return result;
}
pub fn specBytes(spec: T.Spec) [168]u8 {
    var result: [168]u8 = undefined;
    put(u32, result[0..4], spec.ordinal);
    put(u32, result[4..8], @intFromEnum(spec.role));
    put(u16, result[8..10], spec.fixed_tree);
    put(u16, result[10..12], spec.shared_tree);
    for ([_]T.Digest{ spec.schema, spec.job_witness, spec.public_statement, spec.expected_fixed.value }, 0..) |digest, i| @memcpy(result[12 + 32 * i ..][0..32], &digest);
    put(u64, result[140..148], spec.instance_epoch);
    put(u64, result[148..156], spec.first_request);
    put(u64, result[156..164], spec.request_count);
    put(u32, result[164..168], @intCast(spec.column_logs.len));
    return result;
}
fn put(comptime I: type, destination: *[@sizeOf(I)]u8, value: I) void {
    std.mem.writeInt(I, destination, value, .little);
}
