//! Canonical binary custody for the nonproduction bulk-memcpy statement.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const harness = frontend.testing.bulk_memcpy_proof_harness_v1;

pub const magic = "STWBMS01";
pub const format_version: u16 = 1;
pub const encoded_size: usize = 8 + 2 + 1 +
    2 * (4 + 4) +
    (15 + 1 + 4 + 1) * 4 * 4 +
    2 + 2 + 3 * 4 * 4 + 3;
const identity_domain = "stwo-zig/riscv/bulk-memcpy-statement/v1\x00";

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    statement: harness.StatementV1,
) ![]u8 {
    try statement.validate();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll(magic);
    try writer.writeInt(u16, format_version, .little);
    try writer.writeByte(@intFromBool(statement.production_eligible));
    try encodeClaim(writer, statement.caller);
    try encodeClaim(writer, statement.words);
    try writer.writeInt(u16, statement.residual.format, .little);
    try writer.writeInt(u16, statement.residual.base_relation_count, .little);
    try encodeQm31(writer, statement.residual.call_relation_sum);
    try encodeQm31(writer, statement.residual.external_base_sum);
    try encodeQm31(writer, statement.residual.combined_component_sum);
    try writer.writeByte(@intFromBool(statement.residual.call_relation_closed));
    try writer.writeByte(@intFromBool(
        statement.residual.external_base_tables_required,
    ));
    try writer.writeByte(@intFromBool(statement.residual.production_eligible));
    const result = try output.toOwnedSlice(allocator);
    errdefer allocator.free(result);
    if (result.len != encoded_size)
        return error.InvalidBulkMemcpyStatementArtifact;
    return result;
}

pub fn decode(bytes: []const u8) !harness.StatementV1 {
    if (bytes.len != encoded_size)
        return error.InvalidBulkMemcpyStatementArtifact;
    var cursor = Cursor{ .bytes = bytes };
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic) or
        try cursor.int(u16) != format_version)
    {
        return error.InvalidBulkMemcpyStatementArtifact;
    }
    const production_eligible = try cursor.boolean();
    const result = harness.StatementV1{
        .format = format_version,
        .caller = .{
            .log_size = try cursor.int(u32),
            .n_rows = try cursor.int(u32),
            .batch_sums = try decodeQm31Array(15, &cursor),
            .component_sum = try decodeQm31(&cursor),
        },
        .words = .{
            .log_size = try cursor.int(u32),
            .n_rows = try cursor.int(u32),
            .batch_sums = try decodeQm31Array(4, &cursor),
            .component_sum = try decodeQm31(&cursor),
        },
        .residual = .{
            .format = try cursor.int(u16),
            .base_relation_count = try cursor.int(u16),
            .call_relation_sum = try decodeQm31(&cursor),
            .external_base_sum = try decodeQm31(&cursor),
            .combined_component_sum = try decodeQm31(&cursor),
            .call_relation_closed = try cursor.boolean(),
            .external_base_tables_required = try cursor.boolean(),
            .production_eligible = try cursor.boolean(),
        },
        .production_eligible = production_eligible,
    };
    if (cursor.position != bytes.len)
        return error.InvalidBulkMemcpyStatementArtifact;
    try result.validate();
    return result;
}

pub fn decodeCanonical(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !harness.StatementV1 {
    const result = try decode(bytes);
    const canonical = try encodeAlloc(allocator, result);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalBulkMemcpyStatementArtifact;
    return result;
}

pub fn identity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hash.update(bytes);
    return hash.finalResult();
}

fn encodeClaim(writer: anytype, claim: anytype) !void {
    try writer.writeInt(u32, claim.log_size, .little);
    try writer.writeInt(u32, claim.n_rows, .little);
    for (claim.batch_sums) |sum| try encodeQm31(writer, sum);
    try encodeQm31(writer, claim.component_sum);
}

fn encodeQm31(writer: anytype, value: QM31) !void {
    for (value.toM31Array()) |limb|
        try writer.writeInt(u32, limb.toU32(), .little);
}

fn decodeQm31Array(
    comptime count: usize,
    cursor: *Cursor,
) ![count]QM31 {
    var result: [count]QM31 = undefined;
    for (&result) |*value| value.* = try decodeQm31(cursor);
    return result;
}

fn decodeQm31(cursor: *Cursor) !QM31 {
    var limbs: [4]M31 = undefined;
    for (&limbs) |*limb| {
        const value = try cursor.int(u32);
        if (value >= stwo_core.fields.m31.Modulus)
            return error.InvalidBulkMemcpyStatementArtifact;
        limb.* = M31.fromCanonical(value);
    }
    return QM31.fromM31Array(limbs);
}

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn take(self: *Cursor, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.position, count) catch
            return error.InvalidBulkMemcpyStatementArtifact;
        if (end > self.bytes.len)
            return error.InvalidBulkMemcpyStatementArtifact;
        const result = self.bytes[self.position..end];
        self.position = end;
        return result;
    }

    fn int(self: *Cursor, comptime T: type) !T {
        const bytes = try self.take(@sizeOf(T));
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, fixed, .little);
    }

    fn boolean(self: *Cursor) !bool {
        return switch ((try self.take(1))[0]) {
            0 => false,
            1 => true,
            else => error.InvalidBulkMemcpyStatementArtifact,
        };
    }
};

comptime {
    if (harness.production_active)
        @compileError("bulk memcpy statement artifact is diagnostic-only");
}
