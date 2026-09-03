//! Canonical, cold-decodable custody for one candidate bulk-memcpy tape.
//!
//! This format is deliberately local to the nonproduction retained-workload
//! bridge. It serializes every semantic caller, aligned-span, word, and
//! execution-row field with explicit little-endian integers and strict bools.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const tape_mod = frontend.runner.guest_precompile.bulk_memcpy_session_tape_v1;

pub const magic = "STWBMT01";
pub const format_version: u16 = 1;
pub const maximum_artifact_bytes: usize = 4 * 1024 * 1024;
pub const maximum_execution_artifact_bytes: usize = 64 * 1024 * 1024;
const identity_domain = "stwo-zig/riscv/bulk-memcpy-tape-artifact/v1\x00";

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    tape: *const tape_mod.Frozen,
) ![]u8 {
    return encodeAllocBounded(allocator, tape, maximum_artifact_bytes);
}

/// The live candidate observer may hold a full 2^22-cycle segment. Preserve
/// the exact V1 bytes while admitting a separately named, larger diagnostic
/// bound; ordinary retained microproof callers keep the 4 MiB default above.
pub fn encodeExecutionAlloc(
    allocator: std.mem.Allocator,
    tape: *const tape_mod.Frozen,
) ![]u8 {
    return encodeAllocBounded(
        allocator,
        tape,
        maximum_execution_artifact_bytes,
    );
}

fn encodeAllocBounded(
    allocator: std.mem.Allocator,
    tape: *const tape_mod.Frozen,
    maximum_bytes: usize,
) ![]u8 {
    try tape.validate();
    if (tape.records().len > std.math.maxInt(u32) or
        tape.wordRows().len > std.math.maxInt(u32) or
        tape.rows().len > std.math.maxInt(u32))
    {
        return error.BulkMemcpyTapeArtifactLimitExceeded;
    }
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll(magic);
    try writer.writeInt(u16, format_version, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeInt(
        u64,
        std.math.cast(u64, tape.externalStepOrigin()) orelse
            return error.BulkMemcpyTapeArtifactLimitExceeded,
        .little,
    );
    try writer.writeInt(u32, @intCast(tape.records().len), .little);
    try writer.writeInt(u32, @intCast(tape.wordRows().len), .little);
    try writer.writeInt(u32, @intCast(tape.rows().len), .little);
    for (tape.records(), tape.rows()) |record, execution| {
        try encodeCallRecord(writer, record);
        try encodeExecutionRow(writer, execution);
        const first: usize = record.first_word_row;
        const end = first + record.word_row_count;
        for (tape.wordRows()[first..end]) |row| try encodeWordRow(writer, row);
    }
    if (output.items.len == 0 or output.items.len > maximum_bytes)
        return error.BulkMemcpyTapeArtifactLimitExceeded;
    return output.toOwnedSlice(allocator);
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !tape_mod.Frozen {
    return decodeAllocBounded(allocator, bytes, maximum_artifact_bytes);
}

pub fn decodeExecutionAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !tape_mod.Frozen {
    return decodeAllocBounded(
        allocator,
        bytes,
        maximum_execution_artifact_bytes,
    );
}

fn decodeAllocBounded(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    maximum_bytes: usize,
) !tape_mod.Frozen {
    if (bytes.len == 0 or bytes.len > maximum_bytes)
        return error.InvalidBulkMemcpyTapeArtifact;
    var cursor = Cursor{ .bytes = bytes };
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic))
        return error.InvalidBulkMemcpyTapeArtifact;
    if (try cursor.int(u16) != format_version or try cursor.int(u16) != 0)
        return error.InvalidBulkMemcpyTapeArtifact;
    const external_origin = std.math.cast(usize, try cursor.int(u64)) orelse
        return error.InvalidBulkMemcpyTapeArtifact;
    const call_count: usize = try cursor.int(u32);
    const word_count: usize = try cursor.int(u32);
    const execution_count: usize = try cursor.int(u32);
    if (call_count == 0 or call_count != execution_count or
        call_count > word_count)
    {
        return error.InvalidBulkMemcpyTapeArtifact;
    }

    var builder = try tape_mod.Builder.init(
        allocator,
        call_count,
        word_count,
        external_origin,
    );
    errdefer builder.deinit();
    var decoded_words: usize = 0;
    for (0..call_count) |call_index| {
        const encoded_record = try decodeCallRecord(&cursor);
        const encoded_execution = try decodeExecutionRow(&cursor);
        const row_count: usize = encoded_record.word_row_count;
        const rows = try allocator.alloc(tape_mod.WordRow, row_count);
        defer allocator.free(rows);
        for (rows) |*row| row.* = try decodeWordRow(&cursor);
        try builder.reserveOne(row_count);
        builder.appendAssumeCapacity(
            encoded_execution.inst_word,
            encoded_record.caller,
            rows,
        );
        if (!std.meta.eql(builder.records()[call_index], encoded_record) or
            !std.meta.eql(builder.rows()[call_index], encoded_execution))
        {
            return error.InvalidBulkMemcpyTapeArtifact;
        }
        decoded_words = std.math.add(usize, decoded_words, row_count) catch
            return error.InvalidBulkMemcpyTapeArtifact;
    }
    if (decoded_words != word_count or cursor.position != bytes.len)
        return error.InvalidBulkMemcpyTapeArtifact;
    try builder.validate();
    var result = builder.freeze();
    errdefer result.deinit();
    const canonical = try encodeAllocBounded(allocator, &result, maximum_bytes);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalBulkMemcpyTapeArtifact;
    return result;
}

pub fn identity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hash.update(bytes);
    return hash.finalResult();
}

fn encodeCallRecord(writer: anytype, record: tape_mod.CallRecord) !void {
    inline for (.{
        record.caller.execution_clock,
        record.caller.pc,
        record.caller.destination_previous_clock,
        record.caller.source_previous_clock,
        record.caller.length_previous_clock,
        record.caller.destination,
        record.caller.source,
        record.caller.length,
        record.caller.call_index,
        record.aligned_spans.source.first_word,
        record.aligned_spans.source.word_count,
        record.aligned_spans.source.end_word_exclusive,
        record.aligned_spans.destination.first_word,
        record.aligned_spans.destination.word_count,
        record.aligned_spans.destination.end_word_exclusive,
        record.first_word_row,
        record.word_row_count,
    }) |value| try writer.writeInt(u32, value, .little);
}

fn decodeCallRecord(cursor: *Cursor) !tape_mod.CallRecord {
    return .{
        .caller = .{
            .execution_clock = try cursor.int(u32),
            .pc = try cursor.int(u32),
            .destination_previous_clock = try cursor.int(u32),
            .source_previous_clock = try cursor.int(u32),
            .length_previous_clock = try cursor.int(u32),
            .destination = try cursor.int(u32),
            .source = try cursor.int(u32),
            .length = try cursor.int(u32),
            .call_index = try cursor.int(u32),
        },
        .aligned_spans = .{
            .source = .{
                .first_word = try cursor.int(u32),
                .word_count = try cursor.int(u32),
                .end_word_exclusive = try cursor.int(u32),
            },
            .destination = .{
                .first_word = try cursor.int(u32),
                .word_count = try cursor.int(u32),
                .end_word_exclusive = try cursor.int(u32),
            },
        },
        .first_word_row = try cursor.int(u32),
        .word_row_count = try cursor.int(u32),
    };
}

fn encodeExecutionRow(writer: anytype, row: tape_mod.ExecutionRow) !void {
    inline for (.{
        row.execution_clock,
        row.pc,
        row.inst_word,
        row.call_index,
        row.first_word_row,
        row.word_row_count,
    }) |value| try writer.writeInt(u32, value, .little);
}

fn decodeExecutionRow(cursor: *Cursor) !tape_mod.ExecutionRow {
    return .{
        .execution_clock = try cursor.int(u32),
        .pc = try cursor.int(u32),
        .inst_word = try cursor.int(u32),
        .call_index = try cursor.int(u32),
        .first_word_row = try cursor.int(u32),
        .word_row_count = try cursor.int(u32),
    };
}

fn encodeWordRow(writer: anytype, row: tape_mod.WordRow) !void {
    inline for (.{ row.active, row.is_first, row.is_last }) |value|
        try writer.writeByte(@intFromBool(value));
    inline for (.{
        row.execution_clock,
        row.call_index,
        row.pc,
        row.word_index,
        row.expected_word_count,
        row.length,
        row.source_word_index,
        row.destination_word_index,
        row.source_previous_clock,
        row.destination_previous_clock,
    }) |value| try writer.writeInt(u32, value, .little);
    try writer.writeAll(&row.source_bytes);
    try writer.writeAll(&row.destination_before);
    try writer.writeAll(&row.destination_after);
    inline for (.{ row.byte_mask, row.start_selectors, row.end_selectors }) |values|
        for (values) |value| try writer.writeByte(@intFromBool(value));
}

fn decodeWordRow(cursor: *Cursor) !tape_mod.WordRow {
    var row = tape_mod.WordRow{
        .active = try cursor.boolean(),
        .is_first = try cursor.boolean(),
        .is_last = try cursor.boolean(),
        .execution_clock = try cursor.int(u32),
        .call_index = try cursor.int(u32),
        .pc = try cursor.int(u32),
        .word_index = try cursor.int(u32),
        .expected_word_count = try cursor.int(u32),
        .length = try cursor.int(u32),
        .source_word_index = try cursor.int(u32),
        .destination_word_index = try cursor.int(u32),
        .source_previous_clock = try cursor.int(u32),
        .destination_previous_clock = try cursor.int(u32),
        .source_bytes = undefined,
        .destination_before = undefined,
        .destination_after = undefined,
        .byte_mask = undefined,
        .start_selectors = undefined,
        .end_selectors = undefined,
    };
    @memcpy(&row.source_bytes, try cursor.take(row.source_bytes.len));
    @memcpy(&row.destination_before, try cursor.take(row.destination_before.len));
    @memcpy(&row.destination_after, try cursor.take(row.destination_after.len));
    inline for (.{ &row.byte_mask, &row.start_selectors, &row.end_selectors }) |values| {
        for (values) |*value| value.* = try cursor.boolean();
    }
    return row;
}

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn take(self: *Cursor, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.position, count) catch
            return error.InvalidBulkMemcpyTapeArtifact;
        if (end > self.bytes.len) return error.InvalidBulkMemcpyTapeArtifact;
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
            else => error.InvalidBulkMemcpyTapeArtifact,
        };
    }
};
