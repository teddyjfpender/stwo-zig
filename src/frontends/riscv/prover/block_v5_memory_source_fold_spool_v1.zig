//! Witness-once full fold census spool. Canonical compact operands are private
//! proposals, never source/root authority. Original PAGE proofs must close the
//! source/hash/indexed/routing equations and match all first-round commitments.
const std = @import("std");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Codec = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Hash = std.crypto.hash.sha2.Sha256;
pub const MAGIC = "B5FSPL01";
pub const FOOTER_MAGIC = "B5FSEND1";
pub const HEADER_BYTES: usize = 128;
pub const FOOTER_BYTES: usize = 80;
pub const BUFFER_RECORDS: usize = 64;
pub const BUFFER_BYTES: usize = BUFFER_RECORDS * Codec.RECORD_BYTES;
comptime {
    if (std.meta.fields(Fold.Census).len != 8) @compileError("source fold spool census grammar requires an explicit version migration");
}
pub const Limits = struct { max_file_bytes: u64 = 512 << 30, max_operations: u64 = 1_000_000_000 };
pub const Pin = struct {
    admission_id: [32]u8,
    census: Fold.Census,
    byte_len: u64,
    sha256: [32]u8,
    pub fn require(self: Pin, admitted: *const Batch.Admission, limits: Limits) !void {
        try validateLimits(limits);
        try admitted.require();
        try self.census.require(&admitted.source, admitted.limits);
        const count = try self.census.operations();
        if (!std.meta.eql(self.admission_id, admitted.identity) or count > limits.max_operations or
            self.byte_len != try length(count) or self.byte_len > limits.max_file_bytes or
            std.mem.allEqual(u8, &self.sha256, 0)) return error.InvalidSourceFoldSpoolPin;
    }
};
pub fn validateLimits(limits: Limits) !void {
    if (limits.max_operations == 0 or limits.max_operations >= @import("stwo_core").fields.m31.Modulus or limits.max_file_bytes < HEADER_BYTES + FOOTER_BYTES + Codec.RECORD_BYTES)
        return error.InvalidSourceFoldSpoolLimits;
}
pub fn length(count: u64) !u64 {
    return std.math.add(u64, HEADER_BYTES + FOOTER_BYTES, try std.math.mul(u64, count, Codec.RECORD_BYTES));
}
fn header(admitted: *const Batch.Admission) [HEADER_BYTES]u8 {
    var out: [HEADER_BYTES]u8 = @splat(0);
    @memcpy(out[0..8], MAGIC);
    std.mem.writeInt(u32, out[8..12], 1, .little);
    std.mem.writeInt(u32, out[12..16], Codec.RECORD_BYTES, .little);
    @memcpy(out[16..48], &admitted.identity);
    @memcpy(out[48..80], &admitted.source.identity);
    @memcpy(out[80..112], &admitted.source.sealed_digest);
    return out;
}
fn footer(census: Fold.Census) ![FOOTER_BYTES]u8 {
    var out: [FOOTER_BYTES]u8 = undefined;
    @memcpy(out[0..8], FOOTER_MAGIC);
    inline for (std.meta.fields(Fold.Census), 0..) |field, index| {
        std.mem.writeInt(u64, out[8 + 8 * index ..][0..8], @field(census, field.name), .little);
    }
    std.mem.writeInt(u64, out[72..80], try census.operations(), .little);
    return out;
}
/// One original tree traversal. No operation vector/main matrix/hash core
/// owner is retained. Failed partial spool files are not accepted or retried.
pub fn collect(dir: std.fs.Dir, name: []const u8, admitted: *const Batch.Admission, source: Fold.Reader, limits: Limits) !Pin {
    try validateLimits(limits);
    try admitted.require();
    if (dir.access(name, .{})) |_| return error.ExistingSourceFoldSpool else |failure| if (failure != error.FileNotFound) return failure;
    var cursor = try Fold.Cursor.init(admitted.source, source, admitted.limits);
    var path: [160]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&path, "{s}.part", .{name});
    const file = try dir.createFile(temporary, .{ .exclusive = true });
    var closed = false;
    defer if (!closed) file.close();
    defer dir.deleteFile(temporary) catch {};
    var hash = Hash.init(.{});
    const prefix = header(admitted);
    try file.writeAll(&prefix);
    hash.update(&prefix);
    var buffer: [BUFFER_BYTES]u8 = undefined;
    var used: usize = 0;
    var count: u64 = 0;
    while (try cursor.next()) |operation| {
        if (operation.ordinal != count) return error.InvalidSourceFoldSpoolOrder;
        count = try std.math.add(u64, count, 1);
        if (count > limits.max_operations or try length(count) > limits.max_file_bytes) return error.SourceFoldSpoolResourceLimit;
        try Codec.encodeOperation(operation, buffer[used..][0..Codec.RECORD_BYTES]);
        used += Codec.RECORD_BYTES;
        if (used == buffer.len) {
            try file.writeAll(&buffer);
            hash.update(&buffer);
            used = 0;
        }
    }
    if (used != 0) {
        try file.writeAll(buffer[0..used]);
        hash.update(buffer[0..used]);
    }
    try cursor.census.require(&admitted.source, admitted.limits);
    if (count != try cursor.census.operations()) return error.InvalidSourceFoldSpoolOrder;
    const suffix = try footer(cursor.census);
    try file.writeAll(&suffix);
    hash.update(&suffix);
    try file.sync();
    const pin = Pin{ .admission_id = admitted.identity, .census = cursor.census, .byte_len = try length(count), .sha256 = hash.finalResult() };
    try pin.require(admitted, limits);
    file.close();
    closed = true;
    std.posix.linkat(dir.fd, temporary, dir.fd, name, 0) catch |failure| switch (failure) {
        error.PathAlreadyExists => return error.ExistingSourceFoldSpool,
        else => return failure,
    };
    errdefer dir.deleteFile(name) catch {};
    try std.posix.fsync(dir.fd);
    return pin;
}
pub const Reader = struct {
    file: std.fs.File,
    pin: Pin,
    hash: Hash,
    buffer: [BUFFER_BYTES]u8 = undefined,
    available: usize = 0,
    next_byte: usize = 0,
    ordinal: u64 = 0,
    offset: u64 = HEADER_BYTES,
    finished: bool = false,
    pub fn open(dir: std.fs.Dir, name: []const u8, pin: Pin, admitted: *const Batch.Admission, limits: Limits) !Reader {
        try pin.require(admitted, limits);
        const file = try dir.openFile(name, .{});
        errdefer file.close();
        if ((try file.stat()).size != pin.byte_len) return error.TruncatedSourceFoldSpool;
        var prefix: [HEADER_BYTES]u8 = undefined;
        if (try file.preadAll(&prefix, 0) != prefix.len or !std.meta.eql(prefix, header(admitted))) return error.InvalidSourceFoldSpoolHeader;
        var hash = Hash.init(.{});
        hash.update(&prefix);
        return .{ .file = file, .pin = pin, .hash = hash };
    }
    pub fn deinit(self: *Reader) void {
        self.file.close();
        self.* = undefined;
    }
    pub fn next(self: *Reader) !?Fold.Operation {
        if (self.finished) return null;
        const count = try self.pin.census.operations();
        if (self.ordinal == count) {
            var suffix: [FOOTER_BYTES]u8 = undefined;
            if (try self.file.preadAll(&suffix, self.offset) != suffix.len or !std.meta.eql(suffix, try footer(self.pin.census))) return error.InvalidSourceFoldSpoolFooter;
            self.hash.update(&suffix);
            if (!std.meta.eql(self.hash.finalResult(), self.pin.sha256)) return error.TamperedSourceFoldSpool;
            self.finished = true;
            return null;
        }
        if (self.next_byte == self.available) {
            // Explicit usize before byte multiplication: do not infer a
            // narrow @min integer type from the fixed64-record buffer.
            const records: usize = @intCast(@min(@as(u64, BUFFER_RECORDS), count - self.ordinal));
            const bytes: usize = records * Codec.RECORD_BYTES;
            if (try self.file.preadAll(self.buffer[0..bytes], self.offset) != bytes) return error.TruncatedSourceFoldSpool;
            self.hash.update(self.buffer[0..bytes]);
            self.offset = try std.math.add(u64, self.offset, bytes);
            self.available = bytes;
            self.next_byte = 0;
        }
        const operation = try Codec.decodeOperation(self.buffer[self.next_byte..][0..Codec.RECORD_BYTES]);
        if (operation.ordinal != self.ordinal) return error.InvalidSourceFoldSpoolOrder;
        self.ordinal = try std.math.add(u64, self.ordinal, 1);
        self.next_byte += Codec.RECORD_BYTES;
        return operation;
    }
    pub fn requireFinished(self: *Reader) !void {
        if (!self.finished or self.ordinal != try self.pin.census.operations()) return error.IncompleteSourceFoldSpool;
    }
};
