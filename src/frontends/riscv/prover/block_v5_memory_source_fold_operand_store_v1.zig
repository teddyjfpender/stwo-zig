//! Durable bounded fold operands, never hash matrices or edit sibling paths.
//! File pins provide integrity only. Every load must be followed by original
//! source/core/capture recommit against independently collected six roots.
const std = @import("std");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const MAGIC = "B5SFOPR1";
pub const RECORD_BYTES: usize = 250;
pub const HEADER_BYTES: usize = 96;
pub const BUFFER_RECORDS: usize = 64;
pub const BUFFER_BYTES: usize = BUFFER_RECORDS * RECORD_BYTES;
const Hash = std.crypto.hash.sha2.Sha256;
pub const Limits = struct { max_file_bytes: usize = 2 << 20, max_operations: u32 = 4096 };
pub const Pin = struct { byte_len: u64, sha256: [32]u8, page_identity: [32]u8 };
fn writeU32(out: []u8, at: *usize, value: u32) void {
    std.mem.writeInt(u32, out[at.*..][0..4], value, .little);
    at.* += 4;
}
fn writeU64(out: []u8, at: *usize, value: u64) void {
    std.mem.writeInt(u64, out[at.*..][0..8], value, .little);
    at.* += 8;
}
fn readU32(input: []const u8, at: *usize) u32 {
    const value = std.mem.readInt(u32, input[at.*..][0..4], .little);
    at.* += 4;
    return value;
}
fn readU64(input: []const u8, at: *usize) u64 {
    const value = std.mem.readInt(u64, input[at.*..][0..8], .little);
    at.* += 8;
    return value;
}
pub fn encodeOperation(operation: Fold.Operation, out: *[RECORD_BYTES]u8) !void {
    try operation.coordinate.validate();
    var at: usize = 0;
    writeU64(out, &at, operation.ordinal);
    writeU32(out, &at, @intFromEnum(operation.kind));
    writeU32(out, &at, operation.coordinate.height);
    writeU32(out, &at, operation.coordinate.index);
    @memcpy(out[at..][0..32], &operation.value.before);
    at += 32;
    @memcpy(out[at..][0..32], &operation.value.after);
    at += 32;
    writeU32(out, &at, operation.leaf.address);
    writeU32(out, &at, operation.leaf.before);
    writeU32(out, &at, operation.leaf.after);
    writeU64(out, &at, operation.leaf.clock);
    out[at] = @intCast(@intFromEnum(operation.leaf.image));
    at += 1;
    out[at] = @intFromBool(operation.leaf.touched);
    at += 1;
    writeU64(out, &at, operation.leaf.image_ordinal);
    writeU64(out, &at, operation.leaf.touch_ordinal);
    for ([_][32]u8{ operation.left.before, operation.left.after, operation.right.before, operation.right.after }) |digest| {
        @memcpy(out[at..][0..32], &digest);
        at += 32;
    }
    std.debug.assert(at == RECORD_BYTES);
}
pub fn decodeOperation(raw: *const [RECORD_BYTES]u8) !Fold.Operation {
    var at: usize = 0;
    const ordinal = readU64(raw, &at);
    const kind = std.meta.intToEnum(Fold.Kind, readU32(raw, &at)) catch return error.InvalidSourceFoldOperandKind;
    const height = readU32(raw, &at);
    const index = readU32(raw, &at);
    var out = Fold.Operation{ .ordinal = ordinal, .kind = kind, .coordinate = .{ .height = height, .index = index }, .value = undefined };
    out.value.before = raw[at..][0..32].*;
    at += 32;
    out.value.after = raw[at..][0..32].*;
    at += 32;
    out.leaf.address = readU32(raw, &at);
    out.leaf.before = readU32(raw, &at);
    out.leaf.after = readU32(raw, &at);
    out.leaf.clock = readU64(raw, &at);
    out.leaf.image = std.meta.intToEnum(Fold.ImageKind, raw[at]) catch return error.InvalidSourceFoldOperandImage;
    at += 1;
    if (raw[at] > 1) return error.InvalidSourceFoldOperandBoolean;
    out.leaf.touched = raw[at] == 1;
    at += 1;
    out.leaf.image_ordinal = readU64(raw, &at);
    out.leaf.touch_ordinal = readU64(raw, &at);
    out.left.before = raw[at..][0..32].*;
    at += 32;
    out.left.after = raw[at..][0..32].*;
    at += 32;
    out.right.before = raw[at..][0..32].*;
    at += 32;
    out.right.after = raw[at..][0..32].*;
    at += 32;
    try out.coordinate.validate();
    if ((kind == .leaf and height != 0) or (kind == .branch and height == 0) or (kind == .root and (height != 30 or index != 0))) return error.InvalidSourceFoldOperandKind;
    std.debug.assert(at == RECORD_BYTES);
    return out;
}
fn length(count: u32, limits: Limits) !usize {
    if (count == 0 or count > limits.max_operations or limits.max_operations > 4096 or limits.max_file_bytes == 0) return error.SourceFoldOperandResourceLimit;
    const bytes = try std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, count, RECORD_BYTES));
    if (bytes > limits.max_file_bytes) return error.SourceFoldOperandResourceLimit;
    return bytes;
}
fn header(page: Protocol.Page, plan_id: [32]u8, page_identity: [32]u8) [HEADER_BYTES]u8 {
    var out: [HEADER_BYTES]u8 = @splat(0);
    @memcpy(out[0..8], MAGIC);
    @memcpy(out[8..40], &plan_id);
    @memcpy(out[40..72], &page_identity);
    std.mem.writeInt(u32, out[72..76], page.index, .little);
    std.mem.writeInt(u64, out[76..84], page.first, .little);
    std.mem.writeInt(u32, out[84..88], page.count, .little);
    std.mem.writeInt(u32, out[88..92], page.row_log, .little);
    std.mem.writeInt(u32, out[92..96], RECORD_BYTES, .little);
    return out;
}
/// Exact existing PAGE framing, also used by same-inode draft promotion.
pub const encodedHeader = header;
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, page: Protocol.Page, plan_id: [32]u8, page_identity: [32]u8, operations: []const Fold.Operation, limits: Limits) !Pin {
    // Keep the existing API; encoding no longer needs an allocator or a second
    // complete page beside the original operations.
    _ = a;
    if (operations.len != page.count or std.mem.allEqual(u8, &page_identity, 0) or std.mem.allEqual(u8, &plan_id, 0)) return error.InvalidSourceFoldOperandPage;
    const bytes = try length(page.count, limits);
    _ = try std.math.add(u64, page.first, page.count - 1);
    var encoded = Encoder{ .prefix = header(page, plan_id, page_identity), .first = page.first, .operations = operations };
    try Files.publishStream(dir, name, &encoded);
    return .{ .byte_len = bytes, .sha256 = encoded.hash.finalResult(), .page_identity = page_identity };
}
const Encoder = struct {
    prefix: [HEADER_BYTES]u8,
    first: u64,
    operations: []const Fold.Operation,
    hash: Hash = Hash.init(.{}),
    pub fn write(self: *Encoder, file: std.fs.File) !void {
        try file.writeAll(&self.prefix);
        self.hash.update(&self.prefix);
        var buffer: [BUFFER_BYTES]u8 = undefined;
        var start: usize = 0;
        while (start < self.operations.len) {
            const count = @min(BUFFER_RECORDS, self.operations.len - start);
            for (self.operations[start..][0..count], 0..) |operation, i| {
                if (operation.ordinal != self.first + start + i) return error.InvalidSourceFoldOperandOrder;
                try encodeOperation(operation, buffer[i * RECORD_BYTES ..][0..RECORD_BYTES]);
            }
            const chunk = buffer[0 .. count * RECORD_BYTES];
            try file.writeAll(chunk);
            self.hash.update(chunk);
            start += count;
        }
    }
};
pub const Loaded = struct {
    a: std.mem.Allocator,
    operations: []Fold.Operation,
    pub fn deinit(self: *Loaded) void {
        self.a.free(self.operations);
        self.* = undefined;
    }
};
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, page: Protocol.Page, plan_id: [32]u8, page_identity: [32]u8, pin: Pin, limits: Limits) !Loaded {
    const bytes = try length(page.count, limits);
    if (pin.byte_len != bytes or !std.meta.eql(pin.page_identity, page_identity)) return error.InvalidSourceFoldOperandPage;
    _ = try std.math.add(u64, page.first, page.count - 1);
    const file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != bytes) return error.TamperedV5BundleFileLength;
    var prefix: [HEADER_BYTES]u8 = undefined;
    if (try file.preadAll(&prefix, 0) != prefix.len) return error.TamperedV5BundleFileLength;
    var hash = Hash.init(.{});
    hash.update(&prefix);
    const valid_header = std.mem.eql(u8, &prefix, &header(page, plan_id, page_identity));
    const operations = try a.alloc(Fold.Operation, page.count);
    errdefer a.free(operations);
    var buffer: [BUFFER_BYTES]u8 = undefined;
    var start: usize = 0;
    var invalid: ?anyerror = null;
    while (start < operations.len) {
        const count = @min(BUFFER_RECORDS, operations.len - start);
        const chunk = buffer[0 .. count * RECORD_BYTES];
        if (try file.preadAll(chunk, HEADER_BYTES + start * RECORD_BYTES) != chunk.len) return error.TamperedV5BundleFileLength;
        hash.update(chunk);
        for (operations[start..][0..count], 0..) |*operation, i| {
            operation.* = decodeOperation(buffer[i * RECORD_BYTES ..][0..RECORD_BYTES]) catch |failure| {
                invalid = failure;
                continue;
            };
            if (operation.ordinal != page.first + start + i) invalid = error.InvalidSourceFoldOperandOrder;
        }
        start += count;
    }
    var trailing: [1]u8 = undefined;
    if (try file.preadAll(&trailing, bytes) != 0 or !std.meta.eql(hash.finalResult(), pin.sha256)) return error.TamperedV5BundleFileHash;
    if (!valid_header) return error.InvalidSourceFoldOperandHeader;
    if (invalid) |failure| return failure;
    return .{ .a = a, .operations = operations };
}
