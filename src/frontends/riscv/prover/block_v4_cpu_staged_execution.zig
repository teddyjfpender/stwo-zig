//! File-backed execution proof bytes with bounded one-leaf receiver loads.
//! Claims are small metadata; every file is checked against its captured hash.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const wire_mod = @import("block_execution_batch_receiver_v2.zig");
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const external = @import("block_execution_external_batch_v2.zig");

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const FilePin = struct { len: u64, sha256: [32]u8 };
pub const Entry = struct {
    native: FilePin,
    opcode: FilePin,
    extension: ?FilePin,
    opcode_claims: []sidecar.Claim,
    extension_claims: []external.Claim,
};

pub const Loaded = struct {
    a: std.mem.Allocator,
    wire: wire_mod.Wire,
    extension: ?batch.SerializedExternalProof,
    native_bytes: []u8,
    opcode_bytes: []u8,
    extension_bytes: ?[]u8,

    pub fn deinit(self: *Loaded) void {
        self.a.free(self.native_bytes);
        self.a.free(self.opcode_bytes);
        if (self.extension_bytes) |bytes| self.a.free(bytes);
        self.* = undefined;
    }
};

pub const Sink = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    entries: []Entry,
    next: usize = 0,
    total_bytes: u64 = 0,

    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, count: usize) !Sink {
        if (count == 0 or count > 1024) return error.InvalidStagedExecutionCount;
        return .{ .a = a, .dir = dir, .entries = try a.alloc(Entry, count) };
    }

    pub fn deinit(self: *Sink) void {
        for (self.entries[0..self.next]) |entry| {
            self.a.free(entry.opcode_claims);
            self.a.free(entry.extension_claims);
        }
        self.a.free(self.entries);
        self.* = undefined;
    }

    pub fn write(self: *Sink, index: usize, wire: wire_mod.Wire, extension_wire: ?batch.SerializedExternalProof) !void {
        if (index != self.next or index >= self.entries.len or wire.native_artifact.len == 0 or
            (extension_wire != null and @as(usize, extension_wire.?.instance_index) != index))
            return error.InvalidStagedExecutionOrder;
        const opcode_claims = try self.a.dupe(sidecar.Claim, wire.sidecar_claims);
        errdefer self.a.free(opcode_claims);
        const extension_claims = try self.a.dupe(external.Claim, if (extension_wire) |value| value.claims else &.{});
        errdefer self.a.free(extension_claims);
        const native = try self.store(.native, index, wire.native_artifact);
        const opcode = try self.store(.opcode, index, wire.sidecar_stark);
        const extension_pin = if (extension_wire) |value| try self.store(.extension, index, value.stark_bytes) else null;
        self.entries[index] = .{ .native = native, .opcode = opcode, .extension = extension_pin, .opcode_claims = opcode_claims, .extension_claims = extension_claims };
        self.next += 1;
    }

    /// The caller releases this before opening the next proof. The loaded
    /// claims borrow Sink metadata and remain valid until Sink.deinit.
    pub fn load(self: *Sink, index: usize) !Loaded {
        if (index >= self.next) return error.MissingStagedExecution;
        const entry = self.entries[index];
        const native = try self.read(.native, index, entry.native);
        errdefer self.a.free(native);
        const opcode = try self.read(.opcode, index, entry.opcode);
        errdefer self.a.free(opcode);
        const extension_bytes = if (entry.extension) |pin| try self.read(.extension, index, pin) else null;
        errdefer if (extension_bytes) |bytes| self.a.free(bytes);
        return .{ .a = self.a, .wire = .{ .native_artifact = native, .sidecar_stark = opcode, .sidecar_claims = entry.opcode_claims }, .extension = if (extension_bytes) |bytes| .{ .instance_index = @intCast(index), .stark_bytes = bytes, .claims = entry.extension_claims } else null, .native_bytes = native, .opcode_bytes = opcode, .extension_bytes = extension_bytes };
    }

    const Kind = enum { native, opcode, extension };
    fn filename(kind: Kind, index: usize, buffer: *[80]u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "block-v4-exec-{d}-{s}.bin", .{ index, @tagName(kind) });
    }
    fn store(self: *Sink, kind: Kind, index: usize, bytes: []const u8) !FilePin {
        if (bytes.len > MAX_FILE_BYTES) return error.StagedExecutionTooLarge;
        var buffer: [80]u8 = undefined;
        var file = try self.dir.createFile(try filename(kind, index, &buffer), .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        self.total_bytes = try std.math.add(u64, self.total_bytes, bytes.len);
        return .{ .len = bytes.len, .sha256 = hash(bytes) };
    }
    fn read(self: *Sink, kind: Kind, index: usize, pin: FilePin) ![]u8 {
        if (pin.len > MAX_FILE_BYTES) return error.StagedExecutionTooLarge;
        var buffer: [80]u8 = undefined;
        var file = try self.dir.openFile(try filename(kind, index, &buffer), .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(self.a, @intCast(pin.len));
        errdefer self.a.free(bytes);
        if (bytes.len != pin.len or !std.mem.eql(u8, &hash(bytes), &pin.sha256))
            return error.ChangedStagedExecution;
        return bytes;
    }
};

fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

test "staged execution bytes open one at a time and reject changed files" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var sink = try Sink.init(a, tmp.dir, 2);
    defer sink.deinit();
    try sink.write(0, .{ .native_artifact = &.{ 1, 2, 3 }, .sidecar_stark = &.{4}, .sidecar_claims = &.{} }, null);
    try sink.write(1, .{ .native_artifact = &.{ 5, 6 }, .sidecar_stark = &.{}, .sidecar_claims = &.{} }, null);
    var loaded = try sink.load(0);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, loaded.wire.native_artifact);
    loaded.deinit();
    var tampered = try tmp.dir.createFile("block-v4-exec-1-native.bin", .{ .truncate = true });
    try tampered.writeAll(&.{ 5, 7 });
    tampered.close();
    try std.testing.expectError(error.ChangedStagedExecution, sink.load(1));
}
