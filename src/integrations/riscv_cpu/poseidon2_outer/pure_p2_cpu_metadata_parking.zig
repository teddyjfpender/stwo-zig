//! Producer-only immutable advice custody. This is not public proof authority:
//! restored rows still enter the same MAIN/GKR/binding constraints as before.
//! Files are unlinked, bounded by the same Store quota as committed MAIN, and
//! restored into the original explicitly budgeted heap (never uncharged mmap).
const std = @import("std");
const engine = @import("stwo_prover_engine");
const CPU = @import("../word16_execution/cpu_source.zig");
const Store = @import("pure_p2_retained_main.zig").Store;
const Reserved = engine.file_backed_allocator.ReservedFile;
const Hash = std.crypto.hash.sha2.Sha256;
const Descriptor = struct {
    program: [32]u8,
    boundary: @import("stwo_riscv_frontend").rv64_air.word16_execution.types.Boundary,
    epoch: u16,
    log: u32,
    compact: bool,
    fn from(source: *const CPU.Source) Descriptor {
        return .{ .program = source.program.identity, .boundary = source.public, .epoch = source.epoch, .log = source.log_size, .compact = source.compact };
    }
};
comptime {
    // Each byte is an initialized field: no padding may reach the digest/file.
    std.debug.assert(@sizeOf(CPU.Metadata) == 56);
    std.debug.assert(@offsetOf(CPU.Metadata, "values") == 0);
    std.debug.assert(@offsetOf(CPU.Metadata, "clocks") == 40);
    std.debug.assert(@offsetOf(CPU.Metadata, "rom_row") == 52);
}
pub const Token = struct {
    store: *Store,
    file: ?Reserved,
    descriptor: Descriptor,
    digest: [32]u8,
    count: usize,
    rounded: usize,
    restored: ?[]const CPU.Metadata = null,
    pub fn deinit(self: *Token) void {
        if (self.file) |*file| {
            file.deinit();
            self.store.releaseAdvice(self.rounded);
        }
        self.file = null;
    }
    /// Allocation, length, descriptor and integrity failures leave both token
    /// and empty source untouched, allowing cleanup or a later bounded retry.
    pub fn restore(self: *Token, source: *CPU.Source) !void {
        const file = self.file orelse return error.OpMetadataParkingConsumed;
        try exclusive(source);
        if (self.restored != null or source.metadata.len != 0 or !std.meta.eql(self.descriptor, Descriptor.from(source))) return error.OpMetadataParkingSource;
        if (try file.file.getEndPos() != self.rounded) return error.OpMetadataParkingLength;
        const values = try source.allocator.alloc(CPU.Metadata, self.count);
        errdefer source.allocator.free(values);
        const bytes = std.mem.sliceAsBytes(values);
        if (try file.file.preadAll(bytes, 0) != bytes.len) return error.OpMetadataParkingLength;
        var digest: [32]u8 = undefined;
        Hash.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &self.digest, &digest)) return error.OpMetadataParkingIntegrity;
        source.metadata = values;
        self.restored = values;
    }
    /// Source construction/MAIN/GKR read metadata through const slices. Keep
    /// the single immutable file through both stages; only the restored heap
    /// view changes ownership from capture to source. No second write/hash.
    pub fn retireRestored(self: *Token, source: *CPU.Source) !void {
        try exclusive(source);
        const values = self.restored orelse return error.OpMetadataParkingNotRestored;
        if (self.file == null or source.metadata.ptr != values.ptr or source.metadata.len != values.len or !std.meta.eql(self.descriptor, Descriptor.from(source))) return error.OpMetadataParkingSource;
        if (@import("builtin").is_test) {
            // Qualification checks the const-consumer invariant across the
            // actual build+seal path; production avoids this redundant pass.
            var digest: [32]u8 = undefined;
            Hash.hash(std.mem.sliceAsBytes(source.metadata), &digest, .{});
            if (!std.mem.eql(u8, &self.digest, &digest)) return error.OpMetadataParkingMutation;
        }
        source.allocator.free(source.metadata);
        source.metadata = &.{};
        self.restored = null;
    }
};
fn exclusive(source: *const CPU.Source) !void {
    if (source.metadata_owner != null or source.capture_seal != null or source.sealed_view) return error.OpMetadataParkingShared;
    if (!source.capture_records_retired or source.device_main.len != 0 or source.device_projection_owner != null) return error.OpMetadataParkingPhase;
}
pub fn roundedBytes(source: *const CPU.Source) !usize {
    try exclusive(source);
    if (source.metadata.len != source.public.steps or source.metadata.len == 0) return error.OpMetadataParkingCount;
    return Reserved.roundedLength(try std.math.mul(usize, source.metadata.len, @sizeOf(CPU.Metadata)));
}
pub fn park(store: *Store, source: *CPU.Source) !Token {
    const rounded = try roundedBytes(source);
    const bytes = std.mem.sliceAsBytes(source.metadata);
    const reserved = try store.reserveAdvice(bytes.len);
    errdefer store.releaseAdvice(reserved);
    std.debug.assert(rounded == reserved);
    var file = try Reserved.init(store.backing.dir, bytes.len);
    errdefer file.deinit();
    var digest: [32]u8 = undefined;
    Hash.hash(bytes, &digest, .{});
    try file.file.pwriteAll(bytes, 0);
    const token = Token{ .store = store, .file = file, .descriptor = Descriptor.from(source), .digest = digest, .count = source.metadata.len, .rounded = rounded };
    // Publish only after all fallible work. Deinit now sees an ordinary empty
    // owned slice, and no downstream source consumer runs until restore.
    source.allocator.free(source.metadata);
    source.metadata = &.{};
    return token;
}

test "OP metadata parking is exact source bound quota charged and failure atomic" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(a, path, 1 << 20, 1 << 20);
    defer store.deinit();
    var program: @import("../word16_execution/program.zig").Program = undefined;
    program.identity = @splat(3);
    var source: CPU.Source = undefined;
    source.allocator = a;
    source.program = &program;
    source.public = std.mem.zeroes(@TypeOf(source.public));
    source.public.steps = 2;
    source.epoch = 1;
    source.log_size = 5;
    source.compact = true;
    source.fused_tail = true;
    source.u8_pairs = true;
    source.main_projection_closed = false;
    source.metadata_owner = null;
    source.capture_seal = null;
    source.sealed_view = false;
    source.capture_records_retired = true;
    source.device_main = &.{};
    source.device_projection_owner = null;
    source.metadata = try a.alloc(CPU.Metadata, 2);
    defer a.free(source.metadata);
    for (@constCast(source.metadata), 0..) |*row, i| row.* = .{ .values = @splat(i + 5), .clocks = @splat(@intCast(i)), .rom_row = @intCast(i) };
    const saved = [2]CPU.Metadata{ source.metadata[0], source.metadata[1] };
    source.capture_seal = .{ .digest = @splat(0) };
    try std.testing.expectError(error.OpMetadataParkingShared, park(&store, &source));
    source.capture_seal = null;
    const old_limit = store.disk_limit;
    store.disk_limit = 1;
    try std.testing.expectError(error.OpParkingDiskLimit, park(&store, &source));
    try std.testing.expectEqualSlices(CPU.Metadata, &saved, source.metadata);
    store.disk_limit = old_limit;
    var token = try park(&store, &source);
    defer token.deinit();
    try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
    try std.testing.expectEqual(token.rounded, store.reserved);
    source.public.final_pc += 4;
    try std.testing.expectError(error.OpMetadataParkingSource, token.restore(&source));
    source.public.final_pc -= 4;
    source.allocator = std.testing.failing_allocator;
    try std.testing.expectError(error.OutOfMemory, token.restore(&source));
    source.allocator = a;
    try std.testing.expect(token.file != null and source.metadata.len == 0);
    try token.file.?.file.pwriteAll(&.{255}, 0);
    try std.testing.expectError(error.OpMetadataParkingIntegrity, token.restore(&source));
    try token.file.?.file.pwriteAll(std.mem.sliceAsBytes(&saved), 0);
    try token.file.?.file.setEndPos(1);
    try std.testing.expectError(error.OpMetadataParkingLength, token.restore(&source));
    try token.file.?.file.setEndPos(token.rounded);
    try token.file.?.file.pwriteAll(std.mem.sliceAsBytes(&saved), 0);
    try token.restore(&source);
    try std.testing.expectEqualSlices(CPU.Metadata, &saved, source.metadata);
    try std.testing.expectEqual(token.rounded, store.reserved);
    try std.testing.expectError(error.OpMetadataParkingSource, token.restore(&source));
    @constCast(source.metadata)[0].clocks[0] += 1;
    try std.testing.expectError(error.OpMetadataParkingMutation, token.retireRestored(&source));
    @constCast(source.metadata)[0].clocks[0] -= 1;
    try token.retireRestored(&source);
    try token.restore(&source);
    try std.testing.expectEqualSlices(CPU.Metadata, &saved, source.metadata);
    token.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
    try std.testing.expectError(error.OpMetadataParkingConsumed, token.restore(&source));
}
