const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const memory = frontend.rv64_air.memory;
const codec = @import("../rv64_ram_context.zig");
const a = std.testing.allocator;

fn sha(bytes: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return value;
}
fn fixture() ![]u8 {
    var native = frontend.rv64.memory.Memory.init(a, .{});
    defer native.deinit();
    try native.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .write = true } });
    try native.store(0x1000, 8, 17);
    const updates = [_]memory.transition.NetUpdate{.{ .address = 0x1000, .value = 19, .byte_mask = 1 }};
    var witness = try memory.transition.Witness.build(a, &native, &.{1}, &updates);
    defer witness.deinit();
    return codec.encode(a, &witness, &updates);
}

test "RV64 public RAM context: canonical roundtrip and independently pinned identity" {
    const bytes = try fixture();
    defer a.free(bytes);
    var value = try codec.decode(a, bytes, sha(bytes));
    defer value.deinit();
    try value.witness.verifyUpdates(a, value.witness.before, value.witness.after, value.page_indices, value.updates);
    const roundtrip = try codec.encode(a, &value.witness, value.updates);
    defer a.free(roundtrip);
    try std.testing.expectEqualSlices(u8, bytes, roundtrip);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.RamContextDigestMismatch, codec.decode(fail.allocator(), bytes, @splat(0)));
}

test "RV64 public RAM context: bounded headers canonical roots and exact changes reject mutations" {
    const bytes = try fixture();
    defer a.free(bytes);
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    changed[0] ^= 1;
    try std.testing.expectError(error.InvalidRamContextVersion, codec.decode(a, changed, sha(changed)));
    @memcpy(changed, bytes);
    std.mem.writeInt(u32, changed[8..12], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidRamContextShape, codec.decode(a, changed, sha(changed)));
    @memcpy(changed, bytes);
    std.mem.writeInt(u32, changed[20..24], @import("stwo_core").fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalDigest, codec.decode(a, changed, sha(changed)));
    @memcpy(changed, bytes);
    changed[92 + 8 + 512 * 11 + 8] ^= 1;
    try std.testing.expectError(error.RamPermissionMutation, codec.decode(a, changed, sha(changed)));
    @memcpy(changed, bytes);
    changed[changed.len - 9] ^= 1;
    try std.testing.expectError(error.RamNetUpdateMismatch, codec.decode(a, changed, sha(changed)));
    try std.testing.expectError(error.InvalidRamContextShape, codec.decode(a, bytes[0 .. bytes.len - 1], sha(bytes[0 .. bytes.len - 1])));
}

fn failingRoundtrip(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var value = try codec.decode(allocator, bytes, sha(bytes));
    defer value.deinit();
    const output = try codec.encode(allocator, &value.witness, value.updates);
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, bytes, output);
}

test "RV64 public RAM context: decode and encode clean every allocation failure" {
    const bytes = try fixture();
    defer a.free(bytes);
    try std.testing.checkAllAllocationFailures(a, failingRoundtrip, .{bytes});
}
