//! Bounded transport for root-facing public metadata. This grants no source,
//! key or execution authority; Receiver.prepare and verifyRoot are mandatory.
const std = @import("std");
const core = @import("stwo_core");
const Receiver = @import("pure_p2_op_root_receiver.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Sponge = core.crypto.poseidon2_m31_sponge;
const MAGIC = "OPR2S001";
pub const Limits = struct { bytes: usize, leaves: usize = 256, claims_per_leaf: usize = 4096 };
pub const Owned = struct {
    metadata: Receiver.Metadata,
    claims: []O,
    pub fn deinit(self: *Owned, a: std.mem.Allocator) void {
        a.free(self.metadata.leaves);
        a.free(self.claims);
        self.* = undefined;
    }
};
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.TruncatedOpRootSidecar;
        const result = self.bytes[self.at..][0..n];
        self.at += n;
        return result;
    }
    fn word(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn digest(self: *Reader) ![36]u8 {
        const result = (try self.take(36))[0..36].*;
        _ = try Sponge.decode(result);
        return result;
    }
};
fn word(out: []u8, at: *usize, value: usize) void {
    std.mem.writeInt(u32, out[at.*..][0..4], @intCast(value), .little);
    at.* += 4;
}
fn copy(out: []u8, at: *usize, value: []const u8) void {
    @memcpy(out[at.*..][0..value.len], value);
    at.* += value.len;
}
fn checkCount(count: usize, limits: Limits) !void {
    if (count == 0 or count > 256 or count > limits.leaves) return error.OpRootSidecarLimit;
}
pub fn encode(a: std.mem.Allocator, metadata: Receiver.Metadata, limits: Limits) ![]u8 {
    try checkCount(metadata.leaves.len, limits);
    _ = try Sponge.decode(metadata.manifest);
    var size: usize = 80;
    for (metadata.leaves, 0..) |leaf, i| {
        if (leaf.ordinal != i) return error.OpRootSidecarOrder;
        if (leaf.claims.len > 4096 or leaf.claims.len > limits.claims_per_leaf) return error.OpRootSidecarLimit;
        _ = try Sponge.decode(leaf.main);
        if (leaf.receipt) |receipt| _ = try Sponge.decode(receipt);
        size = try std.math.add(usize, size, 84 + leaf.claims.len * 32);
        for (leaf.claims) |claim| for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.NoncanonicalOpRootSidecar;
    }
    if (size > limits.bytes) return error.OpRootSidecarLimit;
    const out = try a.alloc(u8, size);
    var at: usize = 0;
    copy(out, &at, MAGIC);
    copy(out, &at, &metadata.execution);
    copy(out, &at, &metadata.manifest);
    word(out, &at, metadata.leaves.len);
    for (metadata.leaves) |leaf| {
        word(out, &at, leaf.ordinal);
        copy(out, &at, &leaf.main);
        word(out, &at, @intFromBool(leaf.receipt != null));
        copy(out, &at, &(leaf.receipt orelse @as([36]u8, @splat(0))));
        word(out, &at, leaf.claims.len);
        for (leaf.claims) |claim| for (claim.toM31Array()) |value| word(out, &at, value.v);
    }
    std.debug.assert(at == size);
    return out;
}
// Validate every count, flag, root, claim and extent before owned allocations.
fn preflight(bytes: []const u8, limits: Limits) !usize {
    if (bytes.len > limits.bytes) return error.OpRootSidecarLimit;
    var r = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try r.take(8), MAGIC)) return error.InvalidOpRootSidecar;
    _ = try r.take(32);
    _ = try r.digest();
    const n = try r.word();
    try checkCount(n, limits);
    var total: usize = 0;
    for (0..n) |i| {
        if (try r.word() != i) return error.OpRootSidecarOrder;
        _ = try r.digest();
        const present = try r.word();
        if (present > 1) return error.InvalidOpRootSidecar;
        const receipt = try r.digest();
        if (present == 0 and !std.mem.allEqual(u8, &receipt, 0)) return error.NoncanonicalOpRootSidecar;
        const claims = try r.word();
        if (claims > 4096 or claims > limits.claims_per_leaf) return error.OpRootSidecarLimit;
        total += claims;
        for (0..@as(usize, claims) * 8) |_| if (try r.word() >= core.fields.m31.Modulus) return error.NoncanonicalOpRootSidecar;
    }
    if (r.at != bytes.len) return error.TrailingOpRootSidecar;
    return total;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !Owned {
    const total = try preflight(bytes, limits);
    var r = Reader{ .bytes = bytes, .at = 8 };
    const execution = (try r.take(32))[0..32].*;
    const manifest = try r.digest();
    const n = try r.word();
    const leaves = try a.alloc(Receiver.Leaf, n);
    errdefer a.free(leaves);
    const claims = try a.alloc(O, total);
    errdefer a.free(claims);
    var offset: usize = 0;
    for (leaves) |*leaf| {
        const ordinal = try r.word();
        const main = try r.digest();
        const present = try r.word();
        const receipt = try r.digest();
        const count = try r.word();
        const values = claims[offset..][0..count];
        for (values) |*value| {
            var coordinates: [8]M = undefined;
            for (&coordinates) |*coordinate| coordinate.* = M.fromCanonical(try r.word());
            value.* = O.fromM31Array(coordinates);
        }
        leaf.* = .{ .ordinal = ordinal, .main = main, .receipt = if (present == 1) receipt else null, .claims = values };
        offset += count;
    }
    std.debug.assert(offset == total and r.at == bytes.len);
    return .{ .metadata = .{ .execution = execution, .manifest = manifest, .leaves = leaves }, .claims = claims };
}

test "OP root sidecar is bounded canonical and allocation failure atomic" {
    const a = std.testing.allocator;
    const digest = Sponge.encode(@splat(M.one()));
    const claims = [_]O{ O.one(), O.zero() };
    const leaves = [_]Receiver.Leaf{
        .{ .ordinal = 0, .main = digest, .receipt = digest, .claims = &claims },
        .{ .ordinal = 1, .main = digest, .receipt = null, .claims = &.{} },
    };
    const metadata = Receiver.Metadata{ .execution = @splat(0x43), .manifest = digest, .leaves = &leaves };
    const limits = Limits{ .bytes = 312 };
    const bytes = try encode(a, metadata, limits);
    defer a.free(bytes);
    try std.testing.expectEqual(@as(usize, 312), bytes.len);
    var restored = try decode(a, bytes, limits);
    defer restored.deinit(a);
    try std.testing.expectEqualDeep(metadata, restored.metadata);
    try std.testing.expectError(error.OpRootSidecarLimit, encode(std.testing.failing_allocator, metadata, .{ .bytes = bytes.len - 1 }));
    try std.testing.expectError(error.OpRootSidecarLimit, decode(std.testing.failing_allocator, bytes, .{ .bytes = bytes.len - 1 }));
    try std.testing.expectError(error.TruncatedOpRootSidecar, decode(std.testing.failing_allocator, bytes[0 .. bytes.len - 1], limits));
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    // Second leaf's absent receipt must contain the unique all-zero encoding.
    changed[272] = 1;
    try std.testing.expectError(error.NoncanonicalOpRootSidecar, decode(std.testing.failing_allocator, changed, limits));
    changed[272] = 0;
    std.mem.writeInt(u32, changed[268..272], 2, .little);
    try std.testing.expectError(error.InvalidOpRootSidecar, decode(std.testing.failing_allocator, changed, limits));
    std.mem.writeInt(u32, changed[268..272], 0, .little);
    std.mem.writeInt(u32, changed[228..232], 0, .little);
    try std.testing.expectError(error.OpRootSidecarOrder, decode(std.testing.failing_allocator, changed, limits));
    std.mem.writeInt(u32, changed[228..232], 1, .little);
    std.mem.writeInt(u32, changed[72..76], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalPoseidonDigest, decode(std.testing.failing_allocator, changed, limits));
    @memcpy(changed[72..76], bytes[72..76]);
    std.mem.writeInt(u32, changed[164..168], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NoncanonicalOpRootSidecar, decode(std.testing.failing_allocator, changed, limits));
    const trailing = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
    defer a.free(trailing);
    try std.testing.expectError(error.TrailingOpRootSidecar, decode(std.testing.failing_allocator, trailing, .{ .bytes = trailing.len }));
    try std.testing.checkAllAllocationFailures(a, decodeAndRelease, .{ bytes, limits });
}
fn decodeAndRelease(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !void {
    var owned = try decode(a, bytes, limits);
    defer owned.deinit(a);
}
