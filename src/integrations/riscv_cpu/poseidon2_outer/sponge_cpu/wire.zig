//! Detached-route durable native fragments. No source kind, key, geometry or
//! statement is selected by these bytes. Receiver-owned Inventory fixes all of
//! those before decoding. CPU local proofs also supply the stage-one child;
//! late detached/catalog local proofs never become stage-one children.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const MAGIC = "OPDSNG01";
pub const Limits = struct { bytes: usize = 2 << 30, proof_bytes: usize = 64 << 20, claims: usize = 1024 };
pub const Fragment = struct {
    main: [36]u8,
    native: []u8,
    local: []u8,
    receipt: ?[36]u8,
    claims: []O,
    pub fn deinit(self: *Fragment, a: std.mem.Allocator) void {
        a.free(self.native);
        a.free(self.local);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const Bundle = struct {
    execution: [32]u8,
    fragments: []Fragment,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.fragments) |*fragment| fragment.deinit(a);
        a.free(self.fragments);
        self.* = undefined;
    }
};
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.DetachedWireTruncated;
        defer self.at += n;
        return self.bytes[self.at..][0..n];
    }
    fn word(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn root(self: *Reader) ![36]u8 {
        const value = (try self.take(36))[0..36].*;
        _ = try core.crypto.poseidon2_m31_sponge.decode(value);
        return value;
    }
};
fn word(out: []u8, at: *usize, value: usize) !void {
    std.mem.writeInt(u32, out[at.*..][0..4], std.math.cast(u32, value) orelse return error.DetachedWireLimit, .little);
    at.* += 4;
}
fn put(out: []u8, at: *usize, value: []const u8) void {
    @memcpy(out[at.*..][0..value.len], value);
    at.* += value.len;
}
pub fn encode(a: std.mem.Allocator, bundle: Bundle, limits: Limits) ![]u8 {
    if (bundle.fragments.len == 0 or bundle.fragments.len > 256) return error.DetachedWireRoster;
    var size: usize = MAGIC.len + 36;
    for (bundle.fragments) |f| {
        _ = try core.crypto.poseidon2_m31_sponge.decode(f.main);
        if (f.native.len == 0 or f.native.len > limits.proof_bytes or f.local.len > limits.proof_bytes or f.claims.len > limits.claims or (f.local.len == 0) != (f.receipt == null)) return error.DetachedWireLimit;
        if (f.receipt) |receipt| _ = try core.crypto.poseidon2_m31_sponge.decode(receipt);
        for (f.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.DetachedWireNoncanonicalClaim;
        size = try std.math.add(usize, size, 52 + @as(usize, if (f.receipt != null) 36 else 0));
        size = try std.math.add(usize, size, try std.math.mul(usize, 32, f.claims.len));
        size = try std.math.add(usize, size, try std.math.add(usize, f.native.len, f.local.len));
    }
    if (size > limits.bytes) return error.DetachedWireLimit;
    const out = try a.alloc(u8, size);
    errdefer a.free(out);
    var at: usize = 0;
    put(out, &at, MAGIC);
    put(out, &at, &bundle.execution);
    try word(out, &at, bundle.fragments.len);
    for (bundle.fragments) |f| {
        put(out, &at, &f.main);
        try word(out, &at, f.native.len);
        try word(out, &at, f.local.len);
        try word(out, &at, f.claims.len);
        try word(out, &at, @intFromBool(f.receipt != null));
        if (f.receipt) |receipt| put(out, &at, &receipt);
        for (f.claims) |claim| for (claim.toM31Array()) |v| try word(out, &at, v.v);
        put(out, &at, f.native);
        put(out, &at, f.local);
    }
    std.debug.assert(at == size);
    return out;
}
fn header(r: *Reader, execution: [32]u8, count: usize) !void {
    if (!std.mem.eql(u8, try r.take(MAGIC.len), MAGIC)) return error.DetachedWireProfile;
    if (!std.mem.eql(u8, try r.take(32), &execution)) return error.DetachedWireExecution;
    if (try r.word() != count) return error.DetachedWireRoster;
}
fn preflight(bytes: []const u8, execution: [32]u8, count: usize, limits: Limits) !void {
    if (count == 0 or count > 256 or bytes.len > limits.bytes) return error.DetachedWireLimit;
    var r = Reader{ .bytes = bytes };
    try header(&r, execution, count);
    for (0..count) |_| {
        _ = try r.root();
        const native = try r.word();
        const local = try r.word();
        const claims = try r.word();
        const receipt = try r.word();
        if (native == 0 or native > limits.proof_bytes or local > limits.proof_bytes or claims > limits.claims or receipt > 1 or (local == 0) != (receipt == 0)) return error.DetachedWireLimit;
        if (receipt != 0) _ = try r.root();
        for (0..try std.math.mul(usize, claims, 8)) |_| if (try r.word() >= core.fields.m31.Modulus) return error.DetachedWireNoncanonicalClaim;
        _ = try r.take(native);
        _ = try r.take(local);
    }
    if (r.at != bytes.len) return error.DetachedWireTrailing;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, execution: [32]u8, count: usize, limits: Limits) !Bundle {
    try preflight(bytes, execution, count, limits);
    var r = Reader{ .bytes = bytes };
    try header(&r, execution, count);
    const fragments = try a.alloc(Fragment, count);
    errdefer a.free(fragments);
    var made: usize = 0;
    errdefer for (fragments[0..made]) |*f| f.deinit(a);
    for (fragments) |*f| {
        const main = try r.root();
        const native_len = try r.word();
        const local_len = try r.word();
        const claims_len = try r.word();
        const receipt = if (try r.word() != 0) try r.root() else null;
        const claims = try a.alloc(O, claims_len);
        errdefer a.free(claims);
        for (claims) |*claim| {
            var coords: [8]M = undefined;
            for (&coords) |*v| v.* = M.fromCanonical(try r.word());
            claim.* = O.fromM31Array(coords);
        }
        const native = try a.dupe(u8, try r.take(native_len));
        errdefer a.free(native);
        const local = try a.dupe(u8, try r.take(local_len));
        f.* = .{ .main = main, .native = native, .local = local, .receipt = receipt, .claims = claims };
        made += 1;
    }
    return .{ .execution = execution, .fragments = fragments };
}
test "detached bundle rejects wrong authority and all lengths before allocation" {
    const a = std.testing.allocator;
    var native = [_]u8{ 1, 2 };
    var local = [_]u8{3};
    var claims = [_]O{O.one()};
    const root = @import("../pure_p2_native.zig").hashWords(&.{7});
    var fragments = [_]Fragment{.{ .main = root, .native = &native, .local = &local, .receipt = root, .claims = &claims }};
    const bundle = Bundle{ .execution = @splat(9), .fragments = &fragments };
    const bytes = try encode(a, bundle, .{});
    defer a.free(bytes);
    var decoded = try decode(a, bytes, bundle.execution, 1, .{});
    defer decoded.deinit(a);
    try std.testing.expectEqualSlices(u8, &native, decoded.fragments[0].native);
    try std.testing.expect(decoded.fragments[0].claims[0].eql(O.one()));
    try std.testing.expectError(error.DetachedWireExecution, decode(std.testing.failing_allocator, bytes, @splat(8), 1, .{}));
    try std.testing.expectError(error.DetachedWireRoster, decode(std.testing.failing_allocator, bytes, bundle.execution, 2, .{}));
    try std.testing.expectError(error.DetachedWireLimit, encode(std.testing.failing_allocator, bundle, .{ .bytes = bytes.len - 1 }));
    try std.testing.expectError(error.DetachedWireTruncated, decode(std.testing.failing_allocator, bytes[0 .. bytes.len - 1], bundle.execution, 1, .{}));
}
