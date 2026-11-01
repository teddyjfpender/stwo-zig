//! Bounded stage-one file, not execution acceptance. Trusted roster, statement,
//! FIXED identities and relation selection are supplied independently; the file
//! cannot redefine them. Decode -> verifyAndSeal -> ALL physical proofs/closure.
const std = @import("std");
const Manifest = @import("manifest.zig");
const ChildWire = @import("wire.zig");
pub const MAGIC = "RV64MGK1";
pub const MAX_BYTES = 64 << 20;
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *@This(), len: usize) ![]const u8 {
        if (len > self.bytes.len - self.at) return error.TruncatedGlobalGkrManifest;
        const out = self.bytes[self.at..][0..len];
        self.at += len;
        return out;
    }
    fn integer(self: *@This()) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn digest(self: *@This()) ![32]u8 {
        return (try self.take(32))[0..32].*;
    }
};
fn integer(out: *std.ArrayList(u8), a: std.mem.Allocator, value: usize) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, std.math.cast(u32, value) orelse return error.GlobalGkrManifestLimit, .little);
    try out.appendSlice(a, &bytes);
}
fn header(r: *Reader, execution: [32]u8, expected: []const Manifest.ExpectedWorker) !void {
    if (!std.mem.eql(u8, try r.take(MAGIC.len), MAGIC)) return error.GlobalGkrManifestProfile;
    const statement = try r.digest();
    if (!std.mem.eql(u8, &statement, &execution)) return error.GlobalGkrManifestExecution;
    if (try r.integer() != expected.len) return error.GlobalGkrManifestRoster;
}
const EncodedChild = struct { digest: [32]u8, bytes: []const u8 };
const Entry = struct { main: [32]u8, child: ?EncodedChild };
fn entry(r: *Reader, worker: Manifest.ExpectedWorker) !Entry {
    if (try r.integer() != worker.ordinal) return error.GlobalGkrManifestOrdinal;
    const main = try r.digest();
    const local = try r.integer();
    if (local != @intFromBool(worker.kind == .cpu)) return error.GlobalGkrManifestProfile;
    const child: ?EncodedChild = if (local == 1) value: {
        const digest = try r.digest();
        const len = try r.integer();
        if (len == 0 or len > ChildWire.MAX_BYTES) return error.GlobalGkrManifestLimit;
        break :value .{ .digest = digest, .bytes = try r.take(len) };
    } else null;
    return .{ .main = main, .child = child };
}
/// Preflight the complete framing before any owned proof/entry allocation.
fn preflight(bytes: []const u8, execution: [32]u8, expected: []const Manifest.ExpectedWorker) !void {
    try Manifest.validateRoster(expected);
    if (bytes.len > MAX_BYTES) return error.GlobalGkrManifestLimit;
    var r = Reader{ .bytes = bytes };
    try header(&r, execution, expected);
    for (expected) |worker| _ = try entry(&r, worker);
    if (r.at != bytes.len) return error.TrailingGlobalGkrManifest;
}
pub fn encode(a: std.mem.Allocator, execution: [32]u8, expected: []const Manifest.ExpectedWorker, stages: []const Manifest.StageOne) ![]u8 {
    try Manifest.validateStageOneShape(expected, stages);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, MAGIC);
    try out.appendSlice(a, &execution);
    try integer(&out, a, expected.len);
    for (expected, stages) |worker, stage| {
        try integer(&out, a, worker.ordinal);
        try out.appendSlice(a, &stage.main);
        try integer(&out, a, @intFromBool(stage.local != null));
        if (stage.local) |local| {
            const bytes = try ChildWire.encode(a, worker.local_instances.?, local.proof);
            defer a.free(bytes);
            if (bytes.len > MAX_BYTES -| out.items.len or MAX_BYTES -| out.items.len -| bytes.len < 36) return error.GlobalGkrManifestLimit;
            try out.appendSlice(a, &local.receipt_digest);
            try integer(&out, a, bytes.len);
            try out.appendSlice(a, bytes);
        }
        if (out.items.len > MAX_BYTES) return error.GlobalGkrManifestLimit;
    }
    return out.toOwnedSlice(a);
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    stages: []Manifest.StageOne,
    children: []?ChildWire.Owned,
    pub fn deinit(self: *@This()) void {
        for (self.children) |*child| if (child.*) |*owned| owned.deinit();
        self.allocator.free(self.children);
        self.allocator.free(self.stages);
        self.* = undefined;
    }
    pub fn verifyAndSeal(self: *const @This(), a: std.mem.Allocator, execution: [32]u8, expected: []const Manifest.ExpectedWorker) !Manifest.PendingManifest {
        return Manifest.verifyAndSeal(a, execution, expected, self.stages);
    }
};
pub fn decode(a: std.mem.Allocator, execution: [32]u8, expected: []const Manifest.ExpectedWorker, bytes: []const u8) !Owned {
    try preflight(bytes, execution, expected);
    const stages = try a.alloc(Manifest.StageOne, expected.len);
    errdefer a.free(stages);
    const children = try a.alloc(?ChildWire.Owned, expected.len);
    @memset(children, null);
    errdefer {
        for (children) |*child| if (child.*) |*owned| owned.deinit();
        a.free(children);
    }
    var r = Reader{ .bytes = bytes };
    try header(&r, execution, expected);
    for (expected, stages, children, 0..) |worker, *stage, *child, i| {
        const value = try entry(&r, worker);
        stage.* = .{ .main = value.main, .local = null };
        if (value.child) |local| {
            // Use the stable caller allocator, never a pointer into a moved
            // enclosing arena. Each child owns its independent decoder arena.
            child.* = try ChildWire.decode(a, worker.local_instances.?, local.bytes);
            stage.local = .{ .proof = &children[i].?.proof, .receipt_digest = local.digest };
        }
    }
    return .{ .allocator = a, .stages = stages, .children = children };
}
