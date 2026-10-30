//! Exact original admission serialization, without executing a CPU channel.
//! Values are immutable public operands; hash/transcript work runs on device.
const std = @import("std");
const core = @import("stwo_core");
pub const Kind = enum { words, felts, root };
pub const Frame = struct { kind: Kind, first: u32, count: u32 };
pub const Prefix = struct { words: []const u32, frames: []const Frame, claims_start: u32 };
pub fn derive(a: std.mem.Allocator, admission: anytype, claim_count: usize) !Prefix {
    var b = Recorder{ .a = a };
    defer b.words.deinit(a);
    defer b.frames.deinit(a);
    try admission.mix(&b);
    try b.check();
    const prefix_count = b.frames.items.len;
    const dummy = try a.alloc(core.fields.qm31.QM31, claim_count);
    defer a.free(dummy);
    @memset(dummy, core.fields.qm31.QM31.zero());
    const claims_start: u32 = @intCast(b.words.items.len);
    try admission.mixClaims(&b, dummy);
    try b.check();
    if (b.frames.items.len != prefix_count + 2 or b.frames.items[prefix_count].kind != .words or b.frames.items[prefix_count].count != 3 or b.frames.items[prefix_count + 1].kind != .felts) return error.InvalidResidentAdmissionFraming;
    // Only the claims header is static; live physical claims are absorbed later.
    b.words.shrinkRetainingCapacity(claims_start + 3);
    b.frames.shrinkRetainingCapacity(prefix_count);
    const words = try b.words.toOwnedSlice(a);
    errdefer a.free(words);
    return .{ .words = words, .frames = try b.frames.toOwnedSlice(a), .claims_start = claims_start };
}
const Recorder = struct {
    a: std.mem.Allocator,
    words: std.ArrayList(u32) = .empty,
    frames: std.ArrayList(Frame) = .empty,
    failed: ?anyerror = null,
    pub fn mixU32s(self: *Recorder, words: []const u32) void {
        self.append(.words, words) catch |e| {
            self.failed = e;
        };
    }
    pub fn mixRoot(self: *Recorder, root: [32]u8) void {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, root[i * 4 ..][0..4], .little);
        self.append(.root, &words) catch |e| {
            self.failed = e;
        };
    }
    pub fn mixFelts(self: *Recorder, values: []const core.fields.qm31.QM31) void {
        if (self.failed != null) return;
        const first = self.words.items.len;
        for (values) |q| for (q.toM31Array()) |v| self.words.append(self.a, v.v) catch |e| {
            self.failed = e;
            return;
        };
        self.frame(.felts, first) catch |e| {
            self.failed = e;
        };
    }
    fn append(self: *Recorder, kind: Kind, words: []const u32) !void {
        if (self.failed != null) return;
        const first = self.words.items.len;
        try self.words.appendSlice(self.a, words);
        try self.frame(kind, first);
    }
    fn frame(self: *Recorder, kind: Kind, first: usize) !void {
        if (self.words.items.len > std.math.maxInt(u32)) return error.ResidentAdmissionSizeLimit;
        try self.frames.append(self.a, .{ .kind = kind, .first = @intCast(first), .count = @intCast(self.words.items.len - first) });
    }
    fn check(self: *const Recorder) !void {
        if (self.failed) |e| return e;
    }
};
