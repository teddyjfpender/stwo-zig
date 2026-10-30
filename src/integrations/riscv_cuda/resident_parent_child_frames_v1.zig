//! Cold original hash-frame and retry endpoint anchors for child FS replay.
//! All numeric sources are raw packet words or device replay trace/output.
const std = @import("std");
const core = @import("stwo_core");
const Replay = @import("resident_parent_child_transcript_v1.zig");
const Hash = @import("../../frontends/riscv/recursion/air/blake3_hash_plan.zig");
pub const Kind = enum(u32) { literal, packet, trace, output };
pub const Word = struct { kind: Kind, index: u32 };
pub const Encoding = enum { bytes4, scalar };
pub const Anchor = struct { circuit: u32, wire: u32, value: Word, encoding: Encoding };
pub const Frame = struct { circuit: u32, task: u32, attempt: ?u32, words: []const Word, sources: []const Anchor, digest: [8]u32 };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    frames: []const Frame,
    ports: []const Anchor,
    lengths: []const usize,
    g_rows: usize,
    xor_rows: usize,
    pub fn init(a: std.mem.Allocator, replay: *const Replay.Owned, namespace: u32, max_words: usize) !Owned {
        if (namespace != 1_000_000) return error.UnqualifiedResidentChildNamespace;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        var b = Builder{ .a = temp, .limit = max_words };
        for (replay.ports) |p| try b.ports.append(temp, .{ .circuit = p.circuit, .wire = p.wire, .value = convert(p.value), .encoding = .bytes4 });
        var circuit = namespace + 2;
        // Original initial state is a fixed public boundary, not a hash invocation.
        const initial = (core.channel.blake3.Channel{}).digestBytes();
        for (0..8) |i| try b.ports.append(temp, .{ .circuit = namespace, .wire = @intCast(i), .value = .{ .kind = .literal, .index = std.mem.readInt(u32, initial[i * 4 ..][0..4], .little) }, .encoding = .bytes4 });
        for (0..2) |i| try b.ports.append(temp, .{ .circuit = namespace + 1, .wire = @intCast(i), .value = .{ .kind = .literal, .index = 0 }, .encoding = .bytes4 });
        for (replay.tasks, 0..) |t, index| switch (t.kind) {
            0 => {},
            1, 2, 3, 4, 6 => {
                var words: std.ArrayList(Word) = .empty;
                try prefix(temp, &words, t.kind);
                for (0..8) |j| try words.append(temp, .{ .kind = .trace, .index = t.trace_first + @as(u32, @intCast(j)) });
                if (t.kind == 1 or t.kind == 2) {
                    try words.append(temp, .{ .kind = .literal, .index = if (t.kind == 2) t.count / 4 else t.count });
                    try words.append(temp, .{ .kind = .literal, .index = 0 });
                }
                if (t.kind == 6) try words.append(temp, .{ .kind = .literal, .index = t.aux });
                for (replay.refs[t.first..][0..t.count]) |v| try words.append(temp, convert(v));
                const hash_circuit = circuit + @as(u32, @intFromBool(t.kind == 4));
                try b.frame(hash_circuit, @intCast(index), null, try words.toOwnedSlice(temp));
                circuit += if (t.kind == 4 or t.kind == 6) @as(u32, 2) else 1;
            },
            5, 7 => {
                for (0..t.attempt_count) |attempt| {
                    const offset = t.attempt_first + @as(u32, @intCast(attempt)) * 32;
                    var words: std.ArrayList(Word) = .empty;
                    try prefix(temp, &words, 5);
                    for (0..8) |j| try words.append(temp, .{ .kind = .trace, .index = offset + 22 + @as(u32, @intCast(j)) });
                    try words.append(temp, .{ .kind = .trace, .index = offset + 18 });
                    try words.append(temp, .{ .kind = .trace, .index = offset + 19 });
                    const current = circuit + @as(u32, @intCast(2 * attempt));
                    try b.frame(current, @intCast(index), @intCast(attempt), try words.toOwnedSlice(temp));
                    if (t.kind == 5) {
                        for (0..8) |j| try b.ports.append(temp, .{ .circuit = current + 1, .wire = @intCast(j), .value = .{ .kind = .trace, .index = offset + 8 + @as(u32, @intCast(j)) }, .encoding = .scalar });
                        try b.ports.append(temp, .{ .circuit = current + 1, .wire = 8, .value = .{ .kind = .trace, .index = offset + 17 }, .encoding = .scalar });
                    } else {
                        const n = @min(8, t.count - @as(u32, @intCast(8 * attempt)));
                        for (0..n) |j| try b.ports.append(temp, .{ .circuit = current + 1, .wire = @intCast(j), .value = .{ .kind = .output, .index = t.output + @as(u32, @intCast(8 * attempt + j)) }, .encoding = .bytes4 });
                    }
                    for (0..2) |j| try b.ports.append(temp, .{ .circuit = circuit + 2 * t.attempt_count, .wire = @intCast(2 * attempt + j), .value = .{ .kind = .trace, .index = offset + 20 + @as(u32, @intCast(j)) }, .encoding = .bytes4 });
                    if (t.kind == 5) try b.ports.append(temp, .{ .circuit = circuit + 2 * t.attempt_count + 1, .wire = @intCast(attempt), .value = .{ .kind = .trace, .index = offset + 16 }, .encoding = .scalar });
                }
                if (t.kind == 5) {
                    try b.ports.append(temp, .{ .circuit = circuit + 2 * t.attempt_count + 1, .wire = t.attempt_count, .value = .{ .kind = .trace, .index = t.attempt_first + 32 * (t.attempt_count - 1) + 30 }, .encoding = .scalar });
                    try b.ports.append(temp, .{ .circuit = circuit + 2 * t.attempt_count + 2, .wire = 8, .value = .{ .kind = .trace, .index = t.attempt_first + 32 * (t.attempt_count - 1) + 31 }, .encoding = .scalar });
                    for (0..t.count) |j| try b.ports.append(temp, .{ .circuit = circuit + 2 * t.attempt_count + 2, .wire = @intCast(j), .value = .{ .kind = .output, .index = t.output + @as(u32, @intCast(j)) }, .encoding = .scalar });
                }
                circuit += 2 * t.attempt_count + @as(u32, if (t.kind == 5) 3 else 1);
            },
            else => return error.InvalidResidentChildFrame,
        };
        const frames = try b.frames.toOwnedSlice(temp);
        const lengths = try temp.alloc(usize, frames.len);
        for (frames, lengths) |f, *n| n.* = f.words.len * 4;
        return .{ .arena = arena, .frames = frames, .ports = try b.ports.toOwnedSlice(temp), .lengths = lengths, .g_rows = b.g_rows, .xor_rows = b.xor_rows };
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn convert(v: Replay.Ref) Word {
    return .{ .kind = if (v.kind == 0) .literal else .packet, .index = v.index };
}
fn prefix(a: std.mem.Allocator, out: *std.ArrayList(Word), domain: u32) !void {
    const bytes = core.channel.blake3.PROTOCOL_ID;
    comptime std.debug.assert(bytes.len == 27);
    for (0..6) |i| try out.append(a, .{ .kind = .literal, .index = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little) });
    try out.append(a, .{ .kind = .literal, .index = @as(u32, bytes[24]) | (@as(u32, bytes[25]) << 8) | (@as(u32, bytes[26]) << 16) | (domain << 24) });
}
const Builder = struct {
    a: std.mem.Allocator,
    limit: usize,
    total: usize = 0,
    g_rows: usize = 0,
    xor_rows: usize = 0,
    frames: std.ArrayList(Frame) = .empty,
    ports: std.ArrayList(Anchor) = .empty,
    fn frame(self: *Builder, circuit: u32, task: u32, attempt: ?u32, words: []const Word) !void {
        self.total = try std.math.add(usize, self.total, words.len);
        if (self.total > self.limit) return error.ResidentChildFrameLimit;
        var plan = try Hash.build(self.a, words.len * 4);
        defer plan.deinit();
        const sources = try self.a.alloc(Anchor, plan.sources.len);
        for (plan.sources, sources) |source, *out| out.* = .{ .circuit = circuit, .wire = source.wire, .encoding = .bytes4, .value = switch (source.value) {
            .constant => |v| .{ .kind = .literal, .index = v },
            .input => |s| blk: {
                if (s.offset % 4 != 0 or s.len != 4 or s.offset / 4 >= words.len) return error.InvalidResidentChildFrame;
                break :blk words[s.offset / 4];
            },
        } };
        try self.frames.append(self.a, .{ .circuit = circuit, .task = task, .attempt = attempt, .words = words, .sources = sources, .digest = plan.output });
        self.g_rows += plan.g.len;
        self.xor_rows += plan.xor.len;
    }
};
