//! Canonical frame routing from up to two authenticated digest roles.
//! Optional word payloads share the same byte router and authenticated producers.
const std = @import("std");
const core = @import("stwo_core");
const framing = core.channel.blake3.framing;
const graph = @import("blake3_hash_plan.zig");
const route = @import("blake3_byte_route.zig");
pub const Caller = struct { circuit: u32, first_wire: u32 };
pub const Binding = struct { role: framing.DigestRole, caller: Caller };
pub const PayloadBinding = struct { role: framing.PayloadRole, caller: Caller, word_count: usize };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    schedules: []route.Schedule,
    child_uses: [2][8]u32,
    payload_uses: []u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.schedules);
        self.allocator.free(self.payload_uses);
        self.* = undefined;
    }
};
const Ref = union(enum) { constant: u8, source: struct { child: u2, word: u32, byte: u2 } };
const Symbols = struct {
    refs: []Ref,
    cursor: usize = 0,
    bindings: []const Binding,
    seen: [2]bool = @splat(false),
    invalid: bool = false,
    payload: ?PayloadBinding,
    payload_seen: usize = 0,
    pub fn update(self: *Symbols, bytes: []const u8) void {
        for (bytes) |byte| {
            self.refs[self.cursor] = .{ .constant = byte };
            self.cursor += 1;
        }
    }
    pub fn protocolWord(self: *Symbols, role: framing.PayloadRole, index: usize, value: u32) void {
        if (self.payload) |payload| {
            if (role != payload.role or index != self.payload_seen or index >= payload.word_count) {
                self.invalid = true;
                framing.writeInt(self, u32, value);
                return;
            }
            for (0..4) |byte| {
                self.refs[self.cursor] = .{ .source = .{ .child = 2, .word = @intCast(index), .byte = @intCast(byte) } };
                self.cursor += 1;
            }
            self.payload_seen += 1;
        } else framing.writeInt(self, u32, value);
    }
    pub fn protocolDigest(self: *Symbols, role: framing.DigestRole, _: framing.Digest) void {
        var slot: ?u1 = null;
        for (self.bindings, 0..) |binding, i| if (binding.role == role) {
            slot = @intCast(i);
            self.seen[i] = true;
        };
        const child = slot orelse {
            self.invalid = true;
            self.update(&@as([32]u8, @splat(0)));
            return;
        };
        for (0..32) |i| {
            self.refs[self.cursor] = .{ .source = .{ .child = child, .word = @intCast(i / 4), .byte = @intCast(i % 4) } };
            self.cursor += 1;
        }
    }
};
pub fn build(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding) !Plan {
    return buildWithPayload(a, circuit, frame, bindings, null);
}
pub fn buildWithPayload(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding) !Plan {
    const p = core.fields.m31.Modulus;
    if (circuit >= p or bindings.len > 2) return error.InvalidBlake3FrameCaller;
    for (bindings, 0..) |binding, i| {
        const caller = binding.caller;
        if (caller.circuit >= p or caller.circuit == circuit or caller.first_wire >= p - 7) return error.InvalidBlake3FrameCaller;
        for (bindings[0..i]) |earlier| {
            const overlaps = earlier.caller.circuit == caller.circuit and earlier.caller.first_wire < caller.first_wire + 8 and caller.first_wire < earlier.caller.first_wire + 8;
            if (earlier.role == binding.role or overlaps) return error.InvalidBlake3FrameCaller;
        }
    }
    if (payload) |item| {
        const count: usize = switch (frame) {
            .words => |v| if (item.role == .words) v.values.len else return error.InvalidBlake3FrameCaller,
            .felts => |v| if (item.role == .felts) try std.math.mul(usize, v.values.len, 4) else return error.InvalidBlake3FrameCaller,
            .leaf => |v| if (item.role == .leaf) v.len else return error.InvalidBlake3FrameCaller,
            .integer => if (item.role == .integer) 2 else return error.InvalidBlake3FrameCaller,
            .pow => if (item.role == .nonce) 2 else return error.InvalidBlake3FrameCaller,
            .draw => if (item.role == .draw_index) 2 else return error.InvalidBlake3FrameCaller,
            else => return error.InvalidBlake3FrameCaller,
        };
        if (count != item.word_count or item.caller.circuit >= p or item.caller.circuit == circuit or item.caller.first_wire >= p or @as(u64, item.caller.first_wire) + count > p) return error.InvalidBlake3FrameCaller;
        for (bindings) |binding| if (binding.caller.circuit == item.caller.circuit) return error.InvalidBlake3FrameCaller;
    }
    const refs = try a.alloc(Ref, try frame.encodedSize());
    defer a.free(refs);
    var sink = Symbols{ .refs = refs, .bindings = bindings, .payload = payload };
    frame.write(&sink);
    for (sink.seen[0..bindings.len]) |seen| if (!seen) return error.InvalidBlake3FrameCaller;
    if (payload) |item| if (sink.payload_seen != item.word_count) return error.InvalidBlake3FrameCaller;
    if (sink.invalid) return error.InvalidBlake3FrameCaller;
    if (sink.cursor != refs.len) return error.InvalidBlake3Frame;
    var hash = try graph.build(a, refs.len);
    defer hash.deinit();
    var schedules: std.ArrayList(route.Schedule) = .empty;
    defer schedules.deinit(a);
    var counts: [2][8]u32 = .{ @splat(0), @splat(0) };
    const payload_counts = try a.alloc(u32, if (payload) |item| item.word_count else 0);
    errdefer a.free(payload_counts);
    @memset(payload_counts, 0);
    for (hash.sources) |source| switch (source.value) {
        .constant => {},
        .input => |part| {
            var s = route.Schedule{ .sources = .{ null, null }, .destination = .{ .circuit = circuit, .wire = source.wire }, .uses = hash.uses[source.wire], .bytes = @splat(.{ .constant = 0 }) };
            var owners: [2]?struct { child: u2, word: u32 } = .{ null, null };
            for (refs[part.offset..][0..part.len], 0..) |ref, i| switch (ref) {
                .constant => |value| s.bytes[i] = .{ .constant = value },
                .source => |d| {
                    const caller = if (d.child == 2) payload.?.caller else bindings[d.child].caller;
                    const endpoint = route.Endpoint{ .circuit = caller.circuit, .wire = caller.first_wire + d.word };
                    var slot: ?u1 = null;
                    for (s.sources, 0..) |existing, j| if (existing) |e| {
                        if (std.meta.eql(e, endpoint)) {
                            slot = @intCast(j);
                            break;
                        }
                    };
                    if (slot == null) for (&s.sources, 0..) |*existing, j| if (existing.* == null) {
                        existing.* = endpoint;
                        owners[j] = .{ .child = d.child, .word = d.word };
                        slot = @intCast(j);
                        break;
                    };
                    s.bytes[i] = .{ .source = .{ .word = slot orelse return error.Blake3RouteTooWide, .byte = d.byte } };
                },
            };
            for (owners) |owner| if (owner) |o| {
                if (o.child == 2) payload_counts[o.word] += 1 else counts[o.child][o.word] += 1;
            };
            try schedules.append(a, s);
        },
    };
    return .{ .allocator = a, .schedules = try schedules.toOwnedSlice(a), .child_uses = counts, .payload_uses = payload_counts };
}
pub fn witnessRow(schedule: route.Schedule, callers: []const Caller, digests: []const [32]u8) !route.Row {
    return witnessRowWithPayload(schedule, callers, digests, null, &.{});
}
pub fn witnessRowWithPayload(schedule: route.Schedule, callers: []const Caller, digests: []const [32]u8, payload: ?PayloadBinding, values: []const u32) !route.Row {
    if (callers.len != digests.len or callers.len > 2) return error.InvalidBlake3FrameCaller;
    var words: [2]u32 = @splat(0);
    for (schedule.sources, 0..) |maybe, i| if (maybe) |endpoint| {
        var found = false;
        for (callers, digests) |caller, digest| if (endpoint.circuit == caller.circuit and endpoint.wire >= caller.first_wire and endpoint.wire - caller.first_wire < 8) {
            const offset = (endpoint.wire - caller.first_wire) * 4;
            words[i] = std.mem.readInt(u32, digest[offset..][0..4], .little);
            found = true;
        };
        if (payload) |item| {
            if (values.len != item.word_count) return error.InvalidBlake3FrameCaller;
            if (endpoint.circuit == item.caller.circuit and endpoint.wire >= item.caller.first_wire and endpoint.wire - item.caller.first_wire < values.len) {
                words[i] = values[endpoint.wire - item.caller.first_wire];
                found = true;
            }
        }
        if (!found) return error.InvalidBlake3FrameCaller;
    };
    return route.logicalRow(schedule, words);
}
