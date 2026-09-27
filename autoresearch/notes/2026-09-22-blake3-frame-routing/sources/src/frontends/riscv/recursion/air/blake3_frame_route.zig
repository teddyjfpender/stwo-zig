//! Canonical frame routing from up to two authenticated digest roles.
//! Non-digest payloads are public constants; callers must bind their producers.
const std = @import("std");
const core = @import("stwo_core");
const framing = core.channel.blake3.framing;
const graph = @import("blake3_hash_plan.zig");
const route = @import("blake3_byte_route.zig");
pub const Caller = struct { circuit: u32, first_wire: u32 };
pub const Binding = struct { role: framing.DigestRole, caller: Caller };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    schedules: []route.Schedule,
    child_uses: [2][8]u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.schedules);
        self.* = undefined;
    }
};
const Ref = union(enum) { constant: u8, digest: struct { child: u1, word: u3, byte: u2 } };
const Symbols = struct {
    refs: []Ref,
    cursor: usize = 0,
    bindings: []const Binding,
    seen: [2]bool = @splat(false),
    invalid: bool = false,
    pub fn update(self: *Symbols, bytes: []const u8) void {
        for (bytes) |byte| {
            self.refs[self.cursor] = .{ .constant = byte };
            self.cursor += 1;
        }
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
            self.refs[self.cursor] = .{ .digest = .{ .child = child, .word = @intCast(i / 4), .byte = @intCast(i % 4) } };
            self.cursor += 1;
        }
    }
};
pub fn build(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding) !Plan {
    const p = core.fields.m31.Modulus;
    if (circuit >= p or bindings.len > 2) return error.InvalidBlake3FrameCaller;
    for (bindings, 0..) |binding, i| {
        const caller = binding.caller;
        if (caller.circuit >= p or caller.circuit == circuit or caller.first_wire >= p - 7) return error.InvalidBlake3FrameCaller;
        for (bindings[0..i]) |earlier| if (earlier.role == binding.role or earlier.caller.circuit == caller.circuit) return error.InvalidBlake3FrameCaller;
    }
    const refs = try a.alloc(Ref, try frame.encodedSize());
    defer a.free(refs);
    var sink = Symbols{ .refs = refs, .bindings = bindings };
    frame.write(&sink);
    for (sink.seen[0..bindings.len]) |seen| if (!seen) return error.InvalidBlake3FrameCaller;
    if (sink.invalid) return error.InvalidBlake3FrameCaller;
    if (sink.cursor != refs.len) return error.InvalidBlake3Frame;
    var hash = try graph.build(a, refs.len);
    defer hash.deinit();
    var schedules: std.ArrayList(route.Schedule) = .empty;
    defer schedules.deinit(a);
    var counts: [2][8]u32 = .{ @splat(0), @splat(0) };
    for (hash.sources) |source| switch (source.value) {
        .constant => {},
        .input => |part| {
            var s = route.Schedule{ .sources = .{ null, null }, .destination = .{ .circuit = circuit, .wire = source.wire }, .uses = hash.uses[source.wire], .bytes = @splat(.{ .constant = 0 }) };
            var owners: [2]?struct { child: u1, word: u3 } = .{ null, null };
            for (refs[part.offset..][0..part.len], 0..) |ref, i| switch (ref) {
                .constant => |value| s.bytes[i] = .{ .constant = value },
                .digest => |d| {
                    const endpoint = route.Endpoint{ .circuit = bindings[d.child].caller.circuit, .wire = bindings[d.child].caller.first_wire + d.word };
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
                counts[o.child][o.word] += 1;
            };
            try schedules.append(a, s);
        },
    };
    return .{ .allocator = a, .schedules = try schedules.toOwnedSlice(a), .child_uses = counts };
}
pub fn witnessRow(schedule: route.Schedule, callers: []const Caller, digests: []const [32]u8) !route.Row {
    if (callers.len != digests.len or callers.len > 2) return error.InvalidBlake3FrameCaller;
    var words: [2]u32 = @splat(0);
    for (schedule.sources, 0..) |maybe, i| if (maybe) |endpoint| {
        var found = false;
        for (callers, digests) |caller, digest| if (endpoint.circuit == caller.circuit and endpoint.wire >= caller.first_wire and endpoint.wire - caller.first_wire < 8) {
            const offset = (endpoint.wire - caller.first_wire) * 4;
            words[i] = std.mem.readInt(u32, digest[offset..][0..4], .little);
            found = true;
        };
        if (!found) return error.InvalidBlake3FrameCaller;
    };
    return route.logicalRow(schedule, words);
}
