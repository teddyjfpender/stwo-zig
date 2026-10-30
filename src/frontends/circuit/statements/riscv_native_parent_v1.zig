//! Typed public statement of the opt-in RISC native-parent circuit wrapper.
//! CLOSED means a receiver-admitted B8 closed window/fold theorem; a raw VK
//! digest, a standalone PCS proof, or an arbitrary circuit output is not CLOSED.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("../builder/mod.zig");
const ch = @import("../builder/blake3_channel_reuse_v1.zig");
pub const Digest = [32]u8;
pub const DOMAIN: u32 = 0x52384357;
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const Role = enum(u32) { closed_window = 1 };
pub const Statement = struct {
    role: Role = .closed_window,
    elf_sha256: Digest,
    first_cycle: u32,
    cycles: u32,
    incoming_snapshot_id: Digest,
    outgoing_snapshot_id: Digest,
    /// PC followed by x0..x31, in both boundaries.
    initial_cpu: [33]u32,
    final_cpu: [33]u32,
    initial_policy_id: ?Digest,
    terminal_policy_id: ?Digest,
    native_key_id: Digest,
    native_public_id: Digest,
    native_fixed_root: Digest,
    native_main_root: Digest,
    /// Independent instance admission, not a universal registry identifier.
    admission_id: Digest,
    pub fn validate(s: Statement) !void {
        if (s.first_cycle == 0 or s.cycles == 0 or try std.math.add(u32, s.first_cycle, s.cycles) >= 1 << 30 or s.initial_cpu[1] != 0 or s.final_cpu[1] != 0 or (s.initial_cpu[0] | s.final_cpu[0]) & 3 != 0) return error.InvalidRiscCircuitStatement;
    }
    /// A homogeneous RISC fold must constrain these SAME operands in-circuit;
    /// this host helper is only preflight and never substitutes for that gate.
    pub fn requireAdjacent(children: []const Statement) !void {
        if (children.len < 2 or children.len > 4) return error.InvalidRiscCircuitFanIn;
        var out = children[0];
        try out.validate();
        for (children[1..]) |right| {
            try right.validate();
            if (!std.meta.eql(out.elf_sha256, right.elf_sha256) or try std.math.add(u32, out.first_cycle, out.cycles) != right.first_cycle or !std.meta.eql(out.outgoing_snapshot_id, right.incoming_snapshot_id) or !std.meta.eql(out.final_cpu, right.initial_cpu) or out.terminal_policy_id != null or right.initial_policy_id != null) return error.NonAdjacentRiscCircuitStatements;
            out.cycles = try std.math.add(u32, out.cycles, right.cycles);
            out.outgoing_snapshot_id = right.outgoing_snapshot_id;
            out.final_cpu = right.final_cpu;
            out.terminal_policy_id = right.terminal_policy_id;
        }
        try out.validate();
    }
};
pub const W = b.wrappers.U32Wrapper(b.Var);
pub const Wires = struct {
    /// Canonical words, with lengths/presence bits included in the frame.
    words: []const W,
    pub fn digest(self: Wires, comptime V: type, ctx: *b.Context(V)) !ch.Digest {
        return ch.hashWords(V, ctx, self.words);
    }
};

/// The wrapper pins this request statement through independently admitted
/// instance authority. Request words remain wires; the explicit equalities
/// prevent an untrusted prefix from selecting another public supply or span.
pub fn allocate(comptime V: type, ctx: *b.Context(V), statement: Statement) !Wires {
    const words = try encodeWords(ctx.scratch(), statement);
    const result = try ctx.scratch().alloc(W, words.len);
    for (result, words) |*wire, value| {
        wire.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
        try ctx.eq(wire.get(), (try b.wrappers.constU32(V, ctx, value)).get());
    }
    return .{ .words = result };
}
pub fn encodeWords(a: std.mem.Allocator, statement: Statement) ![]u32 {
    try statement.validate();
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(a);
    try words.appendSlice(a, &.{ DOMAIN, VERSION, @intFromEnum(statement.role), 70, 26, 1, statement.first_cycle, statement.cycles });
    try appendDigest(&words, a, statement.elf_sha256);
    try appendDigest(&words, a, statement.incoming_snapshot_id);
    try appendDigest(&words, a, statement.outgoing_snapshot_id);
    try words.appendSlice(a, &statement.initial_cpu);
    try words.appendSlice(a, &statement.final_cpu);
    try words.appendSlice(a, &.{ @intFromBool(statement.initial_policy_id != null), @intFromBool(statement.terminal_policy_id != null) });
    try appendDigest(&words, a, statement.initial_policy_id orelse @splat(0));
    try appendDigest(&words, a, statement.terminal_policy_id orelse @splat(0));
    inline for (.{ statement.native_key_id, statement.native_public_id, statement.native_fixed_root, statement.native_main_root, statement.admission_id }) |value| try appendDigest(&words, a, value);
    return words.toOwnedSlice(a);
}
pub fn digest(a: std.mem.Allocator, statement: Statement) !Digest {
    const words = try encodeWords(a, statement);
    defer a.free(words);
    var h = std.crypto.hash.Blake3.init(.{});
    for (words) |word| {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, word, .little);
        h.update(&encoded);
    }
    var result: Digest = undefined;
    h.final(&result);
    return result;
}
fn appendDigest(words: *std.ArrayList(u32), a: std.mem.Allocator, value: Digest) !void {
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, value[4 * i ..][0..4], .little));
}
