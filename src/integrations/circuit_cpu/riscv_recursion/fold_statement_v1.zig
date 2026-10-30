//! Typed CLOSED_FOLD certificate and the arithmetic boundary law. The same
//! statement words are hashed as child outputs AND used by adjacency gates.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const Native = @import("stwo_circuit_frontend").statements.riscv_native_parent_v1;
const Original = @import("../riscv_originals_v1/statement.zig");
const Hash = b.blake3_channel_reuse_v1;
const Q = core.fields.qm31.QM31;
pub const D = [32]u8;
pub const W = b.wrappers.U32Wrapper(b.Var);
pub const production_active = false;
pub const ROLE_WINDOW: u32 = 1;
pub const ROLE_FOLD: u32 = 2;
pub const ROLE_ORIGINALS: u32 = Original.ROLE;
pub const Span = struct {
    elf_sha256: D,
    first_cycle: u32,
    cycles: u32,
    incoming_snapshot_id: D,
    outgoing_snapshot_id: D,
    initial_cpu: [33]u32,
    final_cpu: [33]u32,
    initial_policy_id: ?D,
    terminal_policy_id: ?D,
    pub fn fromNative(s: Native.Statement) Span {
        return .{ .elf_sha256 = s.elf_sha256, .first_cycle = s.first_cycle, .cycles = s.cycles, .incoming_snapshot_id = s.incoming_snapshot_id, .outgoing_snapshot_id = s.outgoing_snapshot_id, .initial_cpu = s.initial_cpu, .final_cpu = s.final_cpu, .initial_policy_id = s.initial_policy_id, .terminal_policy_id = s.terminal_policy_id };
    }
    pub fn fromOriginal(s: Original.Statement) Span {
        // Public helpers may inspect malformed statements before validation.
        // Sentinel zero is rejected by Span.validate, avoiding narrowing traps.
        var initial: [33]u32 = undefined;
        initial[0] = s.span.initial_cpu.pc;
        @memcpy(initial[1..], &s.span.initial_cpu.regs);
        var final: [33]u32 = undefined;
        final[0] = s.span.final_cpu.pc;
        @memcpy(final[1..], &s.span.final_cpu.regs);
        return .{ .elf_sha256 = s.span.elf_sha256, .first_cycle = std.math.cast(u32, s.span.first_cycle) orelse 0, .cycles = std.math.cast(u32, s.span.cycles) orelse 0, .incoming_snapshot_id = s.span.incoming_snapshot_id, .outgoing_snapshot_id = s.span.outgoing_snapshot_id, .initial_cpu = initial, .final_cpu = final, .initial_policy_id = s.span.initial_policy_id, .terminal_policy_id = s.span.terminal_policy_id };
    }
    pub fn validate(s: Span) !void {
        if (s.first_cycle == 0 or s.cycles == 0 or try std.math.add(u32, s.first_cycle, s.cycles) >= 1 << 30 or s.initial_cpu[1] != 0 or s.final_cpu[1] != 0 or (s.initial_cpu[0] | s.final_cpu[0]) & 3 != 0) return error.InvalidRiscFoldSpan;
    }
    pub fn merge(left: Span, right: Span) !Span {
        try left.validate();
        try right.validate();
        if (!std.meta.eql(left.elf_sha256, right.elf_sha256) or try std.math.add(u32, left.first_cycle, left.cycles) != right.first_cycle or !std.meta.eql(left.outgoing_snapshot_id, right.incoming_snapshot_id) or !std.meta.eql(left.final_cpu, right.initial_cpu) or left.terminal_policy_id != null or right.initial_policy_id != null) return error.NonAdjacentRiscFoldSpans;
        var out = left;
        out.cycles = try std.math.add(u32, left.cycles, right.cycles);
        out.outgoing_snapshot_id = right.outgoing_snapshot_id;
        out.final_cpu = right.final_cpu;
        out.terminal_policy_id = right.terminal_policy_id;
        try out.validate();
        return out;
    }
};
pub const Child = struct { role: u32, registry_id: D, preprocessed_root: D, circuit_hash: D, output_digest: D };
pub const Statement = struct {
    role: u32 = ROLE_FOLD,
    span: Span,
    children: [2]Child,
    depth: u32,
    /// Number of circuit leaves. A legacy window-role leaf may wrap an already
    /// aggregated native Upper.Tree; a direct-original leaf is one window join.
    leaves: u32,
    pub fn validate(s: Statement) !void {
        try s.span.validate();
        if (s.role != ROLE_FOLD or s.depth == 0 or s.depth > 16 or s.leaves < 2 or s.leaves > 2048) return error.InvalidRiscFoldRoleOrDepth;
        for (s.children) |child| if (child.role != ROLE_WINDOW and child.role != ROLE_FOLD and child.role != ROLE_ORIGINALS) return error.InvalidRiscFoldChildRole;
    }
    pub fn words(s: Statement, a: std.mem.Allocator) ![]u32 {
        try s.validate();
        var out: std.ArrayList(u32) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, &.{ 0x52384346, 1, s.role, 70, 26, 1, s.span.first_cycle, s.span.cycles });
        try appendDigest(a, &out, s.span.elf_sha256);
        try appendDigest(a, &out, s.span.incoming_snapshot_id);
        try appendDigest(a, &out, s.span.outgoing_snapshot_id);
        try out.appendSlice(a, &s.span.initial_cpu);
        try out.appendSlice(a, &s.span.final_cpu);
        try out.appendSlice(a, &.{ @intFromBool(s.span.initial_policy_id != null), @intFromBool(s.span.terminal_policy_id != null) });
        try appendDigest(a, &out, s.span.initial_policy_id orelse @splat(0));
        try appendDigest(a, &out, s.span.terminal_policy_id orelse @splat(0));
        for (s.children) |child| {
            try out.append(a, child.role);
            inline for (.{ child.registry_id, child.preprocessed_root, child.circuit_hash, child.output_digest }) |d| try appendDigest(a, &out, d);
        }
        try out.appendSlice(a, &.{ s.depth, s.leaves });
        return out.toOwnedSlice(a);
    }
};
pub const Certificate = union(enum) {
    window: Native.Statement,
    fold: Statement,
    originals: Original.Statement,
    pub fn role(s: Certificate) u32 {
        return switch (s) {
            .window => ROLE_WINDOW,
            .fold => ROLE_FOLD,
            .originals => ROLE_ORIGINALS,
        };
    }
    pub fn span(s: Certificate) Span {
        return switch (s) {
            .window => |v| Span.fromNative(v),
            .fold => |v| v.span,
            .originals => |v| Span.fromOriginal(v),
        };
    }
    pub fn depth(s: Certificate) u32 {
        return switch (s) {
            .window, .originals => 0,
            .fold => |v| v.depth,
        };
    }
    pub fn leaves(s: Certificate) u32 {
        return switch (s) {
            .window, .originals => 1,
            .fold => |v| v.leaves,
        };
    }
    pub fn encode(s: Certificate, a: std.mem.Allocator) ![]u32 {
        return switch (s) {
            .window => |v| Native.encodeWords(a, v),
            .fold => |v| v.words(a),
            .originals => |v| blk: {
                const words = try v.encodeWords();
                break :blk a.dupe(u32, &words);
            },
        };
    }
    pub fn digest(s: Certificate, a: std.mem.Allocator) !D {
        const words = try s.encode(a);
        defer a.free(words);
        var h = std.crypto.hash.Blake3.init(.{});
        for (words) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            h.update(&bytes);
        }
        var result: D = undefined;
        h.final(&result);
        return result;
    }
    pub fn allocate(s: Certificate, comptime V: type, ctx: *b.Context(V)) !View {
        const values = try s.encode(ctx.scratch());
        const words = try ctx.scratch().alloc(W, values.len);
        for (words, values) |*word, value| {
            word.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
            try ctx.eq(word.get(), (try b.wrappers.constU32(V, ctx, value)).get());
        }
        const view = View{ .words = words };
        try view.requireRole(V, ctx, s.role());
        return view;
    }
};
pub const View = struct {
    words: []const W,
    pub fn digest(v: View, comptime V: type, ctx: *b.Context(V)) !Hash.Digest {
        return Hash.hashWords(V, ctx, v.words);
    }
    pub fn requireRole(v: View, comptime V: type, ctx: *b.Context(V), role: u32) !void {
        const expected_len: usize = switch (role) {
            ROLE_WINDOW => 156,
            ROLE_FOLD => 184,
            ROLE_ORIGINALS => Original.WORDS,
            else => return error.InvalidRiscFoldChildRole,
        };
        if (v.words.len != expected_len) return error.InvalidRiscFoldChildRole;
        // Keep old-role gate topology/keys byte-identical. New role has its own
        // explicit domain/version checks in addition to the pinned certificate.
        if (role == ROLE_ORIGINALS) {
            try ctx.eq(v.words[0].get(), (try b.wrappers.constU32(V, ctx, Original.DOMAIN)).get());
            try ctx.eq(v.words[1].get(), (try b.wrappers.constU32(V, ctx, Original.VERSION)).get());
        }
        try ctx.eq(v.words[2].get(), (try b.wrappers.constU32(V, ctx, role)).get());
        for ([_]u32{ 70, 26, 1 }, 3..) |value, i| try ctx.eq(v.words[i].get(), (try b.wrappers.constU32(V, ctx, value)).get());
    }
};

/// Exact shared public prefix: [domain,version,role,q,pow,blowup,start,cycles],
/// ELF8, incoming8, outgoing8, CPU33+33, presence2, policy8+8.
/// All three Views are actual hashed statement operands, never host digests.
pub fn constrainMerge(comptime V: type, ctx: *b.Context(V), left: View, right: View, parent: View) !void {
    if (left.words.len < 116 or right.words.len < 116 or parent.words.len != 184) return error.InvalidRiscFoldStatementShape;
    const l = left.words;
    const r = right.words;
    const p = parent.words;
    try parent.requireRole(V, ctx, ROLE_FOLD);
    const ls = try boundedPositive(V, ctx, l[6]);
    const lc = try boundedPositive(V, ctx, l[7]);
    const rs = try boundedPositive(V, ctx, r[6]);
    const rc = try boundedPositive(V, ctx, r[7]);
    const ps = try boundedPositive(V, ctx, p[6]);
    const pc = try boundedPositive(V, ctx, p[7]);
    for ([_][2]b.Var{ .{ ls, lc }, .{ rs, rc }, .{ ps, pc } }) |pair| {
        const end = try ctx.add(pair[0], pair[1]);
        _ = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{end}, 1), 30);
    }
    try ctx.eq(try ctx.add(ls, lc), rs);
    try ctx.eq(ps, ls);
    try ctx.eq(pc, try ctx.add(lc, rc));
    try eqWords(V, ctx, l[8..16], r[8..16]);
    try eqWords(V, ctx, p[8..16], l[8..16]);
    try eqWords(V, ctx, l[24..32], r[16..24]);
    try eqWords(V, ctx, p[16..24], l[16..24]);
    try eqWords(V, ctx, p[24..32], r[24..32]);
    try eqWords(V, ctx, l[65..98], r[32..65]);
    try eqWords(V, ctx, p[32..65], l[32..65]);
    try eqWords(V, ctx, p[65..98], r[65..98]);
    const zero = try b.wrappers.constU32(V, ctx, 0);
    try ctx.eq(l[99].get(), zero.get()); // no interior terminal policy.
    try ctx.eq(r[98].get(), zero.get()); // no interior initialization policy.
    try ctx.eq(p[98].get(), l[98].get());
    try ctx.eq(p[99].get(), r[99].get());
    try eqWords(V, ctx, p[100..108], l[100..108]);
    try eqWords(V, ctx, p[108..116], r[108..116]);
    for ([_]View{ left, right, parent }) |view| {
        try ctx.eq(view.words[33].get(), zero.get());
        try ctx.eq(view.words[66].get(), zero.get());
        for ([_]usize{ 32, 65 }) |i| {
            const low = try b.simd.unpackIdx(V, ctx, b.simd.Simd.fromPacked(&.{view.words[i].get()}, 2), 0);
            const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{low}, 1), 16);
            for (bits[0..2]) |bit| try ctx.eq(try b.simd.unpackIdx(V, ctx, bit, 0), ctx.zero());
        }
        for ([_]usize{ 98, 99 }, [_]usize{ 100, 108 }) |presence, first| {
            const high = try b.simd.unpackIdx(V, ctx, b.simd.Simd.fromPacked(&.{view.words[presence].get()}, 2), 1);
            try ctx.eq(high, ctx.zero());
            const flag = try scalar(V, ctx, view.words[presence]);
            try ctx.eq(try ctx.mul(flag, try ctx.sub(flag, ctx.one())), ctx.zero());
            for (view.words[first..][0..8]) |word| try ctx.eq(try ctx.mul(try ctx.sub(ctx.one(), flag), word.get()), ctx.zero());
        }
    }
}
fn scalar(comptime V: type, ctx: *b.Context(V), word: W) !b.Var {
    const limbs = b.simd.Simd.fromPacked(&.{word.get()}, 2);
    return ctx.add(try b.simd.unpackIdx(V, ctx, limbs, 0), try ctx.mul(try ctx.constant(Q.fromU32Unchecked(65536, 0, 0, 0)), try b.simd.unpackIdx(V, ctx, limbs, 1)));
}
fn boundedPositive(comptime V: type, ctx: *b.Context(V), word: W) !b.Var {
    const high = try b.simd.unpackIdx(V, ctx, b.simd.Simd.fromPacked(&.{word.get()}, 2), 1);
    _ = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{high}, 1), 14);
    const result = try scalar(V, ctx, word);
    _ = try ctx.inv(result);
    return result;
}
fn eqWords(comptime V: type, ctx: *b.Context(V), left: []const W, right: []const W) !void {
    if (left.len != right.len) return error.InvalidRiscFoldStatementShape;
    for (left, right) |l, r| try ctx.eq(l.get(), r.get());
}
fn appendDigest(a: std.mem.Allocator, out: *std.ArrayList(u32), digest: D) !void {
    for (0..8) |i| try out.append(a, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
}
