//! Complete Miller truth OODS/PCS statement for the pure-P2 recursive lane.
//! Public-frame equality plus global Wire closure remain root obligations.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const N = A.crypto.bn254_tower.narrow;
const Eq = N.equations;
const S = N.source;
const C = @import("full_p2_common.zig");
const Frame = @import("full_p2_frame.zig");
const WorkerCircuit = @import("pure_p2_worker_circuit.zig");
const Native = @import("pure_p2_tower_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const F = C.F;
const O = C.O;
const LF = Eq.LayoutForField(.frontier, O);
const LC = Eq.LayoutForField(.arithmetic, O);
fn exposeRoot(frame: *Frame.Frame, hash: C.Hash) !C.Hash {
    var words: [9]Frame.Word = undefined;
    for (&words, hash) |*word, value| word.* = try circuit.builder.blake.m31ToU32(C.Q, frame.ctx, value);
    try frame.free_words.appendSlice(frame.ctx.scratch(), &words);
    return hash;
}
pub const Statement = struct {
    key: *const Native.Key,
    binding: WorkerCircuit.Binding,
    ordinal: Frame.Word,
    statement: Frame.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    claims: [4]F,
    calls: F,
    first_id: F,
    pub fn init(frame: *Frame.Frame, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, manifest: [36]u8, claims: [4]O, physical: struct { fixed: C.Hash, main: C.Hash }) !Statement {
        if (!std.meta.eql(expected, try key.expected(span, expected.ordinal))) return error.OpTowerRecursiveStatement;
        const ctx = frame.ctx;
        try Frame.requireRoot(ctx, physical.fixed, key.root);
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        const fixed = try exposeRoot(frame, physical.fixed);
        _ = try exposeRoot(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*wire, value| wire.* = try ctx.guess(C.Q.fromBase(value));
        _ = try exposeRoot(frame, manifest_wires);
        var claim_wires: [4]F = undefined;
        for (&claim_wires, claims) |*wire, value| wire.* = try frame.guessOm(value);
        try C.eq(ctx, claim_wires[0].add(claim_wires[2]), F.zero());
        const calls = try frame.guessU32(span.calls);
        const first = try frame.guessU32(span.first_id);
        return .{ .key = key, .binding = .{ .identity = key.identity, .root = key.root, .profile = key.profile }, .ordinal = ordinal.word, .statement = statement, .fixed = fixed, .manifest = manifest_wires, .claims = claim_wires, .calls = calls.base, .first_id = first.base };
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WorkerCircuit.mixBeginForKind(ctx, channel, @intFromEnum(@import("../word16_global_execution/services/gkr_local/manifest.zig").Kind.delegation), self.ordinal, self.statement, self.fixed, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(self: *Statement, ctx: *C.Context, channel: *C.Channel) !Eq.ChallengesFor(F) {
        try channel.mixConstU32s(ctx, &.{ 0x4f50544c, 1, 9, 35 });
        try channel.mixRoot(ctx, self.manifest);
        const bytes = try channel.draw(ctx);
        const carries = try channel.draw(ctx);
        try channel.mixConstU32s(ctx, &.{0x53575031});
        var ssa: A.crypto.curves.equations.WireFor(F) = undefined;
        ssa.offset = try channel.draw(ctx);
        for (&ssa.coefficients) |*coefficient| coefficient.* = try channel.draw(ctx);
        const shared = try @import("pure_p2_manifest_circuit.zig").drawShared(ctx, self.manifest);
        return .{ .bytes = bytes, .carries = carries, .ssa = ssa, .wire = shared.wire };
    }
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WorkerCircuit.mixManifestAndClaims(ctx, channel, self.manifest, &self.claims);
    }
    const View = struct {
        sampled: []const []const []const F,
        offsets: [3]usize,
        pub fn fixed(self: *const @This(), c: usize) F {
            return self.sampled[0][self.offsets[0] + c][0];
        }
        pub fn main(self: *const @This(), c: usize) F {
            return self.sampled[1][self.offsets[1] + c][0];
        }
        pub fn previousActive(self: *const @This()) F {
            return self.sampled[1][self.offsets[1]][1];
        }
        pub fn interaction(self: *const @This(), c: usize) F {
            return self.sampled[2][self.offsets[2] + c][0];
        }
        pub fn previousInteraction(self: *const @This(), c: usize) F {
            return self.sampled[2][self.offsets[2] + c][1];
        }
    };
    pub fn evalComposition(self: *Statement, _: *C.Context, point: C.Point, sampled: []const []const []const F, alpha: F, ch: Eq.ChallengesFor(F)) !F {
        const global_log = @max(self.key.frontier_log, self.key.arithmetic_log);
        var accumulator = E.lane.PointAccumulator(F).init(alpha);
        inline for (.{ S.Role.frontier, S.Role.arithmetic }, 0..) |role, index| {
            const L = Eq.LayoutForField(role, O);
            const offsets: [3]usize = if (role == .frontier) .{ 0, 0, 0 } else .{ S.FIXED, LF.MAIN, LF.INTERACTION };
            const widths = L.widths();
            if (sampled.len < 3) return error.InvalidOpTowerRecursiveMask;
            for (widths, 0..) |width, tree| {
                if (sampled[tree].len < offsets[tree] + width) return error.InvalidOpTowerRecursiveMask;
                for (sampled[tree][offsets[tree]..][0..width], 0..) |values, column| {
                    const previous = N.ForField(O).Component(role).previousMask(tree, column);
                    if (values.len != @as(usize, if (previous) 2 else 1)) return error.InvalidOpTowerRecursiveMask;
                }
            }
            const view = View{ .sampled = sampled, .offsets = offsets };
            const log = if (role == .frontier) self.key.frontier_log else self.key.arithmetic_log;
            var sink = E.SinkFor(F){ .accumulator = &accumulator, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global_log, log) };
            Eq.EquationsForField(role, O).emit(F, &view, .{ .calls = self.calls, .first_id = self.first_id, .nonempty = F.one() }, .{ .ssa = self.claims[2 * index], .wire = self.claims[2 * index + 1] }, ch, &sink);
            if (sink.count != L.CONSTRAINTS) return error.InvalidOpTowerRecursiveConstraintCount;
        }
        return accumulator.finalize();
    }
};
/// Immutable source shape. Offsets live on the global lifted domain, exactly
/// as the native component's maskPoints, including smaller frontier columns.
pub fn geometry(a: std.mem.Allocator, key: *const Native.Key) !@import("../rv64_recursion/om31_poseidon/mod.zig").Shape {
    const logs = try a.alloc([]const u32, 4);
    for (0..3) |tree| logs[tree] = try key.logs(a, tree);
    const global_log = @max(key.frontier_log, key.arithmetic_log);
    const composition = try a.alloc(u32, 16);
    @memset(composition, global_log);
    logs[3] = composition;
    const masks = try a.alloc([]const []const i32, 4);
    for (masks, logs) |*tree, sizes| {
        const columns = try a.alloc([]const i32, sizes.len);
        @memset(columns, &.{0});
        tree.* = columns;
    }
    inline for (.{ S.Role.frontier, S.Role.arithmetic }) |role| {
        const L = Eq.LayoutForField(role, O);
        const offsets: [3]usize = if (role == .frontier) .{ 0, 0, 0 } else .{ S.FIXED, LF.MAIN, LF.INTERACTION };
        for (L.widths(), 0..) |width, tree| for (0..width) |column| {
            if (N.ForField(O).Component(role).previousMask(tree, column)) @constCast(masks[tree])[offsets[tree] + column] = &.{ 0, -1 };
        };
    }
    const out = @import("../rv64_recursion/om31_poseidon/mod.zig").Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global_log, .composition_log_split = 1, .pcs = key.profile.config() };
    try out.validate();
    return out;
}
pub fn expectedWords(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, claims: [4]O) ![]u32 {
    if (!std.meta.eql(expected, try key.expected(span, expected.ordinal))) return error.OpTowerRecursiveStatement;
    var words: std.ArrayList(u32) = .empty;
    errdefer words.deinit(a);
    try words.append(a, expected.ordinal);
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, expected.statement[4 * i ..][0..4], .little));
    for ([_][36]u8{ key.root, main, manifest }) |root| for (try core.crypto.poseidon2_m31_sponge.decode(root)) |coordinate| try words.append(a, coordinate.v);
    for (claims) |claim| for (claim.toM31Array()) |coordinate| try words.append(a, coordinate.v);
    try words.appendSlice(a, &.{ span.calls, span.first_id });
    return words.toOwnedSlice(a);
}
