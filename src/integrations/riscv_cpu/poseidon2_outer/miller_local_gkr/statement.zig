//! Opt-in recursive truth-local-GKR+physical-P2 statement. The original MAIN,
//! terminal projection, global LogUp, full native PCS and public frame bind as
//! one source-derived leaf; no component or marginal is accepted separately.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const WC = @import("../pure_p2_worker_circuit.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Tower = A.crypto.bn254_tower.narrow;
const Eq = @import("equations.zig");
const Native = @import("worker.zig");
const Child = @import("child.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const F = C.F;
fn expose(frame: *Public.Frame, hash: C.Hash) !C.Hash {
    var words: [9]Public.Word = undefined;
    for (&words, hash) |*word, value| word.* = try circuit.builder.blake.m31ToU32(C.Q, frame.ctx, value);
    try frame.free_words.appendSlice(frame.ctx.scratch(), &words);
    return hash;
}
pub const Statement = struct {
    key: *const Native.Key,
    span: Native.Span,
    ordinal: Public.Word,
    statement: Public.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    receipt: C.Hash,
    claims: [2]F,
    calls: F,
    first: F,
    pending: Child.Pending,
    pub fn init(frame: *Public.Frame, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, manifest: [36]u8, receipt: [36]u8, claims: [2]C.O, physical: struct { fixed: C.Hash, main: C.Hash }, native_child: anytype) !Statement {
        try Native.validateExpected(key, span, expected);
        const geometry_ = try key.geometry(span);
        const ctx = frame.ctx;
        try Public.requireRoot(ctx, physical.fixed, key.base.root);
        for ([_]u32{ 0x4f504d47, 1 }) |tag| try frame.free_words.append(ctx.scratch(), try circuit.builder.wrappers.constU32(C.Q, ctx, tag));
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        _ = try expose(frame, physical.fixed);
        _ = try expose(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*wire, v| wire.* = try ctx.guess(C.Q.fromBase(v));
        _ = try expose(frame, manifest_wires);
        // Requests vary within one immutable geometry class. Use public wires
        // for transcript counts, not source constants that rebuild the key.
        const calls_word = try circuit.builder.wrappers.guessU32(C.Q, ctx, circuit.builder.wrappers.u32Value(C.Q, span.calls));
        const first_word = try circuit.builder.wrappers.guessU32(C.Q, ctx, circuit.builder.wrappers.u32Value(C.Q, span.first_id));
        const calls_base = C.base(try circuit.native_verifier.channel.wordToM31(C.Q, ctx, calls_word));
        const first_base = C.base(try circuit.native_verifier.channel.wordToM31(C.Q, ctx, first_word));
        const child_proof = try G.wireProof(ctx, native_child);
        var pending = try Child.verify(ctx, .{ .statement = statement, .fixed = physical.fixed, .main = physical.main, .manifest = manifest_wires, .ordinal = ordinal.word, .calls = calls_word, .first_id = first_word }, geometry_, &child_proof);
        errdefer pending.artifact.deinit(ctx.gpa);
        var receipt_wires: C.Hash = undefined;
        for (&receipt_wires, try core.crypto.poseidon2_m31_sponge.decode(receipt)) |*wire, v| wire.* = try ctx.guess(C.Q.fromBase(v));
        for (receipt_wires, pending.receipt) |actual, want| try ctx.eq(actual, want);
        _ = try expose(frame, receipt_wires);
        var claim_wires: [2]F = undefined;
        for (&claim_wires, claims) |*wire, v| wire.* = try frame.guessOm(v);
        try frame.free_words.appendSlice(ctx.scratch(), &.{ calls_word, first_word });
        return .{ .key = key, .span = span, .ordinal = ordinal.word, .statement = statement, .fixed = physical.fixed, .manifest = manifest_wires, .receipt = receipt_wires, .claims = claim_wires, .calls = calls_base, .first = first_base, .pending = pending };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.artifact.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, ch: *C.Channel) !void {
        const binding = WC.Binding{ .identity = self.key.identity, .root = self.key.base.root, .profile = self.key.base.profile };
        const Kind = @import("../../word16_global_execution/services/gkr_local/manifest.zig").Kind;
        try WC.mixBeginForKind(ctx, ch, @intFromEnum(Kind.delegation), self.ordinal, self.statement, self.fixed, binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, ch: *C.Channel) !void {
        try ch.mixConstU32s(ctx, &.{ 0x4f504d47, 2, 8, 9, 2 });
        try ch.mixRoot(ctx, self.manifest);
        try ch.mixRoot(ctx, self.receipt);
        try ch.mixFelts(ctx, &self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: C.Point, samples: []const []const []const F, alpha: F, _: void) !F {
        const geometry_ = try self.key.geometry(self.span);
        const shared = try @import("../pure_p2_manifest_circuit.zig").drawShared(ctx, self.manifest);
        var ch = self.pending.challenges;
        ch.wire = shared.wire;
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        var offsets: [3]usize = .{ 0, 0, 0 };
        const global = @max(geometry_.frontier_log, geometry_.arithmetic_log);
        inline for (.{ Tower.source.Role.frontier, Tower.source.Role.arithmetic }) |role| {
            const L = Eq.Layout(role);
            const log = if (role == .frontier) geometry_.frontier_log else geometry_.arithmetic_log;
            const values = self.pending.artifact;
            const instances = try geometry_.instances();
            var bindings: [L.LOCAL_INSTANCES]Eq.BindingFor(F) = undefined;
            var aux: [L.LOCAL_INSTANCES]B.AuxFor(F) = undefined;
            const local_point = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, log);
            const anchors = try MP.evalAnchorsFor(F, log, local_point);
            for (&bindings, &aux, 0..) |*binding, *helper, slot| {
                const index = if (role == .frontier) 3 else slot;
                const instance = instances[index];
                const variables = try instance.variables();
                if (values.n_variables_by_instance.len != 4 or values.claims_to_verify_by_instance.len != 4 or values.n_variables_by_instance[index] != variables or values.ood_point.len < variables) return error.LocalGkrPointGeometryMismatch;
                const suffix = values.ood_point[values.ood_point.len - variables ..];
                const weights = try @import("projection.zig").laneWeightsFor(F, ctx.scratch(), suffix[log..]);
                const mle = try MP.MleEvalPointFor(F).init(suffix[0..log]);
                const claims = values.claims_to_verify_by_instance[index];
                if (claims.len != 2) return error.LocalGkrProjectionShape;
                binding.* = .{ .instance = instance, .weights = weights, .eta = self.pending.eta, .target = claims[0].add(self.pending.eta.mul(claims[1])).mul(F.fromBase(try core.fields.m31.M31.fromCanonical(@intCast(try instance.rows())).inv())) };
                helper.* = .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(F, &mle, local_point), .eq0 = mle.eq0, .eq1 = mle.eq1 };
            }
            if (samples.len < 3) return error.MillerRecursiveMask;
            for (L.widths(), 0..) |width, tree| {
                if (samples[tree].len < offsets[tree] + width) return error.MillerRecursiveMask;
                for (samples[tree][offsets[tree]..][0..width], 0..) |column, c| if (column.len != L.shifts(tree, c).len) return error.MillerRecursiveMask;
            }
            const View = struct {
                values: []const []const []const F,
                offsets: [3]usize,
                fn get(v: *const @This(), tree: usize, column: usize, shift: i32) F {
                    const index = std.mem.indexOfScalar(i32, L.shifts(tree, column), shift) orelse unreachable;
                    return v.values[tree][v.offsets[tree] + column][index];
                }
                pub fn fixed(v: *const @This(), c: usize) F {
                    return v.get(0, c, 0);
                }
                pub fn main(v: *const @This(), c: usize) F {
                    return v.get(1, c, 0);
                }
                pub fn previousActive(v: *const @This()) F {
                    return v.get(1, 0, -1);
                }
                pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) F {
                    return v.get(2, c, shift);
                }
            };
            const view = View{ .values = samples, .offsets = offsets };
            var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, log) };
            try Eq.emit(role, F, &view, .{ .calls = self.calls, .first_id = self.first, .nonempty = F.one() }, ch, &bindings, &aux, self.claims[if (role == .frontier) 0 else 1], &sink);
            if (sink.count != L.CONSTRAINTS) return error.MillerRecursiveConstraintCount;
            for (L.widths(), 0..) |width, tree| offsets[tree] += width;
        }
        return acc.finalize();
    }
};

pub fn geometry(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span) !@import("../../rv64_recursion/om31_poseidon/mod.zig").Shape {
    const geometry_ = try key.geometry(span);
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    var global: u32 = 0;
    global = @max(geometry_.frontier_log, geometry_.arithmetic_log);
    for (0..3) |tree| {
        logs[tree] = try key.logs(a, tree);
        const offsets = try a.alloc([]const i32, logs[tree].len);
        var at: usize = 0;
        inline for (.{ Tower.source.Role.frontier, Tower.source.Role.arithmetic }) |role| for (0..Eq.Layout(role).widths()[tree]) |col| {
            offsets[at] = Eq.Layout(role).shifts(tree, col);
            at += 1;
        };
        masks[tree] = offsets;
    }
    const split: u32 = 1;
    const count = @as(usize, 8) << @intCast(split);
    const comp = try a.alloc(u32, count);
    @memset(comp, global);
    logs[3] = comp;
    const shifts = try a.alloc([]const i32, count);
    @memset(shifts, &.{0});
    masks[3] = shifts;
    const out = @import("../../rv64_recursion/om31_poseidon/mod.zig").Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global, .composition_log_split = split, .pcs = key.base.profile.config() };
    try out.validate();
    return out;
}
pub fn expectedWords(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, receipt: [36]u8, claims: [2]C.O) ![]u32 {
    try Native.validateExpected(key, span, expected);
    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, &.{ 0x4f504d47, 1, expected.ordinal });
    for (0..8) |i| try out.append(a, std.mem.readInt(u32, expected.statement[i * 4 ..][0..4], .little));
    for ([_][36]u8{ key.base.root, main, manifest, receipt }) |hash| for (try core.crypto.poseidon2_m31_sponge.decode(hash)) |v| try out.append(a, v.v);
    for (claims) |claim| for (claim.toM31Array()) |v| try out.append(a, v.v);
    try out.appendSlice(a, &.{ span.calls, span.first_id });
    return out.toOwnedSlice(a);
}
