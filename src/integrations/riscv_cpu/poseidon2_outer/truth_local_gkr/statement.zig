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
const R = @import("../../word16_global_execution/services/roster.zig");
const Shape = @import("authority.zig");
const Role = @import("component.zig");
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
    truth: R.Truth,
    ordinal: Public.Word,
    statement: Public.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    receipt: C.Hash,
    claims: [2]F,
    calls: F,
    first: F,
    pending: Child.Pending,
    pub fn init(frame: *Public.Frame, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, manifest: [36]u8, receipt: [36]u8, claims: [2]C.O, physical: struct { fixed: C.Hash, main: C.Hash }, native_child: anytype) !Statement {
        try Native.validateExpected(key, truth, expected);
        const shapes = try Shape.shapes(truth);
        const ctx = frame.ctx;
        try Public.requireRoot(ctx, physical.fixed, key.base.root);
        for ([_]u32{ 0x4f505447, 1 }) |tag| try frame.free_words.append(ctx.scratch(), try circuit.builder.wrappers.constU32(C.Q, ctx, tag));
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        _ = try expose(frame, physical.fixed);
        _ = try expose(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*wire, v| wire.* = try ctx.guess(C.Q.fromBase(v));
        _ = try expose(frame, manifest_wires);
        const child_proof = try G.wireProof(ctx, native_child);
        var pending = try Child.verify(ctx, .{ .statement = statement, .fixed = physical.fixed, .main = physical.main, .manifest = manifest_wires, .ordinal = ordinal.word }, shapes, &child_proof);
        errdefer pending.artifact.deinit(ctx.gpa);
        var receipt_wires: C.Hash = undefined;
        for (&receipt_wires, try core.crypto.poseidon2_m31_sponge.decode(receipt)) |*wire, v| wire.* = try ctx.guess(C.Q.fromBase(v));
        for (receipt_wires, pending.receipt) |actual, want| try ctx.eq(actual, want);
        _ = try expose(frame, receipt_wires);
        var claim_wires: [2]F = undefined;
        for (&claim_wires, claims) |*wire, v| wire.* = try frame.guessOm(v);
        if (truth == .keccak) try C.eq(ctx, claim_wires[1], F.zero());
        const calls = try frame.guessU32(truth.count());
        const first = try frame.guessU32(truth.first());
        return .{ .key = key, .truth = truth, .ordinal = ordinal.word, .statement = statement, .fixed = physical.fixed, .manifest = manifest_wires, .receipt = receipt_wires, .claims = claim_wires, .calls = calls.base, .first = first.base, .pending = pending };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.artifact.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, ch: *C.Channel) !void {
        const binding = WC.Binding{ .identity = self.key.identity, .root = self.key.base.root, .profile = self.key.base.profile };
        const Kind = @import("../../word16_global_execution/services/gkr_local/manifest.zig").Kind;
        if (self.truth == .keccak) try WC.mixBeginForKind(ctx, ch, @intFromEnum(Kind.keccak), self.ordinal, self.statement, self.fixed, binding) else if (self.truth.secp.setup.kind == .add) try WC.mixBeginForKind(ctx, ch, @intFromEnum(Kind.secp_add), self.ordinal, self.statement, self.fixed, binding) else try WC.mixBeginForKind(ctx, ch, @intFromEnum(Kind.secp_double), self.ordinal, self.statement, self.fixed, binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, ch: *C.Channel) !void {
        try ch.mixConstU32s(ctx, &.{ 0x4f505447, 2, 8, 9, 2 });
        try ch.mixRoot(ctx, self.manifest);
        try ch.mixRoot(ctx, self.receipt);
        try ch.mixFelts(ctx, &self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: C.Point, samples: []const []const []const F, alpha: F, _: void) !F {
        const shapes = try Shape.shapes(self.truth);
        var global: u32 = 0;
        for (shapes) |shape| global = @max(global, shape.original.log_size);
        const shared = try @import("../pure_p2_manifest_circuit.zig").drawShared(ctx, self.manifest);
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        var offsets: [3]usize = .{ 0, 0, 0 };
        const workspace = try ctx.scratch().create(Role.Component.Workspace(F));
        for (shapes, 0..) |shape, index| {
            const instance = shape.instance();
            const variables = try instance.variables();
            if (index >= self.pending.artifact.n_variables_by_instance.len or self.pending.artifact.n_variables_by_instance[index] != variables or self.pending.artifact.ood_point.len < variables) return error.LocalGkrPointGeometryMismatch;
            const suffix = self.pending.artifact.ood_point[self.pending.artifact.ood_point.len - variables ..];
            const weights = try @import("projection.zig").laneWeightsFor(F, ctx.scratch(), suffix[instance.row_log..]);
            const mle = try MP.MleEvalPointFor(F).init(suffix[0..instance.row_log]);
            const terminal = self.pending.artifact.claims_to_verify_by_instance[index];
            if (terminal.len != 2) return error.LocalGkrProjectionShape;
            const target = terminal[0].add(self.pending.eta.mul(terminal[1])).mul(F.fromBase(try core.fields.m31.M31.fromCanonical(@intCast(try instance.rows())).inv()));
            const local_point = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, instance.row_log);
            const anchors = try MP.evalAnchorsFor(F, instance.row_log, local_point);
            const step = core.poly.circle.canonic.CanonicCoset.new(instance.row_log).coset().step;
            const last_anchor = try MP.evalIsFirstFor(F, core.poly.circle.canonic.CanonicCoset.new(instance.row_log).coset(), local_point.add(.{ .x = F.fromBase(step.x), .y = F.fromBase(step.y) }));
            const Sampler = struct {
                values: []const []const []const F,
                offsets: [3]usize,
                shape: Shape.Shape,
                last_value: F,
                pub fn last(s: @This()) !F {
                    return s.last_value;
                }
                pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !F {
                    const shifts = s.shape.shifts(tree, col);
                    const position = std.mem.indexOfScalar(i32, shifts, shift) orelse return error.OpTruthRecursiveMask;
                    if (s.values[tree][s.offsets[tree] + col].len != shifts.len) return error.OpTruthRecursiveMask;
                    return s.values[tree][s.offsets[tree] + col][position];
                }
            };
            var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, instance.row_log) };
            const crypto = index == 0 or (index == 1 and self.truth == .secp);
            try Role.emitShapeWithParameters(shape, if (self.truth == .secp) A.crypto.secp256k1.program.get(self.truth.secp.setup.kind) else null, F, Sampler{ .values = samples, .offsets = offsets, .shape = shape, .last_value = last_anchor }, &sink, workspace, .{ .original = .{ .span = .{ .calls = if (crypto) self.calls else F.zero(), .first_id = if (crypto) self.first else F.one(), .nonempty = if (crypto) F.one() else F.zero() }, .local = self.pending.challenges, .kio = shared.kio, .wire = shared.wire, .claim = F.zero(), .global_claim = if (crypto) self.claims[index] else F.zero() }, .weights = weights, .eta = self.pending.eta, .target = target }, .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(F, &mle, local_point), .eq0 = mle.eq0, .eq1 = mle.eq1 });
            if (sink.count != shape.constraints()) return error.OpTruthRecursiveConstraintCount;
            for (shape.widths(), 0..) |width, tree| offsets[tree] += width;
        }
        return acc.finalize();
    }
};
pub fn geometry(a: std.mem.Allocator, key: *const Native.Key, truth: R.Truth) !@import("../../rv64_recursion/om31_poseidon/mod.zig").Shape {
    try key.require(truth);
    const shapes = try Shape.shapes(truth);
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    var global: u32 = 0;
    for (shapes) |shape| global = @max(global, shape.original.log_size);
    for (0..3) |tree| {
        logs[tree] = try Native.logs(a, shapes, tree);
        const offsets = try a.alloc([]const i32, logs[tree].len);
        var at: usize = 0;
        for (shapes) |shape| for (0..shape.widths()[tree]) |col| {
            offsets[at] = shape.shifts(tree, col);
            at += 1;
        };
        masks[tree] = offsets;
    }
    const split: u32 = if (truth == .keccak) 2 else 1;
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
pub fn expectedWords(a: std.mem.Allocator, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, receipt: [36]u8, claims: [2]C.O) ![]u32 {
    try Native.validateExpected(key, truth, expected);
    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, &.{ 0x4f505447, 1, expected.ordinal });
    for (0..8) |i| try out.append(a, std.mem.readInt(u32, expected.statement[i * 4 ..][0..4], .little));
    for ([_][36]u8{ key.base.root, main, manifest, receipt }) |hash| for (try core.crypto.poseidon2_m31_sponge.decode(hash)) |v| try out.append(a, v.v);
    for (claims) |claim| for (claim.toM31Array()) |v| try out.append(a, v.v);
    try out.appendSlice(a, &.{ truth.count(), truth.first() });
    return out.toOwnedSlice(a);
}
