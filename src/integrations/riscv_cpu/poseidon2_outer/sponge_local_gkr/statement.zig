//! Source-owned complete detached fragment statement. All original equations,
//! GKR terminals, global claims, PCS and FRI are authenticated; execution closes
//! only at the independently admitted CPU/detached/truth inventory receiver.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const WC = @import("../pure_p2_worker_circuit.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const Authority = @import("authority.zig");
const Child = @import("child.zig");
const Eq = @import("equations.zig");
const Worker = @import("worker.zig");
const Key = @import("key.zig").Key;
const F = C.F;
fn expose(frame: *Public.Frame, hash: C.Hash) !C.Hash {
    for (hash) |port| try frame.free_words.append(frame.ctx.scratch(), try circuit.builder.blake.m31ToU32(C.Q, frame.ctx, port));
    return hash;
}
pub const Statement = struct {
    key: *const Key,
    geometry: Authority.Geometry,
    ordinal: Public.Word,
    statement: Public.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    claims: [8][3]F,
    global: Eq.GlobalFor(F),
    pending: Child.Pending,
    bindings: [8]Eq.BindingFor(F),
    points: [8]MP.MleEvalPointFor(F),
    public: Eq.PublicFor(F),
    pub fn init(frame: *Public.Frame, key: *const Key, geometry: Authority.Geometry, ordinal: u32, manifest: [36]u8, claims: [8][3]C.O, physical: struct { fixed: C.Hash, main: C.Hash }, native_child: anytype) !Statement {
        if (!geometry.detached) return error.SpongeLocalScopeFlavor;
        const derived = try key.statementDetached(geometry);
        try Worker.requireClaims(claims);
        const ctx = frame.ctx;
        const a = ctx.scratch();
        try Public.requireRoot(ctx, physical.fixed, key.root);
        for ([_]u32{ @intFromEnum(Worker.Kind.detached_sponge_fragment), 1 }) |tag| try frame.free_words.append(a, try circuit.builder.wrappers.constU32(C.Q, ctx, tag));
        const ordinal_wire = try frame.guessU32(ordinal);
        const statement = try frame.guessDigest(derived);
        _ = try expose(frame, physical.fixed);
        _ = try expose(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*port, value| port.* = try ctx.guess(C.Q.fromBase(value));
        _ = try expose(frame, manifest_wires);
        const calls = try frame.guessU32(geometry.calls);
        const permutations = try frame.guessU32(geometry.permutations);
        const first = try frame.guessU32(geometry.first_id);
        const proof = try G.wireProof(ctx, native_child);
        var pending = try Child.verify(ctx, .{ .statement = statement, .fixed = physical.fixed, .main = physical.main, .manifest = manifest_wires, .ordinal = ordinal_wire.word, .calls = calls.word, .permutations = permutations.word, .first_id = first.word }, geometry, &proof);
        errdefer pending.deinit(ctx.gpa);
        _ = try expose(frame, pending.receipt);
        var wires: [8][3]F = undefined;
        inline for (Authority.detached_roles, 0..) |role, i| {
            for (&wires[i], claims[i]) |*port, value| port.* = try frame.guessOm(value);
            if (comptime Eq.globalCount(role, false) == 0) try C.eq(ctx, wires[i][0], F.zero());
            if (comptime Eq.globalCount(role, true) == 0) try C.eq(ctx, wires[i][1], F.zero());
            if (comptime role != .detached_descriptor) try C.eq(ctx, wires[i][2], F.zero());
        }
        const shared = try @import("../pure_p2_manifest_circuit.zig").drawShared(ctx, manifest_wires);
        var bindings: [8]Eq.BindingFor(F) = undefined;
        var points: [8]MP.MleEvalPointFor(F) = undefined;
        for (try geometry.instances(), &bindings, &points, 0..) |instance, *binding, *point, i| {
            const n = try instance.variables();
            if (pending.artifact.n_variables_by_instance[i] != n or pending.artifact.ood_point.len < n) return error.LocalGkrPointGeometryMismatch;
            const suffix = pending.artifact.ood_point[pending.artifact.ood_point.len - n ..];
            const weights = try @import("projection.zig").laneWeightsFor(F, a, suffix[instance.row_log..]);
            const marginal = pending.artifact.claims_to_verify_by_instance[i];
            if (marginal.len != 2) return error.SpongeLocalQueryShape;
            binding.* = .{ .instance = instance, .weights = weights, .eta = pending.eta, .target = marginal[0].add(pending.eta.mul(marginal[1])).mul(F.fromBase(try core.fields.m31.M31.fromCanonical(@intCast(try instance.rows())).inv())) };
            point.* = try MP.MleEvalPointFor(F).init(suffix[0..instance.row_log]);
        }
        return .{ .key = key, .geometry = geometry, .ordinal = ordinal_wire.word, .statement = statement, .fixed = physical.fixed, .manifest = manifest_wires, .claims = wires, .global = .{ .ram = .{ .offset = shared.ram.offset, .coefficients = shared.ram.coefficients }, .io = .{ .offset = shared.kio.offset, .coefficients = shared.kio.coefficients }, .wire = shared.wire }, .pending = pending, .bindings = bindings, .points = points, .public = .{ .calls = calls.base, .permutations = permutations.base, .first_id = first.base } };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WC.mixBeginForKind(ctx, channel, @intFromEnum(Worker.Kind.detached_sponge_fragment), self.ordinal, self.statement, self.fixed, .{ .identity = self.key.identity, .root = self.key.root, .profile = self.key.profile });
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixConstU32s(ctx, &.{ 0x53504753, 1, 9, 24 });
        try channel.mixRoot(ctx, self.manifest);
        try channel.mixRoot(ctx, self.pending.receipt);
        for (self.claims) |claims| try channel.mixFelts(ctx, &claims);
    }
    pub fn evalComposition(self: *Statement, _: *C.Context, point: C.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        var acc = E.lane.PointAccumulator(F).init(alpha);
        var global: u32 = 0;
        for (try self.geometry.instances()) |v| global = @max(global, v.row_log);
        var offsets: [3]usize = @splat(0);
        inline for (Authority.detached_roles, 0..) |role, i| {
            const L = Eq.Layout(role);
            for (L.widths(), 0..) |width, tree| {
                if (tree >= sampled.len or sampled[tree].len < offsets[tree] + width) return error.SpongeLocalMaskShape;
                for (sampled[tree][offsets[tree]..][0..width], 0..) |v, c| if (v.len != L.shifts(tree, c).len) return error.SpongeLocalMaskShape;
            }
            const View = struct {
                values: []const []const []const F,
                offsets: [3]usize,
                fn get(v: *const @This(), tree: usize, column: usize, shift: i32) F {
                    const at = std.mem.indexOfScalar(i32, L.shifts(tree, column), shift) orelse unreachable;
                    return v.values[tree][v.offsets[tree] + column][at];
                }
                pub fn fixed(v: *const @This(), c: usize) F {
                    return v.get(0, c, 0);
                }
                pub fn main(v: *const @This(), c: usize) F {
                    return v.get(1, c, 0);
                }
                pub fn previousMain(v: *const @This(), c: usize) F {
                    const shifts = L.shifts(1, c);
                    return v.get(1, c, if (shifts.len == 2) shifts[1] else 0);
                }
                pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) F {
                    return v.get(2, c, shift);
                }
            };
            const log = self.bindings[i].instance.row_log;
            const local = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, log);
            const anchors = try MP.evalAnchorsFor(F, log, local);
            const aux = B.AuxFor(F){ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(F, &self.points[i], local), .eq0 = self.points[i].eq0, .eq1 = self.points[i].eq1 };
            var sink = E.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, log) };
            try Eq.emit(role, F, &View{ .values = sampled, .offsets = offsets }, self.public, self.pending.challenges, self.global, self.bindings[i], aux, self.claims[i], &sink);
            if (sink.count != L.CONSTRAINTS) return error.SpongeLocalConstraintCount;
            for (&offsets, L.widths()) |*at, width| at.* += width;
        }
        return acc.finalize();
    }
};
pub fn expectedWords(a: std.mem.Allocator, key: *const Key, geometry: Authority.Geometry, ordinal: u32, manifest: [36]u8, main: [36]u8, receipt: [36]u8, claims: [8][3]C.O) ![]u32 {
    try Worker.requireClaims(claims);
    const statement = try key.statementDetached(geometry);
    var words = std.ArrayList(u32).empty;
    errdefer words.deinit(a);
    try words.appendSlice(a, &.{ @intFromEnum(Worker.Kind.detached_sponge_fragment), 1, ordinal });
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, statement[4 * i ..][0..4], .little));
    for ([_][36]u8{ key.root, main, manifest }) |root| for (try core.crypto.poseidon2_m31_sponge.decode(root)) |v| try words.append(a, v.v);
    try words.appendSlice(a, &.{ geometry.calls, geometry.permutations, geometry.first_id });
    for (try core.crypto.poseidon2_m31_sponge.decode(receipt)) |v| try words.append(a, v.v);
    for (claims) |row| for (row) |claim| for (claim.toM31Array()) |v| try words.append(a, v.v);
    return words.toOwnedSlice(a);
}
