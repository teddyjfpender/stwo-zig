//! Complete source-owned CPU-frontier recursive statement. The original CPU
//! publics/OODS body is shared; the typed child owns its full receipt/artifact.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const WC = @import("../pure_p2_worker_circuit.zig");
const Body = @import("../pure_p2_cpu_publics.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const Native = @import("native.zig");
const Child = @import("child.zig");
const Frame = @import("frame.zig");
const Eq = @import("equations.zig");
const CPU = @import("worker.zig");
const Key = @import("key.zig").Key;
const F = C.F;
fn expose(frame: *Public.Frame, hash: C.Hash) !C.Hash {
    for (hash) |port| try frame.free_words.append(frame.ctx.scratch(), try circuit.builder.blake.m31ToU32(C.Q, frame.ctx, port));
    return hash;
}
pub const Statement = struct {
    key: *const Key,
    body: Body.Body,
    instances: []const Frame.Instance,
    ordinal: Public.Word,
    statement: Public.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    claims: []const F,
    shared: Public.Shared,
    pending: Child.Pending,
    frontier: Eq.BindingFor(F),
    point: MP.MleEvalPointFor(F),
    public: Eq.PublicFor(F),
    pub fn init(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, key: *const Key, expected: CPU.Expected, manifest: [36]u8, native_claims: []const C.O, physical: struct { fixed: C.Hash, main: C.Hash }, native_child: anytype) !Statement {
        const derived = try key.statement(setup, request, first, span, expected.ordinal);
        if (!std.mem.eql(u8, &derived, &expected.statement) or native_claims.len < 1) return error.SpongeCpuStatement;
        const ctx = frame.ctx;
        const a = ctx.scratch();
        const roster = try Frame.Roster.init(a, setup, request.sponge.calls, key.frontier_log, request.base.epoch, expected.ordinal);
        // Context scratch owns the source descriptors for the complete build.
        try Public.requireRoot(ctx, physical.fixed, key.root);
        for ([_]u32{ @intFromEnum(CPU.Kind.sponge_cpu), 1 }) |tag| try frame.free_words.append(a, try circuit.builder.wrappers.constU32(C.Q, ctx, tag));
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        _ = try expose(frame, physical.fixed);
        _ = try expose(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*port, value| port.* = try ctx.guess(C.Q.fromBase(value));
        _ = try expose(frame, manifest_wires);
        const epoch = try frame.guessU32(request.base.epoch);
        const calls = try frame.guessU32(request.sponge.calls);
        const proof = try G.wireProof(ctx, native_child);
        var pending = try Child.verify(ctx, .{ .statement = statement, .fixed = physical.fixed, .main = physical.main, .ordinal = ordinal.word, .epoch = epoch.word, .calls = calls.word }, roster.instances, &proof);
        errdefer pending.deinit(ctx.gpa);
        _ = try expose(frame, pending.receipt);
        const claims = try a.alloc(F, native_claims.len);
        for (claims, native_claims) |*port, value| port.* = try frame.guessOm(value);
        const shared = try @import("../pure_p2_manifest_circuit.zig").drawShared(ctx, manifest_wires);
        var storage: @import("stwo_prover_engine").lookups.verifier_kernel.Artifact(F) = undefined;
        const terminal = try pending.legacy(roster.legacy.len, &storage);
        const body = try Body.initWithEpoch(frame, setup, request, first, span, roster.legacy, .{ .artifact = terminal.artifact, .challenges = terminal.challenges, .eta = terminal.eta }, claims[0 .. claims.len - 1], shared, epoch);
        const instance = roster.instances[roster.instances.len - 1];
        const n = try instance.variables();
        const index = roster.instances.len - 1;
        if (pending.artifact.n_variables_by_instance[index] != n or pending.artifact.ood_point.len < n) return error.SpongeCpuGeometry;
        const suffix = pending.artifact.ood_point[pending.artifact.ood_point.len - n ..];
        const weights = try @import("../truth_local_gkr/projection.zig").laneWeightsFor(F, a, suffix[key.frontier_log..]);
        const marginals = pending.artifact.claims_to_verify_by_instance[index];
        if (weights.len != 4 or marginals.len != 2) return error.SpongeCpuGeometry;
        const binding = Eq.BindingFor(F){ .weights = weights[0..4].*, .eta = pending.eta, .target = marginals[0].add(pending.eta.mul(marginals[1])).mul(F.fromBase(try core.fields.m31.M31.fromCanonical(@intCast(try instance.rows())).inv())) };
        return .{ .key = key, .body = body, .instances = roster.instances, .ordinal = ordinal.word, .statement = statement, .fixed = physical.fixed, .manifest = manifest_wires, .claims = claims, .shared = shared, .pending = pending, .frontier = binding, .point = try MP.MleEvalPointFor(F).init(suffix[0..key.frontier_log]), .public = .{ .calls = calls.base, .epoch = epoch.base, .ordinal = ordinal.base, .nonempty = try Body.flag(ctx, calls.base, request.sponge.calls) } };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WC.mixBeginForKind(ctx, channel, @intFromEnum(CPU.Kind.sponge_cpu), self.ordinal, self.statement, self.fixed, .{ .identity = self.key.identity, .root = self.key.root, .profile = self.key.profile });
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WC.mixManifestAndClaims(ctx, channel, self.manifest, self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: C.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        var acc = E.lane.PointAccumulator(F).init(alpha);
        const global = self.globalLog();
        try Body.emitComposition(self.body.setup, &self.body.plan, self.body.publics, ctx, point, global, sampled, &acc);
        const L = Eq.Layout;
        const offsets = [3]usize{ self.body.setup.columnCount(0), self.body.setup.columnCount(1), self.body.plan.inter_columns };
        if (sampled.len < 3) return error.SpongeCpuMask;
        for (L.widths(), 0..) |width, tree| {
            if (sampled[tree].len < offsets[tree] + width) return error.SpongeCpuMask;
            for (sampled[tree][offsets[tree]..][0..width], 0..) |column, c| if (column.len != L.shifts(tree, c).len) return error.SpongeCpuMask;
        }
        const View = struct {
            values: []const []const []const F,
            offsets: [3]usize,
            fn get(v: *const @This(), tree: usize, column: usize, shift: i32) F {
                const index = std.mem.indexOfScalar(i32, Eq.Layout.shifts(tree, column), shift) orelse unreachable;
                return v.values[tree][v.offsets[tree] + column][index];
            }
            pub fn fixed(v: *const @This(), c: usize) F {
                return v.get(0, c, 0);
            }
            pub fn main(v: *const @This(), c: usize) F {
                return v.get(1, c, 0);
            }
            pub fn previousMain(v: *const @This(), c: usize) F {
                return v.get(1, c, if (c == 0) -1 else 0);
            }
            pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) F {
                return v.get(2, c, shift);
            }
        };
        const local = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, self.key.frontier_log);
        const anchors = try MP.evalAnchorsFor(F, self.key.frontier_log, local);
        const aux = B.AuxFor(F){ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(F, &self.point, local), .eq0 = self.point.eq0, .eq1 = self.point.eq1 };
        var sink = E.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, self.key.frontier_log) };
        try Eq.emit(F, &View{ .values = sampled, .offsets = offsets }, self.public, self.pending.challenges, self.shared.wire, self.frontier, aux, self.claims[self.claims.len - 1], &sink);
        if (sink.count != L.CONSTRAINTS) return error.SpongeCpuConstraintCount;
        return acc.finalize();
    }
    fn globalLog(self: *const Statement) u32 {
        var log = self.key.frontier_log;
        for (self.body.plan.slots) |slot| log = @max(log, slot.log);
        return log;
    }
};
pub fn expectedWords(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, key: *const Key, expected: CPU.Expected, manifest: [36]u8, main: [36]u8, receipt: [36]u8, claims: []const C.O) ![]u32 {
    if (!std.mem.eql(u8, &expected.statement, &try key.statement(setup, request, first, span, expected.ordinal)) or claims.len < 1) return error.SpongeCpuStatement;
    var words = std.ArrayList(u32).empty;
    errdefer words.deinit(a);
    try words.appendSlice(a, &.{ @intFromEnum(CPU.Kind.sponge_cpu), 1, expected.ordinal });
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, expected.statement[4 * i ..][0..4], .little));
    for ([_][36]u8{ key.root, main, manifest }) |root| for (try core.crypto.poseidon2_m31_sponge.decode(root)) |v| try words.append(a, v.v);
    try words.appendSlice(a, &.{ request.base.epoch, request.sponge.calls });
    for (try core.crypto.poseidon2_m31_sponge.decode(receipt)) |v| try words.append(a, v.v);
    for (claims) |claim| for (claim.toM31Array()) |v| try words.append(a, v.v);
    try Body.appendExpected(a, &words, setup, request, first, span, claims.len - 1, false);
    return words.toOwnedSlice(a);
}
