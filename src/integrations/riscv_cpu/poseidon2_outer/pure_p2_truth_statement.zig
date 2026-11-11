//! Complete native pure-P2 truth catalog authority. The root independently
//! binds these public words and closes the execution-wide KIO/Wire obligations.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("full_p2_common.zig");
const Frame = @import("full_p2_frame.zig");
const WC = @import("pure_p2_worker_circuit.zig");
const Native = @import("pure_p2_truth_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const G = @import("../word16_global_execution/services/gkr_local/truth_components.zig");
const Role = @import("../word16_global_execution/services/gkr_local/truth_role.zig");
const VR = @import("../word16_global_execution/services/gkr_local/truth_v3_role.zig").Component;
const Catalog = @import("../word16_global_execution/services/gkr_local/truth_catalog.zig");
const TF = @import("../word16_global_execution/services/gkr_local/truth_fractions.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const F = C.F;
const O = C.O;
fn classic(truth: R.Truth) bool {
    return truth == .keccak or truth == .secp;
}
const K = @import("../word16_global_execution/services/gkr_local/manifest.zig").Kind;
const kindKeccak = @intFromEnum(K.keccak);
const kindAdd = @intFromEnum(K.secp_add);
const kindDouble = @intFromEnum(K.secp_double);
const kindDelegation = @intFromEnum(K.delegation);
fn expose(frame: *Frame.Frame, hash: C.Hash) !C.Hash {
    var words: [9]Frame.Word = undefined;
    for (&words, hash) |*word, value| word.* = try circuit.builder.blake.m31ToU32(C.Q, frame.ctx, value);
    try frame.free_words.appendSlice(frame.ctx.scratch(), &words);
    return hash;
}
const Challenges = union(enum) { classic: TF.ChallengesFor(F), delegated: F };
pub const Statement = struct {
    key: *const Native.Key,
    truth: R.Truth,
    binding: WC.Binding,
    ordinal: Frame.Word,
    statement: Frame.Digest,
    fixed: C.Hash,
    manifest: C.Hash,
    claims: []const F,
    first_id: F,
    calls: F,
    pub fn init(frame: *Frame.Frame, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, manifest: [36]u8, claims: []const O, physical: struct { fixed: C.Hash, main: C.Hash }) !Statement {
        if (!std.meta.eql(expected, try key.expected(truth, expected.ordinal)) or claims.len != @as(usize, if (classic(truth)) 5 else 1)) return error.OpTruthRecursiveStatement;
        const ctx = frame.ctx;
        try Frame.requireRoot(ctx, physical.fixed, key.root);
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        const fixed = try expose(frame, physical.fixed);
        _ = try expose(frame, physical.main);
        var manifest_wires: C.Hash = undefined;
        for (&manifest_wires, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*wire, value| wire.* = try ctx.guess(C.Q.fromBase(value));
        _ = try expose(frame, manifest_wires);
        const claim_wires = try ctx.scratch().alloc(F, claims.len);
        for (claim_wires, claims) |*wire, value| wire.* = try frame.guessOm(value);
        if (classic(truth)) {
            try C.eq(ctx, claim_wires[0].add(claim_wires[1]).add(claim_wires[2]), F.zero());
            if (truth == .keccak) try C.eq(ctx, claim_wires[4], F.zero());
        }
        const calls = try frame.guessU32(truth.count());
        const first = try frame.guessU32(truth.first());
        return .{ .key = key, .truth = truth, .binding = .{ .identity = key.identity, .root = key.root, .profile = key.profile }, .ordinal = ordinal.word, .statement = statement, .fixed = fixed, .manifest = manifest_wires, .claims = claim_wires, .first_id = first.base, .calls = calls.base };
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        switch (self.truth) {
            .keccak => try WC.mixBeginForKind(ctx, channel, kindKeccak, self.ordinal, self.statement, self.fixed, self.binding),
            .secp => |t| if (t.setup.kind == .add) try WC.mixBeginForKind(ctx, channel, kindAdd, self.ordinal, self.statement, self.fixed, self.binding) else try WC.mixBeginForKind(ctx, channel, kindDouble, self.ordinal, self.statement, self.fixed, self.binding),
            else => try WC.mixBeginForKind(ctx, channel, kindDelegation, self.ordinal, self.statement, self.fixed, self.binding),
        }
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(self: *Statement, ctx: *C.Context, channel: *C.Channel) !Challenges {
        try channel.mixConstU32s(ctx, &.{ 0x4f50544c, 2, 9, @intFromEnum(std.meta.activeTag(self.truth)) });
        try channel.mixRoot(ctx, self.manifest);
        var draw = Frame.Draw{ .ctx = ctx, .channel = channel };
        const result: Challenges = if (classic(self.truth)) .{ .classic = TF.ChallengesFor(F).draw(&draw) } else .{ .delegated = @import("../word16_global_execution/services/gkr_local/truth_v3_worker.zig").drawLocal(&draw) };
        try draw.finish();
        return result;
    }
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WC.mixManifestAndClaims(ctx, channel, self.manifest, self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: C.Point, samples: []const []const []const F, alpha: F, local: Challenges) !F {
        const shared = try @import("pure_p2_manifest_circuit.zig").drawShared(ctx, self.manifest);
        var acc = A.evaluation.lane.PointAccumulator(F).init(alpha);
        if (classic(self.truth)) {
            const ds = try G.shapesForDeclaration(@import("../word16_global_execution/services/wire.zig").TruthDeclaration.from(self.truth));
            var global: u32 = 0;
            for (ds) |d| global = @max(global, d.log_size);
            var offsets: [3]usize = @splat(0);
            const workspace = try ctx.scratch().create(Role.Component.Workspace(F));
            for (ds, 0..) |d, index| {
                const local_point = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, global, d.log_size);
                const step = core.poly.circle.canonic.CanonicCoset.new(d.log_size).coset().step;
                const last_anchor = try MP.evalIsFirstFor(F, core.poly.circle.canonic.CanonicCoset.new(d.log_size).coset(), local_point.add(.{ .x = F.fromBase(step.x), .y = F.fromBase(step.y) }));
                const Sampler = struct {
                    values: []const []const []const F,
                    offsets: [3]usize,
                    descriptor: Role.Shape,
                    last_value: F,
                    pub fn last(s: @This()) !F {
                        return s.last_value;
                    }
                    pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !F {
                        const shifts = s.descriptor.shifts(tree, col);
                        const position = std.mem.indexOfScalar(i32, shifts, shift) orelse return error.OpTruthRecursiveMask;
                        if (s.values[tree][s.offsets[tree] + col].len != shifts.len) return error.OpTruthRecursiveMask;
                        return s.values[tree][s.offsets[tree] + col][position];
                    }
                };
                var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, global, d.log_size) };
                const crypto_role = d.kind == .keccak or d.kind == .product or d.kind == .linear;
                try Role.emitShape(d, if (self.truth == .secp) A.crypto.secp256k1.program.get(self.truth.secp.setup.kind) else null, F, Sampler{ .values = samples, .offsets = offsets, .descriptor = d, .last_value = last_anchor }, &sink, workspace, .{ .span = .{ .calls = if (crypto_role) self.calls else F.zero(), .first_id = if (crypto_role) self.first_id else F.one(), .nonempty = if (crypto_role) F.one() else F.zero() }, .local = local.classic, .kio = shared.kio, .wire = shared.wire, .claim = self.claims[index], .global_claim = if (index == 0) self.claims[3] else if (index == 1 and self.truth == .secp) self.claims[4] else F.zero() });
                if (sink.count != d.nConstraints()) return error.OpTruthRecursiveConstraintCount;
                for (d.widths(), 0..) |width, t| offsets[t] += width;
            }
        } else {
            const role = VR{ .truth = self.truth, .wire = .{ .offset = O.zero(), .coefficients = @splat(O.zero()) } };
            const d = try Catalog.descriptor(self.truth);
            const a = ctx.scratch();
            const fixed = try a.alloc(F, d.shape.fixed);
            const main = try a.alloc(F, d.shape.main);
            const prior = try a.alloc(F, d.shape.main);
            @memset(prior, F.zero());
            const inter = try a.alloc(F, d.shape.inter);
            const prev_inter = try a.alloc(F, d.shape.inter);
            @memset(prev_inter, F.zero());
            for (fixed, samples[0]) |*v, s| {
                if (s.len != 1) return error.OpTruthRecursiveMask;
                v.* = s[0];
            }
            for (main, samples[1], 0..) |*v, s, col| {
                if (s.len != @as(usize, if (role.previousMain(col)) 2 else 1)) return error.OpTruthRecursiveMask;
                v.* = s[0];
                if (role.previousMain(col)) prior[col] = s[1];
            }
            for (inter, samples[2], 0..) |*v, s, col| {
                if (s.len != @as(usize, if (role.previousInter(col)) 2 else 1)) return error.OpTruthRecursiveMask;
                v.* = s[0];
                if (role.previousInter(col)) prev_inter[col] = s[1];
            }
            var sink = A.evaluation.SinkFor(F){ .accumulator = &acc, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, d.log_size, d.log_size) };
            const span = A.evaluation.CallSpanFor(F){ .first_id = self.first_id, .calls = self.calls, .nonempty = F.one() };
            try role.emitMainWithSpan(F, fixed, main, prior, span, &sink);
            try role.emitGlobalWithParameters(F, fixed, main, inter, prev_inter, .{ .span = span, .wire = shared.wire, .bytes = local.delegated, .claim = self.claims[0] }, &sink);
            if (sink.count != d.nConstraints()) return error.OpTruthRecursiveConstraintCount;
        }
        return acc.finalize();
    }
};
pub fn geometry(a: std.mem.Allocator, key: *const Native.Key, truth: R.Truth) !@import("../rv64_recursion/om31_poseidon/mod.zig").Shape {
    try key.require(truth);
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    var global: u32 = 0;
    var split: u32 = undefined;
    if (classic(truth)) {
        const ds = try G.shapesForDeclaration(@import("../word16_global_execution/services/wire.zig").TruthDeclaration.from(truth));
        split = if (truth == .keccak) 2 else 1;
        for (ds) |d| global = @max(global, d.log_size);
        for (0..3) |tree| {
            var count: usize = 0;
            for (ds) |d| count += d.widths()[tree];
            const sizes = try a.alloc(u32, count);
            const shifts = try a.alloc([]const i32, count);
            var at: usize = 0;
            for (ds) |d| for (0..d.widths()[tree]) |col| {
                sizes[at] = d.log_size;
                shifts[at] = d.shifts(tree, col);
                at += 1;
            };
            logs[tree] = sizes;
            masks[tree] = shifts;
        }
    } else {
        const d = try Catalog.descriptor(truth);
        global = d.log_size;
        const role = VR{ .truth = truth, .wire = .{ .offset = O.zero(), .coefficients = @splat(O.zero()) } };
        split = role.compositionLogSplit();
        for (d.widths(), 0..) |width, tree| {
            const sizes = try a.alloc(u32, width);
            @memset(sizes, global);
            logs[tree] = sizes;
            const shifts = try a.alloc([]const i32, width);
            for (shifts, 0..) |*s, col| s.* = if ((tree == 1 and role.previousMain(col)) or (tree == 2 and role.previousInter(col))) &.{ 0, -1 } else &.{0};
            masks[tree] = shifts;
        }
    }
    const count = @as(usize, 8) << @intCast(split);
    const comp = try a.alloc(u32, count);
    @memset(comp, global);
    logs[3] = comp;
    const shifts = try a.alloc([]const i32, count);
    @memset(shifts, &.{0});
    masks[3] = shifts;
    const out = @import("../rv64_recursion/om31_poseidon/mod.zig").Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global, .composition_log_split = split, .pcs = key.profile.config() };
    try out.validate();
    return out;
}
pub fn expectedWords(a: std.mem.Allocator, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, claims: []const O) ![]u32 {
    if (!std.meta.eql(expected, try key.expected(truth, expected.ordinal)) or claims.len != @as(usize, if (classic(truth)) 5 else 1)) return error.OpTruthRecursiveStatement;
    var words: std.ArrayList(u32) = .empty;
    errdefer words.deinit(a);
    try words.append(a, expected.ordinal);
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, expected.statement[4 * i ..][0..4], .little));
    for ([_][36]u8{ key.root, main, manifest }) |root| for (try core.crypto.poseidon2_m31_sponge.decode(root)) |v| try words.append(a, v.v);
    for (claims) |claim| for (claim.toM31Array()) |v| try words.append(a, v.v);
    try words.appendSlice(a, &.{ truth.count(), truth.first() });
    return words.toOwnedSlice(a);
}
