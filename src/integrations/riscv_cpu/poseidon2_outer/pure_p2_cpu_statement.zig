//! Complete source-bound CPU equations for the actual OP pure-P2 native suite.
//! Original CPU AIR, typed full-root frames and independently admitted source geometry.
//! The caller admits immutable setup/topology and the root authenticates the
//! returned public frame against its independently reconstructed request,
//! manifest, local receipt and physical-claim vector. This module is not a
//! root receiver and deliberately does not replace native boundary validation.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("full_p2_common.zig");
const V = @import("../rv64_recursion/om31_native/mod.zig");
const Public = @import("full_p2_frame.zig");
const Gkr = @import("../logup_gkr/om31_circuit_verifier.zig");
const Child = @import("full_p2_child.zig");
const Oods = @import("../rv64_recursion/om31_native/cpu_oods.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Worker = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig");
const M = @import("pure_p2_manifest.zig");
const WorkerCircuit = @import("pure_p2_worker_circuit.zig");
const W = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const F = C.F;
pub const Physical = struct { fixed: C.Hash, main: C.Hash, fixed_source: [36]u8 };
const Phase = @import("phase_census.zig");
const CpuPublics = @import("pure_p2_cpu_publics.zig");
fn exposeRoot(frame: *Public.Frame, hash: C.Hash) !C.Hash {
    var words: [9]Public.Word = undefined;
    for (&words, hash) |*word, value| word.* = try @import("stwo_circuit_frontend").builder.blake.m31ToU32(C.Q, frame.ctx, value);
    try frame.free_words.appendSlice(frame.ctx.scratch(), &words);
    return hash;
}
pub const Statement = struct {
    /// The original public witnesses, retained for typed-summary constraints.
    /// Saving these handles adds no guesses or equations to legacy leaves.
    pub const ChainInputs = CpuPublics.ChainInputs;
    setup: *const R.CpuSetup,
    plan: Components.Plan,
    config: core.pcs.PcsConfig,
    binding: WorkerCircuit.Binding,
    ordinal: Public.Word,
    statement: Public.Digest,
    manifest: C.Hash,
    fixed: C.Hash,
    claims: []const F,
    pending: Child.Pending,
    publics: []const Oods.PublicFor(F),
    chain_inputs: ChainInputs,
    phase: Phase.Parts,
    last_phase: Phase.Counts = .{},

    /// Native input is witness assignment only. Every request scalar consumed
    /// by an equation is a guessed public word in `frame`; none becomes a
    /// circuit constant. Program/geometry/config and fixed authority are the
    /// independently admitted immutable topology.
    pub fn init(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.Expected, manifest: [36]u8, native_claims: []const C.O, physical: Physical, native_child: anytype, config: core.pcs.PcsConfig, binding: WorkerCircuit.Binding) !Statement {
        return initMode(frame, setup, request, first, expected, manifest, native_claims, physical, native_child, config, binding, null);
    }
    pub fn initForOp(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, span: T.OpTowerSpan, expected: M.Expected, manifest: [36]u8, native_claims: []const C.O, physical: Physical, native_child: anytype, config: core.pcs.PcsConfig, binding: WorkerCircuit.Binding) !Statement {
        return initMode(frame, setup, request, first, expected, manifest, native_claims, physical, native_child, config, binding, span);
    }
    fn initMode(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.Expected, manifest: [36]u8, native_claims: []const C.O, physical: Physical, native_child: anytype, config: core.pcs.PcsConfig, binding: WorkerCircuit.Binding, op_span: ?T.OpTowerSpan) !Statement {
        const ctx = frame.ctx;
        const phase_start = Phase.Counts.take(try C.sidecar(ctx));
        const a = ctx.scratch();
        if (expected.kind != .cpu) return error.WideCpuProofShape;
        if (op_span) |span| {
            if (!setup.op_only) return error.UnsupportedOpPurePoseidonStatement;
            try span.validate(setup.bridges);
            const B = @import("stwo_circuit_frontend").builder;
            try frame.free_words.appendSlice(a, &.{ try B.wrappers.constU32(C.Q, ctx, 0x4f505350), try B.wrappers.constU32(C.Q, ctx, 1) });
        } else if (setup.op_only or setup.bridges.tower != null) return error.UnsupportedOpPurePoseidonStatement;
        if (!std.meta.eql(config, binding.profile.config()) or expected.profile != binding.profile or !std.mem.eql(u8, &binding.identity, &expected.fixed_identity)) return error.UnsupportedWideServicesConfig;
        if (!std.mem.eql(u8, &binding.root, &expected.fixed) or !std.mem.eql(u8, &physical.fixed_source, &expected.fixed)) return error.WideCpuStatementMismatch;
        const derived_instances = if (op_span != null) try @import("../word16_global_execution/services/gkr_local/roster.zig").fromOpSetup(a, setup) else try @import("../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, setup);
        const admitted_instances = expected.local_instances orelse return error.WideCpuLocalRequired;
        if (derived_instances.len != admitted_instances.len) return error.WideCpuRosterMismatch;
        for (derived_instances, admitted_instances) |derived, admitted| if (!std.meta.eql(derived, admitted)) return error.WideCpuRosterMismatch;
        try Public.requireRoot(ctx, physical.fixed, physical.fixed_source);
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        const scope = Child.Scope{ .ordinal = ordinal.word, .statement = statement, .fixed = try exposeRoot(frame, physical.fixed), .main = try exposeRoot(frame, physical.main) };
        var manifest_words: C.Hash = undefined;
        for (&manifest_words, try core.crypto.poseidon2_m31_sponge.decode(manifest)) |*port, value| port.* = try ctx.guess(C.Q.fromBase(value));
        _ = try exposeRoot(frame, manifest_words);
        const child_proof = try Gkr.wireProof(ctx, native_child);
        const before_local = Phase.Counts.take(try C.sidecar(ctx));
        var pending = try Child.verify(ctx, scope, expected.local_instances orelse return error.WideCpuLocalRequired, &child_proof);
        errdefer pending.artifact.deinit(ctx.gpa);
        const after_local = Phase.Counts.take(try C.sidecar(ctx));
        _ = try exposeRoot(frame, pending.receipt);
        const claims = try a.alloc(F, native_claims.len);
        for (claims, native_claims) |*wire, value| wire.* = try frame.guessOm(value);
        const shared = try @import("pure_p2_manifest_circuit.zig").drawShared(ctx, manifest_words);
        const after_shared = Phase.Counts.take(try C.sidecar(ctx));
        const body = try CpuPublics.init(frame, setup, request, first, op_span, expected.local_instances.?, .{ .artifact = &pending.artifact, .challenges = pending.challenges, .eta = pending.eta }, claims, shared);
        const plan = body.plan;
        const publics = body.publics;
        const chain_inputs = body.chain_inputs;
        return .{ .setup = setup, .plan = plan, .config = config, .binding = binding, .ordinal = ordinal.word, .statement = statement, .manifest = manifest_words, .fixed = physical.fixed, .claims = claims, .pending = pending, .publics = publics, .chain_inputs = chain_inputs, .phase = .{ .public_scope = before_local.sub(phase_start), .local_gkr = after_local.sub(before_local), .claims_shared = after_shared.sub(after_local), .source_publics = Phase.Counts.take(try C.sidecar(ctx)).sub(after_shared) } };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.artifact.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WorkerCircuit.mixBegin(ctx, channel, self.ordinal, self.statement, self.fixed, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try WorkerCircuit.mixManifestAndClaims(ctx, channel, self.manifest, self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        const phase_before = Phase.Counts.take(try C.sidecar(ctx));
        var accumulator = E.lane.PointAccumulator(F).init(alpha);
        try CpuPublics.emitComposition(self.setup, &self.plan, self.publics, ctx, point, self.globalLog(), sampled, &accumulator);
        const result = accumulator.finalize();
        self.phase.cpu_oods = self.phase.cpu_oods.add(Phase.Counts.take(try C.sidecar(ctx)).sub(phase_before));
        return result;
    }
    pub fn notePcsPhase(self: *Statement, ctx: *C.Context, phase: @import("../rv64_recursion/om31_poseidon/mod.zig").PcsPhase) !void {
        const now = Phase.Counts.take(try C.sidecar(ctx));
        const delta = now.sub(self.last_phase);
        switch (phase) {
            .begin => {},
            .oods => self.phase.pcs_oods_and_transcript = delta.sub(self.phase.cpu_oods),
            .transcript => self.phase.pcs_sampled_mix_and_queries = delta,
            .merkle => self.phase.pcs_merkle = delta,
            .deep => self.phase.deep = delta,
            .fri => self.phase.fri = delta,
        }
        self.last_phase = now;
    }
    fn globalLog(self: *const Statement) u32 {
        var log: u32 = 0;
        for (self.plan.slots) |slot| log = @max(log, slot.log);
        return log;
    }
};

/// Exact root-side public frame projection. The receiver supplies independently
/// admitted setup/request/manifest/root/receipt/claims after native inventory,
/// boundary and global closure validation. No producer-declared scalar is an
/// authority merely because this encoder can serialize it.
pub fn expectedWords(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.Expected, manifest: [36]u8, main_root: [36]u8, receipt: [36]u8, claims: []const C.O) ![]u32 {
    return expectedWordsMode(a, setup, request, first, expected, manifest, main_root, receipt, claims, null);
}
pub fn expectedWordsForOp(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, span: T.OpTowerSpan, expected: M.Expected, manifest: [36]u8, main_root: [36]u8, receipt: [36]u8, claims: []const C.O) ![]u32 {
    return expectedWordsMode(a, setup, request, first, expected, manifest, main_root, receipt, claims, span);
}
fn expectedWordsMode(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.Expected, manifest: [36]u8, main_root: [36]u8, receipt: [36]u8, claims: []const C.O, op_span: ?T.OpTowerSpan) ![]u32 {
    if (op_span) |span| {
        if (!setup.op_only) return error.UnsupportedOpPurePoseidonStatement;
        try span.validate(setup.bridges);
    } else if (setup.op_only or setup.bridges.tower != null) return error.UnsupportedOpPurePoseidonStatement;
    var words: std.ArrayList(u32) = .empty;
    errdefer words.deinit(a);
    if (op_span != null) try words.appendSlice(a, &.{ 0x4f505350, 1 });
    try words.append(a, expected.ordinal);
    for (0..8) |i| try words.append(a, std.mem.readInt(u32, expected.statement[4 * i ..][0..4], .little));
    for ([_][36]u8{ expected.fixed, main_root, manifest, receipt }) |root| {
        const coordinates = try core.crypto.poseidon2_m31_sponge.decode(root);
        for (coordinates) |coordinate| try words.append(a, coordinate.v);
    }
    for (claims) |claim| for (claim.toM31Array()) |coordinate| try words.append(a, coordinate.v);
    try CpuPublics.appendExpected(a, &words, setup, request, first, op_span, claims.len, true);
    return words.toOwnedSlice(a);
}
