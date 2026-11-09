//! Opt-in CPU flavor, sharing original source custody, global witnesses,
//! components, PCS, transcript framing and GKR engine. No execution admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const BaseCpu = @import("../pure_p2_cpu_worker.zig");
const Parts = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Classic = @import("../../word16_global_execution/services/gkr_local/classic_witness.zig");
const Global = @import("../../word16_global_execution/services/gkr_local/global_cpu.zig");
const Metadata = @import("../../word16_global_execution/services/gkr_local/global_metadata.zig");
const Frame = @import("frame.zig");
const Source = @import("source.zig");
const Native = @import("native.zig");
const Binding = @import("binding.zig");
const Eq = @import("equations.zig");
const Frontier = @import("component.zig").Component;
const Key = @import("key.zig").Key;
const Provider = @import("provider.zig").Provider;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Kind = enum(u32) { sponge_cpu = 0x53504350 };
pub const Expected = struct { kind: Kind = .sponge_cpu, ordinal: u32, statement: [32]u8 };
pub const StageOne = struct { main: [36]u8, receipt: [36]u8 };
pub const Encoded = struct {
    bytes: []u8,
    local: []u8,
    receipt: [36]u8,
    claims: []O,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.local);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const Worker = struct {
    allocator: std.mem.Allocator,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    setup: *const R.CpuSetup,
    request: P.Request,
    span: T.OpTowerSpan,
    first: [T.FAMILIES]u32,
    expected: Expected,
    key: *const Key,
    source: R.Sources,
    frontier: Source.Source,
    roster: Frame.Roster,
    plan: Parts.Plan,
    scheme: W.Scheme,
    channel: W.Channel,
    child: ?Native.Unbound = null,
    budget: *Budget,
    global_limit: usize,
    owns_scheme: bool = true,
    sealed: bool = false,
    consumed: bool = false,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, ordinal: u32, key: *const Key, source: R.Sources, frontier: Source.Source, limits: BaseCpu.Limits) !Worker {
        try key.require(setup);
        if (frontier.records.len != request.sponge.calls or frontier.epoch != request.base.epoch or frontier.ordinal != ordinal or frontier.log != key.frontier_log) return error.SpongeCpuCallCoverage;
        const statement = try key.statement(setup, request, first, span, ordinal);
        var roster = try Frame.Roster.init(a, setup, request.sponge.calls, frontier.log, frontier.epoch, ordinal);
        errdefer roster.deinit();
        var plan = try Parts.Plan.initForOp(a, setup);
        errdefer plan.deinit();
        const budget = try Budget.createRetainingParent(a, limits.gkr_bytes);
        errdefer budget.destroy();
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        const expected = Expected{ .ordinal = ordinal, .statement = statement };
        return .{ .allocator = a, .setup = setup, .request = request, .span = span, .first = first, .expected = expected, .key = key, .source = source, .frontier = frontier, .roster = roster, .plan = plan, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root), .budget = budget, .global_limit = limits.global_bytes };
    }
    fn provider(self: *const Worker) Provider {
        return .{ .legacy = .{ .source = &self.source }, .frontier = &self.frontier };
    }
    fn scope(self: *const Worker, main: [36]u8) Native.Scope {
        return .{ .statement = self.expected.statement, .fixed = self.key.root, .main = main, .ordinal = self.expected.ordinal, .epoch = self.frontier.epoch, .calls = self.request.sponge.calls };
    }
    pub fn seal(self: *Worker) !StageOne {
        if (self.sealed or self.consumed) return error.PoseidonNativePhase;
        self.consumed = true;
        try self.frontier.mergeInto(&self.source);
        var tree = try self.key.retainFixedTree();
        self.scheme.appendCommittedTree(self.allocator, tree, &self.channel) catch |err| {
            tree.deinit(self.allocator);
            return err;
        };
        const main = try takeMain(self.allocator, &self.source, &self.frontier, self.setup);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        const root = self.scheme.trees.items[1].root();
        var local_gkr = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "local_gkr", "CPU local source-streamed GKR");
        defer local_gkr.end();
        self.child = try Native.proveUnbound(self.budget.allocator(), self.scope(root), self.roster.instances, self.provider());
        self.sealed = true;
        self.consumed = false;
        return .{ .main = root, .receipt = self.child.?.digest };
    }
    pub fn complete(self: *Worker, manifest: [36]u8) !Encoded {
        if (!self.sealed or self.consumed) return error.PoseidonNativePhase;
        const a = self.allocator;
        const shared = try Manifest.drawShared(manifest);
        const child = &self.child.?;
        const pending = Native.Pending{ .artifact = child.result.artifact, .challenges = child.challenges, .eta = child.eta, .digest = child.digest };
        var prefix: engine.lookups.gkr_verifier.ForField(O).GkrArtifact = undefined;
        const terminal = try pending.checkedLegacy(self.roster.legacy.len, &prefix);
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "CPU terminal binding and shared global relations");
        defer generation.end();
        var binding = try @import("../../word16_global_execution/services/gkr_local/witness.zig").Witness.initFromProvider(a, self.budget.allocator(), self.roster.legacy, &child.challenges, @import("../../word16_global_execution/services/gkr_local/native_provider.zig").Provider{ .source = &self.source }, &prefix, child.eta);
        defer binding.deinit();
        const witnesses = try a.alloc(?Classic.Witness, self.plan.slots.len);
        defer a.free(witnesses);
        @memset(witnesses, null);
        defer for (witnesses) |*w| if (w.*) |*v| v.deinit();
        const claims = try a.alloc(O, self.plan.claim_count + 1);
        errdefer a.free(claims);
        for (self.plan.slots, witnesses) |slot, *w| {
            const n = Global.claimCount(slot.origin);
            if (n == 0) continue;
            const p = Metadata.Provider{ .source = &self.source, .origin = slot.origin, .log_size = slot.log, .shared = shared };
            w.* = if (slot.origin == .core and (slot.origin.core == .initial or slot.origin.core == .terminal)) try Classic.Witness.initPublicBoundary(a, slot.log, try Metadata.groups(slot.origin), p, self.global_limit) else try Classic.Witness.init(a, slot.log, try Metadata.groups(slot.origin), p, self.global_limit);
            @memcpy(claims[slot.claim_offset..][0..n], w.*.?.claimSlice());
        }
        try BaseCpu.checkPublicClaims(self.request, &self.plan, shared, claims[0..self.plan.claim_count]);
        var set = try Parts.Set.initForOpChecked(a, self.setup, self.request, self.first, self.span, &self.plan, terminal, shared, claims[0..self.plan.claim_count]);
        defer set.deinit();
        const last = self.roster.instances.len - 1;
        const data = try Binding.Data.init(self.roster.instances[last], &pending, last);
        var frontier_binding = try Binding.Witness.init(a, self.roster.instances[last], self.provider(), &pending, &data, shared.wire);
        defer frontier_binding.deinit();
        claims[self.plan.claim_count] = frontier_binding.claim;
        const frontier = Frontier{ .log_size = self.frontier.log, .public = .{ .calls = self.request.sponge.calls, .epoch = self.frontier.epoch, .ordinal = self.expected.ordinal }, .data = &data, .challenges = child.challenges, .wire = shared.wire, .claim = frontier_binding.claim, .offsets = .{ self.setup.columnCount(0), self.setup.columnCount(1), self.plan.inter_columns } };
        const old_handles = try set.provers(a);
        defer a.free(old_handles);
        const handles = try a.alloc(engine.air.component_prover.ForField(O).ComponentProver, old_handles.len + 1);
        defer a.free(handles);
        @memcpy(handles[0..old_handles.len], old_handles);
        handles[old_handles.len] = frontier.asProverComponent();
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, self.plan.inter_columns + Eq.Layout.INTERACTION);
        defer a.free(columns);
        for (self.plan.slots, witnesses) |slot, w| {
            var offset = slot.inter_offset;
            if (slot.binding_index) |i| {
                fillColumns(binding.columns[i], slot.log, columns[offset..][0..16]);
                offset += 16;
            }
            if (w) |v| fillColumns(v.data, slot.log, columns[offset..][0..v.width()]);
        }
        fillColumns(frontier_binding.data, self.frontier.log, columns[self.plan.inter_columns..]);
        generation.end();
        Protocol.mixManifestAndClaims(&self.channel, manifest, claims);
        try self.scheme.commitBorrowedStreamingWithRecorder(a, columns, 64, self.native_recorder, &self.channel);
        self.consumed = true;
        const scheme = self.scheme;
        self.owns_scheme = false;
        self.scheme = undefined;
        var proof = try W.Prover.prove(a, handles, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        const bytes = try W.Wire.encodeProofBytesBinary(a, proof.proof);
        errdefer a.free(bytes);
        return .{ .bytes = bytes, .local = try Native.encode(a, self.roster.instances, &child.result.proof), .receipt = child.digest, .claims = claims };
    }
    pub fn deinit(self: *Worker) void {
        if (self.child) |*child| child.deinit(self.budget.allocator());
        self.source.deinit();
        self.frontier.deinit();
        self.roster.deinit();
        self.plan.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
};
fn fillColumns(data: []const M, log: u32, columns: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(data.len == rows * columns.len);
    for (columns, 0..) |*v, c| v.* = .{ .log_size = log, .values = data[c * rows ..][0..rows] };
}
fn takeMain(a: std.mem.Allocator, source: *R.Sources, frontier: *Source.Source, setup: *const R.CpuSetup) !@import("../../word16_execution/main_ownership.zig").Commit {
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, setup.columnCount(1) + Eq.Layout.MAIN);
    errdefer a.free(columns);
    const base = try source.takeMain(setup);
    errdefer base.deinit(a);
    const backings = try a.alloc([]M, base.backings.len + 1);
    errdefer a.free(backings);
    const tail = try frontier.takeMain();
    @memcpy(columns[0..base.columns.len], base.columns);
    @memcpy(backings[0..base.backings.len], base.backings);
    backings[base.backings.len] = tail;
    fillColumns(tail, frontier.log, columns[base.columns.len..]);
    a.free(base.columns);
    a.free(base.backings);
    return .{ .columns = columns, .backings = backings };
}
pub fn verify(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, ordinal: u32, key: *const Key, manifest: [36]u8, main: [36]u8, encoded: *const Encoded) !Manifest.Claims {
    return verifyWithCapture(a, setup, request, span, first, ordinal, key, manifest, main, encoded, null);
}
pub fn verifyWithCapture(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, ordinal: u32, key: *const Key, manifest: [36]u8, main: [36]u8, encoded: *const Encoded, output_capture: anytype) !Manifest.Claims {
    const expected = Expected{ .ordinal = ordinal, .statement = try key.statement(setup, request, first, span, ordinal) };
    var roster = try Frame.Roster.init(a, setup, request.sponge.calls, key.frontier_log, request.base.epoch, ordinal);
    defer roster.deinit();
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root) or !std.mem.eql(u8, &roots[1], &main)) return error.SpongeCpuProofScope;
    var decoded = try Native.decode(a, roster.instances, encoded.local);
    defer decoded.deinit();
    const scope = Native.Scope{ .statement = expected.statement, .fixed = key.root, .main = main, .ordinal = ordinal, .epoch = request.base.epoch, .calls = request.sponge.calls };
    var pending = try Native.verifyPending(a, scope, roster.instances, &decoded.proof, encoded.receipt);
    defer pending.deinit(a);
    var plan = try Parts.Plan.initForOp(a, setup);
    defer plan.deinit();
    if (encoded.claims.len != plan.claim_count + 1) return error.SpongeCpuClaims;
    const shared = try Manifest.drawShared(manifest);
    try BaseCpu.checkPublicClaims(request, &plan, shared, encoded.claims[0..plan.claim_count]);
    var prefix: engine.lookups.gkr_verifier.ForField(O).GkrArtifact = undefined;
    var set = try Parts.Set.initForOpChecked(a, setup, request, first, span, &plan, try pending.checkedLegacy(roster.legacy.len, &prefix), shared, encoded.claims[0..plan.claim_count]);
    defer set.deinit();
    const last = roster.instances.len - 1;
    const data = try Binding.Data.init(roster.instances[last], &pending, last);
    const frontier = Frontier{ .log_size = key.frontier_log, .public = .{ .calls = request.sponge.calls, .epoch = request.base.epoch, .ordinal = ordinal }, .data = &data, .challenges = pending.challenges, .wire = shared.wire, .claim = encoded.claims[plan.claim_count], .offsets = .{ setup.columnCount(0), setup.columnCount(1), plan.inter_columns } };
    const old_handles = try set.verifiers(a);
    defer a.free(old_handles);
    const Air = core.air.components.ForField(O);
    const handles = try a.alloc(Air.Component, old_handles.len + 1);
    defer a.free(handles);
    @memcpy(handles[0..old_handles.len], old_handles);
    handles[old_handles.len] = frontier.asVerifierComponent();
    var channel = Protocol.begin(key.profile, expected, key.identity, key.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    for (0..3) |tree| {
        const base_logs = if (tree < 2) try setup.logs(a, tree) else try plan.interLogs(a);
        defer a.free(base_logs);
        const logs = try a.alloc(u32, base_logs.len + Eq.Layout.widths()[tree]);
        defer a.free(logs);
        @memcpy(logs[0..base_logs.len], base_logs);
        @memset(logs[base_logs.len..], key.frontier_log);
        if (tree == 2) Protocol.mixManifestAndClaims(&channel, manifest, encoded.claims);
        try receiver.commit(a, roots[tree], logs, &channel);
    }
    if (comptime @TypeOf(output_capture) == @TypeOf(null)) {
        var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &channel, &receiver, &proof, &capture);
        capture.deinit(a);
    } else try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &channel, &receiver, &proof, output_capture);
    var claims = try Parts.Set.aggregate(&plan, encoded.claims[0..plan.claim_count]);
    claims.wire = claims.wire.add(encoded.claims[plan.claim_count]);
    return claims;
}
