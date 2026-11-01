//! Actual classic-OM truth worker and fresh receiver. Local claims close INSIDE
//! each truth; only independently authenticated pure KIO/Wire debt escapes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const Manifest = @import("manifest.zig");
const W = @import("worker_protocol.zig");
const TF = @import("truth_fractions.zig");
const Frame = @import("truth_frame.zig");
const Metadata = @import("truth_metadata.zig");
const GM = @import("truth_global_metadata.zig");
const GW = @import("truth_global_witness.zig");
const Local = @import("truth_classic.zig");
const Classic = @import("classic_witness.zig");
const Components = @import("truth_components.zig").Components;
const O = W.O;
const M = core.fields.m31.M31;
const Commit = @import("../../../word16_execution/main_ownership.zig").Commit;
pub const TruthEncoded = struct {
    bytes: []u8,
    claims: []O,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub fn truthMass(truth: R.Truth) !Manifest.Mass {
    return switch (truth) {
        .keccak => |t| .{ .ram = 0, .kio = (try A.crypto.keccak.layout.admitRoster(&.{t.calls}, &.{})).io, .wire = 0 },
        .secp => |t| blk: {
            const p = A.crypto.secp256k1.program.get(t.setup.kind);
            const mass = try A.crypto.secp256k1.layout.admitRoster(&.{ .{ .kind = .product, .program = p, .calls = t.calls, .first_id = t.first_id, .log = t.setup.logs[0] }, .{ .kind = .linear, .program = p, .calls = t.calls, .first_id = t.first_id, .log = t.setup.logs[1] } }, &.{});
            break :blk .{ .ram = 0, .kio = 0, .wire = mass.wires };
        },
    };
}
pub fn truthStatement(truth: R.Truth, config: W.PcsConfig, execution: [32]u8) [32]u8 {
    var ch = W.Channel.init();
    config.mixInto(&ch);
    ch.mixU32s(&.{ 0x54574f31, 1, 8, @intFromEnum(truth.family()), truth.first(), truth.count() });
    W.digest(&ch, execution);
    W.digest(&ch, truth.key().root);
    switch (truth) {
        .keccak => |t| ch.mixU32s(&.{t.setup.log}),
        .secp => |t| ch.mixU32s(&.{ @intFromEnum(t.setup.kind), t.setup.logs[0], t.setup.logs[1], @intFromEnum(@TypeOf(t.setup.*).byte_policy) }),
    }
    return ch.digestBytes();
}
fn validateExpected(truth: R.Truth, expected: Manifest.ExpectedWorker) !void {
    const kind: Manifest.Kind = switch (truth) {
        .keccak => .keccak,
        .secp => |t| if (t.setup.kind == .add) .secp_add else .secp_double,
    };
    if (expected.kind != kind or expected.local_instances != null or !std.mem.eql(u8, &expected.fixed, &truth.key().root) or !std.meta.eql(expected.mass, try truthMass(truth))) return error.WideTruthExpectedMismatch;
    const relations = Manifest.Relations{ .ram = false, .kio = kind == .keccak, .wire = kind != .keccak };
    if (!std.meta.eql(relations, expected.global_relations)) return error.WideTruthExpectedMismatch;
}
fn templates(truth: R.Truth) !Components {
    return Components.init(truth, undefined, undefined, &@as([5]O, @splat(O.zero())));
}
fn expectedFrames(truth: R.Truth) ![3]Frame.Instance {
    const c = try templates(truth);
    return .{ c.items[0].instance(), c.items[1].instance(), c.items[2].instance() };
}
fn validatePending(expected: Manifest.ExpectedWorker, pending: *const Manifest.PendingManifest, index: usize) !void {
    if (index >= pending.entries.len or index != expected.ordinal) return error.GlobalGkrManifestOrdinal;
    const e = pending.entries[index];
    if (e.kind != expected.kind or e.local != null or !std.meta.eql(e.mass, expected.mass) or !std.meta.eql(e.global_relations, expected.global_relations) or !std.mem.eql(u8, &e.scope.statement, &expected.statement) or !std.mem.eql(u8, &e.scope.fixed, &expected.fixed)) return error.WideTruthManifestMismatch;
}
fn claimsResult(truth: R.Truth, claims: []const O) !Manifest.Claims {
    if (claims.len != 5) return error.InvalidWideTruthClaims;
    return .{ .ram = O.zero(), .kio = if (truth == .keccak) claims[3] else O.zero(), .wire = if (truth == .secp) claims[3].add(claims[4]) else O.zero() };
}
pub const TruthWorker = struct {
    allocator: std.mem.Allocator,
    truth: R.Truth,
    source: R.TruthSource,
    expected: Manifest.ExpectedWorker,
    scheme: W.Scheme,
    channel: W.Channel,
    owns_scheme: bool = true,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    owns_source: bool = true,
    sealed: bool = false,
    started: bool = false,
    failed: bool = false,
    pub fn init(a: std.mem.Allocator, truth: R.Truth, source: R.TruthSource, expected: Manifest.ExpectedWorker, config: W.PcsConfig, global_budget: usize) !TruthWorker {
        try validateExpected(truth, expected);
        const frames = try expectedFrames(truth);
        _ = try Metadata.Provider.initClassic(&source, frames);
        try admit(frames, global_budget);
        var scheme = try W.Scheme.init(a, config);
        scheme.setCompactPolynomialStorage(5);
        return .{ .allocator = a, .truth = truth, .source = source, .expected = expected, .scheme = scheme, .channel = W.begin(config, expected) };
    }
    pub fn deinit(self: *TruthWorker, a: std.mem.Allocator) void {
        if (self.owns_scheme) self.scheme.deinit(a);
        if (self.owns_source) self.source.deinit();
        self.* = undefined;
    }
    /// Host custody only. Store lifetime must cover this worker and its proof.
    pub fn spillMain(self: *TruthWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.started or self.failed) return error.InvalidWideTruthPhase;
        return store.spill(self.allocator, &self.scheme.trees.items[1]);
    }
    pub fn restoreMain(self: *TruthWorker, store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!self.sealed or self.started or self.failed) return error.InvalidWideTruthPhase;
        return store.restore(&self.scheme.trees.items[1]);
    }
    pub fn seal(self: *TruthWorker, a: std.mem.Allocator) !Manifest.StageOne {
        if (self.sealed or self.started or self.failed) return error.InvalidWideTruthPhase;
        errdefer self.failed = true;
        try W.appendFixed(a, self.truth.key(), self.expected.fixed, &self.scheme, &self.channel);
        const main = try self.source.takeMain();
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        var roots = try self.scheme.roots(a);
        defer roots.deinit(a);
        if (roots.items.len != 2) return error.WideTruthRoots;
        self.sealed = true;
        return .{ .main = roots.items[1], .local = null };
    }
    pub fn complete(self: *TruthWorker, a: std.mem.Allocator, pending: *const Manifest.PendingManifest, index: usize, global_budget: usize) !TruthEncoded {
        if (!self.sealed or self.started or self.failed) return error.InvalidWideTruthPhase;
        try validatePending(self.expected, pending, index);
        var roots = try self.scheme.roots(a);
        defer roots.deinit(a);
        if (roots.items.len != 2) return error.WideTruthRoots;
        try pending.checkPhysicalRoots(index, roots.items[0], roots.items[1]);
        const frames = try expectedFrames(self.truth);
        try admit(frames, global_budget);
        self.started = true;
        errdefer self.failed = true;
        const local = TF.ChallengesFor(O).draw(&self.channel);
        const metadata = try Metadata.Provider.initClassic(&self.source, frames);
        var gm = try GM.Provider.init(a, &self.source, global_budget);
        defer gm.deinit();
        var locals: [3]Classic.Witness = undefined;
        var done: usize = 0;
        defer for (locals[0..done]) |*v| v.deinit();
        for (frames, &locals) |frame, *v| {
            v.* = try Local.generate(a, &metadata, frame, &local, global_budget);
            done += 1;
        }
        var globals: [2]Classic.Witness = undefined;
        var gd: usize = 0;
        defer for (globals[0..gd]) |*v| v.deinit();
        const gch = GW.Challenges{ .io = pending.shared.kio, .wire = pending.shared.wire };
        globals[0] = try GW.generate(a, &gm, frames[0].role, &gch, global_budget);
        gd = 1;
        if (self.truth == .secp) {
            globals[1] = try GW.generate(a, &gm, frames[1].role, &gch, global_budget);
            gd = 2;
        }
        const claims = try a.alloc(O, 5);
        errdefer a.free(claims);
        for (locals, 0..) |v, i| claims[i] = v.claims[0];
        claims[3] = globals[0].claims[0];
        claims[4] = if (gd == 2) globals[1].claims[0] else O.zero();
        var components = try Components.init(self.truth, local, pending.shared, claims);
        W.mixManifestAndClaims(&self.channel, pending.digest, claims);
        const inter = try take(a, &locals, globals[0..gd]);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, 64, self.native_recorder, &self.channel);
        self.owns_scheme = false;
        var proof = try W.Prover.prove(a, &components.provers(), &self.channel, self.scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        const bytes = try W.encodePhysical(a, proof.proof);
        self.source.deinit();
        self.owns_source = false;
        return .{ .bytes = bytes, .claims = claims };
    }
};
fn admit(frames: [3]Frame.Instance, budget: usize) !void {
    var output: usize = 0;
    var scratch: usize = 0;
    for (frames, 0..) |frame, i| {
        const rows = try frame.rows();
        const global: usize = if (i == 0) (if (frame.role == .keccak) 208 else 32) else if (i == 1 and frame.role == .linear) 32 else 0;
        output = try std.math.add(usize, output, try std.math.mul(usize, rows, 4 * (Local.columns(frame) + global)));
        const bytes = try std.math.mul(usize, @min(rows, Classic.ROW_CHUNK) * Local.inverseCount(frame), 2 * @sizeOf(O) + @sizeOf(Classic.Numerator));
        scratch = @max(scratch, bytes);
    }
    if (try std.math.add(usize, output, scratch) > budget) return error.WideTruthBudgetExceeded;
}
fn take(a: std.mem.Allocator, locals: *[3]Classic.Witness, globals: []Classic.Witness) !Commit {
    var width: usize = 0;
    for (locals) |*v| width += v.width();
    for (globals) |*v| width += v.width();
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, width);
    errdefer a.free(columns);
    const backings = try a.alloc([]M, 3 + globals.len);
    errdefer a.free(backings);
    var col: usize = 0;
    var owner: usize = 0;
    for (locals, 0..) |*v, i| {
        const rows = @as(usize, 1) << @intCast(v.log_size);
        for (0..v.width()) |c| {
            columns[col] = .{ .log_size = v.log_size, .values = v.data[c * rows ..][0..rows] };
            col += 1;
        }
        backings[owner] = v.data;
        owner += 1;
        if (i < globals.len) {
            const g = &globals[i];
            const n = @as(usize, 1) << @intCast(g.log_size);
            for (0..g.width()) |c| {
                columns[col] = .{ .log_size = g.log_size, .values = g.data[c * n ..][0..n] };
                col += 1;
            }
            backings[owner] = g.data;
            owner += 1;
        }
    }
    for (locals) |*v| v.data = &.{};
    for (globals) |*v| v.data = &.{};
    return .{ .columns = columns, .backings = backings };
}
pub fn verifyTruth(a: std.mem.Allocator, truth: R.Truth, expected: Manifest.ExpectedWorker, pending: *const Manifest.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const TruthEncoded) !Manifest.Claims {
    try validateExpected(truth, expected);
    try validatePending(expected, pending, index);
    var proof = try W.decodePhysical(a, encoded.bytes);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.WideTruthRoots;
    try pending.checkPhysicalRoots(index, roots[0], roots[1]);
    var ch = W.begin(config, expected);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    const shape = try templates(truth);
    for (0..2) |tree| {
        const logs = try shape.logs(a, tree);
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &ch);
    }
    const local = TF.ChallengesFor(O).draw(&ch);
    var components = try Components.init(truth, local, pending.shared, encoded.claims);
    W.mixManifestAndClaims(&ch, pending.digest, encoded.claims);
    const logs = try components.logs(a, 2);
    defer a.free(logs);
    try receiver.commit(a, roots[2], logs, &ch);
    owns_proof = false; // core receiver consumes proof on every path.
    try core.verifier.ForField(O).verify(W.H, W.MC, a, &components.verifiers(), &ch, &receiver, proof);
    return claimsResult(truth, encoded.claims);
}
