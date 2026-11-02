//! Physical V3 truth worker. Local BYTE closes internally; manifest owns Wire35.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const C = @import("truth_v3_catalog.zig");
const Role = @import("truth_v3_role.zig").Component;
const Gen = @import("truth_v3_witness.zig");
const W = @import("worker_protocol.zig");
const M = @import("manifest.zig");
const Fixed = @import("fixed_authority.zig");
const O = W.O;
pub const TruthEncoded = @import("truth_worker.zig").TruthEncoded;
pub fn truthMass(truth: R.Truth) !M.Mass {
    var x = struct {
        wires: usize = 0,
        pub fn call(s: *@This(), comptime T: type) !void {
            s.wires = T.wires;
        }
    }{};
    try C.visit(truth, &x);
    return .{ .ram = 0, .kio = 0, .wire = try std.math.mul(u64, truth.count(), x.wires) };
}
pub fn truthStatement(truth: R.Truth, config: W.PcsConfig, execution: [32]u8) ![32]u8 {
    try C.validate(truth);
    const d = try C.shape(truth);
    var ch = W.Channel.init();
    config.mixInto(&ch);
    ch.mixU32s(&.{ 0x56335431, 1, 8, @intFromEnum(std.meta.activeTag(truth)), @intFromEnum(truth.family()), truth.first(), truth.count(), try C.logSize(truth), @intCast(d.main), @intCast(d.inter), @intCast(d.constraints), d.degree });
    W.digest(&ch, execution);
    W.digest(&ch, truth.key().root);
    return ch.digestBytes();
}
pub fn truthStatementWithAuthority(truth: R.Truth, config: W.PcsConfig, execution: [32]u8, fixed: ?*const Fixed.Binding) ![32]u8 {
    const b = try truthStatement(truth, config, execution);
    return if (fixed) |f| f.statement(b) else b;
}
fn expected(truth: R.Truth, e: M.ExpectedWorker, fixed: ?*const Fixed.Binding) !void {
    try C.validate(truth);
    const root = if (fixed) |f| f.root() else truth.key().root;
    if (e.kind != .delegation or e.local_instances != null or !std.mem.eql(u8, &root, &e.fixed) or !std.meta.eql(e.mass, try truthMass(truth)) or !std.meta.eql(e.global_relations, M.Relations{ .ram = false, .kio = false, .wire = true })) return error.V3TruthExpectedMismatch;
}
fn pendingCheck(e: M.ExpectedWorker, p: *const M.PendingManifest, i: usize) !void {
    if (i >= p.entries.len or i != e.ordinal) return error.GlobalGkrManifestOrdinal;
    const v = p.entries[i];
    if (v.kind != e.kind or v.local != null or !std.meta.eql(v.mass, e.mass) or !std.meta.eql(v.global_relations, e.global_relations) or !std.mem.eql(u8, &v.scope.statement, &e.statement) or !std.mem.eql(u8, &v.scope.fixed, &e.fixed)) return error.V3TruthManifestMismatch;
}
fn local(ch: *W.Channel) O {
    ch.mixU32s(&.{ 0x56334259, 1, 8 });
    return ch.drawSecureFelt();
}
fn component(truth: R.Truth, wire: @TypeOf(@as(M.Shared, undefined).wire), bytes: O, claim: O) Role {
    return .{ .truth = truth, .wire = wire, .bytes = bytes, .claim = claim };
}
fn logs(a: std.mem.Allocator, truth: R.Truth, tree: usize) ![]u32 {
    const d = try C.shape(truth);
    const widths = [3]usize{ d.fixed, d.main, d.inter };
    if (tree > 2) return error.InvalidV3Tree;
    const out = try a.alloc(u32, widths[tree]);
    @memset(out, try C.logSize(truth));
    return out;
}
pub fn interactionBytes(truth: R.Truth) !usize {
    const d = try C.shape(truth);
    return std.math.mul(usize, try std.math.mul(usize, d.inter, @as(usize, 1) << @intCast(try C.logSize(truth))), 4);
}
pub fn scratchBytes(truth: R.Truth) !usize {
    var x = struct {
        bytes: usize = 0,
        pub fn call(s: *@This(), comptime T: type) !void {
            s.bytes = @sizeOf(T.N.Row) + 256 * @sizeOf(O) + 8 * (T.byte_batches + T.wire_batches) * @sizeOf(@import("stwo_prover_engine").pcs.ColumnEvaluation) + @sizeOf([]core.fields.m31.M31) + @sizeOf(O);
        }
    }{};
    try C.visit(truth, &x);
    return x.bytes;
}
pub fn admit(truth: R.Truth, budget: usize) !void {
    if (try std.math.add(usize, try interactionBytes(truth), try scratchBytes(truth)) > budget) return error.V3TruthBudgetExceeded;
}
pub fn validateSource(truth: R.Truth, source: *const R.TruthSource) !void {
    if (!std.mem.eql(u8, @tagName(truth), @tagName(source.*))) return error.V3TruthSourceMismatch;
    switch (source.*) {
        .sha256 => |v| {
            try v.source.validateMetadata();
            if (v.source.log_size != try C.logSize(truth) or v.source.first_id != truth.first() or v.source.inputs.len != truth.count()) return error.V3TruthSourceMismatch;
        },
        .arith256_mod => |v| {
            try v.source.validateMetadata();
            if (v.source.log_size != try C.logSize(truth) or v.source.first_id != truth.first() or v.source.inputs.len != truth.count()) return error.V3TruthSourceMismatch;
        },
        .curve => |u| {
            if (std.meta.activeTag(u) != truth.curve.setup.op) return error.V3TruthSourceMismatch;
            switch (u) {
                inline else => |v| {
                    try v.validateMetadata();
                    if (v.log_size != try C.logSize(truth) or v.first_id != truth.first() or v.packets.len != truth.count()) return error.V3TruthSourceMismatch;
                },
            }
        },
        .secp_row => |u| {
            if (std.meta.activeTag(u) != truth.secp_row.setup.kind) return error.V3TruthSourceMismatch;
            switch (u) {
                inline else => |v| {
                    try v.validateMetadata();
                    if (v.log_size != try C.logSize(truth) or v.first_id != truth.first() or v.packets.len != truth.count()) return error.V3TruthSourceMismatch;
                },
            }
        },
        else => return error.NotV3Truth,
    }
}
pub const NativeTruthWorker = struct {
    allocator: std.mem.Allocator,
    truth: R.Truth,
    source: R.TruthSource,
    expected: M.ExpectedWorker,
    scheme: W.Scheme,
    channel: W.Channel,
    owns_scheme: bool = true,
    owns_source: bool = true,
    sealed: bool = false,
    started: bool = false,
    failed: bool = false,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    fixed_authority: ?Fixed.Binding = null,
    pub fn init(a: std.mem.Allocator, truth: R.Truth, source: R.TruthSource, e: M.ExpectedWorker, config: W.PcsConfig, budget: usize) !@This() {
        return initWithAuthority(a, truth, source, e, config, budget, null);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, truth: R.Truth, source: R.TruthSource, e: M.ExpectedWorker, config: W.PcsConfig, budget: usize, fixed: ?*const Fixed.Binding) !@This() {
        if (fixed) |f| try f.require(truth.key(), config) else try W.validateConfig(config);
        try expected(truth, e, fixed);
        try validateSource(truth, &source);
        try admit(truth, budget);
        var scheme = try W.Scheme.init(a, config);
        scheme.setCompactPolynomialStorage(5);
        return .{ .allocator = a, .truth = truth, .source = source, .expected = e, .scheme = scheme, .channel = if (fixed) |f| f.begin(config, e) else W.begin(config, e), .fixed_authority = if (fixed) |f| f.retain() else null };
    }
    pub fn deinit(s: *@This(), a: std.mem.Allocator) void {
        if (s.owns_scheme) s.scheme.deinit(a);
        if (s.owns_source) s.source.deinit();
        if (s.fixed_authority) |*f| f.deinit();
        s.* = undefined;
    }
    pub fn spillMain(s: *@This(), store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!s.sealed or s.started or s.failed) return error.InvalidV3TruthPhase;
        return store.spill(s.allocator, &s.scheme.trees.items[1]);
    }
    pub fn restoreMain(s: *@This(), store: *@import("../../retained_main_store.zig").Store) !usize {
        if (!s.sealed or s.started or s.failed) return error.InvalidV3TruthPhase;
        return store.restore(&s.scheme.trees.items[1]);
    }
    pub fn seal(s: *@This(), a: std.mem.Allocator) !M.StageOne {
        if (s.sealed or s.started or s.failed) return error.InvalidV3TruthPhase;
        errdefer s.failed = true;
        if (s.fixed_authority) |*f| try f.append(a, s.truth.key(), s.expected.fixed, &s.scheme, &s.channel) else try W.appendFixed(a, s.truth.key(), s.expected.fixed, &s.scheme, &s.channel);
        const main = try s.source.takeMain();
        try s.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 64, s.native_recorder, &s.channel);
        var roots = try s.scheme.roots(a);
        defer roots.deinit(a);
        if (roots.items.len != 2) return error.V3TruthRoots;
        s.sealed = true;
        return .{ .main = roots.items[1], .local = null };
    }
    pub fn complete(s: *@This(), a: std.mem.Allocator, p: *const M.PendingManifest, index: usize, budget: usize) !TruthEncoded {
        if (!s.sealed or s.started or s.failed) return error.InvalidV3TruthPhase;
        try pendingCheck(s.expected, p, index);
        var roots = try s.scheme.roots(a);
        defer roots.deinit(a);
        if (roots.items.len != 2) return error.V3TruthRoots;
        try p.checkPhysicalRoots(index, roots.items[0], roots.items[1]);
        try admit(s.truth, budget);
        s.started = true;
        errdefer s.failed = true;
        const bytes = local(&s.channel);
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(s.native_recorder, "interaction_generation", "V3 truth local BYTE and global Wire cumulative interactions");
        defer generation.end();
        var witness = try Gen.generate(a, &s.source, p.shared.wire, bytes, budget);
        defer witness.deinit();
        generation.end();
        const claims = try a.dupe(O, &.{witness.claim});
        errdefer a.free(claims);
        var role = component(s.truth, p.shared.wire, bytes, witness.claim);
        W.mixManifestAndClaims(&s.channel, p.digest, claims);
        const inter = try witness.take(a);
        try s.scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, 64, s.native_recorder, &s.channel);
        s.owns_scheme = false;
        var proof = try W.Prover.prove(a, &.{role.asProverComponent()}, &s.channel, s.scheme, .{ .recorder = s.native_recorder });
        defer proof.deinit(a);
        const encoded = try W.encodePhysical(a, proof.proof);
        s.source.deinit();
        s.owns_source = false;
        return .{ .bytes = encoded, .claims = claims };
    }
};
pub const TruthWorker = NativeTruthWorker;
pub fn verifyTruth(a: std.mem.Allocator, truth: R.Truth, e: M.ExpectedWorker, p: *const M.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const TruthEncoded) !M.Claims {
    return verifyTruthWithAuthority(a, truth, e, p, index, config, encoded, null);
}
pub fn verifyTruthWithAuthority(a: std.mem.Allocator, truth: R.Truth, e: M.ExpectedWorker, p: *const M.PendingManifest, index: usize, config: W.PcsConfig, encoded: *const TruthEncoded, fixed: ?*const Fixed.Binding) !M.Claims {
    if (fixed) |f| try f.require(truth.key(), config) else try W.validateConfig(config);
    try expected(truth, e, fixed);
    try pendingCheck(e, p, index);
    if (encoded.claims.len != 1) return error.V3TruthClaims;
    var proof = try W.decodePhysical(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    try @import("truth_worker.zig").validateProofConfig(&proof, config);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.V3TruthRoots;
    try p.checkPhysicalRoots(index, roots[0], roots[1]);
    var ch = if (fixed) |f| f.begin(config, e) else W.begin(config, e);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, config);
    defer receiver.deinit(a);
    for (0..2) |t| {
        const ls = try logs(a, truth, t);
        defer a.free(ls);
        try receiver.commit(a, roots[t], ls, &ch);
    }
    const bytes = local(&ch);
    var role = component(truth, p.shared.wire, bytes, encoded.claims[0]);
    W.mixManifestAndClaims(&ch, p.digest, encoded.claims);
    const ls = try logs(a, truth, 2);
    defer a.free(ls);
    try receiver.commit(a, roots[2], ls, &ch);
    owns = false;
    try core.verifier.ForField(O).verify(W.H, W.MC, a, &.{role.asVerifierComponent()}, &ch, &receiver, proof);
    return .{ .ram = O.zero(), .kio = O.zero(), .wire = encoded.claims[0] };
}

pub const descriptor = C.descriptor;
pub const metadataByteUpperBound = C.metadataByteUpperBound;
