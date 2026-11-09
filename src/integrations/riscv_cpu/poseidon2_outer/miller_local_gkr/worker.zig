//! Isolated, explicitly bounded Miller local-GKR candidate. A verified fragment
//! leaves global Wire debt pending; no runtime/schema2 admission is granted.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const Tower = A.crypto.bn254_tower.narrow;
const S = Tower.source;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Classic = @import("../pure_p2_tower_worker.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Manifest = @import("../pure_p2_manifest.zig");
const Native = @import("native.zig");
const Shapes = @import("authority.zig");
const C = @import("component.zig");
const Eq = @import("equations.zig");
const Input = @import("source_inputs.zig");
const Binding = @import("witness.zig");
const Global = @import("global_witness.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
pub const Span = Classic.Span;
pub const Key = struct {
    base: Classic.Key,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, profile: Protocol.Profile, frontier_log: u32, arithmetic_log: u32) !Key {
        var base = try Classic.Key.init(a, profile, frontier_log, arithmetic_log);
        errdefer base.deinit();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(Shapes.DOMAIN);
        hash.update(&base.identity);
        var word: [4]u8 = undefined;
        for ([_]usize{ 24, 56, 98, 32, 8, 1 }) |value| {
            std.mem.writeInt(u32, &word, @intCast(value), .little);
            hash.update(&word);
        }
        return .{ .base = base, .identity = hash.finalResult() };
    }
    pub fn deinit(self: *Key) void {
        self.base.deinit();
        self.* = undefined;
    }
    pub fn geometry(self: *const Key, span: Span) !Shapes.Geometry {
        try self.base.validateSpan(span);
        const result = Shapes.Geometry{ .calls = span.calls, .first_id = span.first_id, .frontier_log = self.base.frontier_log, .arithmetic_log = self.base.arithmetic_log };
        _ = try result.instances();
        return result;
    }
    pub fn statement(self: *const Key, span: Span) ![32]u8 {
        _ = try self.geometry(span);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(Shapes.DOMAIN);
        hash.update(&self.identity);
        hash.update(&try self.base.statement(span));
        return hash.finalResult();
    }
    pub fn expected(self: *const Key, span: Span, ordinal: u32) !Manifest.Expected {
        var out = try self.base.expected(span, ordinal);
        out.fixed_identity = self.identity;
        out.statement = try self.statement(span);
        return out;
    }
    pub fn logs(self: *const Key, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree > 2) return error.MillerLocalGeometry;
        const widths = [2]usize{ Eq.Layout(.frontier).widths()[tree], Eq.Layout(.arithmetic).widths()[tree] };
        const out = try a.alloc(u32, widths[0] + widths[1]);
        @memset(out[0..widths[0]], self.base.frontier_log);
        @memset(out[widths[0]..], self.base.arithmetic_log);
        return out;
    }
};
pub const SealedScope = Classic.SealedScope;
pub const Limits = struct { live_bytes: usize, main_bytes: usize, interaction_bytes: usize, advice_bytes: usize, gkr_bytes: usize };
pub const Resources = struct {
    main_bytes: usize,
    interaction_bytes: usize,
    advice_bytes: usize,
    child_peak_bytes: usize,
    pub fn derive(key: *const Key, span: Span) !Resources {
        const g = try key.geometry(span);
        const instances = try g.instances();
        const old = try Classic.ResourcePlan.derive(&key.base, span);
        var plan = engine.lookups.resource.ForField(O).Plan{};
        var facts: usize = 0;
        for (instances) |instance| {
            try plan.add(.{ .kind = .multiplicities, .variables = try instance.variables() });
            facts = try std.math.add(usize, facts, try instance.facts());
        }
        try plan.finish();
        return .{ .main_bytes = old.main_bytes, .advice_bytes = old.advice_bytes, .interaction_bytes = 4 * (24 * (@as(usize, 1) << @intCast(g.frontier_log)) + 56 * (@as(usize, 1) << @intCast(g.arithmetic_log))), .child_peak_bytes = try std.math.add(usize, try std.math.mul(usize, facts, @import("../../word16_global_execution/services/gkr_local/resource.zig").SOURCE_CHECKPOINT_BYTES_PER_FACT), try std.math.add(usize, plan.metadata_bytes, 65536)) };
    }
    pub fn admit(self: Resources, limits: Limits) !void {
        if (limits.live_bytes == 0 or limits.gkr_bytes == 0 or self.main_bytes > limits.main_bytes or self.interaction_bytes > limits.interaction_bytes or self.advice_bytes > limits.advice_bytes or self.child_peak_bytes > limits.gkr_bytes) return error.MillerLocalBudget;
        // A necessary preflight floor. All source, PCS, binding and prover
        // allocations remain charged to the separate hard whole-worker cap.
        if (try std.math.add(usize, self.advice_bytes, try std.math.add(usize, self.main_bytes, self.child_peak_bytes)) > limits.live_bytes) return error.MillerLocalBudget;
    }
};
pub const Encoded = struct {
    bytes: []u8,
    local: []u8,
    receipt: [36]u8,
    claims: [2]O,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.local);
        self.* = undefined;
    }
};
pub fn validateExpected(key: *const Key, span: Span, expected: Manifest.Expected) !void {
    if (!std.meta.eql(expected, try key.expected(span, expected.ordinal))) return error.MillerLocalExpected;
}
fn checkPending(key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, ordinal: usize) !void {
    try validateExpected(key, span, expected);
    if (ordinal != expected.ordinal or ordinal >= pending.entries.len or !std.meta.eql(pending.shared, try Manifest.drawShared(pending.digest))) return error.MillerLocalManifest;
    const entry = pending.entries[ordinal];
    if (!std.meta.eql(entry.authority, expected) or !std.meta.eql(entry.global_relations, expected.global_relations) or entry.local != null or entry.scope.ordinal != expected.ordinal or !std.mem.eql(u8, &entry.scope.fixed, &expected.fixed) or !std.mem.eql(u8, &entry.scope.statement, &expected.statement)) return error.MillerLocalManifest;
}
pub fn scopeFor(expected: Manifest.Expected, main: [36]u8, manifest: [36]u8) Native.Scope {
    return .{ .statement = expected.statement, .fixed = expected.fixed, .main = main, .manifest = manifest, .ordinal = expected.ordinal };
}
pub fn mixClaims(channel: *W.Channel, manifest: [36]u8, receipt: [36]u8, claims: [2]O) void {
    channel.mixU32s(&.{ 0x4f504d47, 2, 8, 9, 2 });
    channel.mixRoot(manifest);
    channel.mixRoot(receipt);
    channel.mixFelts(&claims);
}
const Set = struct {
    allocator: std.mem.Allocator,
    fd: *C.Data(.frontier),
    ad: *C.Data(.arithmetic),
    front: C.Component(.frontier),
    arith: C.Component(.arithmetic),
    fn init(a: std.mem.Allocator, key: *const Key, span: Span, terminal: Native.Terminal, shared: Manifest.Shared, claims: [2]O) !Set {
        for (claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.MillerLocalClaim;
        const g = try key.geometry(span);
        const fd = try a.create(C.Data(.frontier));
        errdefer a.destroy(fd);
        fd.* = try C.Data(.frontier).init(a, g, terminal);
        errdefer fd.deinit();
        const ad = try a.create(C.Data(.arithmetic));
        errdefer a.destroy(ad);
        ad.* = try C.Data(.arithmetic).init(a, g, terminal);
        errdefer ad.deinit();
        var ch = terminal.challenges;
        ch.wire = shared.wire;
        return .{ .allocator = a, .fd = fd, .ad = ad, .front = .{ .log_size = g.frontier_log, .public = .{ .calls = span.calls, .first_id = span.first_id }, .data = fd, .challenges = ch, .global_claim = claims[0] }, .arith = .{ .log_size = g.arithmetic_log, .public = .{ .calls = span.calls, .first_id = span.first_id }, .data = ad, .challenges = ch, .global_claim = claims[1], .offsets = .{ S.FIXED, S.mainWidth(.frontier), Eq.Layout(.frontier).INTERACTION } } };
    }
    fn deinit(self: *Set) void {
        self.fd.deinit();
        self.ad.deinit();
        self.allocator.destroy(self.fd);
        self.allocator.destroy(self.ad);
        self.* = undefined;
    }
};
fn columns(data: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) !void {
    const rows = @as(usize, 1) << @intCast(log);
    if (data.len != try std.math.mul(usize, rows, out.len)) return error.MillerLocalGeometry;
    for (out, 0..) |*column, c| column.* = .{ .log_size = log, .values = data[c * rows ..][0..rows] };
}
fn takeInter(a: std.mem.Allocator, geometry: Shapes.Geometry, binding: *Binding.Witness, front: *Global.Witness, arith: *Global.Witness) !Commit {
    const headers = try a.alloc(engine.pcs.ColumnEvaluation, 80);
    errdefer a.free(headers);
    const owners = try a.alloc([]M, 6);
    errdefer a.free(owners);
    try columns(binding.columns[3], geometry.frontier_log, headers[0..16]);
    try columns(front.data, geometry.frontier_log, headers[16..24]);
    for (0..3) |index| try columns(binding.columns[index], geometry.arithmetic_log, headers[24 + 16 * index ..][0..16]);
    try columns(arith.data, geometry.arithmetic_log, headers[72..80]);
    owners[0] = binding.columns[3];
    owners[1] = front.data;
    for (0..3) |index| owners[2 + index] = binding.columns[index];
    owners[5] = arith.data;
    for (&binding.columns) |*data| data.* = &.{};
    front.data = &.{};
    arith.data = &.{};
    return .{ .columns = headers, .backings = owners };
}
pub const Worker = struct {
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    allocator: std.mem.Allocator,
    output_allocator: std.mem.Allocator,
    budget: *Budget,
    key: *const Key,
    span: Span,
    expected: Manifest.Expected,
    limits: Limits,
    frontier: Tower.trace.SourceForField(.frontier, O),
    arithmetic: Tower.trace.SourceForField(.arithmetic, O),
    scheme: W.Scheme,
    channel: W.Channel,
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    owns_sources: bool = true,
    pub fn init(backing: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, input: []const Tower.trace.Input, limits: Limits) !Worker {
        try validateExpected(key, span, expected);
        if (input.len != span.calls) return error.OpTowerCallCount;
        try (try Resources.derive(key, span)).admit(limits);
        const budget = try Budget.createRetainingParent(backing, limits.live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var f = try Tower.trace.SourceForField(.frontier, O).initWithoutFixed(a, input, span.first_id, key.base.frontier_log);
        errdefer f.deinit();
        var c = try Tower.trace.SourceForField(.arithmetic, O).initWithoutFixed(a, input, span.first_id, key.base.arithmetic_log);
        errdefer c.deinit();
        var scheme = try W.Prover.init(a, key.base.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        return .{ .allocator = a, .output_allocator = backing, .budget = budget, .key = key, .span = span, .expected = expected, .limits = limits, .frontier = f, .arithmetic = c, .scheme = scheme, .channel = Protocol.begin(key.base.profile, expected, key.identity, key.base.root) };
    }
    pub fn deinit(self: *Worker) void {
        if (self.owns_sources) {
            self.frontier.deinit();
            self.arithmetic.deinit();
        }
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    fn takeMain(self: *Worker) !Commit {
        const headers = try self.allocator.alloc(engine.pcs.ColumnEvaluation, 403);
        errdefer self.allocator.free(headers);
        const owners = try self.allocator.alloc([]M, 2);
        errdefer self.allocator.free(owners);
        try columns(self.frontier.main, self.frontier.log_size, headers[0..33]);
        try columns(self.arithmetic.main, self.arithmetic.log_size, headers[33..]);
        owners[0] = self.frontier.main;
        owners[1] = self.arithmetic.main;
        self.frontier.main = &.{};
        self.arithmetic.main = &.{};
        return .{ .columns = headers, .backings = owners };
    }
    pub fn seal(self: *Worker) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.OpTowerPhase;
        self.consumed = true;
        var tree = self.key.base.tree.retainShared();
        self.scheme.appendCommittedTree(self.allocator, tree, &self.channel) catch |err| {
            tree.deinit(self.key.base.allocator);
            return err;
        };
        const main = try self.takeMain();
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 64, self.native_recorder, &self.channel);
        self.sealed = true;
        self.consumed = false;
        return .{ .main = self.scheme.trees.items[1].root(), .local = null };
    }
    pub fn complete(self: *Worker, pending: *const Manifest.Pending, ordinal: usize) !Encoded {
        if (!self.sealed or self.consumed) return error.OpTowerPhase;
        try checkPending(self.key, self.span, self.expected, pending, ordinal);
        try pending.checkPhysicalRoots(ordinal, self.key.base.root, self.scheme.trees.items[1].root());
        return self.completeSealed(.{ .manifest = pending.digest, .main = self.scheme.trees.items[1].root() });
    }
    pub fn completeSealed(self: *Worker, sealed: SealedScope) !Encoded {
        if (!self.sealed or self.consumed) return error.OpTowerPhase;
        try validateExpected(self.key, self.span, self.expected);
        if (!std.mem.eql(u8, &sealed.main, &self.scheme.trees.items[1].root())) return error.GlobalGkrPhysicalRootMismatch;
        const shared = try Manifest.drawShared(sealed.manifest);
        self.consumed = true;
        const a = self.allocator;
        const geometry = try self.key.geometry(self.span);
        const child_budget = try Budget.createRetainingParent(a, self.limits.gkr_bytes);
        defer child_budget.destroy();
        const ga = child_budget.allocator();
        var gkr_scope = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "local_gkr", "Miller local BYTE, U15 and shared SSA GKR");
        defer gkr_scope.end();
        var child = try Native.proveUnboundWithOptions(ga, scopeFor(self.expected, self.scheme.trees.items[1].root(), sealed.manifest), geometry, Input.Provider{ .frontier = &self.frontier, .arithmetic = &self.arithmetic }, .{ .coefficient_encoding = .fixed4 });
        defer child.deinit(ga);
        gkr_scope.end();
        var binding = try Binding.Witness.init(a, geometry, &child.challenges, Input.Provider{ .frontier = &self.frontier, .arithmetic = &self.arithmetic }, &child.result.artifact, child.eta);
        defer binding.deinit();
        var ch = child.challenges;
        ch.wire = shared.wire;
        var fg = try Global.generate(.frontier, a, &self.frontier, ch, self.limits.interaction_bytes);
        defer fg.deinit();
        var ag = try Global.generate(.arithmetic, a, &self.arithmetic, ch, self.limits.interaction_bytes);
        defer ag.deinit();
        const claims = [2]O{ fg.claim, ag.claim };
        var set = try Set.init(a, self.key, self.span, child.terminal(), shared, claims);
        defer set.deinit();
        mixClaims(&self.channel, sealed.manifest, child.digest, claims);
        const inter = try takeInter(a, geometry, &binding, &fg, &ag);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, 64, self.native_recorder, &self.channel);
        const handles = [_]engine.air.component_prover.ForField(O).ComponentProver{ set.front.asProverComponent(), set.arith.asProverComponent() };
        const scheme = self.scheme;
        self.owns_scheme = false;
        self.scheme = undefined;
        var proof = try W.Prover.prove(a, &handles, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        const native_bytes = try W.Wire.encodeProofBytesBinary(self.output_allocator, proof.proof);
        errdefer self.output_allocator.free(native_bytes);
        const local_bytes = try Native.encode(self.output_allocator, geometry, &child.result.proof);
        // The physical proof now retains the authenticated source obligations;
        // no source method or math replay is needed after successful completion.
        self.frontier.deinit();
        self.arithmetic.deinit();
        self.owns_sources = false;
        return .{ .bytes = native_bytes, .local = local_bytes, .receipt = child.digest, .claims = claims };
    }
};
pub fn verify(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, ordinal: usize, encoded: *const Encoded) !Manifest.Claims {
    return verifyWithCapture(a, key, span, expected, pending, ordinal, encoded, null);
}
pub fn verifyWithCapture(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, pending: *const Manifest.Pending, ordinal: usize, encoded: *const Encoded, capture_output: anytype) !Manifest.Claims {
    try checkPending(key, span, expected, pending, ordinal);
    return verifySealedWithCapture(a, key, span, expected, .{ .manifest = pending.digest, .main = pending.entries[ordinal].scope.main }, encoded, capture_output);
}
pub fn verifySealed(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, sealed: SealedScope, encoded: *const Encoded) !Manifest.Claims {
    return verifySealedWithCapture(a, key, span, expected, sealed, encoded, null);
}
pub fn verifySealedWithCapture(a: std.mem.Allocator, key: *const Key, span: Span, expected: Manifest.Expected, sealed: SealedScope, encoded: *const Encoded, capture_output: anytype) !Manifest.Claims {
    try validateExpected(key, span, expected);
    const shared = try Manifest.drawShared(sealed.manifest);
    for (encoded.claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.MillerLocalClaim;
    _ = try core.crypto.poseidon2_m31_sponge.decode(encoded.receipt);
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.base.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.base.root)) return error.OpTowerProofShape;
    if (!std.mem.eql(u8, &sealed.main, &roots[1])) return error.GlobalGkrPhysicalRootMismatch;
    const geometry = try key.geometry(span);
    var local = try Native.decode(a, geometry, encoded.local);
    defer local.deinit();
    var checked = try Native.verifyPending(a, scopeFor(expected, roots[1], sealed.manifest), geometry, &local.proof, encoded.receipt);
    defer checked.deinit(a);
    var set = try Set.init(a, key, span, checked.terminal(), shared, encoded.claims);
    defer set.deinit();
    var channel = Protocol.begin(key.base.profile, expected, key.identity, key.base.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.base.profile.config());
    defer receiver.deinit(a);
    for (0..3) |tree| {
        if (tree == 2) mixClaims(&channel, sealed.manifest, encoded.receipt, encoded.claims);
        const logs = try key.logs(a, tree);
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &channel);
    }
    const handles = [_]core.air.components.ForField(O).Component{ set.front.asVerifierComponent(), set.arith.asVerifierComponent() };
    if (comptime @TypeOf(capture_output) == @TypeOf(null)) {
        var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, &capture);
        capture.deinit(a);
    } else try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &receiver, &proof, capture_output);
    return .{ .ram = O.zero(), .kio = O.zero(), .wire = encoded.claims[0].add(encoded.claims[1]) };
}

const MAGIC = "OPMLPCS1";
const HEADER = 124;
pub fn encode(a: std.mem.Allocator, value: *const Encoded) ![]u8 {
    _ = try core.crypto.poseidon2_m31_sponge.decode(value.receipt);
    if (value.local.len == 0 or value.local.len > Native.Wire.MAX_BYTES or value.bytes.len == 0) return error.MillerLocalEnvelope;
    const size = try std.math.add(usize, HEADER, try std.math.add(usize, value.bytes.len, value.local.len));
    for (value.claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.MillerLocalEnvelope;
    const out = try a.alloc(u8, size);
    @memcpy(out[0..8], MAGIC);
    std.mem.writeInt(u64, out[8..16], value.bytes.len, .little);
    std.mem.writeInt(u64, out[16..24], value.local.len, .little);
    @memcpy(out[24..60], &value.receipt);
    for (value.claims, 0..) |claim, j| for (claim.toM31Array(), 0..) |coordinate, i| std.mem.writeInt(u32, out[60 + 32 * j + 4 * i ..][0..4], coordinate.v, .little);
    @memcpy(out[HEADER..][0..value.bytes.len], value.bytes);
    @memcpy(out[HEADER + value.bytes.len ..], value.local);
    return out;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, max_bytes: usize) !Encoded {
    if (bytes.len < HEADER or bytes.len > max_bytes or !std.mem.eql(u8, bytes[0..8], MAGIC)) return error.MillerLocalEnvelope;
    const pcs = std.math.cast(usize, std.mem.readInt(u64, bytes[8..16], .little)) orelse return error.MillerLocalEnvelope;
    const local = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .little)) orelse return error.MillerLocalEnvelope;
    if (pcs == 0 or local == 0 or pcs > bytes.len - HEADER or local > Native.Wire.MAX_BYTES or local != bytes.len - HEADER - pcs) return error.MillerLocalEnvelope;
    const receipt = bytes[24..60].*;
    _ = try core.crypto.poseidon2_m31_sponge.decode(receipt);
    var claims: [2]O = undefined;
    for (&claims, 0..) |*claim, j| {
        var coords: [8]core.fields.m31.M31 = undefined;
        for (&coords, 0..) |*coordinate, i| {
            const value = std.mem.readInt(u32, bytes[60 + 32 * j + 4 * i ..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.MillerLocalEnvelope;
            coordinate.* = core.fields.m31.M31.fromCanonical(value);
        }
        claim.* = O.fromM31Array(coords);
    }
    const proof = try a.dupe(u8, bytes[HEADER..][0..pcs]);
    errdefer a.free(proof);
    return .{ .bytes = proof, .local = try a.dupe(u8, bytes[HEADER + pcs ..]), .receipt = receipt, .claims = claims };
}

pub fn runWithHook(a: std.mem.Allocator, comptime Hook: type) !void {
    return runMode(a, Hook, false);
}
fn runMode(a: std.mem.Allocator, comptime Hook: type, comptime sealed_parity: bool) !void {
    var key = try Key.init(a, .op_target_b4_q72_p0_fold4_v1, 8, 15);
    defer key.deinit();
    const span = Span{ .calls = 1, .first_id = 7 };
    const expected = try key.expected(span, 0);
    const input = [_]Tower.trace.Input{@splat(1)};
    const limits = Limits{ .live_bytes = 2 << 30, .main_bytes = 128 << 20, .interaction_bytes = 32 << 20, .advice_bytes = 1 << 20, .gkr_bytes = 512 << 20 };
    var too_small = limits;
    too_small.gkr_bytes = 1;
    try std.testing.expectError(error.MillerLocalBudget, Worker.init(a, &key, span, expected, &input, too_small));
    try std.testing.expectError(error.MillerLocalExpected, Worker.init(a, &key, span, try key.base.expected(span, 0), &input, limits));
    var worker = try Worker.init(a, &key, span, expected, &input, limits);
    defer worker.deinit();
    const stage = try worker.seal();
    try std.testing.expectEqual(@as(usize, 0), worker.frontier.main.len);
    try std.testing.expectEqual(@as(usize, 0), worker.arithmetic.main.len);
    try std.testing.expectError(error.OpTowerPhase, worker.seal());
    // Fragment-only synthetic challenge, exactly like the catalog fixture.
    // Complete execution acceptance MUST independently call verifyAndSeal.
    var entries = [_]Manifest.Entry{.{ .authority = expected, .scope = .{ .statement = expected.statement, .fixed = expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null, .global_relations = expected.global_relations }};
    const digest = try Manifest.digest([_]u8{31} ** 32, &entries);
    const pending = Manifest.Pending{ .entries = &entries, .digest = digest, .shared = try Manifest.drawShared(digest) };
    var encoded = try worker.complete(&pending, 0);
    defer encoded.deinit(a);
    try std.testing.expectError(error.OpTowerPhase, worker.complete(&pending, 0));
    try std.testing.expectEqual(@as(usize, 0), worker.budget.snapshot().live_bytes);
    const envelope = try encode(a, &encoded);
    defer a.free(envelope);
    var restored = try decode(a, envelope, 16 << 20);
    defer restored.deinit(a);
    var fresh = try Key.init(a, key.base.profile, 8, 15);
    defer fresh.deinit();
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    const claims = try verifyWithCapture(a, &fresh, span, expected, &pending, 0, &restored, &capture);
    defer capture.deinit(a);
    if (sealed_parity) {
        const sealed = SealedScope{ .manifest = digest, .main = stage.main };
        const checked = try verifySealed(a, &fresh, span, expected, sealed, &restored);
        try std.testing.expectEqualDeep(claims, checked);
        var other = try Worker.init(a, &key, span, expected, &input, limits);
        defer other.deinit();
        const second_stage = try other.seal();
        try std.testing.expectEqualSlices(u8, &stage.main, &second_stage.main);
        var bad = sealed;
        bad.main = @import("../pure_p2_native.zig").hashWords(&.{777});
        try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, other.completeSealed(bad));
        var bad_pending = pending;
        bad_pending.shared.wire.offset = bad_pending.shared.wire.offset.add(O.one());
        try std.testing.expectError(error.MillerLocalManifest, other.complete(&bad_pending, 0));
        try std.testing.expect(!other.consumed);
        var second = try other.completeSealed(sealed);
        defer second.deinit(a);
        try std.testing.expectError(error.OpTowerPhase, other.completeSealed(sealed));
        try std.testing.expectEqualSlices(u8, encoded.bytes, second.bytes);
        try std.testing.expectEqualSlices(u8, encoded.local, second.local);
        try std.testing.expectEqualSlices(u8, &encoded.receipt, &second.receipt);
        try std.testing.expectEqualDeep(encoded.claims, second.claims);
        try std.testing.expectEqual(@as(usize, 0), other.budget.snapshot().live_bytes);
        try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, verifySealed(a, &fresh, span, expected, bad, &restored));
        bad = sealed;
        bad.manifest = @import("../pure_p2_native.zig").hashWords(&.{778});
        try std.testing.expect(std.meta.isError(verifySealed(a, &fresh, span, expected, bad, &restored)));
        try std.testing.expectError(error.MillerLocalManifest, verify(a, &fresh, span, expected, &bad_pending, 0, &restored));
        const changed_span = Span{ .calls = 1, .first_id = 8 };
        try std.testing.expectError(error.MillerLocalExpected, verifySealed(a, &fresh, changed_span, expected, sealed, &restored));
        try std.testing.expect(std.meta.isError(verifySealed(a, &fresh, changed_span, try fresh.expected(changed_span, 0), sealed, &restored)));
        var wrong_key = fresh; // Borrowed base; never deinit twice.
        wrong_key.identity[0] ^= 1;
        try std.testing.expectError(error.MillerLocalExpected, verifySealed(a, &wrong_key, span, expected, sealed, &restored));
        try std.testing.expect(std.meta.isError(verifySealed(a, &wrong_key, span, try wrong_key.expected(span, 0), sealed, &restored)));
        std.debug.print("OP_MILLER_SEALED local=true exact_PCS_GKR_receipt_claims=true fresh_key=true phase_cleanup=true negative_MAIN_manifest_span_key_shared=true\n", .{});
    }
    if (comptime Hook != void) try Hook.run(a, &fresh, span, expected, &pending, &restored, &capture);
    std.debug.print("OP_MILLER_GKR_WORKER native_bytes={d} local_bytes={d} peak_requested={d} retained_requested={d} source_expected=true fresh_receiver=true inventory_accepted=false\n", .{ restored.bytes.len, restored.local.len, worker.budget.snapshot().peak_live_bytes, worker.budget.snapshot().live_bytes });
    try std.testing.expect(claims.wire.eql(restored.claims[0].add(restored.claims[1])));
    const original_receipt = restored.receipt;
    restored.receipt[0] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, verify(a, &fresh, span, expected, &pending, 0, &restored));
    restored.receipt = original_receipt;
    const other_span = Span{ .calls = 1, .first_id = 8 };
    const other_expected = try fresh.expected(other_span, 0);
    var other_entries = [_]Manifest.Entry{.{ .authority = other_expected, .scope = .{ .statement = other_expected.statement, .fixed = other_expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null, .global_relations = other_expected.global_relations }};
    const other_digest = try Manifest.digest([_]u8{31} ** 32, &other_entries);
    const other_pending = Manifest.Pending{ .entries = &other_entries, .digest = other_digest, .shared = try Manifest.drawShared(other_digest) };
    if (verify(a, &fresh, other_span, other_expected, &other_pending, 0, &restored)) |_| return error.SwitchedMillerSpanAccepted else |_| {}
    restored.claims[0] = restored.claims[0].add(O.one());
    restored.claims[1] = restored.claims[1].sub(O.one());
    if (verify(a, &fresh, span, expected, &pending, 0, &restored)) |_| return error.ForgedBalancedMillerDebtAccepted else |_| {}
}

test "Miller local GKR bounded worker codec and exact source admission" {
    try runWithHook(std.testing.allocator, void);
}

fn codecAllocations(a: std.mem.Allocator, source: *const Encoded) !void {
    const envelope = try encode(a, source);
    defer a.free(envelope);
    var value = try decode(a, envelope, 4096);
    defer value.deinit(a);
    try std.testing.expectEqualSlices(u8, source.bytes, value.bytes);
    try std.testing.expectEqualSlices(u8, source.local, value.local);
}
test "Miller local GKR envelope failures are bounded canonical and allocation atomic" {
    const a = std.testing.allocator;
    const value = Encoded{ .bytes = @constCast("native"), .local = @constCast("local"), .receipt = @import("../pure_p2_native.zig").hashWords(&.{1}), .claims = .{ O.zero(), O.zero() } };
    try std.testing.checkAllAllocationFailures(a, codecAllocations, .{&value});
    const envelope = try encode(a, &value);
    defer a.free(envelope);
    try std.testing.expectError(error.MillerLocalEnvelope, decode(std.testing.failing_allocator, envelope, 1));
    std.mem.writeInt(u32, envelope[60..64], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.MillerLocalEnvelope, decode(std.testing.failing_allocator, envelope, 4096));
    std.mem.writeInt(u32, envelope[60..64], 0, .little);
    envelope[0] ^= 1;
    try std.testing.expectError(error.MillerLocalEnvelope, decode(std.testing.failing_allocator, envelope, 4096));
}

test "OP Miller sealed pending local GKR fragment exact physical parity and authority guards" {
    try runMode(std.testing.allocator, void, true);
}
