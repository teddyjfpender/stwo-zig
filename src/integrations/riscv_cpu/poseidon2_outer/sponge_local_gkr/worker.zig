//! Detached fragment worker: shared PCS/GKR/global source authorities, no
//! independent execution admission. All MAIN seals precede shared challenges.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("authority.zig");
const Source = @import("source.zig");
const Native = @import("native.zig");
const Fraction = @import("fractions.zig");
const Binding = @import("witness.zig");
const Global = @import("global_witness.zig");
const Component = @import("component.zig");
const Key = @import("key.zig").Key;
const Stages = @import("stages.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = core.fields.om31.OM31;
const Manifest = @import("../pure_p2_manifest.zig");
pub const Kind = enum(u32) { detached_sponge_fragment = 0x53504753 };
pub const Expected = struct { kind: Kind = .detached_sponge_fragment, ordinal: u32, statement: [32]u8 };
pub const Encoded = struct {
    bytes: []u8,
    local: []u8,
    receipt: [36]u8,
    claims: [8][3]O,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.local);
        self.* = undefined;
    }
};
pub const Worker = struct {
    allocator: std.mem.Allocator,
    native_recorder: ?*@import("stwo_prover_api").stage_profile.Recorder = null,
    geometry: R.Geometry,
    key: *const Key,
    expected: Expected,
    source: Source.Source,
    scheme: W.Scheme,
    channel: W.Channel,
    global_limit: usize,
    owns_scheme: bool = true,
    sealed: bool = false,
    consumed: bool = false,
    pub fn init(a: std.mem.Allocator, g: R.Geometry, key: *const Key, ordinal: u32, calls: []const A.crypto.keccak_sponge.types.Call, words: []const A.memory.closed_ram.types.State, global_limit: usize) !Worker {
        if (!g.detached) return error.SpongeLocalScopeFlavor;
        try key.require(g);
        const source = try Source.Source.init(a, g, calls, words);
        errdefer {
            var own = source;
            own.deinit();
        }
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        const expected = Expected{ .ordinal = ordinal, .statement = try key.statementDetached(g) };
        return .{ .allocator = a, .geometry = g, .key = key, .expected = expected, .source = source, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root), .global_limit = global_limit };
    }
    pub fn seal(self: *Worker) ![36]u8 {
        if (self.sealed or self.consumed) return error.PoseidonNativePhase;
        self.consumed = true;
        var tree = try self.key.retainFixedTree();
        self.scheme.appendCommittedTree(self.allocator, tree, &self.channel) catch |err| {
            tree.deinit(self.allocator);
            return err;
        };
        const instances = try self.geometry.instances();
        var columns: [Stages.totalWidth(1, true)]engine.pcs.ColumnEvaluation = undefined;
        var offset: usize = 0;
        inline for (R.detached_roles, 0..) |role, i| {
            Stages.columns(self.source.main[i], instances[i].row_log, columns[offset..][0..R.mainWidth(role)]);
            offset += R.mainWidth(role);
        }
        try self.scheme.commitBorrowedStreamingWithRecorder(self.allocator, &columns, 64, self.native_recorder, &self.channel);
        // Source metadata is itself MAIN and will serve the checkpoint reader.
        // It stays live until complete; never rebuild a second wide witness.
        self.sealed = true;
        self.consumed = false;
        return self.scheme.trees.items[1].root();
    }
    pub fn complete(self: *Worker, manifest: [36]u8) !Encoded {
        return self.completeMode(manifest, false);
    }
    /// Test-only producer of a valid physical STARK with a phantom unused
    /// claim: this demonstrates why policy rejection is required separately.
    pub fn completePhantomForTest(self: *Worker, manifest: [36]u8) !Encoded {
        if (!@import("builtin").is_test) @compileError("test-only phantom control");
        return self.completeMode(manifest, true);
    }
    fn completeMode(self: *Worker, manifest: [36]u8, comptime phantom: bool) !Encoded {
        if (!self.sealed or self.consumed) return error.PoseidonNativePhase;
        const a = self.allocator;
        const scope = Native.DetachedScope{ .statement = self.expected.statement, .fixed = self.key.root, .main = self.scheme.trees.items[1].root(), .manifest = manifest, .ordinal = self.expected.ordinal };
        const provider = Fraction.Provider{ .source = &self.source };
        var local_gkr = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "local_gkr", "Detached sponge local source-streamed GKR");
        defer local_gkr.end();
        var child = try Native.proveDetachedUnboundWithOptions(a, scope, self.geometry, provider, .{ .coefficient_encoding = .fixed4 });
        defer child.deinit(a);
        local_gkr.end();
        var generation = try @import("stwo_prover_api").stage_profile.StageScope.begin(self.native_recorder, "interaction_generation", "Detached terminal binding and original global RAM KIO Wire");
        defer generation.end();
        var binding = try Binding.Witness.init(a, self.geometry, &child.challenges, provider, &child.result.artifact, child.eta);
        defer binding.deinit();
        const shared = try Stages.globalDraw(manifest);
        const instances = try self.geometry.instances();
        var data: Stages.tupleTypes(true, true) = undefined;
        var components: Stages.tupleTypes(false, true) = undefined;
        var globals: [8]Global.Witness = undefined;
        var initialized: usize = 0;
        defer inline for (0..8) |i| if (i < initialized) {
            data[i].deinit();
            globals[i].deinit();
        };
        var claims: [8][3]O = undefined;
        var columns: [Stages.totalWidth(2, true)]engine.pcs.ColumnEvaluation = undefined;
        var provers: [8]engine.air.component_prover.ForField(O).ComponentProver = undefined;
        var offsets: [3]usize = @splat(0);
        inline for (R.detached_roles, 0..) |role, i| {
            data[i] = try Component.Data(role).init(a, self.geometry, child.terminal());
            globals[i] = Global.generate(role, a, &self.source, shared, self.global_limit) catch |err| {
                data[i].deinit();
                return err;
            };
            initialized += 1;
            claims[i] = globals[i].claims;
            components[i] = .{ .log_size = instances[i].row_log, .public = .{ .calls = self.geometry.calls, .permutations = self.geometry.permutations, .first_id = self.geometry.first_id }, .data = &data[i], .challenges = child.challenges, .global_challenges = shared, .global_claims = claims[i], .offsets = offsets };
            provers[i] = components[i].asProverComponent();
            const rows = try instances[i].rows();
            const width = R.interactionWidth(role);
            Stages.columns(binding.columns[i], instances[i].row_log, columns[offsets[2]..][0..16]);
            for (columns[offsets[2] + 16 ..][0 .. width - 16], 0..) |*c, j| c.* = .{ .log_size = instances[i].row_log, .values = globals[i].data[j * rows ..][0..rows] };
            offsets[0] += R.fixedWidth(role);
            offsets[1] += R.mainWidth(role);
            offsets[2] += width;
        }
        if (comptime phantom) claims[5][0] = O.one();
        generation.end();
        Stages.mix(&self.channel, scope, child.digest, O.zero(), claims);
        try self.scheme.commitBorrowedStreamingWithRecorder(a, &columns, 64, self.native_recorder, &self.channel);
        self.consumed = true;
        const scheme = self.scheme;
        self.owns_scheme = false;
        self.scheme = undefined;
        var proof = try W.Prover.prove(a, &provers, &self.channel, scheme, .{ .recorder = self.native_recorder });
        defer proof.deinit(a);
        const bytes = try W.Wire.encodeProofBytesBinary(a, proof.proof);
        errdefer a.free(bytes);
        return .{ .bytes = bytes, .local = try Native.encode(a, self.geometry, &child.result.proof), .receipt = child.digest, .claims = claims };
    }
    pub fn deinit(self: *Worker) void {
        self.source.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, g: R.Geometry, key: *const Key, ordinal: u32, manifest: [36]u8, main: [36]u8, encoded: *const Encoded) !Manifest.Claims {
    return verifyWithCapture(a, g, key, ordinal, manifest, main, encoded, null);
}
pub fn verifyWithCapture(a: std.mem.Allocator, g: R.Geometry, key: *const Key, ordinal: u32, manifest: [36]u8, main: [36]u8, encoded: *const Encoded, captured: ?*core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H)) !Manifest.Claims {
    return verifyMode(a, g, key, ordinal, manifest, main, encoded, captured, true);
}
pub fn verifyPhantomPhysicalForTest(a: std.mem.Allocator, g: R.Geometry, key: *const Key, ordinal: u32, manifest: [36]u8, main: [36]u8, encoded: *const Encoded) !Manifest.Claims {
    if (!@import("builtin").is_test) @compileError("test-only raw physical control");
    return verifyMode(a, g, key, ordinal, manifest, main, encoded, null, false);
}
fn verifyMode(a: std.mem.Allocator, g: R.Geometry, key: *const Key, ordinal: u32, manifest: [36]u8, main: [36]u8, encoded: *const Encoded, captured: ?*core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H), comptime policy: bool) !Manifest.Claims {
    if (!g.detached) return error.SpongeLocalScopeFlavor;
    if (comptime policy) try requireClaims(encoded.claims);
    const expected = Expected{ .ordinal = ordinal, .statement = try key.statementDetached(g) };
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root) or !std.mem.eql(u8, &roots[1], &main)) return error.SpongeCpuProofScope;
    const scope = Native.DetachedScope{ .statement = expected.statement, .fixed = key.root, .main = main, .manifest = manifest, .ordinal = ordinal };
    var local = try Native.decode(a, g, encoded.local);
    defer local.deinit();
    var pending = try Native.verifyDetachedPending(a, scope, g, &local.proof, encoded.receipt);
    defer pending.deinit(a);
    const shared = try Stages.globalDraw(manifest);
    const instances = try g.instances();
    var data: Stages.tupleTypes(true, true) = undefined;
    var components: Stages.tupleTypes(false, true) = undefined;
    var initialized: usize = 0;
    defer inline for (0..8) |i| if (i < initialized) data[i].deinit();
    var verifiers: [8]core.air.components.ForField(O).Component = undefined;
    var offsets: [3]usize = @splat(0);
    inline for (R.detached_roles, 0..) |role, i| {
        data[i] = try Component.Data(role).init(a, g, pending.terminal());
        initialized += 1;
        components[i] = .{ .log_size = instances[i].row_log, .public = .{ .calls = g.calls, .permutations = g.permutations, .first_id = g.first_id }, .data = &data[i], .challenges = pending.challenges, .global_challenges = shared, .global_claims = encoded.claims[i], .offsets = offsets };
        if (comptime !policy) {
            // Remove ONLY the native component's existing absent-slot policy
            // for the raw-AIR positive control. The transcript still commits
            // the phantom claim, and no present relation is changed.
            if (comptime @import("equations.zig").globalCount(role, false) == 0) components[i].global_claims[0] = O.zero();
            if (comptime @import("equations.zig").globalCount(role, true) == 0) components[i].global_claims[1] = O.zero();
            if (comptime role != .detached_descriptor) components[i].global_claims[2] = O.zero();
        }
        verifiers[i] = components[i].asVerifierComponent();
        offsets[0] += R.fixedWidth(role);
        offsets[1] += R.mainWidth(role);
        offsets[2] += R.interactionWidth(role);
    }
    var channel = Protocol.begin(key.profile, expected, key.identity, key.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    inline for (0..3) |tree| {
        var logs: [Stages.totalWidth(tree, true)]u32 = undefined;
        var first: usize = 0;
        inline for (R.detached_roles, 0..) |role, i| {
            const width = switch (tree) {
                0 => R.fixedWidth(role),
                1 => R.mainWidth(role),
                else => R.interactionWidth(role),
            };
            @memset(logs[first..][0..width], instances[i].row_log);
            first += width;
        }
        if (tree == 2) Stages.mix(&channel, scope, encoded.receipt, O.zero(), encoded.claims);
        try receiver.commit(a, roots[tree], &logs, &channel);
    }
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &verifiers, &channel, &receiver, &proof, &capture);
    if (captured) |out| out.* = capture else capture.deinit(a);
    var claims = Manifest.Claims{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
    for (encoded.claims) |c| {
        claims.ram = claims.ram.add(c[0]);
        claims.kio = claims.kio.add(c[1]);
        claims.wire = claims.wire.add(c[2]);
    }
    return claims;
}

/// A role with no physical relation cannot contribute aggregate debt. These
/// slots are still explicitly framed, and must be canonical zero on reception.
pub fn requireClaims(claims: [8][3]O) !void {
    inline for (R.detached_roles, 0..) |role, i| {
        if (comptime @import("equations.zig").globalCount(role, false) == 0) if (!claims[i][0].isZero()) return error.SpongeAbsentGlobalClaim;
        if (comptime @import("equations.zig").globalCount(role, true) == 0) if (!claims[i][1].isZero()) return error.SpongeAbsentGlobalClaim;
        if (comptime role != .detached_descriptor) if (!claims[i][2].isZero()) return error.SpongeAbsentGlobalClaim;
    }
}
test "detached sponge absent global slots cannot carry aggregate debt" {
    var claims: [8][3]O = @splat(@splat(O.zero()));
    try requireClaims(claims);
    inline for (R.detached_roles, 0..) |role, i| {
        inline for (0..3) |r| if (comptime (r == 0 and @import("equations.zig").globalCount(role, false) == 0) or (r == 1 and @import("equations.zig").globalCount(role, true) == 0) or (r == 2 and role != .detached_descriptor)) {
            claims[i][r] = O.one();
            try std.testing.expectError(error.SpongeAbsentGlobalClaim, requireClaims(claims));
            claims[i][r] = O.zero();
        };
    }
}
