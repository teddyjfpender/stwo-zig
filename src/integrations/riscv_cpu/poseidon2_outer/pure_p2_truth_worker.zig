//! Concrete pure-P2 native truth catalog: existing Keccak/secp and V3 providers.
//! One PCS lifecycle reuses the original source equations and witness authority.
//! Production admission and recursion are separate gates.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = W.O;
const Manifest = @import("pure_p2_manifest.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const Old = @import("../word16_global_execution/services/gkr_local/truth_worker.zig");
const V3 = @import("../word16_global_execution/services/gkr_local/truth_v3_worker.zig");
const Catalog = @import("../word16_global_execution/services/gkr_local/truth_v3_catalog.zig");
const ClassicComponents = @import("../word16_global_execution/services/gkr_local/truth_components.zig").Components;
const V3Role = @import("../word16_global_execution/services/gkr_local/truth_v3_role.zig").Component;
const TF = @import("../word16_global_execution/services/gkr_local/truth_fractions.zig");
const Metadata = @import("../word16_global_execution/services/gkr_local/truth_metadata.zig");
const GM = @import("../word16_global_execution/services/gkr_local/truth_global_metadata.zig");
const GW = @import("../word16_global_execution/services/gkr_local/truth_global_witness.zig");
const Local = @import("../word16_global_execution/services/gkr_local/truth_classic.zig");
const Classic = @import("../word16_global_execution/services/gkr_local/classic_witness.zig");
const V3Witness = @import("../word16_global_execution/services/gkr_local/truth_v3_witness.zig");
const Commit = @import("../word16_execution/main_ownership.zig").Commit;
pub const Encoded = Old.TruthEncoded;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Limits = struct { live_bytes: usize, main_bytes: usize, interaction_bytes: usize, advice_bytes: usize };
/// A factory produces untrusted advice inside the worker's allocator. Its
/// returned kind/geometry is checked and every column is physically proved.
/// The immutable key and original input inventory remain caller-owned.
pub const SourceBuilder = struct {
    context: *const anyopaque,
    build: *const fn (*const anyopaque, std.mem.Allocator, R.Truth) anyerror!R.TruthSource,
    pub fn fromAdvice(advice: *const @import("../word16_global_execution/services/collector.zig").Advice) SourceBuilder {
        return .{ .context = advice, .build = struct {
            fn run(context: *const anyopaque, a: std.mem.Allocator, truth: R.Truth) !R.TruthSource {
                const input: *const @import("../word16_global_execution/services/collector.zig").Advice = @ptrCast(@alignCast(context));
                return R.TruthSource.init(a, truth, input);
            }
        }.run };
    }
};
pub const ResourcePlan = struct {
    main_bytes: usize,
    interaction_bytes: usize,
    advice_bytes: usize,
    pub fn derive(a: std.mem.Allocator, truth: R.Truth, profile: Protocol.Profile) !ResourcePlan {
        try validateTruth(truth);
        const shape = try template(truth);
        var main: usize = 0;
        var inter: usize = 0;
        for ([_]usize{ 1, 2 }) |tree| {
            const logs = try shape.logs(a, tree);
            defer a.free(logs);
            for (logs) |log| {
                if (log > 26) return error.OpTruthResourceGeometry;
                const bytes = try std.math.mul(usize, @as(usize, 1) << @intCast(log), 4);
                if (tree == 1) main = try std.math.add(usize, main, bytes) else inter = try std.math.add(usize, inter, bytes);
            }
        }
        const advice = if (classic(truth)) (try @import("../word16_global_execution/services/gkr_local/truth_retention.zig").forTruth(a, truth, profile.config(), std.math.maxInt(usize))).global_metadata_bytes else try Catalog.metadataByteUpperBound(truth);
        return .{ .main_bytes = main, .interaction_bytes = inter, .advice_bytes = advice };
    }
    pub fn admit(self: ResourcePlan, limits: Limits) !void {
        if (limits.live_bytes == 0 or self.main_bytes > limits.main_bytes or self.interaction_bytes > limits.interaction_bytes or self.advice_bytes > limits.advice_bytes) return error.OpTruthBudget;
    }
};

const ENVELOPE = "OPTRP201";
pub fn encode(a: std.mem.Allocator, proof: *const Encoded) ![]u8 {
    if (proof.claims.len != 1 and proof.claims.len != 5) return error.OpTruthEnvelope;
    const header = 20 + 32 * proof.claims.len;
    const out = try a.alloc(u8, try std.math.add(usize, header, proof.bytes.len));
    @memcpy(out[0..8], ENVELOPE);
    std.mem.writeInt(u32, out[8..12], @intCast(proof.claims.len), .little);
    std.mem.writeInt(u64, out[12..20], proof.bytes.len, .little);
    for (proof.claims, 0..) |claim, j| for (claim.toM31Array(), 0..) |coordinate, i| std.mem.writeInt(u32, out[20 + 32 * j + 4 * i ..][0..4], coordinate.v, .little);
    @memcpy(out[header..], proof.bytes);
    return out;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, max_bytes: usize) !Encoded {
    if (bytes.len < 20 or bytes.len > max_bytes or !std.mem.eql(u8, bytes[0..8], ENVELOPE)) return error.OpTruthEnvelope;
    const count = std.mem.readInt(u32, bytes[8..12], .little);
    if (count != 1 and count != 5) return error.OpTruthEnvelope;
    const header = 20 + 32 * @as(usize, count);
    if (bytes.len < header or std.mem.readInt(u64, bytes[12..20], .little) != bytes.len - header) return error.OpTruthEnvelope;
    const claims = try a.alloc(O, count);
    errdefer a.free(claims);
    for (claims, 0..) |*claim, j| {
        var coordinates: [8]core.fields.m31.M31 = undefined;
        for (&coordinates, 0..) |*coordinate, i| {
            const value = std.mem.readInt(u32, bytes[20 + 32 * j + 4 * i ..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.OpTruthEnvelope;
            coordinate.* = core.fields.m31.M31.fromCanonical(value);
        }
        claim.* = O.fromM31Array(coordinates);
    }
    return .{ .bytes = try a.dupe(u8, bytes[header..]), .claims = claims };
}

fn classic(truth: R.Truth) bool {
    return truth == .keccak or truth == .secp;
}
fn validateTruth(truth: R.Truth) !void {
    if (truth.count() == 0) return error.EmptyOpTruth;
    if (classic(truth)) try @import("../word16_global_execution/services/gkr_local/truth_profile.zig").validate(truth) else try Catalog.validate(truth);
}
fn mass(truth: R.Truth) !@import("../word16_global_execution/services/gkr_local/manifest.zig").Mass {
    return if (classic(truth)) Old.truthMass(truth) else V3.truthMass(truth);
}
fn relations(truth: R.Truth) Manifest.Relations {
    return .{ .ram = false, .kio = truth == .keccak, .wire = truth != .keccak };
}
fn kind(truth: R.Truth) @import("../word16_global_execution/services/gkr_local/manifest.zig").Kind {
    return switch (truth) {
        .keccak => .keccak,
        .secp => |t| if (t.setup.kind == .add) .secp_add else .secp_double,
        else => .delegation,
    };
}
const LocalChallenges = union(enum) { classic: TF.ChallengesFor(O), delegated: O };
fn drawLocal(truth: R.Truth, channel: *W.Channel, manifest: W.H.Hash) LocalChallenges {
    channel.mixU32s(&.{ 0x4f50544c, 2, 9, @intFromEnum(std.meta.activeTag(truth)) });
    channel.mixRoot(manifest);
    return if (classic(truth)) .{ .classic = TF.ChallengesFor(O).draw(channel) } else .{ .delegated = V3.drawLocal(channel) };
}
const Components = union(enum) {
    classic: ClassicComponents,
    delegated: V3Role,
    fn init(truth: R.Truth, local: LocalChallenges, shared: Manifest.Shared, claims: []const O) !Components {
        if (classic(truth)) return .{ .classic = try ClassicComponents.init(truth, local.classic, shared, claims) };
        if (claims.len != 1) return error.OpTruthClaims;
        for (claims[0].toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.OpTruthClaims;
        return .{ .delegated = .{ .truth = truth, .wire = shared.wire, .bytes = local.delegated, .claim = claims[0] } };
    }
    fn logs(self: *const Components, a: std.mem.Allocator, tree: usize) ![]u32 {
        return switch (self.*) {
            .classic => |*c| c.logs(a, tree),
            .delegated => |c| block: {
                if (tree > 2) return error.OpTruthTree;
                const shape = try Catalog.shape(c.truth);
                const widths = [_]usize{ shape.fixed, shape.main, shape.inter };
                const out = try a.alloc(u32, widths[tree]);
                @memset(out, try Catalog.logSize(c.truth));
                break :block out;
            },
        };
    }
    fn provers(self: *Components, a: std.mem.Allocator) ![]engine.air.component_prover.ForField(O).ComponentProver {
        return switch (self.*) {
            .classic => |*c| a.dupe(engine.air.component_prover.ForField(O).ComponentProver, &c.provers()),
            .delegated => |*c| a.dupe(engine.air.component_prover.ForField(O).ComponentProver, &.{c.asProverComponent()}),
        };
    }
    fn verifiers(self: *const Components, a: std.mem.Allocator) ![]core.air.components.ForField(O).Component {
        return switch (self.*) {
            .classic => |*c| a.dupe(core.air.components.ForField(O).Component, &c.verifiers()),
            .delegated => |*c| a.dupe(core.air.components.ForField(O).Component, &.{c.asVerifierComponent()}),
        };
    }
};
fn template(truth: R.Truth) !Components {
    if (classic(truth)) return .{ .classic = try Old.templates(truth) };
    return .{ .delegated = .{ .truth = truth, .wire = undefined, .bytes = O.zero(), .claim = O.zero() } };
}
fn geometryIdentity(a: std.mem.Allocator, truth: R.Truth) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("opstack-pure-p2/truth-ordered-geometry/v1\x00");
    hash.update(@tagName(truth));
    const declaration = @import("../word16_global_execution/services/wire.zig").TruthDeclaration.from(truth);
    var authority: [12]u8 = undefined;
    std.mem.writeInt(u32, authority[0..4], @intFromEnum(declaration.family), .little);
    std.mem.writeInt(u32, authority[4..8], declaration.logs[0], .little);
    std.mem.writeInt(u32, authority[8..12], declaration.logs[1], .little);
    hash.update(&authority);
    hash.update(&truth.key().root);
    const shape = try template(truth);
    for (0..3) |tree| {
        const logs = try shape.logs(a, tree);
        defer a.free(logs);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(logs.len), .little);
        hash.update(&bytes);
        for (logs) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            hash.update(&bytes);
        }
    }
    return hash.finalResult();
}
pub const Key = struct {
    allocator: std.mem.Allocator,
    profile: Protocol.Profile,
    source_root: [32]u8,
    source_geometry: [32]u8,
    identity: [32]u8,
    root: W.H.Hash,
    tree: W.Scheme.CommittedTree,
    pub fn init(a: std.mem.Allocator, truth: R.Truth, profile: Protocol.Profile) !Key {
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        try validateTruth(truth);
        const fixed = switch (truth) {
            inline else => |t| try t.setup.fixedColumns(a),
        };
        defer a.free(fixed);
        var scheme = try W.Prover.init(a, profile.config());
        defer scheme.deinit(a);
        var channel = W.Channel.init();
        try scheme.commitBorrowedStreaming(a, fixed, 64, &channel);
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        try tree.share(a);
        const root = tree.root();
        const geometry = try geometryIdentity(a, truth);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack-pure-p2/truth-source-fixed/v1\x00");
        hash.update(&profile.identity());
        hash.update(&geometry);
        hash.update(&root);
        return .{ .allocator = a, .profile = profile, .source_root = truth.key().root, .source_geometry = geometry, .identity = hash.finalResult(), .root = root, .tree = tree };
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn require(self: *const Key, truth: R.Truth) !void {
        try validateTruth(truth);
        if (!std.mem.eql(u8, &self.source_root, &truth.key().root) or !std.mem.eql(u8, &self.root, &self.tree.root()) or !std.mem.eql(u8, &self.source_geometry, &try geometryIdentity(self.allocator, truth))) return error.OpTruthFixedAuthority;
    }
    pub fn statement(self: *const Key, truth: R.Truth) ![32]u8 {
        try self.require(truth);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack-pure-p2/truth-source-statement/v1\x00");
        hash.update(&self.identity);
        hash.update(&self.root);
        var span: [8]u8 = undefined;
        std.mem.writeInt(u32, span[0..4], truth.first(), .little);
        std.mem.writeInt(u32, span[4..8], truth.count(), .little);
        hash.update(&span);
        return hash.finalResult();
    }
    pub fn expected(self: *const Key, truth: R.Truth, ordinal: u32) !Manifest.Expected {
        return .{ .kind = kind(truth), .ordinal = ordinal, .profile = self.profile, .fixed_identity = self.identity, .fixed = self.root, .statement = try self.statement(truth), .mass = try mass(truth), .global_relations = relations(truth), .local_instances = null };
    }
    fn append(self: *const Key, a: std.mem.Allocator, scheme: *W.Scheme, channel: *W.Channel) !void {
        if (scheme.trees.items.len != 0 or !std.meta.eql(scheme.config, self.profile.config())) return error.OpTruthPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, channel);
    }
};
fn validateExpected(key: *const Key, truth: R.Truth, expected: Manifest.Expected) !void {
    try key.require(truth);
    if (expected.profile != key.profile or expected.kind != kind(truth) or expected.local_instances != null or !std.mem.eql(u8, &expected.fixed, &key.root) or !std.mem.eql(u8, &expected.fixed_identity, &key.identity) or !std.mem.eql(u8, &expected.statement, &try key.statement(truth)) or !std.meta.eql(expected.mass, try mass(truth)) or !std.meta.eql(expected.global_relations, relations(truth))) return error.OpTruthExpected;
}
fn checkPending(expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize) !void {
    if (index != expected.ordinal or index >= pending.entries.len) return error.GlobalGkrManifestOrdinal;
    const entry = pending.entries[index];
    if (!std.meta.eql(entry.authority, expected) or entry.local != null or entry.scope.ordinal != expected.ordinal or !std.meta.eql(entry.global_relations, expected.global_relations) or !std.mem.eql(u8, &entry.scope.fixed, &expected.fixed) or !std.mem.eql(u8, &entry.scope.statement, &expected.statement)) return error.OpTruthManifest;
}
fn admit(truth: R.Truth, budget: usize) !void {
    if (classic(truth)) try Old.admit(try Old.expectedFrames(truth), budget) else try V3.admit(truth, budget);
}
fn requireAllocator(a: std.mem.Allocator, other: std.mem.Allocator) !void {
    if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, other)) return error.OpTruthSourceAllocator;
}
fn validateAllocator(a: std.mem.Allocator, source: *const R.TruthSource) !void {
    switch (source.*) {
        .sha256 => |s| try requireAllocator(a, s.source.allocator),
        .arith256_mod => |s| try requireAllocator(a, s.source.allocator),
        inline .curve, .secp_row => |u| switch (u) {
            inline else => |s| try requireAllocator(a, s.allocator),
        },
        .keccak => |s| {
            try requireAllocator(a, s.permutation.allocator);
            try requireAllocator(a, s.chi.allocator);
            try requireAllocator(a, s.xor5.allocator);
        },
        .secp => |s| {
            try requireAllocator(a, s.batch.product.allocator);
            try requireAllocator(a, s.batch.linear.allocator);
            try requireAllocator(a, s.bytes.allocator);
        },
    }
}
const Generated = struct { commit: Commit, claims: []O };
fn generate(a: std.mem.Allocator, truth: R.Truth, source: *const R.TruthSource, local: LocalChallenges, shared: Manifest.Shared, budget: usize) !Generated {
    if (!classic(truth)) {
        var witness = try V3Witness.generate(a, source, shared.wire, local.delegated, budget);
        defer witness.deinit();
        const claims = try a.dupe(O, &.{witness.claim});
        errdefer a.free(claims);
        return .{ .claims = claims, .commit = try witness.take(a) };
    }
    const frames = try Old.expectedFrames(truth);
    const metadata = try Metadata.Provider.initClassic(source, frames);
    var global_metadata = try GM.Provider.init(a, source, budget);
    defer global_metadata.deinit();
    var locals: [3]Classic.Witness = undefined;
    var count: usize = 0;
    defer for (locals[0..count]) |*witness| witness.deinit();
    for (frames, &locals) |frame, *witness| {
        witness.* = try Local.generate(a, &metadata, frame, &local.classic, budget);
        count += 1;
    }
    var globals: [2]Classic.Witness = undefined;
    var global_count: usize = 0;
    defer for (globals[0..global_count]) |*witness| witness.deinit();
    const challenges = GW.Challenges{ .io = shared.kio, .wire = shared.wire };
    globals[0] = try GW.generate(a, &global_metadata, frames[0].role, &challenges, budget);
    global_count = 1;
    if (truth == .secp) {
        globals[1] = try GW.generate(a, &global_metadata, frames[1].role, &challenges, budget);
        global_count = 2;
    }
    const claims = try a.alloc(O, 5);
    errdefer a.free(claims);
    for (locals, 0..) |witness, i| claims[i] = witness.claims[0];
    claims[3] = globals[0].claims[0];
    claims[4] = if (global_count == 2) globals[1].claims[0] else O.zero();
    return .{ .claims = claims, .commit = try Old.take(a, &locals, globals[0..global_count]) };
}
pub const Worker = struct {
    allocator: std.mem.Allocator,
    parent_allocator: std.mem.Allocator,
    budget_owner: *Budget,
    resources: ResourcePlan,
    key: *const Key,
    truth: R.Truth,
    source: ?R.TruthSource,
    expected: Manifest.Expected,
    budget: usize,
    scheme: W.Scheme,
    channel: W.Channel,
    sealed: bool = false,
    consumed: bool = false,
    owns_scheme: bool = true,
    pub fn init(backing: std.mem.Allocator, key: *const Key, truth: R.Truth, builder: SourceBuilder, expected: Manifest.Expected, limits: Limits) !Worker {
        try validateExpected(key, truth, expected);
        const resources = try ResourcePlan.derive(backing, truth, key.profile);
        try resources.admit(limits);
        try admit(truth, limits.interaction_bytes);
        const owner = try Budget.createRetainingParent(backing, limits.live_bytes);
        errdefer owner.destroy();
        const a = owner.allocator();
        var source = try builder.build(builder.context, a, truth);
        errdefer source.deinit();
        try validateAllocator(a, &source);
        if (classic(truth)) _ = try Metadata.Provider.initClassic(&source, try Old.expectedFrames(truth)) else try V3.validateSource(truth, &source);
        var scheme = try W.Prover.init(a, key.profile.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(1);
        return .{ .allocator = a, .parent_allocator = backing, .budget_owner = owner, .resources = resources, .key = key, .truth = truth, .source = source, .expected = expected, .budget = limits.interaction_bytes, .scheme = scheme, .channel = Protocol.begin(key.profile, expected, key.identity, key.root) };
    }
    pub fn deinit(self: *Worker) void {
        if (self.source) |*source| source.deinit();
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.budget_owner.destroy();
        self.* = undefined;
    }
    pub fn seal(self: *Worker) !Manifest.StageOne {
        if (self.sealed or self.consumed) return error.OpTruthPhase;
        self.consumed = true;
        try self.key.append(self.allocator, &self.scheme, &self.channel);
        const main = try self.source.?.takeMain();
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 64, null, &self.channel);
        self.sealed = true;
        self.consumed = false;
        return .{ .main = self.scheme.trees.items[1].root(), .local = null };
    }
    pub fn complete(self: *Worker, pending: *const Manifest.Pending, index: usize) !Encoded {
        if (!self.sealed or self.consumed) return error.OpTruthPhase;
        try checkPending(self.expected, pending, index);
        try pending.checkPhysicalRoots(index, self.key.root, self.scheme.trees.items[1].root());
        self.consumed = true;
        const local = drawLocal(self.truth, &self.channel, pending.digest);
        const generated = try generate(self.allocator, self.truth, &self.source.?, local, pending.shared, self.budget);
        defer self.allocator.free(generated.claims);
        var owns_inter = true;
        defer if (owns_inter) generated.commit.deinit(self.allocator);
        var components = try Components.init(self.truth, local, pending.shared, generated.claims);
        const handles = try components.provers(self.allocator);
        defer self.allocator.free(handles);
        Protocol.mixManifestAndClaims(&self.channel, pending.digest, generated.claims);
        owns_inter = false; // owned commit consumes every backing on all paths.
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, generated.commit.columns, generated.commit.backings, 64, null, &self.channel);
        self.source.?.deinit();
        self.source = null;
        self.owns_scheme = false;
        var proof = try W.Prover.prove(self.allocator, handles, &self.channel, self.scheme, .{});
        defer proof.deinit(self.allocator);
        const output = try W.Wire.encodeProofBytesBinary(self.parent_allocator, proof.proof);
        errdefer self.parent_allocator.free(output);
        return .{ .bytes = output, .claims = try self.parent_allocator.dupe(O, generated.claims) };
    }
};
pub fn verify(a: std.mem.Allocator, key: *const Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, index: usize, encoded: *const Encoded) !Manifest.Claims {
    try validateExpected(key, truth, expected);
    try checkPending(expected, pending, index);
    var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.meta.eql(proof.commitment_scheme_proof.config, key.profile.config()) or proof.commitment_scheme_proof.revision_config != null or !std.mem.eql(u8, &roots[0], &key.root)) return error.OpTruthProofShape;
    try pending.checkPhysicalRoots(index, key.root, roots[1]);
    var channel = Protocol.begin(key.profile, expected, key.identity, key.root);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    const shape = try template(truth);
    for (0..2) |tree| {
        const logs = try shape.logs(a, tree);
        defer a.free(logs);
        try receiver.commit(a, roots[tree], logs, &channel);
    }
    const local = drawLocal(truth, &channel, pending.digest);
    var components = try Components.init(truth, local, pending.shared, encoded.claims);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    Protocol.mixManifestAndClaims(&channel, pending.digest, encoded.claims);
    const logs = try components.logs(a, 2);
    defer a.free(logs);
    try receiver.commit(a, roots[2], logs, &channel);
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, handles, &channel, &receiver, &proof, &capture);
    capture.deinit(a);
    return if (classic(truth)) Old.claimsResult(truth, encoded.claims) else .{ .ram = O.zero(), .kio = O.zero(), .wire = encoded.claims[0] };
}
