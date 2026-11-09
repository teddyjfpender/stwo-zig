//! Explicit opt-in pure-P2 serialized sponge local GKR. Successful checks leave physical
//! source-terminal and global KIO/Wire obligations PENDING; never execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Authority = @import("authority.zig");
const Frame = Authority;
const Boundary = @import("boundary.zig").Boundary;
const Fractions = @import("fractions.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Input = @import("source_inputs.zig");
const Base = @import("../pure_p2_native.zig");
const Framing = @import("../pure_p2_framing.zig");
const S = core.crypto.poseidon2_m31_sponge;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
pub const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const WIRE_MAGIC = "OPSPGKR1";
pub const DETACHED_MAGIC = "OPSDETG1";
fn magic(g: Authority.Geometry) []const u8 {
    return if (g.detached) DETACHED_MAGIC else WIRE_MAGIC;
}
pub fn encode(a: std.mem.Allocator, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof) ![]u8 {
    _ = try geometry.instances();
    const frames = try geometry.instances();
    return Wire.encodeFor(a, &frames, proof, magic(geometry));
}
pub fn decode(a: std.mem.Allocator, geometry: Authority.Geometry, bytes: []const u8) !Wire.Owned {
    _ = try geometry.instances();
    const frames = try geometry.instances();
    return Wire.decodeFor(a, &frames, bytes, magic(geometry));
}
pub const Channel = Base.Channel;
pub const Challenges = Fractions.Challenges;
pub const Scope = struct { statement: [32]u8, fixed: S.Digest, main: S.Digest, manifest: S.Digest, ordinal: u32, boundary: [32]u8 };
pub const DetachedScope = struct { statement: [32]u8, fixed: S.Digest, main: S.Digest, manifest: S.Digest, ordinal: u32 };
pub const DOMAIN = [_]u32{ 0x4f505347, 1, 8, 9 };
pub const DETACHED_DOMAIN = [_]u32{ 0x4f505344, 1, 8, 9 };
fn mixDigest32(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn begin(scope: anytype, geometry: Authority.Geometry) !Channel {
    _ = try geometry.instances();
    if (geometry.detached == @hasField(@TypeOf(scope), "boundary")) return error.SpongeLocalScopeFlavor;
    _ = try S.decode(scope.fixed);
    _ = try S.decode(scope.main);
    _ = try S.decode(scope.manifest);
    var channel = Channel.init();
    channel.mixU32s(if (geometry.detached) &DETACHED_DOMAIN else &DOMAIN);
    mixDigest32(&channel, scope.statement);
    if (comptime @hasField(@TypeOf(scope), "boundary")) mixDigest32(&channel, scope.boundary);
    channel.mixRoot(scope.fixed);
    channel.mixRoot(scope.main);
    channel.mixRoot(scope.manifest);
    channel.mixU32s(&.{ scope.ordinal, 8, geometry.calls, geometry.permutations, geometry.first_id });
    for (try geometry.instances()) |instance| {
        channel.mixU32s(&.{ @intFromEnum(instance.role), instance.row_log, instance.queries() });
    }
    return channel;
}
/// The scope and each source policy are typed independently of the CPU receipt;
/// only the canonical bounded proof payload is shared.
pub fn receipt(scope: anytype, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, marginals: []const []const O) !S.Digest {
    var writer = Base.ReceiptWriter{};
    try emitReceipt(scope, geometry, proof, marginals, &writer);
    return writer.finish();
}
/// One typed receipt authority for native and in-circuit values.
pub fn emitReceipt(scope: anytype, geometry: Authority.Geometry, proof: anytype, marginals: anytype, writer: anytype) !void {
    _ = try geometry.instances();
    if (geometry.detached == @hasField(@TypeOf(scope), "boundary")) return error.SpongeLocalScopeFlavor;
    for (if (geometry.detached) DETACHED_DOMAIN else DOMAIN) |tag| writer.tag(tag);
    writer.rawDigest(scope.statement);
    if (comptime @hasField(@TypeOf(scope), "boundary")) writer.rawDigest(scope.boundary);
    writer.root(scope.fixed);
    writer.root(scope.main);
    writer.root(scope.manifest);
    writer.integer(scope.ordinal);
    writer.integer(8);
    writer.integer(if (@hasField(@TypeOf(scope), "calls")) scope.calls else geometry.calls);
    writer.integer(if (@hasField(@TypeOf(scope), "first_id")) scope.first_id else geometry.first_id);
    writer.integer(geometry.permutations);
    var variables: [8]u32 = undefined;
    for (try geometry.instances(), &variables) |instance, *n| {
        n.* = try instance.variables();
        writer.integer(@intFromEnum(instance.role));
        writer.integer(instance.row_log);
        writer.integer(instance.queries());
    }
    try Framing.emitPayload(proof, &variables, marginals, writer);
}
/// The common mixed-height verifier point uses suffix variables per instance.
pub fn splitPoint(instance: Frame.Instance, point: []const O, variables: usize) !struct { row: []const O, lane: []const O } {
    if (variables != try instance.variables() or point.len < variables or point.len > 30) return error.LocalGkrPointGeometryMismatch;
    const local = point[point.len - variables ..];
    return .{ .row = local[0..instance.row_log], .lane = local[instance.row_log..] };
}
/// Borrowed terminal data only. Even a verifier-derived view is pending its
/// authenticated source AIR; this handle grants no execution acceptance.
pub const Terminal = struct { artifact: *const GV.GkrArtifact, challenges: Challenges, eta: O };
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    challenges: Challenges,
    eta: O,
    digest: S.Digest,
    pub fn terminal(self: *const @This()) Terminal {
        return .{ .artifact = &self.artifact, .challenges = self.challenges, .eta = self.eta };
    }
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verifyPending(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, expected_digest: S.Digest, boundary: Boundary) !Pending {
    if (geometry.detached) return error.SpongeLocalScopeFlavor;
    return verifyCore(a, scope, geometry, proof, expected_digest, boundary);
}
pub fn verifyDetachedPending(a: std.mem.Allocator, scope: DetachedScope, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, expected_digest: S.Digest) !Pending {
    if (!geometry.detached) return error.SpongeLocalScopeFlavor;
    return verifyCore(a, scope, geometry, proof, expected_digest, null);
}
fn verifyCore(a: std.mem.Allocator, scope: anytype, geometry: Authority.Geometry, proof: *const GV.GkrBatchProof, expected_digest: S.Digest, boundary: ?Boundary) !Pending {
    if (comptime @hasField(@TypeOf(scope), "boundary")) {
        const b = boundary orelse return error.SpongeLocalBoundary;
        if (b.calls.len != geometry.calls or !std.mem.eql(u8, &(try b.digest()), &scope.boundary)) return error.SpongeLocalBoundary;
    } else if (boundary != null) return error.SpongeLocalBoundary;
    var channel = try begin(scope, geometry);
    const challenges = draw(&channel);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    if (artifact.n_variables_by_instance.len != 8) return error.LocalGkrPointGeometryMismatch;
    for (try geometry.instances(), artifact.n_variables_by_instance) |instance, n| _ = try splitPoint(instance, artifact.ood_point, n);
    try close(a, proof.output_claims_by_instance, if (boundary) |b| try b.ownerClaim(challenges) else O.zero());
    const digest = try receipt(scope, geometry, proof, artifact.claims_to_verify_by_instance);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.LocalGkrReceiptMismatch;
    return .{ .artifact = artifact, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    challenges: Challenges,
    eta: O,
    digest: S.Digest,
    pub fn terminal(self: *const @This()) Terminal {
        return .{ .artifact = &self.result.artifact, .challenges = self.challenges, .eta = self.eta };
    }
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
/// Uses the bounded source/checkpointed engine. The caller must impose a numeric
/// allocator budget before entering; this API grants no production admission.
pub fn proveUnbound(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, provider: anytype, boundary: Boundary) !Unbound {
    return proveUnboundWithOptions(a, scope, geometry, provider, boundary, .{});
}
pub const ProverOptions = GP.Options;
pub fn proveUnboundWithOptions(a: std.mem.Allocator, scope: Scope, geometry: Authority.Geometry, provider: anytype, boundary: Boundary, options: ProverOptions) !Unbound {
    if (geometry.detached) return error.SpongeLocalScopeFlavor;
    return proveCore(a, scope, geometry, provider, boundary, options);
}
pub fn proveDetachedUnboundWithOptions(a: std.mem.Allocator, scope: DetachedScope, geometry: Authority.Geometry, provider: anytype, options: ProverOptions) !Unbound {
    if (!geometry.detached) return error.SpongeLocalScopeFlavor;
    return proveCore(a, scope, geometry, provider, null, options);
}
fn proveCore(a: std.mem.Allocator, scope: anytype, geometry: Authority.Geometry, provider: anytype, boundary: ?Boundary, options: ProverOptions) !Unbound {
    if (comptime @hasField(@TypeOf(scope), "boundary")) {
        const b = boundary orelse return error.SpongeLocalBoundary;
        if (b.calls.len != geometry.calls or !std.mem.eql(u8, &(try b.digest()), &scope.boundary)) return error.SpongeLocalBoundary;
    } else if (boundary != null) return error.SpongeLocalBoundary;
    var channel = try begin(scope, geometry);
    const challenges = draw(&channel);
    var inputs = try Input.Batch(@TypeOf(provider)).init(a, geometry, challenges, provider);
    defer inputs.deinit();
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, inputs.sources, options);
    errdefer result.deinit(a);
    try close(a, result.proof.output_claims_by_instance, if (boundary) |b| try b.ownerClaim(challenges) else O.zero());
    const digest = try receipt(scope, geometry, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .challenges = challenges, .eta = channel.drawSecureFelt(), .digest = digest };
}

/// All namespaces are labeled and independently drawn, including scalar ranges.
pub fn draw(channel: *Channel) Challenges {
    return Fractions.drawFor(O, channel);
}
pub const drawFor = Fractions.drawFor;
/// Exact service boundary is independent of committed descriptor witnesses.
/// Internal OWNER, AND and range debts close jointly under independently drawn
/// namespace challenges. This still leaves global RAM/KIO + CPU execution pending.
pub fn close(a: std.mem.Allocator, outputs: []const []const O, owner_boundary: O) !void {
    if (outputs.len != 8) return error.LocalGkrOutputShape;
    var joined: [9][]const O = undefined;
    @memcpy(joined[0..8], outputs);
    const boundary_pair = [_]O{ owner_boundary, O.one() };
    joined[8] = &boundary_pair;
    try Closure.close(a, &joined);
}
test "serialized sponge local GKR child verifies source closure and independent OWNER boundary" {
    const owner = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 1 << 30);
    defer owner.destroy();
    const a = owner.allocator();
    const source_mod = @import("source.zig");
    const boundary_mod = @import("boundary.zig");
    const g = Authority.Geometry{ .calls = 1, .permutations = 1, .first_id = 1 };
    var source = try source_mod.Source.init(a, g, &.{@import("fixture.zig").call()}, &.{});
    defer source.deinit();
    const calls = [_]boundary_mod.Call{.{ .pointer = 0x4000, .epoch = 1, .tick = 4 }};
    const boundary = Boundary{ .calls = &calls };
    const scope = Scope{ .statement = [_]u8{71} ** 32, .fixed = Base.hashWords(&.{1}), .main = Base.hashWords(&.{2}), .manifest = Base.hashWords(&.{3}), .ordinal = 0, .boundary = try boundary.digest() };
    const provider = Fractions.Provider{ .source = &source };
    var proved = try proveUnboundWithOptions(a, scope, g, provider, boundary, .{ .coefficient_encoding = .fixed4 });
    defer proved.deinit(a);
    const encoded = try encode(a, g, &proved.result.proof);
    defer a.free(encoded);
    var decoded = try decode(a, g, encoded);
    defer decoded.deinit();
    var checked = try verifyPending(a, scope, g, &decoded.proof, proved.digest, boundary);
    defer checked.deinit(a);
    try std.testing.expect(proved.eta.eql(checked.eta));
    var witness = try @import("witness.zig").Witness.init(a, g, &checked.challenges, provider, &checked.artifact, checked.eta);
    defer witness.deinit();
    const original = checked.artifact.claims_to_verify_by_instance[0][0];
    checked.artifact.claims_to_verify_by_instance[0][0] = original.add(O.one());
    try std.testing.expectError(error.UnboundLocalGkrInput, @import("witness.zig").Witness.init(a, g, &checked.challenges, provider, &checked.artifact, checked.eta));
    checked.artifact.claims_to_verify_by_instance[0][0] = original;
    const wrong_calls = [_]boundary_mod.Call{.{ .pointer = 0x4008, .epoch = 1, .tick = 4 }};
    try std.testing.expectError(error.SpongeLocalBoundary, verifyPending(a, scope, g, &decoded.proof, proved.digest, .{ .calls = &wrong_calls }));
    var bad_receipt = proved.digest;
    bad_receipt[35] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, verifyPending(a, scope, g, &decoded.proof, bad_receipt, boundary));
    // Equal-and-opposite field debt across namespaces is not cancellation:
    // tuple coefficients/offsets are drawn independently after MAIN.
    const A = @import("stwo_riscv_frontend").rv64_air;
    const drow = A.witness.physical(0, (try g.instances())[0].row_log);
    const drows = try (try g.instances())[0].rows();
    const pointer_at = A.crypto.keccak_sponge.layout.call.pointer * drows + drow;
    const range_at = A.witness.physical(0, (try g.instances())[6].row_log);
    const old_pointer = source.main[0][pointer_at];
    const old_count = source.main[6][range_at];
    source.main[0][pointer_at] = old_pointer.add(core.fields.m31.M31.fromCanonical(8));
    source.main[6][range_at] = old_count.sub(core.fields.m31.M31.one());
    // A complete source mutation with opposed namespace debt still cannot
    // close under the independent denominator draws. It is not just a forged
    // claimed output vector. Actual PCS MAIN binding is the next enclosing gate.
    try std.testing.expectError(error.UnclosedLocalGkr, proveUnboundWithOptions(a, scope, g, provider, boundary, .{ .coefficient_encoding = .fixed4 }));
    source.main[0][pointer_at] = old_pointer;
    source.main[6][range_at] = old_count;
    const zero = [_]O{ O.zero(), O.one() };
    const plus = [_]O{ O.one(), checked.challenges.owner.offset };
    const minus = [_]O{ O.one().neg(), checked.challenges.u8 };
    try std.testing.expectError(error.UnclosedLocalGkr, close(a, &.{ &plus, &minus, &zero, &zero, &zero, &zero, &zero, &zero }, O.zero()));
}
