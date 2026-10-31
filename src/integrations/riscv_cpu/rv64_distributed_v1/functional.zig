//! EXPERIMENTAL facts-only aggregate. Two actual PCS/FRI proofs share a
//! complete-root-manifest challenge. This accepts no CPU, VM, or RAM execution.
//! The caller independently supplies the complete public fact roster/context.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const air = @import("stwo_riscv_frontend").rv64_air;
const D = @import("manifest.zig");
const T = D.T;
const C = air.word16_v1.binary_component;
const B = air.word16_v1.binary_lookup;
const Tables = air.providers.tables;
const Fixture = @import("../word16/binary_fixture.zig").Fixture;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Roster = C.ExpectedRoster;
const N = 32;
const MAX_PROOF_BYTES = 8 * 1024 * 1024;
const LOGS_CONSUMER = [_]u32{5} ** 14;
const LOGS_PROVIDER = [_]u32{5} ** B.MAIN ++ [_]u32{16};
const INTER_CONSUMER = [_]u32{5} ** 8;
const INTER_PROVIDER = [_]u32{5} ** B.INTERACTION ++ [_]u32{16} ** 8;
const FIXED_CONSUMER = [_]u32{5} ** 34;
const FIXED_PROVIDER = [_]u32{5} ** 2 ++ [_]u32{16} ** 5;

pub const Encoded = struct {
    bytes: []u8,
    /// function, local AND consumer, local AND provider. Every physical claim
    /// is locally transcript-bound before the interaction commitment.
    claims: [3]Q,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
    }
};
pub const Aggregate = struct {
    manifest: D.Manifest,
    proofs: [2]Encoded,
    pub fn deinit(self: *Aggregate, a: std.mem.Allocator) void {
        for (&self.proofs) |*proof| proof.deinit(a);
        self.manifest.deinit();
    }
};

/// Independently known AND/OR/XOR questions and answers. The provider's private
/// truth witness is not used to construct this public statement.
pub fn diagnosticRoster() Roster {
    var roster: Roster = @splat(@splat(M.zero()));
    for (0..3) |i| {
        const x = @as(u64, 0x7fff8000ffff1234) ^ @as(u64, @intCast(i));
        const y = @as(u64, 0xfedcba9876543210) + @as(u64, @intCast(i));
        const z = switch (i) {
            0 => x & y,
            1 => x | y,
            else => x ^ y,
        };
        roster[i][0] = M.fromCanonical(@intCast(16 + i));
        for ([_]u64{ x, y, z }, 0..) |word, j| for (0..4) |limb| {
            roster[i][1 + 4 * j + limb] = M.fromCanonical(@intCast((word >> @intCast(16 * limb)) & 65535));
        };
        roster[i][13] = M.one();
    }
    return roster;
}
fn schema(role: T.Role) T.Digest {
    var digest: T.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(if (role == .public_consumer)
        "rv64.distributed.functional13.public-roster.main14.fixed34.v1"
    else
        "rv64.distributed.functional13.binary42.and65536.v1", &digest, .{});
    return digest;
}
fn admitRoster(roster: *const Roster) !void {
    _ = try C.expectedRosterDigest(roster);
    var mass: u64 = 0;
    for (roster) |row| mass += row[13].v;
    _ = try air.word16_v1.function_bus.admitPositiveMass(&.{mass});
    _ = try air.word16_v1.function_bus.admitPositiveMass(&.{8 * N});
}
/// Receiver independently derives all schemas, immutable roots, and public
/// roster identity before reading a complete manifest from another process.
pub fn expectedInventory(a: std.mem.Allocator, roster: *const Roster) ![2]T.Spec {
    try admitRoster(roster);
    var f = try Fixture.init(a, false);
    defer f.deinit();
    const fixed = try C.expectedMainFixed(a);
    defer a.free(fixed);
    const main = try C.expectedMainValues(a, roster);
    defer a.free(main);
    return specs(a, roster, &f, fixed, main);
}
fn storageDigest(data: []const M) T.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.distributed.native-job.le32.v1");
    var bytes: [4]u8 = undefined;
    for (data) |value| {
        std.mem.writeInt(u32, &bytes, value.v, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}
fn columns(a: std.mem.Allocator, left: []const M, left_log: u32, right: []const M, right_log: u32) ![]Column {
    const l: usize = @as(usize, 1) << @intCast(left_log);
    const r: usize = @as(usize, 1) << @intCast(right_log);
    if (left.len % l != 0 or right.len % r != 0) return error.InvalidFunctionalStorage;
    const output = try a.alloc(Column, left.len / l + right.len / r);
    for (output[0 .. left.len / l], 0..) |*column, i| column.* = .{ .log_size = left_log, .values = left[i * l ..][0..l] };
    for (output[left.len / l ..], 0..) |*column, i| column.* = .{ .log_size = right_log, .values = right[i * r ..][0..r] };
    return output;
}
fn fixedRoot(a: std.mem.Allocator, data: []const Column) !T.CommitmentRoot {
    var scheme = try T.Scheme.init(a, T.P.config());
    defer scheme.deinit(a);
    var channel = T.P.Channel{};
    try scheme.commitBorrowedStreaming(a, data, 8, &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    return .{ .value = roots.items[0] };
}
fn specs(a: std.mem.Allocator, roster: *const Roster, f: *const Fixture, consumer_fixed: []const M, consumer_main: []const M) ![2]T.Spec {
    const cf = try columns(a, consumer_fixed, 5, &.{}, 5);
    defer a.free(cf);
    const pf = try columns(a, f.fixed, 5, f.table.fixed, 16);
    defer a.free(pf);
    const roster_digest = try C.expectedRosterDigest(roster);
    return .{
        .{ .ordinal = 0, .role = .public_consumer, .schema = schema(.public_consumer), .job_witness = storageDigest(consumer_main), .public_statement = roster_digest, .instance_epoch = 0, .first_request = 0, .request_count = 32, .expected_fixed = try fixedRoot(a, cf), .column_logs = &LOGS_CONSUMER },
        .{ .ordinal = 1, .role = .binary, .schema = schema(.binary), .job_witness = storageDigest(f.main), .public_statement = schema(.binary), .instance_epoch = 0, .first_request = 0, .request_count = 32, .expected_fixed = try fixedRoot(a, pf), .column_logs = &LOGS_PROVIDER },
    };
}
const Worker = struct {
    allocator: std.mem.Allocator,
    scheme: T.Scheme,
    channel: T.P.Channel,
    receipt: T.Receipt,
    owns: bool = true,
    fn init(a: std.mem.Allocator, context: T.Context, spec: T.Spec, fixed: []const Column, main: []const Column) !Worker {
        var scheme = try T.Scheme.init(a, T.P.config());
        errdefer scheme.deinit(a);
        var channel = T.P.Channel{};
        try D.beginStage1(context, spec, &channel);
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        return .{ .allocator = a, .scheme = scheme, .channel = channel, .receipt = try T.fromCommitted(a, &scheme, spec) };
    }
    fn deinit(self: *Worker) void {
        if (self.owns) self.scheme.deinit(self.allocator);
    }
    fn prove(self: *Worker, inter: []const Column, claims: [3]Q, component_list: []const C.Component) !Encoded {
        mixClaims(&self.channel, claims);
        try self.scheme.commitBorrowedStreaming(self.allocator, inter, 8, &self.channel);
        var handles: [2]engine.air.component_prover.ComponentProver = undefined;
        for (component_list, 0..) |*component, i| handles[i] = component.asProverComponent();
        self.owns = false; // engine consumes the scheme on success AND error.
        var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, self.allocator, handles[0..component_list.len], &self.channel, self.scheme);
        defer proof.deinit(self.allocator);
        return .{ .bytes = try wire.encodeProofBytesBinary(self.allocator, proof), .claims = claims };
    }
};
fn mixClaims(channel: *T.P.Channel, claims: [3]Q) void {
    channel.mixU32s(&.{ 0x4650434c, 1, 3 });
    channel.mixFelts(&claims);
}
fn localChallenges(channel: *T.P.Channel, function: D.FunctionChallenges) B.Challenges {
    channel.mixU32s(&.{ 0x414e444c, 1, 3 });
    return .{ .and_ = Tables.Challenges.draw(channel), .function = function };
}
fn components(ordinal: usize, roster: *const Roster, ch: B.Challenges, claims: [3]Q) [2]C.Component {
    if (ordinal == 0) return .{
        .{ .kind = .expected_main, .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .and_ = Q.zero(), .function = claims[0] }, .expected_roster = roster },
        undefined,
    };
    return .{
        .{ .kind = .binary, .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .and_ = claims[1], .function = claims[0] } },
        .{ .kind = .and_table, .log_size = 16, .offsets = .{ 2, B.MAIN, B.INTERACTION }, .challenges = ch, .claims = .{ .and_ = claims[2], .function = Q.zero() } },
    };
}
fn consumerInteraction(a: std.mem.Allocator, main: []const M, ch: D.FunctionChallenges) !struct { data: []M, claim: Q } {
    const data = try a.alloc(M, 8 * N);
    errdefer a.free(data);
    var sum = Q.zero();
    for (0..N) |i| {
        const r = air.witness.physical(i, 5);
        var tuple: [13]Q = undefined;
        for (&tuple, 0..) |*v, c| v.* = Q.fromBase(main[c * N + r]);
        const inverse = try ch.denominatorFor(Q, tuple).inv();
        sum = sum.add(inverse.mulM31(main[13 * N + r]));
        for (inverse.toM31Array(), 0..) |v, c| data[c * N + r] = v;
        for (sum.toM31Array(), 0..) |v, c| data[(4 + c) * N + r] = v;
    }
    for (0..N) |r| for (sum.toM31Array(), 0..) |v, c| {
        data[(4 + c) * N + r] = data[(4 + c) * N + r].sub(v);
    };
    return .{ .data = data, .claim = sum };
}
/// Stage-one commitments for BOTH workers are complete before either worker
/// computes an interaction. No supplied-alpha interface exists.
pub fn produce(a: std.mem.Allocator, context: T.Context, roster: *const Roster) !Aggregate {
    try D.validateContext(context);
    try admitRoster(roster);
    var f = try Fixture.init(a, false);
    defer f.deinit();
    const fixed = try C.expectedMainFixed(a);
    defer a.free(fixed);
    const main = try C.expectedMainValues(a, roster);
    defer a.free(main);
    const inventory = try specs(a, roster, &f, fixed, main);
    const cf = try columns(a, fixed, 5, &.{}, 5);
    defer a.free(cf);
    const cm = try columns(a, main, 5, &.{}, 5);
    defer a.free(cm);
    const pf = try columns(a, f.fixed, 5, f.table.fixed, 16);
    defer a.free(pf);
    const pm = try columns(a, f.main, 5, f.request.main, 16);
    defer a.free(pm);
    var first = try Worker.init(a, context, inventory[0], cf, cm);
    defer first.deinit();
    var second = try Worker.init(a, context, inventory[1], pf, pm);
    defer second.deinit();
    var manifest = try D.Manifest.init(a, .{ .context = context, .specs = &inventory }, &.{ first.receipt, second.receipt });
    errdefer manifest.deinit();
    const shared0 = try manifest.resumeWorker(a, 0, &first.scheme, &first.channel);
    const ch0 = localChallenges(&first.channel, shared0.binary);
    const ci = try consumerInteraction(a, main, ch0.function);
    defer a.free(ci.data);
    const cc = components(0, roster, ch0, .{ ci.claim, Q.zero(), Q.zero() });
    const ic = try columns(a, ci.data, 5, &.{}, 5);
    defer a.free(ic);
    var proof0 = try first.prove(ic, .{ ci.claim, Q.zero(), Q.zero() }, cc[0..1]);
    errdefer proof0.deinit(a);
    const shared1 = try manifest.resumeWorker(a, 1, &second.scheme, &second.channel);
    const ch1 = localChallenges(&second.channel, shared1.binary);
    const actual = try f.generate(ch1);
    const claims = [_]Q{ actual[1], actual[0], actual[3] };
    const pc = components(1, roster, ch1, claims);
    const ip = try columns(a, f.inter, 5, f.request.interaction, 16);
    defer a.free(ip);
    return .{ .manifest = manifest, .proofs = .{ proof0, try second.prove(ip, claims, &pc) } };
}
fn verifyOne(a: std.mem.Allocator, manifest: *const D.Manifest, ordinal: usize, roster: *const Roster, encoded: Encoded) !void {
    if (encoded.bytes.len > MAX_PROOF_BYTES) return error.DistributedResourceLimit;
    for (encoded.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NonCanonicalDistributedClaim;
    if (ordinal == 0 and (!encoded.claims[1].isZero() or !encoded.claims[2].isZero())) return error.UnusedDistributedClaim;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidFunctionalProofRoster;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(T.P.Hasher, T.P.MerkleChannel).init(a, T.P.config());
    defer verifier.deinit(a);
    var channel = T.P.Channel{};
    try D.beginStage1(manifest.context, manifest.specs[ordinal], &channel);
    const roots = proof.commitment_scheme_proof.commitments.items;
    try verifier.commit(a, roots[0], if (ordinal == 0) &FIXED_CONSUMER else &FIXED_PROVIDER, &channel);
    try verifier.commit(a, roots[1], manifest.specs[ordinal].column_logs, &channel);
    const shared = try manifest.resumeReceiver(ordinal, &proof, &channel);
    const ch = localChallenges(&channel, shared.binary);
    mixClaims(&channel, encoded.claims);
    try verifier.commit(a, roots[2], if (ordinal == 0) &INTER_CONSUMER else &INTER_PROVIDER, &channel);
    const c = components(ordinal, roster, ch, encoded.claims);
    const count: usize = if (ordinal == 0) 1 else 2;
    var handles: [2]core.air.components.Component = undefined;
    for (c[0..count], 0..) |*component, i| handles[i] = component.asVerifierComponent();
    owns = false;
    try core.verifier.verify(T.P.Hasher, T.P.MerkleChannel, a, handles[0..count], &channel, &verifier, proof);
}
/// Fresh-verifies actual AIR/FRI proofs under independently expected public
/// roster and immutable schemas, THEN closes all physical typed claims.
/// This function accepts ONLY public functional truth facts, never execution.
pub fn verify(a: std.mem.Allocator, expected_context: T.Context, roster: *const Roster, aggregate: *const Aggregate) !void {
    try D.validateContext(expected_context);
    const inventory = try expectedInventory(a, roster);
    try aggregate.manifest.validateExpected(.{ .context = expected_context, .specs = &inventory });
    for (aggregate.proofs, 0..) |encoded, i| try verifyOne(a, &aggregate.manifest, i, roster, encoded);
    if (!aggregate.proofs[1].claims[1].add(aggregate.proofs[1].claims[2]).isZero() or
        !aggregate.proofs[0].claims[0].add(aggregate.proofs[1].claims[0]).isZero()) return error.UnclosedDistributedFunctionalClaims;
}
