//! Shared BINARY truth worker for the experimental register-only aggregate.
//! Actual PCS roots and a complete Manifest are mandatory; no loose alpha API.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const air = @import("stwo_riscv_frontend").rv64_air;
const D = @import("../rv64_distributed_v1/manifest.zig");
const T = D.T;
const Source = air.word16_v1.binary_source;
const P = air.word16_v1.binary_lookup;
const C = air.word16_v1.binary_component;
const Tables = air.providers.tables;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Backend = @import("stwo_cpu_backend").CpuBackend;
pub const Fact = Source.Fact;
pub const Encoded = struct {
    bytes: []u8,
    claims: P.Claims,
    and_table_claim: Q,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
    }
};
pub const Materials = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    fixed: []M,
    table: Tables.Setup,
    fixed_root: T.CommitmentRoot,
    main_logs: [P.MAIN + 1]u32,
    pub fn init(a: std.mem.Allocator, log: u32) !Materials {
        if (log > 20) return error.UnsupportedDistributedBinaryGeometry;
        _ = try Source.massForLog(log);
        const fixed = try Source.fixedForLog(a, log);
        errdefer a.free(fixed);
        var table = try Tables.Setup.init(a, .byte_and);
        errdefer table.deinit();
        const cols = try join(a, fixed, log, table.fixed, 16);
        defer a.free(cols);
        var scheme = try T.Scheme.init(a, T.P.config());
        defer scheme.deinit(a);
        var channel = T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, cols, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        var logs: [P.MAIN + 1]u32 = @splat(log);
        logs[P.MAIN] = 16;
        return .{ .allocator = a, .log_size = log, .fixed = fixed, .table = table, .fixed_root = .{ .value = roots.items[0] }, .main_logs = logs };
    }
    pub fn deinit(self: *Materials) void {
        self.allocator.free(self.fixed);
        self.table.deinit();
        self.* = undefined;
    }
    pub fn descriptor(self: *const Materials, ordinal: u32, queries: u64, job: T.Digest, public_statement: T.Digest) T.Spec {
        return .{ .ordinal = ordinal, .role = .binary, .schema = schema(), .job_witness = job, .public_statement = public_statement, .instance_epoch = 0, .first_request = 0, .request_count = queries, .expected_fixed = self.fixed_root, .column_logs = &self.main_logs };
    }
};
pub fn schema() T.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.distributed.binary-worker.v2.main42.inter24.merged-debt.and65536.function13");
    hash.update(&P.encoding.identity());
    return hash.finalResult();
}
fn validateSpec(materials: *const Materials, spec: T.Spec) !void {
    try T.validateSpec(spec);
    if (spec.role != .binary or !std.mem.eql(u8, &spec.schema, &schema()) or
        !std.meta.eql(spec.expected_fixed, materials.fixed_root) or !std.mem.eql(u32, spec.column_logs, &materials.main_logs)) return error.InvalidDistributedBinaryDescriptor;
}
pub const Stage1 = struct {
    allocator: std.mem.Allocator,
    materials: *const Materials,
    source: Source.Source,
    request: Tables.Request,
    scheme: T.Scheme,
    channel: T.P.Channel,
    receipt: T.Receipt,
    owns_scheme: bool = true,
    completed: bool = false,
    pub fn init(a: std.mem.Allocator, materials: *const Materials, context: T.Context, spec: T.Spec, facts: []const Fact) !Stage1 {
        try validateSpec(materials, spec);
        if (facts.len != spec.request_count) return error.InvalidDistributedBinaryFacts;
        var source = try Source.Source.init(a, facts, materials.log_size);
        errdefer source.deinit();
        var request = try Tables.Request.init(a, &materials.table, source.and_counts);
        errdefer request.deinit();
        var scheme = try T.Scheme.init(a, T.P.config());
        errdefer scheme.deinit(a);
        var channel = T.P.Channel{};
        try D.beginStage1(context, spec, &channel);
        const fixed = try join(a, materials.fixed, materials.log_size, materials.table.fixed, 16);
        defer a.free(fixed);
        const main = try join(a, source.main, materials.log_size, request.main, 16);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        return .{ .allocator = a, .materials = materials, .source = source, .request = request, .scheme = scheme, .channel = channel, .receipt = try T.fromCommitted(a, &scheme, spec) };
    }
    pub fn deinit(self: *Stage1) void {
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        self.source.deinit();
        self.request.deinit();
        self.* = undefined;
    }
    pub fn complete(self: *Stage1, manifest: *const D.Manifest, ordinal: usize) !Encoded {
        if (self.completed) return error.InvalidDistributedBinaryPhase;
        const shared = try manifest.resumeWorker(self.allocator, ordinal, &self.scheme, &self.channel);
        // Stage two is one-shot, including allocation/proof failures. deinit
        // retains responsibility for every source/scheme still owned here.
        self.completed = true;
        const ch = drawLocal(&self.channel, shared.binary);
        const actual = try self.source.generate(ch);
        const table_claim = try self.request.generateInteraction(ch.and_);
        if (!actual.and_.add(table_claim).isZero()) return error.UnclosedDistributedBinaryAnd;
        mixClaims(&self.channel, actual, table_claim);
        const cols = try join(self.allocator, self.source.interaction, self.materials.log_size, self.request.interaction, 16);
        defer self.allocator.free(cols);
        try self.scheme.commitBorrowedStreaming(self.allocator, cols, 8, &self.channel);
        const components = componentsFor(self.materials, ch, actual, table_claim);
        const handles = [_]engine.air.component_prover.ComponentProver{ components[0].asProverComponent(), components[1].asProverComponent() };
        self.completed = true;
        self.owns_scheme = false;
        var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, self.allocator, &handles, &self.channel, self.scheme);
        defer proof.deinit(self.allocator);
        return .{ .bytes = try wire.encodeProofBytesBinary(self.allocator, proof), .claims = actual, .and_table_claim = table_claim };
    }
};
/// Returns only the FUNCTION debt after both real components verify and AND
/// closes LOCALLY. The caller must combine it with verified CPU FUNCTION debt.
pub fn verifyOpen(a: std.mem.Allocator, materials: *const Materials, manifest: *const D.Manifest, ordinal: usize, encoded: Encoded) !Q {
    if (ordinal >= manifest.specs.len) return error.DistributedInventoryMismatch;
    try validateSpec(materials, manifest.specs[ordinal]);
    for ([_]Q{ encoded.claims.and_, encoded.claims.function, encoded.and_table_claim }) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
    if (encoded.bytes.len > 32 * 1024 * 1024) return error.DistributedResourceLimit;
    if (!encoded.claims.and_.add(encoded.and_table_claim).isZero()) return error.UnclosedDistributedBinaryAnd;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidDistributedBinaryProof;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(T.P.Hasher, T.P.MerkleChannel).init(a, T.P.config());
    defer verifier.deinit(a);
    var channel = T.P.Channel{};
    try D.beginStage1(manifest.context, manifest.specs[ordinal], &channel);
    const roots = proof.commitment_scheme_proof.commitments.items;
    var fixed_logs: [7]u32 = @splat(16);
    fixed_logs[0] = materials.log_size;
    fixed_logs[1] = materials.log_size;
    try verifier.commit(a, roots[0], &fixed_logs, &channel);
    try verifier.commit(a, roots[1], &materials.main_logs, &channel);
    const shared = try manifest.resumeReceiver(ordinal, &proof, &channel);
    const ch = drawLocal(&channel, shared.binary);
    mixClaims(&channel, encoded.claims, encoded.and_table_claim);
    var inter_logs: [P.INTERACTION + 8]u32 = @splat(16);
    @memset(inter_logs[0..P.INTERACTION], materials.log_size);
    try verifier.commit(a, roots[2], &inter_logs, &channel);
    const components = componentsFor(materials, ch, encoded.claims, encoded.and_table_claim);
    const handles = [_]core.air.components.Component{ components[0].asVerifierComponent(), components[1].asVerifierComponent() };
    owns = false;
    try core.verifier.verify(T.P.Hasher, T.P.MerkleChannel, a, &handles, &channel, &verifier, proof);
    return encoded.claims.function;
}
fn drawLocal(channel: *T.P.Channel, function: D.FunctionChallenges) P.Challenges {
    channel.mixU32s(&.{ 0x42414e44, 1 });
    return .{ .and_ = Tables.Challenges.draw(channel), .function = function };
}
fn mixClaims(channel: *T.P.Channel, claims: P.Claims, table: Q) void {
    channel.mixU32s(&.{ 0x42434c4d, 1, 3 });
    channel.mixFelts(&.{ claims.function, claims.and_, table });
}
fn componentsFor(materials: *const Materials, ch: P.Challenges, claims: P.Claims, table: Q) [2]C.Component {
    return .{
        .{ .kind = .binary, .log_size = materials.log_size, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = claims },
        .{ .kind = .and_table, .log_size = 16, .offsets = .{ 2, P.MAIN, P.INTERACTION }, .challenges = ch, .claims = .{ .and_ = table, .function = Q.zero() } },
    };
}
fn join(a: std.mem.Allocator, first: []const M, first_log: u32, second: []const M, second_log: u32) ![]Column {
    const n: usize = @as(usize, 1) << @intCast(first_log);
    const m: usize = @as(usize, 1) << @intCast(second_log);
    const columns = try a.alloc(Column, first.len / n + second.len / m);
    for (columns[0 .. first.len / n], 0..) |*column, c| column.* = .{ .log_size = first_log, .values = first[c * n ..][0..n] };
    for (columns[first.len / n ..], 0..) |*column, c| column.* = .{ .log_size = second_log, .values = second[c * m ..][0..m] };
    return columns;
}
