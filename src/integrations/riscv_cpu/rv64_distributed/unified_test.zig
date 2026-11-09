//! Challenge/root-binding qualification ONLY. No accepting V2 CPU, RAM or
//! aggregate proof receiver is constructed by these diagnostic projection tests.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const M = @import("manifest.zig");
const T = M.T;
const Wire = @import("wire.zig");
const Old = @import("manifest_test.zig");
const Felt = core.fields.m31.M31;
const a = std.testing.allocator;
const LOGS = [_]u32{5} ** 14;
fn policy() T.Digest {
    return air.word16_cpu.profile.identity(.alu_binary_v2);
}
fn context() T.Context {
    var value = Old.context();
    value.protocol = .functional13_unified_v2;
    value.policy = policy();
    return value;
}
fn hash(text: []const u8) T.Digest {
    var value: T.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &value, .{});
    return value;
}
const Stage = struct {
    scheme: T.Scheme,
    channel: T.P.Channel,
    spec: T.Spec,
    receipt: T.Receipt,
    fn init(ordinal: u32, role: T.Role) !Stage {
        var fixed: [64]Felt = @splat(Felt.zero());
        fixed[air.witness.physical(0, 5)] = Felt.one();
        fixed[32 + air.witness.physical(31, 5)] = Felt.one();
        const fixed_columns = [_]engine.pcs.ColumnEvaluation{
            .{ .log_size = 5, .values = fixed[0..32] }, .{ .log_size = 5, .values = fixed[32..] },
        };
        var expected = try T.Scheme.init(a, T.P.config());
        defer expected.deinit(a);
        var scratch = T.P.Channel{};
        try expected.commitBorrowedStreaming(a, &fixed_columns, 8, &scratch);
        var roots = try expected.roots(a);
        defer roots.deinit(a);
        const spec = T.Spec{ .ordinal = ordinal, .role = role, .schema = hash("diagnostic-unified-v2-projection14-not-execution"), .job_witness = hash("diagnostic-native-projection-v2"), .public_statement = policy(), .instance_epoch = @as(u64, ordinal) + 1, .first_request = 0, .request_count = if (role == .cpu) 2 else 1, .expected_fixed = .{ .value = roots.items[0] }, .column_logs = &LOGS };
        var data: [14 * 32]Felt = @splat(Felt.zero());
        // Timeless ADD and XOR facts with disjoint global op IDs. Weight is
        // precommitted even though this fixture proves no local truth circuit.
        for (0..2) |fact| {
            if ((role == .alu and fact != 0) or (role == .binary and fact != 1)) continue;
            const pos = air.witness.physical(if (role == .cpu) fact else 0, 5);
            data[pos] = Felt.fromCanonical(if (fact == 0) 0 else 18);
            data[32 + pos] = Felt.fromCanonical(if (fact == 0) 1 else 255);
            data[5 * 32 + pos] = Felt.fromCanonical(if (fact == 0) 2 else 15);
            data[9 * 32 + pos] = Felt.fromCanonical(if (fact == 0) 3 else 240);
            data[13 * 32 + pos] = Felt.one();
        }
        var columns: [14]engine.pcs.ColumnEvaluation = undefined;
        for (&columns, 0..) |*column, c| column.* = .{ .log_size = 5, .values = data[c * 32 ..][0..32] };
        var scheme = try T.Scheme.init(a, T.P.config());
        errdefer scheme.deinit(a);
        var channel = T.P.Channel{};
        try M.beginStage1(context(), spec, &channel);
        try scheme.commitBorrowedStreaming(a, &fixed_columns, 8, &channel);
        try scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
        return .{ .scheme = scheme, .channel = channel, .spec = spec, .receipt = try T.fromCommitted(a, &scheme, spec) };
    }
    fn deinit(self: *Stage) void {
        self.scheme.deinit(a);
    }
};
const Fixture = struct {
    stages: [3]Stage,
    specs: [3]T.Spec,
    receipts: [3]T.Receipt,
    fn init() !Fixture {
        var cpu = try Stage.init(0, .cpu);
        errdefer cpu.deinit();
        var alu = try Stage.init(1, .alu);
        errdefer alu.deinit();
        const binary = try Stage.init(2, .binary);
        return .{ .stages = .{ cpu, alu, binary }, .specs = .{ cpu.spec, alu.spec, binary.spec }, .receipts = .{ cpu.receipt, alu.receipt, binary.receipt } };
    }
    fn expected(self: *const Fixture) M.Expected {
        return .{ .context = context(), .specs = &self.specs };
    }
    fn deinit(self: *Fixture) void {
        for (&self.stages) |*stage| stage.deinit();
    }
};
test "unifiedV2 one vector derives only after complete actual roots and never through V1" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    const common = try manifest.deriveUnifiedFunctionV2(policy());
    try std.testing.expectError(error.DistributedFunctionProtocolMismatch, manifest.derive());
    for (&fixture.stages, 0..) |*stage, ordinal| {
        try std.testing.expectError(error.DistributedFunctionProtocolMismatch, manifest.resumeWorker(a, ordinal, &stage.scheme, &stage.channel));
        const derived = try manifest.resumeWorkerUnifiedFunctionV2(a, ordinal, &stage.scheme, &stage.channel, policy());
        try std.testing.expectEqualDeep(common, derived);
        try std.testing.expectError(error.Stage1TranscriptMismatch, manifest.resumeWorkerUnifiedFunctionV2(a, ordinal, &stage.scheme, &stage.channel, policy()));
    }
    var old = try Old.Fixture.init();
    defer old.deinit();
    var old_manifest = try M.Manifest.init(a, old.expected(), &old.receipts);
    defer old_manifest.deinit();
    try std.testing.expectError(error.DistributedFunctionProtocolMismatch, old_manifest.deriveUnifiedFunctionV2(policy()));
    const independent = try old_manifest.derive();
    try std.testing.expect(!std.meta.eql(independent.alu, independent.binary));
    try std.testing.expect(!std.meta.eql(common, independent.binary));
}
test "unifiedV2 policy opmap completeness and peer root are pinned before challenge" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.IncompleteDistributedManifest, M.Manifest.init(fail.allocator(), fixture.expected(), fixture.receipts[0..2]));
    var bad = fixture.expected();
    bad.context.policy[0] ^= 1;
    try std.testing.expectError(error.DistributedFunctionPolicyMismatch, M.Manifest.init(fail.allocator(), bad, &fixture.receipts));
    bad = fixture.expected();
    bad.context.opcode_map[0] ^= 1;
    try std.testing.expectError(error.InvalidDistributedContext, M.Manifest.init(fail.allocator(), bad, &fixture.receipts));
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    var wrong = policy();
    wrong[0] ^= 1;
    const before = fixture.stages[0].channel.digestBytes();
    try std.testing.expectError(error.DistributedFunctionPolicyMismatch, manifest.resumeWorkerUnifiedFunctionV2(fail.allocator(), 0, &fixture.stages[0].scheme, &fixture.stages[0].channel, wrong));
    try std.testing.expectEqualDeep(before, fixture.stages[0].channel.digestBytes());
    var receipts = fixture.receipts;
    receipts[2].shared.value[0] ^= 1;
    var changed = try M.Manifest.init(a, fixture.expected(), &receipts);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(try manifest.deriveUnifiedFunctionV2(policy()), try changed.deriveUnifiedFunctionV2(policy())));
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("manifest", .{ .read = true });
    defer file.close();
    try Wire.write(file, &manifest);
    try file.seekTo(0);
    var loaded = try Wire.read(a, file, fixture.expected());
    defer loaded.deinit();
    try std.testing.expectEqualDeep(try manifest.deriveUnifiedFunctionV2(policy()), try loaded.deriveUnifiedFunctionV2(policy()));
}
test "unifiedV2 receiver binds actual observed roots but does not verify an invalid proof shell" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    // Intentionally INVALID shell: no FRI, samples, decommitments or PoW.
    // Returning a challenge here is NOT proof/CPU acceptance.
    var proof = std.mem.zeroes(T.P.Proof);
    proof.commitment_scheme_proof.config = T.P.config();
    var roots = [_]T.P.Hasher.Hash{ fixture.receipts[0].fixed.value, fixture.receipts[0].shared.value };
    proof.commitment_scheme_proof.commitments.items = &roots;
    var local = try M.stage1Channel(context(), fixture.specs[0], fixture.receipts[0]);
    const observed = try manifest.resumeReceiverUnifiedFunctionV2(0, &proof, &local, policy());
    try std.testing.expectEqualDeep(try manifest.deriveUnifiedFunctionV2(policy()), observed);
    try std.testing.expectEqual(@as(usize, 0), proof.commitment_scheme_proof.sampled_values.items.len);
    roots[1][0] ^= 1;
    var other = try M.stage1Channel(context(), fixture.specs[0], fixture.receipts[0]);
    try std.testing.expectError(error.Stage1ProofRootMismatch, manifest.resumeReceiverUnifiedFunctionV2(0, &proof, &other, policy()));
}
