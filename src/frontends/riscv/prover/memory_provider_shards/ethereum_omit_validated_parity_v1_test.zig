//! Validated-vs-unvalidated parity for the Ethereum provider-omission path.
//!
//! Every `...Validated` sibling added to the omit path replaces one
//! `ProviderShardPlanV1.validate(calls)` corpus rehash with an O(1)
//! pointer-closed readmission of an already minted
//! `OwnedValidatedPlanCallAuthorityV1`. That is a validation change only: this
//! file pins that both routes accept exactly the same corpus, mint
//! byte-identical Stage-A manifests, admit byte-identical shard call slices,
//! and compute byte-identical aggregate closures -- and that the fast route
//! stays fail-closed against a token minted for a different plan or corpus.
//!
//! The shard *proof bytes* of the same graft are pinned by the backend-bound
//! sibling in `src/integrations/riscv_cpu`; this package is backend-neutral and
//! cannot prove.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const protocol = @import("ethereum_omit_protocol_v1.zig");

/// The manifest, its records, and their identities are hashes of plan data and
/// root bytes only, so a fixed-width root is a complete stand-in here. Nothing
/// in this file commits, proves, or verifies.
const FakeEngine = struct {
    pub const Hasher = struct {
        pub const Hash = [8]u32;
    };
    pub const Channel = Blake2sChannel;
};

const Manifest = protocol.ProviderStageAManifestV1(FakeEngine);
const Extension = protocol.Extension(FakeEngine);

const call_count = 33;
const shard_count = 3;

/// A base-field QM31 stand-in; these fixtures only need distinct values.
fn qm31(value: u32) QM31 {
    return QM31.fromU32Unchecked(value, 0, 0, 0);
}

fn digest(marker: u8) authority.Digest {
    return [_]u8{marker} ** 32;
}

fn callsFixture(allocator: std.mem.Allocator, count: usize) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    return calls;
}

fn request(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = authority.main_column_count,
        .min_shard_log_size = 4,
        .max_shard_log_size = 4,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

fn rootsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]harness.StageACommitment(FakeEngine) {
    const roots = try allocator.alloc(harness.StageACommitment(FakeEngine), count);
    for (roots, 0..) |*value, index| {
        value.* = .{
            .preprocessed_root = [_]u32{@intCast(0x5100 + index)} ** 8,
            .main_root = [_]u32{@intCast(0xa200 + index)} ** 8,
        };
    }
    return roots;
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    calls: []poseidon2_air.Call,
    plan: authority.ProviderShardPlanV1,
    roots: []harness.StageACommitment(FakeEngine),

    fn init(allocator: std.mem.Allocator, session: u8) !Fixture {
        const calls = try callsFixture(allocator, call_count);
        errdefer allocator.free(calls);
        var plan = try authority.ProviderShardPlanV1.create(
            allocator,
            digest(session),
            calls,
            request(calls.len),
        );
        errdefer plan.deinit(allocator);
        const roots = try rootsFixture(allocator, plan.shards.len);
        return .{
            .allocator = allocator,
            .calls = calls,
            .plan = plan,
            .roots = roots,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.roots);
        self.plan.deinit(self.allocator);
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    fn token(
        self: *const Fixture,
    ) !authority.OwnedValidatedPlanCallAuthorityV1 {
        return authority.OwnedValidatedPlanCallAuthorityV1.init(
            self.allocator,
            &self.plan,
            self.calls,
        );
    }
};

fn closureClaims(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    relation: authority.PoseidonRelationContextV1,
) ![]authority.ProviderShardClaimV1 {
    const claims = try allocator.alloc(
        authority.ProviderShardClaimV1,
        plan.shards.len,
    );
    for (claims, plan.shards, 0..) |*claim, descriptor, index| {
        var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
        for (&sums, 0..) |*value, ordinal|
            value.* = qm31(@intCast(index * 7 + ordinal + 1));
        claim.* = .{
            .plan_identity = plan.identity,
            .descriptor_identity = descriptor.identity,
            .shard_index = @intCast(index),
            .relation_context_identity = relation.identity,
            .claims = .{ .sums = sums },
        };
    }
    return claims;
}

test "omit path: validated and unvalidated Stage-A manifests are identical" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0xa7);
    defer fixture.deinit();
    var token = try fixture.token();
    defer token.deinit();

    var plain = try Manifest.createFromRoots(
        allocator,
        &fixture.plan,
        fixture.calls,
        fixture.roots,
    );
    defer plain.deinit(allocator);
    var fast = try Manifest.createFromRootsValidated(
        allocator,
        &fixture.plan,
        fixture.calls,
        &token,
        fixture.roots,
    );
    defer fast.deinit(allocator);

    try std.testing.expectEqualSlices(
        u8,
        &plain.manifest.identity,
        &fast.manifest.identity,
    );
    try std.testing.expectEqual(plain.providers.len, fast.providers.len);
    for (plain.providers, fast.providers) |left, right|
        try std.testing.expect(std.meta.eql(left, right));

    // Both routes readmit each other's manifest, so neither is a weaker check
    // of the same object.
    try plain.manifest.validate(&fixture.plan, fixture.calls);
    try fast.manifest.validateBorrowedValidated(
        &fixture.plan,
        fixture.calls,
        &token,
    );
    try fast.manifest.validate(&fixture.plan, fixture.calls);
    try plain.manifest.validateBorrowedValidated(
        &fixture.plan,
        fixture.calls,
        &token,
    );

    const direct = try Manifest.init(
        &fixture.plan,
        fixture.calls,
        plain.providers,
    );
    const direct_fast = try Manifest.initValidated(
        &fixture.plan,
        fixture.calls,
        &token,
        plain.providers,
    );
    try std.testing.expect(std.meta.eql(direct, direct_fast));
    try std.testing.expectEqualSlices(
        u8,
        &plain.manifest.identity,
        &direct_fast.identity,
    );

    const receipt = token.workReceipt();
    try receipt.validate();
    try std.testing.expectEqual(@as(u64, 1), receipt.full_corpus_validations);
    try std.testing.expect(receipt.fast_pointer_checks > 0);
}

test "omit path: validated and unvalidated shard admission return one slice" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0xb3);
    defer fixture.deinit();
    var token = try fixture.token();
    defer token.deinit();

    try std.testing.expectEqual(
        @as(u32, shard_count),
        fixture.plan.shard_count,
    );
    for (0..fixture.plan.shards.len) |index| {
        const plain = try harness.admittedShard(
            &fixture.plan,
            fixture.calls,
            @intCast(index),
        );
        const fast = try harness.admittedShardValidated(
            &token,
            &fixture.plan,
            fixture.calls,
            @intCast(index),
        );
        try std.testing.expectEqual(plain.ptr, fast.ptr);
        try std.testing.expectEqual(plain.len, fast.len);
    }
    try std.testing.expectEqual(@as(u64, 1), token.workReceipt().full_corpus_validations);
}

test "omit path: validated and unvalidated aggregate closures agree" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0xc9);
    defer fixture.deinit();
    var token = try fixture.token();
    defer token.deinit();

    const relation = try authority.PoseidonRelationContextV1.canonical(
        fixture.plan.session,
        qm31(11),
        qm31(29),
    );
    const claims = try closureClaims(allocator, &fixture.plan, relation);
    defer allocator.free(claims);

    var provider_total = QM31.zero();
    for (claims) |claim| provider_total = provider_total.add(claim.claims.total());
    const core = authority.CorePoseidonClaimV1{
        .plan_identity = fixture.plan.identity,
        .relation_context_identity = relation.identity,
        .claim = provider_total.neg(),
    };

    const plain = try authority.verifyAggregateClosure(
        &fixture.plan,
        fixture.calls,
        relation,
        core,
        claims,
    );
    const fast = try authority.verifyAggregateClosureValidated(
        &token,
        &fixture.plan,
        fixture.calls,
        relation,
        core,
        claims,
    );
    try std.testing.expect(std.meta.eql(plain, fast));
    try std.testing.expect(plain.closed_sum.isZero());
    try std.testing.expectEqual(@as(u32, shard_count), plain.shard_count);
}

test "omit path: validated extension retains the token without changing state" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0xd4);
    defer fixture.deinit();
    var token = try fixture.token();
    defer token.deinit();

    var owned = try Manifest.createFromRoots(
        allocator,
        &fixture.plan,
        fixture.calls,
        fixture.roots,
    );
    defer owned.deinit(allocator);
    const manifest = owned.manifest;

    const plain = try Extension.init(&fixture.plan, fixture.calls, &manifest);
    const fast = try Extension.initValidated(
        &fixture.plan,
        fixture.calls,
        &token,
        &manifest,
    );
    try std.testing.expectEqual(plain.plan, fast.plan);
    try std.testing.expectEqual(plain.calls.ptr, fast.calls.ptr);
    try std.testing.expectEqual(plain.calls.len, fast.calls.len);
    try std.testing.expectEqual(plain.provider_stage_a, fast.provider_stage_a);
    try std.testing.expectEqual(plain.projection_ready, fast.projection_ready);
    try std.testing.expect(plain.validated == null);
    try std.testing.expect(fast.validated == &token);
}

test "omit path: a validated fast route is fail-closed on a foreign token" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0xe1);
    defer fixture.deinit();
    var other = try Fixture.init(allocator, 0xe2);
    defer other.deinit();
    var foreign = try other.token();
    defer foreign.deinit();

    const invalid = error.InvalidValidatedProviderPlanCallAuthority;
    try std.testing.expectError(
        invalid,
        Manifest.createFromRootsValidated(
            allocator,
            &fixture.plan,
            fixture.calls,
            &foreign,
            fixture.roots,
        ),
    );
    try std.testing.expectError(
        invalid,
        harness.admittedShardValidated(
            &foreign,
            &fixture.plan,
            fixture.calls,
            0,
        ),
    );
    try std.testing.expectError(
        invalid,
        Extension.initValidated(
            &fixture.plan,
            fixture.calls,
            &foreign,
            undefined,
        ),
    );

    const relation = try authority.PoseidonRelationContextV1.canonical(
        fixture.plan.session,
        qm31(3),
        qm31(5),
    );
    const claims = try closureClaims(allocator, &fixture.plan, relation);
    defer allocator.free(claims);
    try std.testing.expectError(
        invalid,
        authority.verifyAggregateClosureValidated(
            &foreign,
            &fixture.plan,
            fixture.calls,
            relation,
            .{
                .plan_identity = fixture.plan.identity,
                .relation_context_identity = relation.identity,
                .claim = QM31.zero(),
            },
            claims,
        ),
    );

    // A token whose corpus was mutated after minting is rejected too: the
    // slice identity, not just the plan pointer, is part of the seal.
    var own = try fixture.token();
    defer own.deinit();
    try std.testing.expectError(
        invalid,
        harness.admittedShardValidated(
            &own,
            &fixture.plan,
            fixture.calls[0 .. fixture.calls.len - 1],
            0,
        ),
    );
}
