const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const activation = @import("function_activation_logup.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const logup = @import("../logup.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const activation_test_support = @import("function_activation_logup_test_support.zig");

const generated = source.SourceSpan.generated();

test "F-014 activation LogUp carries the compiler-derived degree-three certificate" {
    try std.testing.expectEqual(
        @as(u32, 1),
        activation.DEGREE_CERTIFICATE.numerator,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        activation.DEGREE_CERTIFICATE.denominator,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        activation.DEGREE_CERTIFICATE.row_window,
    );
    try std.testing.expectEqual(
        @as(u32, 2),
        activation.DEGREE_CERTIFICATE.final,
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        activation.DEGREE_CERTIFICATE.maximum,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        activation.DEGREE_CERTIFICATE.quotient_expansion_bits,
    );
    try std.testing.expect(
        activation.DEGREE_CERTIFICATE.final <=
            activation.MAXIMUM_CONSTRAINT_DEGREE,
    );
    try std.testing.expectEqual(
        m31.Modulus,
        activation.SOURCE_COEFFICIENT_BOUND_EXCLUSIVE,
    );
}

test "F-014 per-function challenges and descriptors bind the sealed frame plan" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = Blake2sChannel{};
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();

    try protocol.validate();
    try protocol.validateAgainst(std.testing.allocator, &fixture.arena, &plan);
    try std.testing.expect(protocol.active);
    try std.testing.expectEqual(@as(usize, 2), protocol.relations.len);
    try std.testing.expectEqual(@as(usize, 4), protocol.events.len);
    try std.testing.expectEqual(@as(usize, 4), protocol.alpha_powers.len);
    try std.testing.expectEqual(@as(usize, 8), protocol.tuple_values.len);
    try std.testing.expectEqual(@as(u32, 2), channel.n_draws);
    try std.testing.expect(!protocol.relations[0].z.eql(protocol.relations[1].z) or
        !protocol.relations[0].alpha.eql(protocol.relations[1].alpha));

    const prepared = try protocol.prepare();
    for (0..prepared.events.len) |event_index| {
        try std.testing.expectEqual(@as(usize, 2), prepared.tupleIds(event_index).?.len);
    }

    var second_channel = Blake2sChannel{};
    var second = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &second_channel,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(u8, &protocol.protocol_digest, &second.protocol_digest);
    try std.testing.expectEqualSlices(u8, &channel.digestBytes(), &second_channel.digestBytes());
}

test "F-014 caller callee and public-root claims balance independently" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = Blake2sChannel{};
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();
    const prepared = try protocol.prepare();
    const witness = balancedWitness();

    var denominators: [4]QM31 = undefined;
    var inverses: [4]QM31 = undefined;
    var pairs: [4]logup.RowPair = undefined;
    var event_claims: [4]QM31 = undefined;
    var relation_claims: [2]QM31 = undefined;
    try prepared.evaluateInto(
        &witness.batches,
        &witness.rows,
        &witness.values,
        &denominators,
        &inverses,
        &pairs,
        &event_claims,
        &relation_claims,
    );
    try prepared.validateClaimProjection(&event_claims, &relation_claims);
    try prepared.verifyClosed(&relation_claims);
    try std.testing.expect(event_claims[0].eql(event_claims[2].neg()));
    try std.testing.expect(event_claims[1].eql(event_claims[3].neg()));
    try std.testing.expect(pairs[0].n1.eql(QM31.one().neg()));
    try std.testing.expect(pairs[2].n1.eql(QM31.one()));

    var prover_claim_channel = channel;
    var verifier_claim_channel = channel;
    var claim_scratch: [2]QM31 = undefined;
    const public = balancedPublicWitness();
    try prepared.mixClaims(
        &prover_claim_channel,
        &event_claims,
        &public.roots,
        &public.values,
        &claim_scratch,
    );
    try prepared.mixClaims(
        &verifier_claim_channel,
        &event_claims,
        &public.roots,
        &public.values,
        &claim_scratch,
    );
    try std.testing.expectEqualSlices(
        u8,
        &prover_claim_channel.digestBytes(),
        &verifier_claim_channel.digestBytes(),
    );
}

test "F-014 omission duplication ownership and challenge mutations reject" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = Blake2sChannel{};
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();
    const prepared = try protocol.prepare();
    var witness = balancedWitness();

    var denominators = [_]QM31{sentinel()} ** 4;
    var inverses = [_]QM31{sentinel()} ** 4;
    var pairs = [_]logup.RowPair{sentinelPair()} ** 4;
    var event_claims = [_]QM31{sentinel()} ** 4;
    var relation_claims = [_]QM31{sentinel()} ** 2;
    try std.testing.expectError(
        error.InvalidBatchShape,
        prepared.evaluateInto(
            witness.batches[0..3],
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);

    witness.batches[1].event_index = 0;
    try std.testing.expectError(
        error.InvalidBatchShape,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    witness.batches[1].event_index = 1;

    const saved_event = protocol.events[2];
    protocol.events[2].owner = fixture.leaf;
    try std.testing.expectError(error.DigestMismatch, protocol.validate());
    protocol.events[2] = saved_event;

    const saved_relation = protocol.relations[1];
    const saved_power = protocol.alpha_powers[protocol.relations[1].alpha_powers.start + 1];
    protocol.relations[1].z = protocol.relations[0].z;
    try std.testing.expectError(error.DuplicateChallenge, protocol.validate());
    protocol.relations[1] = saved_relation;

    protocol.relations[1].alpha = protocol.relations[0].alpha;
    protocol.alpha_powers[protocol.relations[1].alpha_powers.start + 1] =
        protocol.relations[0].alpha;
    try std.testing.expectError(error.DuplicateChallenge, protocol.validate());
    protocol.relations[1] = saved_relation;
    protocol.alpha_powers[protocol.relations[1].alpha_powers.start + 1] = saved_power;

    protocol.relations[1].z = protocol.relations[1].alpha;
    try std.testing.expectError(error.DuplicateChallenge, protocol.validate());
    protocol.relations[1] = saved_relation;

    protocol.relations[1].z = protocol.relations[0].z;
    protocol.relations[1].alpha = protocol.relations[0].alpha;
    protocol.alpha_powers[protocol.relations[1].alpha_powers.start + 1] =
        protocol.relations[0].alpha;
    try std.testing.expectError(error.DuplicateChallenge, protocol.validate());
    protocol.relations[1] = saved_relation;
    protocol.alpha_powers[protocol.relations[1].alpha_powers.start + 1] = saved_power;
    try protocol.validate();

    protocol.relations[1].z = QM31.fromM31(
        M31.fromU32Unchecked(m31.Modulus),
        M31.zero(),
        M31.zero(),
        M31.zero(),
    );
    try std.testing.expectError(error.NonCanonicalChallenge, protocol.validate());
    protocol.relations[1] = saved_relation;
    try protocol.validate();

    const plan_event = plan.events[2];
    plan.events[2].owner = fixture.leaf;
    try std.testing.expectError(
        error.InvalidActivationEvent,
        protocol.validateAgainst(std.testing.allocator, &fixture.arena, &plan),
    );
    plan.events[2] = plan_event;
}

test "F-014 row provenance and multiplicity sources fail closed before publication" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = Blake2sChannel{};
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();
    const prepared = try protocol.prepare();
    var witness = balancedWitness();

    var denominators = [_]QM31{sentinel()} ** 4;
    var inverses = [_]QM31{sentinel()} ** 4;
    var pairs = [_]logup.RowPair{sentinelPair()} ** 4;
    var event_claims = [_]QM31{sentinel()} ** 4;
    var relation_claims = [_]QM31{sentinel()} ** 2;

    witness.batches[0].origin = .public_statement;
    try std.testing.expectError(
        error.InvalidRowOrigin,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);
    witness.batches[0].origin = .trace;

    witness.batches[3].origin = .trace;
    try std.testing.expectError(
        error.InvalidRowOrigin,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);
    witness.batches[3].origin = .public_statement;

    witness.rows[0].multiplicity = M31.fromCanonical(2);
    try std.testing.expectError(
        error.InvalidMultiplicity,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);

    witness.rows[0].multiplicity = M31.one();
    witness.values[0] = M31.fromU32Unchecked(m31.Modulus);
    try std.testing.expectError(
        error.NonCanonicalValue,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);
    witness.values[0] = M31.fromCanonical(7);

    witness.rows[3].multiplicity = M31.fromU32Unchecked(m31.Modulus);
    try std.testing.expectError(
        error.InvalidMultiplicity,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);

    witness.rows[3].multiplicity = M31.fromCanonical(m31.Modulus - 3);
    try std.testing.expectError(
        error.CoefficientBoundExceeded,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);

    // Public roots may deliberately aggregate equal activations. They pass
    // provenance preflight, but an unmatched aggregate remains unbalanced.
    witness.rows[3].multiplicity = M31.fromCanonical(2);
    try prepared.evaluateInto(
        &witness.batches,
        &witness.rows,
        &witness.values,
        &denominators,
        &inverses,
        &pairs,
        &event_claims,
        &relation_claims,
    );
    try std.testing.expectError(
        error.UnbalancedRelation,
        prepared.verifyClosed(&relation_claims),
    );
}

test "F-014 denominator and relation imbalance failures are output atomic" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = CollisionChannel{};
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();
    const prepared = try protocol.prepare();
    var witness = balancedWitness();

    var denominators = [_]QM31{sentinel()} ** 4;
    var inverses = [_]QM31{sentinel()} ** 4;
    var pairs = [_]logup.RowPair{sentinelPair()} ** 4;
    var event_claims = [_]QM31{sentinel()} ** 4;
    var relation_claims = [_]QM31{sentinel()} ** 2;
    try std.testing.expectError(
        error.DenominatorCollision,
        prepared.evaluateInto(
            &witness.batches,
            &witness.rows,
            &witness.values,
            &denominators,
            &inverses,
            &pairs,
            &event_claims,
            &relation_claims,
        ),
    );
    try expectPublishedSentinels(&pairs, &event_claims, &relation_claims);

    // A normal transcript makes the same tuple valid. Mutating only one side
    // of the leaf relation must then leave a non-zero independent claim.
    var normal_channel = Blake2sChannel{};
    var normal_protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &normal_channel,
    );
    defer normal_protocol.deinit();
    const normal = try normal_protocol.prepare();
    witness.values[4] = M31.fromCanonical(9);
    try normal.evaluateInto(
        &witness.batches,
        &witness.rows,
        &witness.values,
        &denominators,
        &inverses,
        &pairs,
        &event_claims,
        &relation_claims,
    );
    try normal.validateClaimProjection(&event_claims, &relation_claims);
    try std.testing.expectError(error.UnbalancedRelation, normal.verifyClosed(&relation_claims));
}

test "F-014 transcript drift changes challenges and claim mutations reject atomically" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();

    var canonical_channel = Blake2sChannel{};
    var canonical = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &canonical_channel,
    );
    defer canonical.deinit();
    var drifted_channel = Blake2sChannel{};
    drifted_channel.mixU64(0xBAD5_EED);
    var drifted = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &drifted_channel,
    );
    defer drifted.deinit();
    try std.testing.expect(!std.mem.eql(
        u8,
        &canonical.protocol_digest,
        &drifted.protocol_digest,
    ));

    const prepared = try canonical.prepare();
    const witness = balancedWitness();
    var denominators: [4]QM31 = undefined;
    var inverses: [4]QM31 = undefined;
    var pairs: [4]logup.RowPair = undefined;
    var event_claims: [4]QM31 = undefined;
    var relation_claims: [2]QM31 = undefined;
    try prepared.evaluateInto(
        &witness.batches,
        &witness.rows,
        &witness.values,
        &denominators,
        &inverses,
        &pairs,
        &event_claims,
        &relation_claims,
    );
    var first_claim_channel = canonical_channel;
    var mutated_claim_channel = canonical_channel;
    var claim_scratch: [2]QM31 = undefined;
    var public = balancedPublicWitness();
    var alias_channel = canonical_channel;
    const before_alias_digest = alias_channel.digestBytes();
    try std.testing.expectError(
        error.AliasedBuffer,
        prepared.mixClaims(
            &alias_channel,
            &event_claims,
            &public.roots,
            &public.values,
            event_claims[0..2],
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before_alias_digest,
        &alias_channel.digestBytes(),
    );
    try prepared.mixClaims(
        &first_claim_channel,
        &event_claims,
        &public.roots,
        &public.values,
        &claim_scratch,
    );

    const before_public_mutation_digest = mutated_claim_channel.digestBytes();
    public.values[0] = M31.fromCanonical(9);
    try std.testing.expectError(
        error.PublicClaimMismatch,
        prepared.mixClaims(
            &mutated_claim_channel,
            &event_claims,
            &public.roots,
            &public.values,
            &claim_scratch,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before_public_mutation_digest,
        &mutated_claim_channel.digestBytes(),
    );
    public.values[0] = M31.fromCanonical(7);

    public.roots[0].event_index = 2;
    try std.testing.expectError(
        error.InvalidPublicRoot,
        prepared.mixClaims(
            &mutated_claim_channel,
            &event_claims,
            &public.roots,
            &public.values,
            &claim_scratch,
        ),
    );
    public.roots[0].event_index = 3;

    const saved_public_claim = event_claims[3];
    event_claims[3] = event_claims[3].add(QM31.one());
    try std.testing.expectError(
        error.PublicClaimMismatch,
        prepared.mixClaims(
            &mutated_claim_channel,
            &event_claims,
            &public.roots,
            &public.values,
            &claim_scratch,
        ),
    );
    event_claims[3] = saved_public_claim;

    const before_mutation_digest = mutated_claim_channel.digestBytes();
    const before_mutation_draws = mutated_claim_channel.n_draws;
    event_claims[0] = event_claims[0].add(QM31.one());
    try std.testing.expectError(
        error.UnbalancedRelation,
        prepared.mixClaims(
            &mutated_claim_channel,
            &event_claims,
            &public.roots,
            &public.values,
            &claim_scratch,
        ),
    );
    const after_mutation_digest = mutated_claim_channel.digestBytes();
    try std.testing.expectEqual(before_mutation_draws, mutated_claim_channel.n_draws);
    try std.testing.expectEqualSlices(
        u8,
        &before_mutation_digest,
        &after_mutation_digest,
    );
}

test "F-014 legacy relation metadata is a zero-cost zero-byte protocol no-op" {
    var fixture = try ActivationFixture.init(std.testing.allocator, false);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    try std.testing.expectEqual(@as(u16, 0), plan.body_ownership_version);
    try std.testing.expect(plan.events.len != 0);
    var channel = Blake2sChannel{};
    const before_digest = channel.digestBytes();
    const before_draws = channel.n_draws;
    var protocol = try activation.compileAndDraw(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        &channel,
    );
    defer protocol.deinit();
    try protocol.validate();
    try std.testing.expect(!protocol.active);
    try std.testing.expectEqual(before_draws, channel.n_draws);
    try std.testing.expectEqualSlices(u8, &before_digest, &channel.digestBytes());

    const prepared = try protocol.prepare();
    try prepared.evaluateInto(
        &.{},
        &.{},
        &.{},
        &.{},
        &.{},
        &.{},
        &.{},
        &.{},
    );
    try prepared.mixClaims(&channel, &.{}, &.{}, &.{}, &.{});
    try std.testing.expectEqual(before_draws, channel.n_draws);
    try std.testing.expectEqualSlices(u8, &before_digest, &channel.digestBytes());
}

test "F-014 compile is allocation-failure atomic and prepared API has no allocator" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );

    comptime {
        const evaluate_info = @typeInfo(@TypeOf(activation.PreparedProtocol.evaluateInto)).@"fn";
        for (evaluate_info.params) |parameter| {
            if (parameter.type != null and parameter.type.? == std.mem.Allocator)
                @compileError("function activation hot evaluation must not allocate");
        }
        const claim_info = @typeInfo(@TypeOf(activation.PreparedProtocol.mixClaims)).@"fn";
        for (claim_info.params) |parameter| {
            if (parameter.type != null and parameter.type.? == std.mem.Allocator)
                @compileError("function activation claim mixing must not allocate");
        }
    }
}

test "F-014 degenerate challenge draw is rejected without advancing the channel" {
    var fixture = try ActivationFixture.init(std.testing.allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    var channel = ZeroAlphaChannel{};
    const before = channel;
    try std.testing.expectError(
        error.DegenerateChallenge,
        activation.compileAndDraw(
            std.testing.allocator,
            &fixture.arena,
            &plan,
            &channel,
        ),
    );
    try std.testing.expectEqualDeep(before, channel);
}

test "F-014 live activation is the sole function LogUp lowering authority" {
    const activation_source = @embedFile("function_activation_logup.zig");
    const declaration_source = @embedFile("functions.zig");
    const frame_source = @embedFile("function_frames.zig");
    const inline_source = @embedFile("function_body_lowering.zig");
    const inline_compiler_source = @embedFile("function_body_lowering_compiler.zig");
    const activation_authority_source = @embedFile("function_activation_authority.zig");
    const language_source = @embedFile("mod.zig");

    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(
            u8,
            activation_source,
            "const logup = @import(\"../logup.zig\");",
        ),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        activation_authority_source,
        "drawSecureFelts",
    ) != null);
    for ([_][]const u8{ declaration_source, frame_source, inline_source }) |retired| {
        try std.testing.expect(std.mem.indexOf(u8, retired, "drawSecureFelts") == null);
        try std.testing.expect(std.mem.indexOf(u8, retired, "RowPair.single") == null);
        try std.testing.expect(std.mem.indexOf(u8, retired, "FNACTV01") == null);
    }
    try std.testing.expect(std.mem.indexOf(
        u8,
        inline_compiler_source,
        "return error.RelationBackedCall;",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        activation_source,
        "@import(\"function_activation_authority.zig\")",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        inline_source,
        "@import(\"function_body_lowering_compiler.zig\")",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        language_source,
        "pub const function_activation_logup = @import(\"function_activation_logup.zig\");",
    ) != null);
}

const allocationFailureCase = activation_test_support.allocationFailureCase;
const Witness = activation_test_support.Witness;
const PublicWitness = activation_test_support.PublicWitness;
const balancedPublicWitness = activation_test_support.balancedPublicWitness;
const balancedWitness = activation_test_support.balancedWitness;
const ActivationFixture = activation_test_support.ActivationFixture;
const CollisionChannel = activation_test_support.CollisionChannel;
const ZeroAlphaChannel = activation_test_support.ZeroAlphaChannel;
const sentinel = activation_test_support.sentinel;
const sentinelPair = activation_test_support.sentinelPair;
const expectPublishedSentinels = activation_test_support.expectPublishedSentinels;
