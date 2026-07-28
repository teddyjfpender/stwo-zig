//! Canonical Stark-V claim-phase transcript foundation for RISC-V proofs.

const std = @import("std");

pub const claims = @import("claims.zig");
pub const protocol = @import("protocol.zig");

pub const Component = claims.Component;
pub const COMPONENT_COUNT = claims.COMPONENT_COUNT;
pub const MainClaim = claims.MainClaim;
pub const InteractionClaim = claims.InteractionClaim;
pub const INTERACTION_POW_BITS = protocol.INTERACTION_POW_BITS;
pub const ProverRelations = protocol.ProverRelations;
pub const PrefixError = protocol.PrefixError;
pub const mixCommittedPrefix = protocol.mixCommittedPrefix;
pub const proveToRelations = protocol.proveToRelations;
pub const verifyToRelations = protocol.verifyToRelations;
pub const finishWithInteractionRoot = protocol.finishWithInteractionRoot;
pub const finishWithoutInteractionRoot = protocol.finishWithoutInteractionRoot;

const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const Blake2sMerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const PublicData = @import("../public_data.zig").PublicData;

fn fixturePublicData() PublicData {
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1040,
        .clock = 17,
        .initial_regs = [_]u32{0} ** 32,
        .final_regs = [_]u32{0} ** 32,
        .reg_last_clock = [_]u32{0} ** 32,
        .program_root = 101,
        .initial_rw_root = 202,
        .final_rw_root = 303,
        .completion = .{
            .kind = .unretired_self_loop,
            .address = 0x1040,
            .value = 0x0000_006f,
            .clock = 0,
        },
        .io_entries = .{
            .input_start = 0x0018_0000,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0x0010_0004,
            .output_data_addr = 0x0010_0008,
            .output_words = &.{},
        },
    };
}

fn fixtureMainClaim() MainClaim {
    var log_sizes: [COMPONENT_COUNT]u32 = undefined;
    for (&log_sizes, 0..) |*value, index| value.* = @intCast(4 + index % 5);
    return MainClaim.init(log_sizes);
}

fn fixtureInteractionClaim() InteractionClaim {
    var sums: [COMPONENT_COUNT]QM31 = undefined;
    for (&sums, 0..) |*value, index| {
        value.* = QM31.fromU32Unchecked(@intCast(31 + index), 0, 0, 0);
    }
    return InteractionClaim.init(sums, &.{ 4, 5, 6, 7 });
}

test "claim phase: prover and verifier replay are byte symmetric" {
    const allocator = std.testing.allocator;
    const data = fixturePublicData();
    const main_claim = fixtureMainClaim();
    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;
    const interaction_root = [_]u8{0x33} ** 32;
    var prover_channel = Blake2sChannel{};
    const prover_result = try proveToRelations(
        Blake2sMerkleChannel,
        allocator,
        &prover_channel,
        &data,
        preprocessed_root,
        main_root,
        &main_claim,
    );
    const interaction_claim = fixtureInteractionClaim();
    finishWithInteractionRoot(
        Blake2sMerkleChannel,
        &prover_channel,
        &interaction_claim,
        interaction_root,
    );

    var verifier_channel = Blake2sChannel{};
    const verifier_relations = try verifyToRelations(
        Blake2sMerkleChannel,
        allocator,
        &verifier_channel,
        &data,
        preprocessed_root,
        main_root,
        &main_claim,
        prover_result.interaction_pow,
    );
    finishWithInteractionRoot(
        Blake2sMerkleChannel,
        &verifier_channel,
        &interaction_claim,
        interaction_root,
    );

    try std.testing.expect(prover_result.relations.registers_state.z.eql(
        verifier_relations.registers_state.z,
    ));
    try std.testing.expectEqual(prover_channel.digestBytes(), verifier_channel.digestBytes());
    try std.testing.expectEqual(prover_channel.n_draws, verifier_channel.n_draws);
}

test "claim phase: invalid interaction proof of work fails before relation draws" {
    const data = fixturePublicData();
    const main_claim = fixtureMainClaim();
    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;
    var prover_channel = Blake2sChannel{};
    mixCommittedPrefix(
        Blake2sMerkleChannel,
        &prover_channel,
        &data,
        preprocessed_root,
        main_root,
        &main_claim,
    );
    const valid_nonce = prover_channel.grind(INTERACTION_POW_BITS);
    var invalid_nonce = valid_nonce +% 1;
    while (prover_channel.verifyPowNonce(INTERACTION_POW_BITS, invalid_nonce)) invalid_nonce +%= 1;

    var verifier_channel = Blake2sChannel{};
    try std.testing.expectError(
        PrefixError.InvalidInteractionProofOfWork,
        verifyToRelations(
            Blake2sMerkleChannel,
            std.testing.allocator,
            &verifier_channel,
            &data,
            preprocessed_root,
            main_root,
            &main_claim,
            invalid_nonce,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), verifier_channel.n_draws);
}

test "claim phase: deterministic pinned transcript checkpoints" {
    // The first two checkpoints preserve the legacy public-data/root prefix.
    // Later checkpoints bind the Sail-authoritative 28-component schema and
    // exact mix-call boundaries. The one-bit grind is a deterministic fixture;
    // production helpers always use INTERACTION_POW_BITS.
    const data = fixturePublicData();
    const main_claim = fixtureMainClaim();
    const interaction_claim = fixtureInteractionClaim();
    var channel = Blake2sChannel{};

    data.mixInto(&channel);
    try expectDigest(channel.digestBytes(), .{
        67,  48,  110, 191, 120, 36, 9,   40, 113, 113, 198, 101, 80,  46,  213, 58,
        114, 227, 178, 70,  8,   57, 224, 40, 196, 108, 167, 179, 132, 126, 169, 152,
    });

    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{0x11} ** 32);
    try expectDigest(channel.digestBytes(), .{
        197, 221, 67, 34,  167, 148, 253, 140, 83,  65,  253, 8,   146, 49, 22,  128,
        56,  208, 33, 129, 228, 96,  209, 51,  162, 161, 196, 125, 231, 20, 147, 29,
    });

    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{0x22} ** 32);
    main_claim.mixInto(&channel);
    try expectDigest(channel.digestBytes(), .{
        33, 120, 47,  140, 74, 81, 212, 253, 169, 67,  110, 253, 213, 217, 125, 154,
        42, 10,  235, 84,  64, 78, 148, 124, 189, 167, 165, 173, 88,  164, 101, 56,
    });

    const nonce = channel.grind(1);
    try std.testing.expectEqual(@as(u64, 0), nonce);
    channel.mixU64(nonce);
    const relations = try @import("../relation_challenges.zig").Relations.draw(
        std.testing.allocator,
        &channel,
    );
    try expectLimbs(relations.registers_state.z, .{
        1211976735,
        1092870877,
        1930337713,
        1027156036,
    });
    try expectLimbs(relations.range_check_m31.alpha, .{
        1459832336,
        724782805,
        1683350619,
        1917464742,
    });
    try std.testing.expectEqual(@as(u32, 12), channel.n_draws);
    try expectDigest(channel.digestBytes(), .{
        87,  44,  30,  9,   218, 170, 59,  160, 57, 191, 219, 144, 105, 126, 143, 6,
        222, 110, 240, 191, 133, 97,  176, 99,  34, 96,  55,  250, 54,  73,  150, 116,
    });

    finishWithInteractionRoot(
        Blake2sMerkleChannel,
        &channel,
        &interaction_claim,
        [_]u8{0x33} ** 32,
    );
    try expectDigest(channel.digestBytes(), .{
        196, 41, 67,  137, 218, 58, 130, 184, 143, 180, 142, 164, 78, 234, 86,  228,
        30,  83, 196, 127, 232, 16, 70,  147, 63,  176, 197, 40,  38, 58,  156, 229,
    });
}

fn expectDigest(actual: [32]u8, expected: [32]u8) !void {
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

fn expectLimbs(actual: QM31, expected: [4]u32) !void {
    for (actual.toM31Array(), expected) |limb, expected_limb| {
        try std.testing.expectEqual(expected_limb, limb.toU32());
    }
}
