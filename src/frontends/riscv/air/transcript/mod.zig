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
    // The first checkpoint deliberately includes the RVST/v1 statement
    // domain prefix. Every later value is regenerated from that authenticated
    // prefix and binds the Sail-authoritative 28-component schema and exact
    // mix-call boundaries. The one-bit grind is a deterministic fixture;
    // production helpers always use INTERACTION_POW_BITS.
    const data = fixturePublicData();
    const main_claim = fixtureMainClaim();
    const interaction_claim = fixtureInteractionClaim();
    var channel = Blake2sChannel{};

    data.mixInto(&channel);
    try expectDigest(channel.digestBytes(), .{
        242, 16, 147, 249, 151, 251, 168, 12,  187, 174, 181, 3,  72, 197, 29, 200,
        22,  50, 131, 135, 18,  202, 160, 249, 220, 39,  164, 94, 22, 100, 56, 51,
    });

    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{0x11} ** 32);
    try expectDigest(channel.digestBytes(), .{
        238, 230, 175, 6,  134, 27, 155, 252, 86,  15,  84, 33, 69, 193, 116, 149,
        10,  10,  197, 43, 176, 99, 168, 124, 175, 211, 6,  49, 90, 150, 160, 117,
    });

    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{0x22} ** 32);
    main_claim.mixInto(&channel);
    try expectDigest(channel.digestBytes(), .{
        31,  43,  238, 7,   163, 205, 175, 216, 192, 7,  154, 119, 81, 241, 124, 251,
        109, 184, 9,   164, 119, 47,  30,  132, 176, 55, 160, 145, 84, 143, 78,  144,
    });

    const nonce = channel.grind(1);
    try std.testing.expectEqual(@as(u64, 0), nonce);
    channel.mixU64(nonce);
    const relations = try @import("../relation_challenges.zig").Relations.draw(
        std.testing.allocator,
        &channel,
    );
    try expectLimbs(relations.registers_state.z, .{
        2016346130,
        1951509438,
        1461118113,
        386917271,
    });
    try expectLimbs(relations.range_check_m31.alpha, .{
        1383787405,
        360336575,
        128396165,
        354039216,
    });
    try std.testing.expectEqual(@as(u32, 12), channel.n_draws);
    try expectDigest(channel.digestBytes(), .{
        97, 48, 202, 71,  73,  34, 81, 68,  68,  14,  124, 129, 102, 197, 222, 86,
        47, 51, 79,  211, 102, 71, 22, 139, 194, 202, 62,  170, 252, 184, 214, 223,
    });

    finishWithInteractionRoot(
        Blake2sMerkleChannel,
        &channel,
        &interaction_claim,
        [_]u8{0x33} ** 32,
    );
    try expectDigest(channel.digestBytes(), .{
        248, 93,  182, 4,   216, 182, 38,  25, 186, 121, 221, 236, 250, 212, 33,  7,
        248, 131, 144, 226, 54,  160, 142, 50, 226, 52,  225, 101, 211, 77,  102, 177,
    });
}

test "claim phase: statement transcript version is digest-bound" {
    const data = fixturePublicData();
    var canonical = Blake2sChannel{};
    data.mixInto(&canonical);

    var changed = VersionMutationChannel{};
    data.mixInto(&changed);
    try std.testing.expect(changed.mutated);
    try std.testing.expect(!std.mem.eql(
        u8,
        &canonical.digestBytes(),
        &changed.inner.digestBytes(),
    ));
}

const VersionMutationChannel = struct {
    inner: Blake2sChannel = .{},
    mutated: bool = false,

    pub fn mixU32s(self: *@This(), values: []const u32) void {
        if (!self.mutated and values.len == 2 and
            values[0] == @import("../public_data.zig").STATEMENT_TRANSCRIPT_DOMAIN)
        {
            var changed = [2]u32{ values[0], values[1] +% 1 };
            self.inner.mixU32s(&changed);
            self.mutated = true;
            return;
        }
        self.inner.mixU32s(values);
    }
};

fn expectDigest(actual: [32]u8, expected: [32]u8) !void {
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

fn expectLimbs(actual: QM31, expected: [4]u32) !void {
    for (actual.toM31Array(), expected) |limb, expected_limb| {
        try std.testing.expectEqual(expected_limb, limb.toU32());
    }
}
