const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");
const subject =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");

test "role0 completion claim consumes actual Ethereum decoded tuple" {
    const completion = try field_public.CompletionProjectionV4.init(
        frontend.air.public_data.Completion.unretiredProgramFetch(
            0x1004,
            frontend.isa.custom0.encodeSecp256k1Recover(7),
        ),
    );
    const relations = frontend.air.relation_challenges.Relations.dummy();
    var claim = try subject.testing.initProjectedClaim(
        completion,
        &relations,
    );
    try claim.validateStructure(&relations);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x1004, 47, 0, 7, 0 },
        &claim.program_tuple,
    );
    try std.testing.expect(!claim.claimed_sum.isZero());

    var circuit = try subject.CompletionProgramCircuitV4.init(
        std.testing.allocator,
    );
    defer circuit.deinit();
    var prepared = try circuit.prepare(std.testing.allocator, &claim);
    defer prepared.deinit();

    claim.program_tuple[3] = 8;
    try std.testing.expectError(
        error.EthereumIncrementalPublicSemanticsMismatchV4,
        claim.validateStructure(&relations),
    );
}

test "role0 completion claim does not synthesize program term for halt" {
    const completion = try field_public.CompletionProjectionV4.init(.{
        .kind = .halt_flag,
        .address = 0x2000,
        .value = 1,
        .clock = 9,
    });
    const relations = frontend.air.relation_challenges.Relations.dummy();
    const claim = try subject.testing.initProjectedClaim(
        completion,
        &relations,
    );
    try claim.validateStructure(&relations);
    try std.testing.expect(claim.claimed_sum.isZero());

    var circuit = try subject.CompletionProgramCircuitV4.init(
        std.testing.allocator,
    );
    defer circuit.deinit();
    var prepared = try circuit.prepare(std.testing.allocator, &claim);
    defer prepared.deinit();
}
