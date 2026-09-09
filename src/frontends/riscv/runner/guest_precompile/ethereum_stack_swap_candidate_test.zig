//! Candidate-only authority, decoder, and session-construction regressions.

const std = @import("std");

const program_decode = @import("../../air/program/decode.zig");
const custom0 = @import("../../isa/custom0.zig");
const authority_mod = @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const combined_decode =
    @import("../../prover/guest_precompile/ethereum_stack_swap_candidate_decode_v1.zig");
const segment_session = @import("../segment_session.zig");
const test_elf = @import("test_elf.zig");

test "Ethereum SWAP candidate authority binds the exact ELF and registry" {
    const elf = test_elf.buildEthereum();
    const authority = try authorityForElf(&elf);
    try authority.validate();
    try authority.validateElf(&elf);
    try std.testing.expect(!authority_mod.production_active);

    var changed_elf = elf;
    changed_elf[changed_elf.len - 1] ^= 1;
    try std.testing.expectError(
        error.EthereumStackSwapGuestIdentityMismatch,
        authority.validateElf(&changed_elf),
    );

    var changed_abi = authority;
    changed_abi.ethereum_abi_version +%= 1;
    try std.testing.expectError(
        error.InvalidEthereumStackSwapAuthority,
        changed_abi.validate(),
    );
    try std.testing.expectError(
        error.InvalidEthereumStackSwapGuestIdentity,
        authority_mod.Authority.create(.{0} ** 32),
    );
}

test "Ethereum SWAP declared decoder adds only the allocated private word" {
    var elf_identity = [_]u8{0} ** 32;
    elf_identity[0] = 1;
    const authority = try authority_mod.Authority.create(elf_identity);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);

    const swap = try decoder.decodeFetchedWord(authority.stack_swap.fixed_word);
    try std.testing.expectEqual(
        program_decode.ProgramValues{
            authority.stack_swap.allocation.proof_opcode_id,
            0,
            10,
            11,
        },
        swap,
    );

    const keccak_word = custom0.encodeKeccakf(5);
    try std.testing.expectEqual(
        try program_decode.decodeProgramWordForProfile(authority_mod.base_profile, keccak_word),
        try decoder.decodeFetchedWord(keccak_word),
    );
    const ordinary_word: u32 = 0x0010_0093;
    try std.testing.expectEqual(
        try program_decode.decodeProgramWordForProfile(authority_mod.base_profile, ordinary_word),
        try decoder.decodeFetchedWord(ordinary_word),
    );

    var changed_registry = authority;
    changed_registry.stack_swap.allocation.registry_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidStackSwapProgramAuthority,
        combined_decode.DeclaredDecodeAuthority.init(changed_registry),
    );
}

test "Ethereum SWAP session construction is explicit and ELF-bound" {
    const elf = test_elf.buildEthereum();
    const authority = try authorityForElf(&elf);
    const CandidateSession =
        segment_session.EthereumStackSwapCandidateExecutionSessionV1();

    try std.testing.expectError(
        error.EthereumStackSwapAuthorityRequired,
        CandidateSession.initLegacy(std.testing.allocator, &elf, .{}),
    );
    var session = try CandidateSession.initCandidateLegacy(
        std.testing.allocator,
        &elf,
        .{},
        authority,
    );
    defer session.deinit();

    var changed_elf = elf;
    changed_elf[changed_elf.len - 1] ^= 1;
    try std.testing.expectError(
        error.EthereumStackSwapGuestIdentityMismatch,
        CandidateSession.initCandidateLegacy(
            std.testing.allocator,
            &changed_elf,
            .{},
            authority,
        ),
    );
}

fn authorityForElf(elf: []const u8) !authority_mod.Authority {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &digest, .{});
    return authority_mod.Authority.create(digest);
}
