//! Pinned execution profiles for the Pokémon checkpoint fixture.

const std = @import("std");
pub const Profile = enum {
    short,
    proof_fast_short,
    proof_fast_dma_probe,
    proof_fast_chunk_1,
    proof_fast_chunk_2,
    start_release,
    battle_chunk_1,
    battle_chunk_2,
};

pub const Spec = struct {
    skip_rows: usize = 0,
    skip_instructions: usize = 0,
    skip_mcycles: u32 = 0,
    rows: usize,
    instructions: usize,
    mcycles: u32,
    lookahead_rows: usize,
    dma_source_bytes: usize,
    actions: usize,
};

pub fn spec(profile: Profile) Spec {
    return switch (profile) {
        .short => .{
            .rows = 1 << 12,
            .instructions = 929,
            .mcycles = 5_211,
            .lookahead_rows = 10_239,
            .dma_source_bytes = 0,
            .actions = 0,
        },
        .proof_fast_short => .{
            .rows = 1 << 13,
            // Derived from the live pinned proof-fast SameBoy checkpoint.
            .instructions = 301,
            .mcycles = 8_600,
            .lookahead_rows = 7_637,
            .dma_source_bytes = 0,
            .actions = 0,
        },
        .proof_fast_dma_probe => .{
            .rows = 1 << 14,
            .instructions = 857,
            .mcycles = 17_415,
            .lookahead_rows = 1,
            .dma_source_bytes = 160,
            .actions = 0,
        },
        .proof_fast_chunk_1 => .{
            .rows = 1 << 17,
            .instructions = 12_425,
            .mcycles = 146_040,
            .lookahead_rows = 10_645,
            .dma_source_bytes = 1_280,
            .actions = 0,
        },
        .proof_fast_chunk_2 => .{
            .skip_rows = 1 << 17,
            .skip_instructions = 12_425,
            .skip_mcycles = 146_040,
            .rows = 1 << 17,
            .instructions = 7_424,
            .mcycles = 141_366,
            .lookahead_rows = 9_727,
            .dma_source_bytes = 1_280,
            .actions = 1,
        },
        .start_release => .{
            .rows = 1 << 17,
            .instructions = 25_115,
            .mcycles = 163_027,
            .lookahead_rows = 10_427,
            .dma_source_bytes = 1_440,
            .actions = 1,
        },
        .battle_chunk_1 => .{
            .skip_rows = 1 << 17,
            .skip_instructions = 25_115,
            .skip_mcycles = 163_027,
            .rows = 1 << 17,
            .instructions = 8_809,
            .mcycles = 142_224,
            .lookahead_rows = 8_651,
            .dma_source_bytes = 1_280,
            .actions = 0,
        },
        .battle_chunk_2 => .{
            .skip_rows = 2 << 17,
            .skip_instructions = 33_924,
            .skip_mcycles = 305_251,
            .rows = 1 << 17,
            .instructions = 8_378,
            .mcycles = 141_631,
            .lookahead_rows = 7_468,
            .dma_source_bytes = 1_280,
            .actions = 1,
        },
    };
}

test "profiles pin power-of-two rows and the START release" {
    const short = spec(.short);
    const proof_fast = spec(.proof_fast_short);
    const proof_fast_first = spec(.proof_fast_chunk_1);
    const proof_fast_second = spec(.proof_fast_chunk_2);
    const action = spec(.start_release);
    const next = spec(.battle_chunk_1);
    const third = spec(.battle_chunk_2);
    try std.testing.expect(std.math.isPowerOfTwo(short.rows));
    try std.testing.expect(std.math.isPowerOfTwo(proof_fast.rows));
    try std.testing.expect(std.math.isPowerOfTwo(proof_fast_first.rows));
    try std.testing.expect(std.math.isPowerOfTwo(proof_fast_second.rows));
    try std.testing.expect(std.math.isPowerOfTwo(action.rows));
    try std.testing.expect(std.math.isPowerOfTwo(next.rows));
    try std.testing.expect(std.math.isPowerOfTwo(third.rows));
    try std.testing.expectEqual(action.rows, next.skip_rows);
    try std.testing.expectEqual(
        proof_fast_first.rows,
        proof_fast_second.skip_rows,
    );
    try std.testing.expectEqual(
        proof_fast_first.instructions,
        proof_fast_second.skip_instructions,
    );
    try std.testing.expectEqual(
        proof_fast_first.mcycles,
        proof_fast_second.skip_mcycles,
    );
    try std.testing.expectEqual(@as(usize, 1), action.actions);
    try std.testing.expectEqual(@as(usize, 1_440), action.dma_source_bytes);
    try std.testing.expectEqual(action.instructions, next.skip_instructions);
    try std.testing.expectEqual(action.mcycles, next.skip_mcycles);
    try std.testing.expectEqual(
        action.rows + next.rows,
        third.skip_rows,
    );
    try std.testing.expectEqual(
        action.instructions + next.instructions,
        third.skip_instructions,
    );
    try std.testing.expectEqual(
        action.mcycles + next.mcycles,
        third.skip_mcycles,
    );
}

test "proof-fast short profile pins exact derived counts" {
    try std.testing.expectEqual(
        Spec{
            .rows = 1 << 13,
            .instructions = 301,
            .mcycles = 8_600,
            .lookahead_rows = 7_637,
            .dma_source_bytes = 0,
            .actions = 0,
        },
        spec(.proof_fast_short),
    );
    try std.testing.expectEqual(@as(usize, 160), spec(.proof_fast_dma_probe).dma_source_bytes);
}
