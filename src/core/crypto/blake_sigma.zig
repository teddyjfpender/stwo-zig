//! The BLAKE2s message schedule: the permutation of the sixteen message words
//! each of the ten rounds reads.
//!
//! This is the one definition shared by the native BLAKE2s hashers
//! (`blake2s_terminal_parallel.sigma`), the Cairo frontend's Blake witness
//! deductions and `blake_sigma_{col}` preprocessed columns, and the circuit
//! recursion builder. Upstream keeps the same table as `BLAKE_SIGMA` in
//! `crates/common/src/preprocessed_columns/blake.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 (re-exported by
//! `crates/circuit_common/src/preprocessed.rs`) and in stwo-cairo `82f2125`.
//! Upstream types the entries as `u32`; they index sixteen words, so `u8`
//! holds them exactly, as the SIMD hashers want.

const std = @import("std");

/// `N_BLAKE_ROUNDS`.
pub const n_rounds = 10;
/// `N_BLAKE_SIGMA_COLS`: message words permuted per round.
pub const n_columns = 16;

/// `BLAKE_SIGMA[round][i]` is the message word the round reads at position `i`.
pub const BLAKE_SIGMA = [n_rounds][n_columns]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

test "blake sigma: every round is a permutation and round 0 is the identity" {
    for (BLAKE_SIGMA, 0..) |round, round_index| {
        var seen = [_]bool{false} ** n_columns;
        for (round, 0..) |word, position| {
            try std.testing.expect(word < n_columns);
            try std.testing.expect(!seen[word]);
            seen[word] = true;
            if (round_index == 0) try std.testing.expectEqual(position, word);
        }
    }
}
