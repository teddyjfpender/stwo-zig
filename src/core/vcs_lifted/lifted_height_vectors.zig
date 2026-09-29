//! Lifted Merkle commitments at explicit heights, from the pinned Rust oracle.
//!
//! Oracle: https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, crates/stwo with feature `prover`:
//! `MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(columns, height, 0)`,
//! then `decommit(positions, columns)`, and `MerkleVerifierLifted::new(root,
//! [3, 2, 3], height).verify(..)` accepting the result. `Blake2sMerkleHasher`
//! there is the plain Blake2s hasher (`Blake2sPlainMerkleHasher` here).
//!
//! The columns have log sizes 3, 2, 3 and value `1000 * seed + 7 * row + 1`
//! with seeds 1, 2, 3. Height 3 is the largest column (the legacy rule);
//! heights 4 and 6 lift every column further.

const std = @import("std");
const M31 = @import("../fields/m31.zig").M31;

pub const column_log_sizes = [_]u32{ 3, 2, 3 };
const column_seeds = [_]u32{ 1, 2, 3 };

/// Fills `storage` with the oracle columns and returns views into it.
pub fn columns(storage: *[column_log_sizes.len][8]M31) [column_log_sizes.len][]const M31 {
    var views: [column_log_sizes.len][]const M31 = undefined;
    for (storage, &views, column_log_sizes, column_seeds) |*values, *view, log_size, seed| {
        const len = @as(usize, 1) << @intCast(log_size);
        for (values[0..len], 0..) |*value, row| value.* = M31.fromCanonical(seed * 1000 + @as(u32, @intCast(row)) * 7 + 1);
        view.* = values[0..len];
    }
    return views;
}

pub const Case = struct {
    height: u32,
    root: *const [64]u8,
    positions: []const usize,
    /// Queried values per column, in query order (duplicates kept).
    values: []const []const u32,
    witness: []const *const [64]u8,
};

pub const cases = [_]Case{
    .{
        .height = 3,
        .root = "4d815dfd1faaf9ee64abe37788572597d44687a4b14283cd4256cebc59b920ad",
        .positions = &.{ 7, 3, 1, 3 },
        .values = &.{
            &.{ 1050, 1022, 1008, 1022 },
            &.{ 2022, 2008, 2008, 2008 },
            &.{ 3050, 3022, 3008, 3022 },
        },
        .witness = &.{
            "ceedd22871c93b9845faa418418713703ae6a50b1abd5890eb20718c1b53522b",
            "2c1d2ce8958d9869ad11aed571301583689bb533eb01bcd491b57f5456d51ecf",
            "b8047c95e824e2a82a94537596835357aace35ce0f965acba7cf57cea36cae73",
            "4516749a3ea3ac3da505fde4ba82ed1a0d43c9a176afb22fbbe5432a2517ec74",
        },
    },
    .{
        .height = 4,
        .root = "360cb50ca1456aafe2955cafde0170044ddf40c48bd68ed4226488069566e82e",
        .positions = &.{ 15, 3, 1, 3 },
        .values = &.{
            &.{ 1050, 1008, 1008, 1008 },
            &.{ 2022, 2008, 2008, 2008 },
            &.{ 3050, 3008, 3008, 3008 },
        },
        .witness = &.{
            "ceedd22871c93b9845faa418418713703ae6a50b1abd5890eb20718c1b53522b",
            "ceedd22871c93b9845faa418418713703ae6a50b1abd5890eb20718c1b53522b",
            "b8047c95e824e2a82a94537596835357aace35ce0f965acba7cf57cea36cae73",
            "308d98bf8927da87b6520262720afb48202ade4602e091fe94c7601d1d338731",
            "afe67cdd47883a728d7dab7eada6aab8a207efab9254bdd8e8f4964f60a001dc",
            "4eb5ee1ac5da8c4cabc9a9bb7a1bca0f9b1696ea3d724f54da9745d1dc47520f",
        },
    },
    .{
        .height = 6,
        .root = "0901de9e022cc45e99374aadbae503cfffcfd1c8f8e04c1fff02d564b018b4b4",
        .positions = &.{ 63, 3, 1, 3 },
        .values = &.{
            &.{ 1050, 1008, 1008, 1008 },
            &.{ 2022, 2008, 2008, 2008 },
            &.{ 3050, 3008, 3008, 3008 },
        },
        .witness = &.{
            "ceedd22871c93b9845faa418418713703ae6a50b1abd5890eb20718c1b53522b",
            "ceedd22871c93b9845faa418418713703ae6a50b1abd5890eb20718c1b53522b",
            "b8047c95e824e2a82a94537596835357aace35ce0f965acba7cf57cea36cae73",
            "308d98bf8927da87b6520262720afb48202ade4602e091fe94c7601d1d338731",
            "f9b9f6176939afc9128c82d872c16c5530dd067e44c7d6363cc2731eddf2431b",
            "2556bb3d314f3ee9c795231416e27d472dfa2c0705ae34246cb8640de836c0b0",
            "33ff04dd78c9dd61d98b9134084a2dd49e32d799689ddb1c9f760aaa6ffa3d9a",
            "40321d10b6fc3fdb0f05f94bca1872717f69f2e1eb7d8b28f966a8c72b1aeb4d",
            "b1c7db579b5766637a69b72c7d39af3a80ed89160b61abdb8c68575c6c659597",
            "dce06d3f3feab59940e170213740d1543780bfe2661d9d0123a6f4a5086b685d",
        },
    },
};
pub const empty_root = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";

pub fn digest(hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}
