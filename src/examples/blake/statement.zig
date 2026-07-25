//! Transcript elements and public claims for the exact Blake AIR.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");

pub const RelationElements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !RelationElements {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{ .z = values[0], .alpha = values[1] };
    }

    pub fn combineBase(
        self: RelationElements,
        values: []const @import("stwo_core").fields.m31.M31,
    ) QM31 {
        var result = QM31.zero();
        var power = QM31.one();
        for (values) |value| {
            result = result.add(power.mulM31(value));
            power = power.mul(self.alpha);
        }
        return result.sub(self.z);
    }

    pub fn combineSecure(
        self: RelationElements,
        values: []const QM31,
    ) QM31 {
        var result = QM31.zero();
        var power = QM31.one();
        for (values) |value| {
            result = result.add(power.mul(value));
            power = power.mul(self.alpha);
        }
        return result.sub(self.z);
    }
};

pub const AllElements = struct {
    blake: RelationElements,
    round: RelationElements,
    xor: [geometry.XOR_TABLES.len]RelationElements,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !AllElements {
        var result: AllElements = undefined;
        result.blake = try RelationElements.draw(allocator, channel);
        result.round = try RelationElements.draw(allocator, channel);
        for (&result.xor) |*elements| {
            elements.* = try RelationElements.draw(allocator, channel);
        }
        return result;
    }

    pub fn xorForWidth(self: *const AllElements, width: u5) *const RelationElements {
        return &self.xor[
            switch (width) {
                12 => 0,
                9 => 1,
                8 => 2,
                7 => 3,
                4 => 4,
                else => unreachable,
            }
        ];
    }
};

pub const Statement0 = struct {
    log_size: u32,
};

pub const Statement1 = struct {
    scheduler_claimed_sum: QM31,
    round_claimed_sums: [constants.ROUND_LOG_SPLIT.len]QM31,
    xor_claimed_sums: [geometry.XOR_TABLES.len]QM31,

    pub fn totalClaimedSum(self: Statement1) QM31 {
        var total = self.scheduler_claimed_sum;
        for (self.round_claimed_sums) |claim| total = total.add(claim);
        for (self.xor_claimed_sums) |claim| total = total.add(claim);
        return total;
    }
};

pub const PreparedStatement = struct {
    stmt0: Statement0,
    stmt1: Statement1,
};

pub fn mixStatement0(channel: anytype, statement: Statement0) void {
    channel.mixU64(statement.log_size);
}

pub fn mixStatement1(channel: anytype, statement: Statement1) void {
    var claims: [
        1 + geometry.XOR_TABLES.len +
            constants.ROUND_LOG_SPLIT.len
    ]QM31 = undefined;
    claims[0] = statement.scheduler_claimed_sum;
    @memcpy(claims[1 .. 1 + geometry.XOR_TABLES.len], &statement.xor_claimed_sums);
    @memcpy(claims[1 + geometry.XOR_TABLES.len ..], &statement.round_claimed_sums);
    channel.mixFelts(&claims);
}

pub fn verify(statement: PreparedStatement) !void {
    if (statement.stmt0.log_size < 4) return error.InvalidLogNRows;
    if (!statement.stmt1.totalClaimedSum().isZero())
        return error.ClaimedSumMismatch;
}

test "exact Blake statement mixes claims in pinned upstream order" {
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const statement = Statement1{
        .scheduler_claimed_sum = QM31.fromU32Unchecked(1, 2, 3, 4),
        .round_claimed_sums = .{
            QM31.fromU32Unchecked(5, 6, 7, 8),
            QM31.fromU32Unchecked(9, 10, 11, 12),
        },
        .xor_claimed_sums = .{
            QM31.fromU32Unchecked(13, 14, 15, 16),
            QM31.fromU32Unchecked(17, 18, 19, 20),
            QM31.fromU32Unchecked(21, 22, 23, 24),
            QM31.fromU32Unchecked(25, 26, 27, 28),
            QM31.fromU32Unchecked(29, 30, 31, 32),
        },
    };
    var actual = Channel{};
    mixStatement1(&actual, statement);

    var expected = Channel{};
    expected.mixFelts(&.{
        statement.scheduler_claimed_sum,
        statement.xor_claimed_sums[0],
        statement.xor_claimed_sums[1],
        statement.xor_claimed_sums[2],
        statement.xor_claimed_sums[3],
        statement.xor_claimed_sums[4],
        statement.round_claimed_sums[0],
        statement.round_claimed_sums[1],
    });
    const actual_draw = try actual.drawSecureFelts(std.testing.allocator, 1);
    defer std.testing.allocator.free(actual_draw);
    const expected_draw = try expected.drawSecureFelts(std.testing.allocator, 1);
    defer std.testing.allocator.free(expected_draw);
    try std.testing.expect(actual_draw[0].eql(expected_draw[0]));
}

test "exact Blake draws seven independent relation pairs" {
    const allocator = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    const elements = try AllElements.draw(allocator, &channel);
    try std.testing.expect(!elements.blake.z.eql(elements.round.z));
    try std.testing.expect(!elements.xor[0].z.eql(elements.xor[1].z));
}
