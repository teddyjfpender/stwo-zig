//! Canonical RISC-V claim transcript representations.
//!
//! Component order is part of the Fiat-Shamir protocol. The first sixteen
//! opcode components preserve the legacy layout; FENCE is appended before the
//! infrastructure block in the Sail-authoritative schema.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Component = enum(u8) {
    auipc,
    base_alu_imm,
    base_alu_reg,
    branch_eq,
    branch_lt,
    div,
    jal,
    jalr,
    load_store,
    lt_imm,
    lt_reg,
    lui,
    mul,
    mulh,
    shifts_imm,
    shifts_reg,
    fence,
    program,
    memory,
    merkle,
    poseidon2,
    clock_update,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const COMPONENT_COUNT: usize = @typeInfo(Component).@"enum".fields.len;

/// Main-trace claim. Stark-V mixes one `u64` log size for each component in
/// canonical order, including components whose trace is empty.
pub const MainClaim = struct {
    log_sizes: [COMPONENT_COUNT]u32,

    pub fn init(log_sizes: [COMPONENT_COUNT]u32) MainClaim {
        return .{ .log_sizes = log_sizes };
    }

    pub fn mixInto(self: *const MainClaim, channel: anytype) void {
        for (self.log_sizes) |log_size| channel.mixU64(@as(u64, log_size));
    }

    pub fn get(self: *const MainClaim, component: Component) u32 {
        return self.log_sizes[@intFromEnum(component)];
    }
};

/// Interaction claim. Claimed sums follow canonical component order. The log
/// sizes follow committed interaction-column order and therefore have a
/// runtime length.
pub const InteractionClaim = struct {
    claimed_sums: [COMPONENT_COUNT]QM31,
    log_sizes: []const u32,

    pub fn init(
        claimed_sums: [COMPONENT_COUNT]QM31,
        log_sizes: []const u32,
    ) InteractionClaim {
        return .{ .claimed_sums = claimed_sums, .log_sizes = log_sizes };
    }

    pub fn mixInto(self: *const InteractionClaim, channel: anytype) void {
        for (self.claimed_sums) |claimed_sum| channel.mixFelts(&.{claimed_sum});
        channel.mixU64(@intCast(self.log_sizes.len));
        for (self.log_sizes) |log_size| channel.mixU64(@as(u64, log_size));
    }

    pub fn total(self: *const InteractionClaim) QM31 {
        var result = QM31.zero();
        for (self.claimed_sums) |claimed_sum| result = result.add(claimed_sum);
        return result;
    }

    pub fn get(self: *const InteractionClaim, component: Component) QM31 {
        return self.claimed_sums[@intFromEnum(component)];
    }
};

test "claim transcript: canonical component order is pinned" {
    try std.testing.expectEqual(@as(usize, 28), COMPONENT_COUNT);
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Component.auipc));
    try std.testing.expectEqual(@as(u8, 15), @intFromEnum(Component.shifts_reg));
    try std.testing.expectEqual(@as(u8, 16), @intFromEnum(Component.fence));
    try std.testing.expectEqual(@as(u8, 17), @intFromEnum(Component.program));
    try std.testing.expectEqual(@as(u8, 21), @intFromEnum(Component.clock_update));
    try std.testing.expectEqual(@as(u8, 27), @intFromEnum(Component.range_check_m31));
}

test "claim transcript: main and interaction mix call boundaries are canonical" {
    const RecordingChannel = struct {
        const Self = @This();
        u64s: [64]u64 = undefined,
        u64_len: usize = 0,
        felts: [COMPONENT_COUNT]QM31 = undefined,
        felt_len: usize = 0,

        fn mixU64(self: *Self, value: u64) void {
            self.u64s[self.u64_len] = value;
            self.u64_len += 1;
        }

        fn mixFelts(self: *Self, values: []const QM31) void {
            std.debug.assert(values.len == 1);
            self.felts[self.felt_len] = values[0];
            self.felt_len += 1;
        }
    };

    var main_sizes: [COMPONENT_COUNT]u32 = undefined;
    for (&main_sizes, 0..) |*value, index| value.* = @intCast(index + 3);
    const main = MainClaim.init(main_sizes);
    var channel = RecordingChannel{};
    main.mixInto(&channel);
    try std.testing.expectEqual(COMPONENT_COUNT, channel.u64_len);
    for (main_sizes, channel.u64s[0..COMPONENT_COUNT]) |expected, actual| {
        try std.testing.expectEqual(@as(u64, expected), actual);
    }

    var sums: [COMPONENT_COUNT]QM31 = undefined;
    for (&sums, 0..) |*value, index| {
        value.* = QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0);
    }
    const interaction = InteractionClaim.init(sums, &.{ 9, 10, 11 });
    interaction.mixInto(&channel);
    try std.testing.expectEqual(COMPONENT_COUNT, channel.felt_len);
    try std.testing.expectEqual(@as(u64, 3), channel.u64s[COMPONENT_COUNT]);
    try std.testing.expectEqualSlices(
        u64,
        &.{ 9, 10, 11 },
        channel.u64s[COMPONENT_COUNT + 1 .. channel.u64_len],
    );
}
