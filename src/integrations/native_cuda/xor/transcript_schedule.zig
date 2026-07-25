//! Fail-closed Fiat-Shamir order for exact four-tree XOR/LogUp.

const std = @import("std");
const shared = @import("../common/transcript_schedule.zig");
const geometry_mod = @import("geometry.zig");

pub const Operation = shared.Operation;
pub const Boundary = shared.Boundary;

pub const Schedule = struct {
    seed_chain: u64,
    fri_tree_count: u32,
    operation_count: u32,

    pub fn init(geometry: geometry_mod.Geometry) !Schedule {
        var seed = shared.SeedBuilder.init(0x584f_525f_4c4f_4755);
        try seed.mix(geometry.statement.log_size);
        try seed.mix(geometry.statement.log_step);
        try seed.mix(geometry.statement.offset);
        try seed.mix(geometry.protocol.pow_bits);
        try seed.mix(geometry.protocol.fri_config.log_blowup_factor);
        try seed.mix(
            geometry.protocol.fri_config.log_last_layer_degree_bound,
        );
        try seed.mix(geometry.protocol.fri_config.n_queries);
        try seed.mix(geometry.protocol.fri_config.fold_step);
        try seed.mix(
            if (geometry.protocol.lifting_log_size) |value|
                @as(u64, value) + 1
            else
                0,
        );
        try seed.mix(geometry.fri_tree_count);
        const fri_count = std.math.cast(
            u32,
            geometry.fri_tree_count,
        ) orelse return error.GeometryOverflow;
        const operation_count = std.math.add(
            u32,
            16,
            std.math.mul(u32, fri_count, 2) catch
                return error.GeometryOverflow,
        ) catch return error.GeometryOverflow;
        return .{
            .seed_chain = seed.finish(),
            .fri_tree_count = fri_count,
            .operation_count = operation_count,
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return chainAt(self.seed_chain, 0);
    }

    pub fn operation(self: Schedule, step: u32) !Operation {
        if (step >= self.operation_count)
            return error.GeometryOverflow;
        return switch (step) {
            0 => .mix_pcs_config,
            1 => .mix_preprocessed_root,
            2 => .mix_main_root,
            3 => .draw_lookup_elements,
            4 => .mix_interaction_root,
            // The CPU oracle hashes these as three distinct Blake2s
            // absorptions: (log_size, log_step), offset, then claimed_sum.
            5...7 => .mix_statement,
            8 => .draw_composition_alpha,
            9 => .mix_composition_root,
            10 => .draw_oods_point,
            11 => .mix_sampled_values,
            12 => .draw_quotient_alpha,
            else => self.operationAfterQuotient(step),
        };
    }

    pub fn boundary(self: Schedule, step: u32) !Boundary {
        _ = try self.operation(step);
        return .{
            .expected_step = step,
            .expected_chain = chainAt(self.seed_chain, step),
            .next_chain = chainAt(self.seed_chain, step + 1),
        };
    }

    pub fn friTreeCount(self: Schedule) u32 {
        return self.fri_tree_count;
    }

    pub fn operationCount(self: Schedule) u32 {
        return self.operation_count;
    }

    fn operationAfterQuotient(
        self: Schedule,
        step: u32,
    ) Operation {
        const fri_offset = step - 13;
        const fri_operations = self.fri_tree_count * 2;
        if (fri_offset < fri_operations) {
            const tree_index = fri_offset / 2;
            return if (fri_offset % 2 == 0)
                .{ .mix_fri_root = tree_index }
            else
                .{ .draw_fri_alpha = tree_index };
        }
        return switch (fri_offset - fri_operations) {
            0 => .mix_last_layer,
            1 => .absorb_pow,
            2 => .draw_queries,
            else => unreachable,
        };
    }
};

fn chainAt(seed: u64, step: u32) u64 {
    return avalanche(
        seed ^ (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15),
    );
}

fn avalanche(input: u64) u64 {
    var value = input;
    value ^= value >> 30;
    value *%= 0xbf58_476d_1ce4_e5b9;
    value ^= value >> 27;
    value *%= 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    return value;
}

test "XOR schedule binds the complete public statement" {
    const pcs = @import("stwo_core").pcs;
    const first = try Schedule.init(try geometry_mod.admit(
        .{ .log_size = 7, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    ));
    const second = try Schedule.init(try geometry_mod.admit(
        .{ .log_size = 7, .log_step = 3, .offset = 6 },
        pcs.PcsConfig.default(),
    ));
    try std.testing.expectEqual(@as(u32, 30), first.operationCount());
    try std.testing.expectEqual(
        Operation.mix_preprocessed_root,
        try first.operation(1),
    );
    try std.testing.expectEqual(
        Operation.draw_lookup_elements,
        try first.operation(3),
    );
    try std.testing.expectEqual(
        Operation.mix_interaction_root,
        try first.operation(4),
    );
    try std.testing.expectEqual(
        Operation.mix_statement,
        try first.operation(5),
    );
    try std.testing.expectEqual(
        Operation.mix_statement,
        try first.operation(6),
    );
    try std.testing.expectEqual(
        Operation.mix_statement,
        try first.operation(7),
    );
    try std.testing.expectEqual(
        Operation.draw_composition_alpha,
        try first.operation(8),
    );
    try std.testing.expect(first.initialChain() != second.initialChain());
}

test "three resident statement absorptions match the CPU XOR oracle" {
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const statement = [_]u32{ 16, 3, 0x1234_5678, 0xfeed_face };
    const claim = QM31.fromU32Unchecked(3, 5, 7, 11);
    const coordinates = claim.toM31Array();
    const claim_words = [_]u32{
        coordinates[0].toU32(),
        coordinates[1].toU32(),
        coordinates[2].toU32(),
        coordinates[3].toU32(),
    };

    var oracle = Channel{};
    oracle.mixU32s(statement[0..2]);
    oracle.mixU64(
        @as(u64, statement[2]) |
            (@as(u64, statement[3]) << 32),
    );
    oracle.mixFelts(&.{claim});

    var resident = Channel{};
    resident.mixU32s(statement[0..2]);
    resident.mixU32s(statement[2..4]);
    resident.mixU32s(&claim_words);
    try std.testing.expectEqual(
        oracle.digestBytes(),
        resident.digestBytes(),
    );

    var collapsed = Channel{};
    collapsed.mixU32s(&statement ++ claim_words);
    try std.testing.expect(!std.mem.eql(
        u8,
        &oracle.digestBytes(),
        &collapsed.digestBytes(),
    ));
}
