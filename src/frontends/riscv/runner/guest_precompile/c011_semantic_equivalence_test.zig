//! C-011 native-scalar versus profile-labelled CUSTOM-0 semantic corpus.

const std = @import("std");
const runner = @import("../mod.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const reference = @import("c011_scalar_reference_test_support.zig");
const elf_support = @import("c011_elf_test_support.zig");

const Kind = enum {
    zero_ish,
    boundary,
    structured,
    deterministic_random,
    duplicate,
    committed_native_input,
};

const Case = struct {
    label: []const u8,
    kind: Kind,
    state: reference.State,
};

const case_count: usize = 21;

const CommittedInput = struct {
    count: u32,
    state: reference.State,
    sha256_hex: []const u8,
};

// Package-owned transcriptions of vectors/riscv_csp/inputs/field_m31_*.bin.
// The second focused test reconstructs their wire bytes and verifies every
// manifest-pinned SHA-256 digest, so a transcription error fails closed.
const committed_inputs = [_]CommittedInput{
    .{
        .count = 2,
        .state = .{
            348700191, 1277004721, 0, 0, 0, 0, 0, 0,
            0,         0,          0, 0, 0, 0, 0, 0,
        },
        .sha256_hex = "36561ae6b6f918ce2d847d5cd6d703f74d56d06e718d3f49704abae56334bbae",
    },
    .{
        .count = 4,
        .state = .{
            834429925, 141747623, 359126271, 674170884, 0, 0, 0, 0,
            0,         0,         0,         0,         0, 0, 0, 0,
        },
        .sha256_hex = "5ed2b6cb824d90221b830649aed0f260d6c1d1fff6f62f34945e0fca074cc5e3",
    },
    .{
        .count = 8,
        .state = .{
            565731507, 1522483971, 1907666014, 1141255636,
            415882750, 2065249819, 516793793,  1949503411,
            0,         0,          0,          0,
            0,         0,          0,          0,
        },
        .sha256_hex = "0ed2711e85a858614f8c1d74c4914f472f33576e3a4917b874c8fd0794880b33",
    },
    .{
        .count = 12,
        .state = .{
            1812754533, 2072294743, 727573531, 385382302,
            2002250047, 1904635076, 351396630, 2082550055,
            1567172379, 597422518,  540659270, 301140157,
            0,          0,          0,         0,
        },
        .sha256_hex = "2d9e23bba1320ab0a43c5886d6027463b5a60af4aaf13fd35a5bfcacda5d2e65",
    },
    .{
        .count = 16,
        .state = .{
            1822236959, 1529036242, 1938862368, 556756824,
            995887474,  505046931,  1020357435, 1870562181,
            1842932960, 239528071,  320976485,  1942538931,
            335948822,  1332637338, 406081543,  2039127037,
        },
        .sha256_hex = "5cf6b1945ad9c287e4adbf60f9a8a526864a1ae0062387244ea93fca7ca7268e",
    },
};

test "C-011 scalar oracle agrees with explicitly labelled CUSTOM-0 corpus" {
    const cases = try makeCorpus();
    try requireCoverage(&cases);

    var states: [case_count]reference.State = undefined;
    for (cases, &states) |case, *state| {
        for (case.state) |word| try std.testing.expect(word < reference.modulus);
        state.* = case.state;
    }

    var elf = try elf_support.build(std.testing.allocator, &states);
    defer elf.deinit();
    try std.testing.expectEqual(
        execution_profile.ExecutionProfile.rv32im_zkvm_poseidon2_v1,
        try runner.elf_loader.requestedExecutionProfile(elf.bytes),
    );
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.run(std.testing.allocator, elf.bytes, 4 * case_count),
    );

    var result = try runner.runPoseidon2Extension(
        std.testing.allocator,
        elf.bytes,
        4 * case_count,
    );
    defer result.deinit();
    try std.testing.expectEqual(runner.CompletionReason.ecall, result.base.completion_reason);
    try std.testing.expectEqual(2 * case_count + 1, result.base.step_count);
    try std.testing.expectEqual(case_count, result.calls.len());
    try std.testing.expectEqual(case_count, result.execution_rows.rows().len);
    try std.testing.expectEqual(case_count + 1, result.base.execution_trace.rows.items.len);

    for (cases, result.calls.records(), 0..) |case, record, index| {
        const expected = reference.permute(case.state);
        if (!std.mem.eql(u32, &expected, &record.output)) {
            std.debug.print("C-011 mismatch in corpus case {d}: {s}\n", .{ index, case.label });
            return error.TestExpectedEqual;
        }
        try std.testing.expectEqualSlices(u32, &case.state, &record.input);
        try std.testing.expectEqualSlices(u32, &expected, &record.output);
        try std.testing.expectEqual(
            elf_support.state_base + @as(u32, @intCast(index * @sizeOf(reference.State))),
            record.state_ptr,
        );
        try std.testing.expectEqual(@as(u32, @intCast(2 + 2 * index)), record.execution_clock);
        try std.testing.expectEqual(@as(u32, @intCast(0x1004 + 8 * index)), record.pc);

        for (case.state, expected, 0..) |input, output, lane| {
            const address = record.state_ptr + @as(u32, @intCast(4 * lane));
            const word = findWord(result.base.rw_memory.words, address) orelse
                return error.TestExpectedEqual;
            try std.testing.expectEqual(input, word.initial_word);
            try std.testing.expectEqual(output, word.final_word);
        }
    }

    // Duplicate relation values stay duplicated even though their storage
    // addresses and architectural records are distinct.
    try std.testing.expectEqualSlices(u32, &cases[9].state, &cases[14].state);
    try std.testing.expectEqualSlices(
        u32,
        &result.calls.records()[9].output,
        &result.calls.records()[14].output,
    );
    try std.testing.expectEqualSlices(u32, &cases[0].state, &cases[15].state);
    try std.testing.expectEqualSlices(
        u32,
        &result.calls.records()[0].output,
        &result.calls.records()[15].output,
    );
}

test "C-011 committed CSP input transcriptions are canonical and SHA-pinned" {
    var encoded: [4 + 4 * reference.width]u8 = undefined;
    for (committed_inputs) |input| {
        const encoded_len = 4 + 4 * @as(usize, input.count);
        std.mem.writeInt(u32, encoded[0..4], input.count, .little);
        for (input.state[0..input.count], 0..) |word, lane| {
            try std.testing.expect(word < reference.modulus);
            std.mem.writeInt(u32, encoded[4 + 4 * lane ..][0..4], word, .little);
        }
        for (input.state[input.count..]) |word| try std.testing.expectEqual(@as(u32, 0), word);

        var actual_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded[0..encoded_len], &actual_digest, .{});
        var expected_digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_digest, input.sha256_hex);
        try std.testing.expectEqualSlices(u8, &expected_digest, &actual_digest);
    }
}

fn makeCorpus() ![case_count]Case {
    var cases: [case_count]Case = undefined;
    cases[0] = .{ .label = "all-zero", .kind = .zero_ish, .state = filled(0) };
    var lane_zero = filled(0);
    lane_zero[0] = 1;
    cases[1] = .{ .label = "one-in-lane-zero", .kind = .zero_ish, .state = lane_zero };
    var sparse = filled(0);
    sparse[0] = 1;
    sparse[7] = 2;
    sparse[15] = 3;
    cases[2] = .{ .label = "sparse-small", .kind = .zero_ish, .state = sparse };

    cases[3] = .{
        .label = "all-modulus-minus-one",
        .kind = .boundary,
        .state = filled(reference.modulus - 1),
    };
    var alternating: reference.State = undefined;
    var near_modulus: reference.State = undefined;
    for (&alternating, &near_modulus, 0..) |*alternate, *near, lane| {
        alternate.* = if (lane & 1 == 0) 0 else reference.modulus - 1;
        near.* = reference.modulus - 1 - @as(u32, @intCast(lane));
    }
    cases[4] = .{ .label = "alternating-boundaries", .kind = .boundary, .state = alternating };
    cases[5] = .{ .label = "near-modulus", .kind = .boundary, .state = near_modulus };

    var ascending: reference.State = undefined;
    var squares: reference.State = undefined;
    var powers: reference.State = undefined;
    for (&ascending, &squares, &powers, 0..) |*linear, *square, *power, lane| {
        const value: u32 = @intCast(lane);
        linear.* = value;
        square.* = value * value;
        power.* = @as(u32, 1) << @intCast(lane);
    }
    cases[6] = .{ .label = "ascending-lanes", .kind = .structured, .state = ascending };
    cases[7] = .{ .label = "square-lanes", .kind = .structured, .state = squares };
    cases[8] = .{ .label = "power-of-two-lanes", .kind = .structured, .state = powers };

    var seed: u64 = 0x5354_574f_4330_3131;
    const random_labels = [_][]const u8{
        "deterministic-random-0",
        "deterministic-random-1",
        "deterministic-random-2",
        "deterministic-random-3",
        "deterministic-random-4",
    };
    for (random_labels, 0..) |label, index| {
        cases[9 + index] = .{
            .label = label,
            .kind = .deterministic_random,
            .state = randomState(&seed),
        };
    }
    cases[14] = .{ .label = "duplicate-random-0", .kind = .duplicate, .state = cases[9].state };
    cases[15] = .{ .label = "duplicate-zero", .kind = .duplicate, .state = cases[0].state };

    cases[16] = .{
        .label = "committed-csp-2fe-zero-padded",
        .kind = .committed_native_input,
        .state = committed_inputs[0].state,
    };
    cases[17] = .{
        .label = "committed-csp-4fe-zero-padded",
        .kind = .committed_native_input,
        .state = committed_inputs[1].state,
    };
    cases[18] = .{
        .label = "committed-csp-8fe-zero-padded",
        .kind = .committed_native_input,
        .state = committed_inputs[2].state,
    };
    cases[19] = .{
        .label = "committed-csp-12fe-zero-padded",
        .kind = .committed_native_input,
        .state = committed_inputs[3].state,
    };
    cases[20] = .{
        .label = "committed-csp-16fe",
        .kind = .committed_native_input,
        .state = committed_inputs[4].state,
    };
    return cases;
}

fn requireCoverage(cases: []const Case) !void {
    var counts = [_]usize{0} ** 6;
    for (cases) |case| counts[@intFromEnum(case.kind)] += 1;
    try std.testing.expect(counts[@intFromEnum(Kind.zero_ish)] >= 3);
    try std.testing.expect(counts[@intFromEnum(Kind.boundary)] >= 3);
    try std.testing.expect(counts[@intFromEnum(Kind.structured)] >= 3);
    try std.testing.expect(counts[@intFromEnum(Kind.deterministic_random)] >= 5);
    try std.testing.expect(counts[@intFromEnum(Kind.duplicate)] >= 2);
    try std.testing.expect(counts[@intFromEnum(Kind.committed_native_input)] == 5);
}

fn randomState(seed: *u64) reference.State {
    var state: reference.State = undefined;
    for (&state) |*word| word.* = @intCast(splitMix64(seed) % reference.modulus);
    return state;
}

fn splitMix64(seed: *u64) u64 {
    seed.* +%= 0x9e37_79b9_7f4a_7c15;
    var value = seed.*;
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    return value ^ (value >> 31);
}

fn filled(value: u32) reference.State {
    return .{value} ** reference.width;
}

fn findWord(words: []const runner.memory_state.WordState, address: u32) ?runner.memory_state.WordState {
    var low: usize = 0;
    var high = words.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (words[middle].addr < address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low < words.len and words[low].addr == address) return words[low];
    return null;
}
