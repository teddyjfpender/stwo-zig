const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const authority_mod = @import("ethereum_incremental_boundary_authority_v3.zig");
const readiness_mod = @import("incremental_native_profile_readiness_v3.zig");

const memory_state = frontend.runner.memory_state;
const public_data = frontend.air.public_data;

const input_words = [_]u32{ 0x4433_2211, 0x0000_6655 };
const output_words = [_]public_data.OutputWord{
    .{ .addr = 0x4020, .value = 4, .clock = 5 },
    .{ .addr = 0x4024, .value = 0x8877_6655, .clock = 6 },
};

test "incremental boundary V3 keeps raw Merkle words while deriving memory multiplicity" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV3{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    var transitions: [sources.len]authority_mod.OpenedTransitionV3 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);

    try std.testing.expectEqual(input_words[0], transitions[1].merkle_words.entry);
    try std.testing.expectEqual(input_words[0], transitions[1].merkle_words.exit);
    try std.testing.expect(transitions[1].public_links.input_entry != null);

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV3 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.entry, rows[0].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.exit, rows[1].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.none, rows[2].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.exit, rows[3].memory_multiplicity);
    try std.testing.expectEqual(input_words[0], rows[2].word);
    try std.testing.expectEqual(input_words[0], rows[3].word);
    try std.testing.expectEqual(@as(u32, 11), rows[2].root);
    try std.testing.expectEqual(@as(u32, 21), rows[3].root);
}

test "incremental boundary V3 authenticates final output and completion links" {
    const data = fixturePublicData();
    const authority = lastAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV3{
        .{
            .word = .{
                .addr = 0x3000,
                .initial_word = 7,
                .final_word = 9,
                .final_clock = 9,
            },
            .entry_clock = 3,
        },
        outputSource(output_words[0], 2),
        outputSource(output_words[1], 3),
        completionSource(5),
    };
    var transitions: [sources.len]authority_mod.OpenedTransitionV3 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);
    try std.testing.expect(transitions[1].public_links.output_exit != null);
    try std.testing.expect(transitions[3].public_links.completion_exit != null);

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV3 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.entry, rows[2].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.none, rows[3].memory_multiplicity);
    try std.testing.expectEqual(output_words[0].value, rows[3].word);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV3.none, rows[7].memory_multiplicity);
}

test "incremental boundary V3 rejects role segment and completion drift" {
    var data = fixturePublicData();
    const authority = firstAuthority(&data);
    var sources = [_]authority_mod.WordBoundarySourceV3{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    sources[1].word.role = .{};
    try std.testing.expectError(
        error.PublicRoleMismatch,
        authority_mod.validateInventory(authority, &sources),
    );
    sources[1] = inputSource(0x4010, input_words[0], 2);

    var bad_position = authority;
    bad_position.coordinate.segment_index = 1;
    try std.testing.expectError(
        error.InvalidSegmentRole,
        authority_mod.validateInventory(bad_position, &sources),
    );

    const last = lastAuthority(&data);
    const last_sources = [_]authority_mod.WordBoundarySourceV3{
        outputSource(output_words[0], 2),
        outputSource(output_words[1], 3),
        completionSource(4),
    };
    data.completion.?.address = 0x4044;
    try std.testing.expectError(
        error.PublicRoleMismatch,
        authority_mod.validateInventory(last, &last_sources),
    );
}

test "incremental boundary V3 rejects inventory and clock mutations" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const missing_input = [_]authority_mod.WordBoundarySourceV3{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
    };
    try std.testing.expectError(
        error.InputWordMissing,
        authority_mod.validateInventory(authority, &missing_input),
    );

    var unaccessed = ordinarySource();
    unaccessed.entry_clock = unaccessed.word.final_clock;
    unaccessed.word.final_word = unaccessed.word.initial_word;
    const otherwise_complete = [_]authority_mod.WordBoundarySourceV3{
        unaccessed,
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    try std.testing.expectError(
        error.OpenedInventoryMismatch,
        authority_mod.validateInventory(authority, &otherwise_complete),
    );

    var value_without_access = ordinarySource();
    value_without_access.entry_clock = value_without_access.word.final_clock;
    const invalid_value = [_]authority_mod.WordBoundarySourceV3{
        value_without_access,
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    try std.testing.expectError(
        error.ValueChangedWithoutAccess,
        authority_mod.validateInventory(authority, &invalid_value),
    );

    var unclosed_input = inputSource(0x4010, input_words[0], 0);
    unclosed_input.word.final_clock = 0;
    const invalid_public = [_]authority_mod.WordBoundarySourceV3{
        ordinarySource(),
        unclosed_input,
        inputSource(0x4014, input_words[1], 3),
    };
    try std.testing.expectError(
        error.UnclosedPublicInput,
        authority_mod.validateInventory(authority, &invalid_public),
    );
}

test "incremental boundary V3 rejects caller-mutated policy and multiplicity" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV3{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    var transitions: [sources.len]authority_mod.OpenedTransitionV3 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);

    transitions[0].coordinate.segment_count += 1;
    try std.testing.expectError(
        error.TransitionCoordinateMismatch,
        transitions[0].validateAgainst(authority),
    );
    transitions[0].coordinate = authority.coordinate;

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV3 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    rows[2].memory_multiplicity = .entry;
    try std.testing.expectError(
        error.BoundaryRowMismatch,
        rows[2].validateAgainst(authority, transitions[1]),
    );
}

test "incremental boundary V3 rejects layout and full-root drift" {
    const data = fixturePublicData();
    var authority = firstAuthority(&data);
    authority.layout.input_base += 4;
    try std.testing.expectError(error.InvalidMemoryLayout, authority.validate());

    authority = firstAuthority(&data);
    authority.continuation_roots.exit ^= 1;
    try std.testing.expectError(error.FullStateRootMismatch, authority.validate());
}

test "incremental native profile readiness is immutable and fail closed" {
    const readiness = readiness_mod.current();
    try readiness.validateCurrent();
    try std.testing.expect(!readiness_mod.PRODUCTION_ACTIVE);
    try std.testing.expectError(
        error.NativeIncrementalProfileUnavailable,
        readiness.requireNativeProofAdmission(),
    );

    var missing: [readiness_mod.ALL_MISSING.len]readiness_mod.MissingAuthorityV3 = undefined;
    const count = try readiness.missingAuthorities(&missing);
    try std.testing.expectEqual(readiness_mod.ALL_MISSING.len, count);
    try std.testing.expectEqualSlices(
        readiness_mod.MissingAuthorityV3,
        &readiness_mod.ALL_MISSING,
        &missing,
    );

    var forged = readiness;
    forged.split_boundary_air = .structural_contract_only;
    try std.testing.expectError(error.ReadinessContractDrift, forged.validateCurrent());
    forged = readiness;
    forged.cold_verifier_capture = .structural_contract_only;
    try std.testing.expectError(error.ReadinessContractDrift, forged.validateCurrent());
}

fn fixturePublicData() public_data.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 3;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = .{
            .kind = .halt_flag,
            .address = 0x4040,
            .value = 1,
            .clock = 7,
        },
        .io_entries = .{
            .input_start = 0x4010,
            .input_len = 6,
            .input_words = &input_words,
            .output_len = 4,
            .output_len_addr = 0x4020,
            .output_data_addr = 0x4024,
            .output_words = &output_words,
        },
    };
}

fn fixtureLayout() memory_state.MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x3100,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x4000,
        .io_end = 0x4100,
        .input_base = 0x4010,
        .input_end = 0x4018,
        .output_len_addr = 0x4020,
        .output_data_addr = 0x4024,
        .output_base = 0x4020,
        .output_end = 0x4100,
    };
}

fn firstAuthority(data: *const public_data.PublicData) authority_mod.SegmentPublicAuthorityV3 {
    return .{
        .coordinate = .{ .segment_index = 0, .segment_count = 3 },
        .segment_role = .{ .is_first = true, .is_last = false },
        .layout = fixtureLayout(),
        .public_data = data,
        .continuation_roots = .{ .entry = 11, .exit = 21 },
    };
}

fn lastAuthority(data: *const public_data.PublicData) authority_mod.SegmentPublicAuthorityV3 {
    return .{
        .coordinate = .{ .segment_index = 2, .segment_count = 3 },
        .segment_role = .{ .is_first = false, .is_last = true },
        .layout = fixtureLayout(),
        .public_data = data,
        .continuation_roots = .{ .entry = 11, .exit = 21 },
    };
}

fn ordinarySource() authority_mod.WordBoundarySourceV3 {
    return .{
        .word = .{
            .addr = 0x3000,
            .initial_word = 7,
            .final_word = 9,
            .final_clock = 5,
        },
        .entry_clock = 1,
    };
}

fn inputSource(address: u32, value: u32, final_clock: u32) authority_mod.WordBoundarySourceV3 {
    return .{
        .word = .{
            .addr = address,
            .initial_word = value,
            .final_word = value,
            .final_clock = final_clock,
            .role = .{ .is_public_input = true },
        },
        .entry_clock = 0,
    };
}

fn outputSource(word: public_data.OutputWord, entry_clock: u32) authority_mod.WordBoundarySourceV3 {
    return .{
        .word = .{
            .addr = word.addr,
            .initial_word = 0,
            .final_word = word.value,
            .final_clock = word.clock,
            .role = .{ .is_public_output = true },
        },
        .entry_clock = entry_clock,
    };
}

fn completionSource(entry_clock: u32) authority_mod.WordBoundarySourceV3 {
    return .{
        .word = .{
            .addr = 0x4040,
            .initial_word = 0,
            .final_word = 1,
            .final_clock = 7,
            .role = .{ .is_public_completion = true },
        },
        .entry_clock = entry_clock,
    };
}
