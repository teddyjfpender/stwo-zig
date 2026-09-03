const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const M31 = @import("stwo_core").fields.m31.M31;
const authority_mod = @import("ethereum_incremental_boundary_authority_v4.zig");

const memory_state = frontend.runner.memory_state;
const public_data = frontend.air.public_data;

const input_words = [_]u32{ 0x4433_2211, 0x0000_6655 };
const output_words = [_]public_data.OutputWord{
    .{ .addr = 0x4020, .value = 4, .clock = 5 },
    .{ .addr = 0x4024, .value = 0x8877_6655, .clock = 6 },
};

test "incremental boundary V4 keeps raw Merkle words while deriving memory multiplicity" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV4{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    var transitions: [sources.len]authority_mod.OpenedTransitionV4 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);

    try std.testing.expectEqual(input_words[0], transitions[1].merkle_words.entry);
    try std.testing.expectEqual(input_words[0], transitions[1].merkle_words.exit);
    try std.testing.expect(transitions[1].public_links.input_entry != null);

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV4 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.entry, rows[0].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.exit, rows[1].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.none, rows[2].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.exit, rows[3].memory_multiplicity);
    try std.testing.expectEqual(input_words[0], rows[2].word);
    try std.testing.expectEqual(input_words[0], rows[3].word);
    try std.testing.expectEqual(@as(u32, 11), rows[2].root);
    try std.testing.expectEqual(@as(u32, 21), rows[3].root);
}

test "incremental boundary V4 authenticates final output and completion links" {
    const data = fixturePublicData();
    const authority = lastAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV4{
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
    var transitions: [sources.len]authority_mod.OpenedTransitionV4 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);
    try std.testing.expect(transitions[1].public_links.output_exit != null);
    try std.testing.expect(transitions[3].public_links.completion_exit != null);

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV4 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.entry, rows[2].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.none, rows[3].memory_multiplicity);
    try std.testing.expectEqual(output_words[0].value, rows[3].word);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.none, rows[7].memory_multiplicity);
}

test "incremental boundary V4 rejects role segment and completion drift" {
    var data = fixturePublicData();
    const authority = firstAuthority(&data);
    var sources = [_]authority_mod.WordBoundarySourceV4{
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
    const last_sources = [_]authority_mod.WordBoundarySourceV4{
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

test "incremental boundary V4 admits untouched public input and rejects clock drift" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const missing_input = [_]authority_mod.WordBoundarySourceV4{
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
    const otherwise_complete = [_]authority_mod.WordBoundarySourceV4{
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
    const invalid_value = [_]authority_mod.WordBoundarySourceV4{
        value_without_access,
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    try std.testing.expectError(
        error.ValueChangedWithoutAccess,
        authority_mod.validateInventory(authority, &invalid_value),
    );

    const untouched_input = inputSource(0x4010, input_words[0], 0);
    const complete_with_untouched_input = [_]authority_mod.WordBoundarySourceV4{
        ordinarySource(),
        untouched_input,
        inputSource(0x4014, input_words[1], 3),
    };
    try authority_mod.validateInventory(authority, &complete_with_untouched_input);
    var transitions: [complete_with_untouched_input.len]authority_mod.OpenedTransitionV4 = undefined;
    try authority_mod.writeOpenedTransitions(
        authority,
        &complete_with_untouched_input,
        &transitions,
    );
    var rows: [complete_with_untouched_input.len * 2]authority_mod.BoundaryRowContractV4 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.none, rows[2].memory_multiplicity);
    try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.exit, rows[3].memory_multiplicity);
    try std.testing.expectEqual(@as(u32, 0), rows[3].clock);
    try std.testing.expectEqual(input_words[0], rows[3].word);

    var changed_without_access = untouched_input;
    changed_without_access.word.final_word ^= 1;
    const invalid_public = [_]authority_mod.WordBoundarySourceV4{
        ordinarySource(),
        changed_without_access,
        inputSource(0x4014, input_words[1], 3),
    };
    try std.testing.expectError(
        error.ValueChangedWithoutAccess,
        authority_mod.validateInventory(authority, &invalid_public),
    );
}

test "incremental boundary V4 rejects caller-mutated policy and multiplicity" {
    const data = fixturePublicData();
    const authority = firstAuthority(&data);
    const sources = [_]authority_mod.WordBoundarySourceV4{
        ordinarySource(),
        inputSource(0x4010, input_words[0], 2),
        inputSource(0x4014, input_words[1], 3),
    };
    var transitions: [sources.len]authority_mod.OpenedTransitionV4 = undefined;
    try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);

    transitions[0].coordinate.segment_count += 1;
    try std.testing.expectError(
        error.TransitionCoordinateMismatch,
        transitions[0].validateAgainst(authority),
    );
    transitions[0].coordinate = authority.coordinate;

    var rows: [sources.len * 2]authority_mod.BoundaryRowContractV4 = undefined;
    try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
    rows[2].memory_multiplicity = .entry;
    try std.testing.expectError(
        error.BoundaryRowMismatch,
        rows[2].validateAgainst(authority, transitions[1]),
    );
}

test "incremental boundary V4 rejects layout and full-root drift" {
    const data = fixturePublicData();
    var authority = firstAuthority(&data);
    authority.layout.input_base += 4;
    try std.testing.expectError(error.InvalidMemoryLayout, authority.validate());

    authority = firstAuthority(&data);
    authority.continuation_roots.exit ^= 1;
    try std.testing.expectError(error.FullStateRootMismatch, authority.validate());
}

test "policy 2 untouched public input closes public LogUp without an opcode row" {
    const relations = frontend.air.relation_challenges.Relations.dummy();
    const values = [_]u32{ 0, 0x4433_2211 };
    for (values) |value| {
        const one_input = [_]u32{value};
        var data = fixturePublicData();
        data.completion = public_data.Completion.canonicalSelfLoop(data.final_pc);
        data.io_entries.input_len = 4;
        data.io_entries.input_words = &one_input;
        data.io_entries.output_len = 0;
        data.io_entries.output_words = &.{};
        try data.validate();

        const source = inputSource(data.io_entries.input_start, value, 0);
        const authority = firstAuthority(&data);
        const sources = [_]authority_mod.WordBoundarySourceV4{source};
        var transitions: [1]authority_mod.OpenedTransitionV4 = undefined;
        try authority_mod.writeOpenedTransitions(authority, &sources, &transitions);
        var rows: [2]authority_mod.BoundaryRowContractV4 = undefined;
        try authority_mod.writeBoundaryRows(authority, &transitions, &rows);
        try std.testing.expectEqual(authority_mod.MemoryMultiplicityV4.exit, rows[1].memory_multiplicity);
        try std.testing.expectEqual(@as(u32, 0), rows[1].clock);

        const public_sum = try frontend.air.public_logup.publicIoMemoryAccessSum(
            &data,
            &relations,
        );
        const denominator = relations.memory_access.combineBase(memoryTuple(rows[1]));
        const exit_sum = try denominator.inv();
        try std.testing.expect(public_sum.sub(exit_sum).isZero());
    }
}

test "legacy WordState golden still suppresses untouched public-input final row" {
    const legacy_word = memory_state.WordState{
        .addr = 0x4010,
        .initial_word = 0,
        .final_word = 0,
        .final_clock = 0,
        .role = .{ .is_public_input = true },
    };
    try std.testing.expect(!legacy_word.includeInitial());
    try std.testing.expect(!legacy_word.includeFinal());

    var claims = try frontend.air.memory_commitment.boundary.build(
        std.testing.allocator,
        &.{legacy_word},
    );
    defer claims.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), claims.rows.len);
    try std.testing.expect(claims.initial_tree == null);
    try std.testing.expect(claims.final_tree == null);

    var untyped_word = legacy_word;
    untyped_word.role = .{};
    const typed_entry = frontend.recursion.segment_statement_v2.snapshotIdentity(
        &.{legacy_word},
        .initial_word,
    );
    const untyped_entry = frontend.recursion.segment_statement_v2.snapshotIdentity(
        &.{untyped_word},
        .initial_word,
    );
    const typed_exit = frontend.recursion.segment_statement_v2.snapshotIdentity(
        &.{legacy_word},
        .final_word,
    );
    const untyped_exit = frontend.recursion.segment_statement_v2.snapshotIdentity(
        &.{untyped_word},
        .final_word,
    );
    try std.testing.expect(std.meta.eql(typed_entry, untyped_entry));
    try std.testing.expect(std.meta.eql(typed_exit, untyped_exit));
}

test "validated V4 authority scans a large input inventory exactly once" {
    const allocator = std.testing.allocator;
    const input_word_count: usize = 16 * 1024;
    const words = try allocator.alloc(u32, input_word_count);
    defer allocator.free(words);
    @memset(words, 0);
    const sources = try allocator.alloc(
        authority_mod.WordBoundarySourceV4,
        input_word_count,
    );
    defer allocator.free(sources);

    const input_start: u32 = 0x0001_0000;
    const input_byte_count: u32 = @intCast(input_word_count * 4);
    for (sources, 0..) |*source, index| {
        source.* = inputSource(
            input_start + @as(u32, @intCast(index * 4)),
            0,
            0,
        );
    }
    const output_len_addr = input_start + input_byte_count;
    const output_data_addr = output_len_addr + 4;
    const data = public_data.PublicData{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = [_]u32{0} ** 32,
        .final_regs = [_]u32{0} ** 32,
        .reg_last_clock = [_]u32{0} ** 32,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = input_start,
            .input_len = input_byte_count,
            .input_words = words,
            .output_len = 0,
            .output_len_addr = output_len_addr,
            .output_data_addr = output_data_addr,
            .output_words = &.{},
        },
    };
    const authority = authority_mod.SegmentPublicAuthorityV4{
        .coordinate = .{ .segment_index = 0, .segment_count = 2 },
        .segment_role = .{ .is_first = true, .is_last = false },
        .layout = .{
            .program_base = 0x1000,
            .program_end = 0x2000,
            .data_base = input_start,
            .data_end = output_data_addr + 4,
            .stack_bottom = 0x0003_0000,
            .stack_top = 0x0004_0000,
            .io_base = input_start,
            .io_end = output_data_addr + 4,
            .input_base = input_start,
            .input_end = output_len_addr,
            .output_len_addr = output_len_addr,
            .output_data_addr = output_data_addr,
            .output_base = output_len_addr,
            .output_end = output_data_addr + 4,
        },
        .public_data = &data,
        .continuation_roots = .{ .entry = 11, .exit = 21 },
    };

    authority_mod.testing.resetValidationCallCount();
    const validated = try authority_mod.ValidatedSegmentPublicAuthorityV4.init(
        authority,
    );
    try validated.validateInventory(sources);
    try std.testing.expect((try validated.expectedRole(
        input_start + input_byte_count - 4,
    )).is_public_input);
    try std.testing.expectEqual(
        @as(?u32, 0),
        validated.publicInputWord(input_start + input_byte_count - 4),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        authority_mod.testing.validationCallCount(),
    );
}

fn memoryTuple(row: authority_mod.BoundaryRowContractV4) [7]M31 {
    return .{
        M31.one(),
        M31.fromU64(row.address),
        M31.fromU64(row.clock),
        M31.fromU64(@as(u8, @truncate(row.word))),
        M31.fromU64(@as(u8, @truncate(row.word >> 8))),
        M31.fromU64(@as(u8, @truncate(row.word >> 16))),
        M31.fromU64(@as(u8, @truncate(row.word >> 24))),
    };
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

fn firstAuthority(data: *const public_data.PublicData) authority_mod.SegmentPublicAuthorityV4 {
    return .{
        .coordinate = .{ .segment_index = 0, .segment_count = 3 },
        .segment_role = .{ .is_first = true, .is_last = false },
        .layout = fixtureLayout(),
        .public_data = data,
        .continuation_roots = .{ .entry = 11, .exit = 21 },
    };
}

fn lastAuthority(data: *const public_data.PublicData) authority_mod.SegmentPublicAuthorityV4 {
    return .{
        .coordinate = .{ .segment_index = 2, .segment_count = 3 },
        .segment_role = .{ .is_first = false, .is_last = true },
        .layout = fixtureLayout(),
        .public_data = data,
        .continuation_roots = .{ .entry = 11, .exit = 21 },
    };
}

fn ordinarySource() authority_mod.WordBoundarySourceV4 {
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

fn inputSource(address: u32, value: u32, final_clock: u32) authority_mod.WordBoundarySourceV4 {
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

fn outputSource(word: public_data.OutputWord, entry_clock: u32) authority_mod.WordBoundarySourceV4 {
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

fn completionSource(entry_clock: u32) authority_mod.WordBoundarySourceV4 {
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
