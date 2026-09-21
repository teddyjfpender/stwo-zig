const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const producer =
    @import("ethereum_incremental_full_leaf_replay_producer_v4.zig");

comptime {
    _ = @import("ethereum_incremental_full_leaf_validated_authority_v4_test.zig");
}

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

test "VM-free incremental full-leaf producer API type instantiates" {
    std.testing.refAllDecls(producer.ProgramV4);
    std.testing.refAllDecls(producer.ReplayAuthorityV4);
    std.testing.refAllDecls(producer.ColdInputV4);
    try std.testing.expect(!producer.PRODUCTION_ACTIVE);
    try std.testing.expectEqual(@as(u16, 4), producer.FORMAT_VERSION);

    // Enter the specialized generic and stop on the value-only authority
    // before any borrowed pointer is observed. Runtime proof coverage is the
    // separately retained q193 full-leaf gate.
    const invalid = producer.ColdInputV4{
        .compact = undefined,
        .public_wire = undefined,
        .role_aware_public = undefined,
        .public_authority = undefined,
        .boundary = undefined,
        .program = undefined,
        .replay_authority = .{
            .source = .{
                .program = .{0} ** 32,
                .input = .{0} ** 32,
                .session = .{0} ** 32,
                .entry_memory = .{0} ** 32,
                .exit_memory = .{0} ** 32,
            },
            .global_first_cycle = 0,
            .entry_cpu_sha256 = .{0} ** 32,
            .exit_cpu_sha256 = .{0} ** 32,
            .completion = null,
        },
    };
    try std.testing.expectError(
        error.MissingSourceIdentity,
        producer.produceAlloc(
            Engine,
            std.testing.allocator,
            invalid,
            .{},
            .{},
        ),
    );
}

test "leaf-local completion consumes the actual declared program word" {
    var minimal_words = [_]frontend.runner.minimal_trace.ProgramWord{
        .{ .address = 0x1000, .word = 0x0010_0093 },
        .{ .address = 0x1004, .word = 0x0020_0113 },
    };
    var statement_words = [_]frontend.runner.memory_state.WordState{
        .{
            .addr = 0x1000,
            .initial_word = minimal_words[0].word,
            .final_word = minimal_words[0].word,
            .final_clock = 0,
        },
        .{
            .addr = 0x1004,
            .initial_word = minimal_words[1].word,
            .final_word = minimal_words[1].word,
            .final_clock = 0,
        },
    };
    const raw_second = minimal_words[1].word;
    const program = producer.ProgramV4{
        .allocator = std.testing.allocator,
        .layout = undefined,
        .minimal_words = &minimal_words,
        .statement_words = &statement_words,
        .program = try frontend.runner.minimal_trace.SliceProgram.init(
            &minimal_words,
        ),
    };
    const completion = try program.completionForProof(
        .{ .is_first = false, .is_last = false },
        frontend.air.public_data.Completion.canonicalSelfLoop(0x1004),
    );
    try std.testing.expectEqual(
        frontend.air.public_data.CompletionKind.unretired_program_fetch,
        completion.kind,
    );
    try std.testing.expectEqual(raw_second, completion.value);
    const already_derived = try program.completionForProof(
        .{ .is_first = false, .is_last = false },
        completion,
    );
    try std.testing.expectEqualDeep(completion, already_derived);
    var snapshot = try program.snapshotForCompletion(
        std.testing.allocator,
        .{ .is_first = false, .is_last = false },
        completion,
    );
    defer snapshot.deinit();
    try std.testing.expectEqual(
        raw_second,
        snapshot.program_words[1].initial_word,
    );
    try std.testing.expectEqual(raw_second, program.minimal_words[1].word);
    try std.testing.expectEqual(raw_second, program.statement_words[1].initial_word);
    try std.testing.expectError(
        error.InvalidIncrementalLeafCompletionProgramV4,
        program.snapshotForCompletion(
            std.testing.allocator,
            .{ .is_first = false, .is_last = false },
            frontend.air.public_data.Completion.canonicalSelfLoop(0x1004),
        ),
    );
    try std.testing.expectError(
        error.InvalidIncrementalLeafCompletionProgramV4,
        program.completionForProof(
            .{ .is_first = false, .is_last = false },
            frontend.air.public_data.Completion.canonicalSelfLoop(0x1008),
        ),
    );
    var wrong_word = completion;
    wrong_word.value +%= 1;
    try std.testing.expectError(
        error.InvalidIncrementalLeafCompletionProgramV4,
        program.completionForProof(
            .{ .is_first = false, .is_last = false },
            wrong_word,
        ),
    );
}
