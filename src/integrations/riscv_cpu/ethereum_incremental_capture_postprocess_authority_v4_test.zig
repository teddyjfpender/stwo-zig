const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const leaf_support = @import("ethereum_block_leaf_support.zig");
const support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

test "nonfinal role completion is exact admitted ELF CUSTOM-0 fetch" {
    const custom_word = frontend.isa.custom0.encodeKeccakf(5);
    const words = [_]frontend.runner.minimal_trace.ProgramWord{
        .{ .address = 0x1000, .word = 0x0000_0013 },
        .{ .address = 0x1004, .word = custom_word },
        .{ .address = 0x1008, .word = 0x0000_006f },
    };
    const program = try subject.ProgramSourceV4.init(&words);
    const completion = try subject.deriveRoleCompletionV4(
        program,
        0,
        2,
        0x1004,
        null,
    );
    try std.testing.expectEqual(
        frontend.air.public_data.CompletionKind.unretired_program_fetch,
        completion.kind,
    );
    try std.testing.expectEqual(@as(u32, 0x1004), completion.address);
    try std.testing.expectEqual(custom_word, completion.value);
    try std.testing.expectEqual(@as(u32, 0), completion.clock);

    const retained = frontend.air.public_data.Completion.canonicalSelfLoop(
        0x1008,
    );
    try std.testing.expectEqualDeep(
        retained,
        try subject.deriveRoleCompletionV4(
            program,
            1,
            2,
            0x1008,
            retained,
        ),
    );
}

test "program fetch authority rejects mutation missing PC and role drift" {
    var words = [_]frontend.runner.minimal_trace.ProgramWord{
        .{ .address = 0x1000, .word = 0x0000_0013 },
        .{ .address = 0x1004, .word = frontend.isa.custom0.encodeKeccakf(5) },
    };
    const program = try subject.ProgramSourceV4.init(&words);
    try std.testing.expectError(
        error.ProgramWordUnavailable,
        subject.deriveRoleCompletionV4(program, 0, 2, 0x1008, null),
    );
    try std.testing.expectError(
        error.IncrementalPostprocessSegmentRoleMismatchV4,
        subject.deriveRoleCompletionV4(
            program,
            0,
            2,
            0x1004,
            frontend.air.public_data.Completion.canonicalSelfLoop(0x1004),
        ),
    );
    words[1].word ^= 0x0000_0080;
    try std.testing.expectError(
        error.IncrementalPostprocessProgramSourceMismatchV4,
        program.validate(),
    );
    try std.testing.expectError(
        error.IncrementalPostprocessProgramSourceMismatchV4,
        subject.deriveRoleCompletionV4(program, 0, 2, 0x1004, null),
    );
}

test "path-free mint input rejects byte identity drift before decoding" {
    const fixture = try support.Fixture.init();
    const retained_source = retainedSource(fixture.leftSource());
    const elf = "not-an-elf";
    const input = "input";
    const output = "output";
    const compact = "not-a-compact-artifact";
    const wire = "not-a-public-wire";
    const expected = execution(elf, input, output);

    var wrong_elf = expected;
    wrong_elf.elf = identity("different-elf");
    try expectIdentityMismatch(
        wrong_elf,
        elf,
        input,
        output,
        &retained_source,
        compact,
        wire,
    );
    var wrong_input = expected;
    wrong_input.input = identity("different-input");
    try expectIdentityMismatch(
        wrong_input,
        elf,
        input,
        output,
        &retained_source,
        compact,
        wire,
    );
    var wrong_output = expected;
    wrong_output.expected_output = identity("different-output");
    try expectIdentityMismatch(
        wrong_output,
        elf,
        input,
        output,
        &retained_source,
        compact,
        wire,
    );
    var wrong_profile = expected;
    wrong_profile.execution_profile_semantic_sha256[0] ^= 1;
    try expectIdentityMismatch(
        wrong_profile,
        elf,
        input,
        output,
        &retained_source,
        compact,
        wire,
    );
    var wrong_count = expected;
    wrong_count.segment_count = 3;
    try expectIdentityMismatch(
        wrong_count,
        elf,
        input,
        output,
        &retained_source,
        compact,
        wire,
    );
}

test "path-free mint input API has no filesystem parameter" {
    comptime {
        if (!@hasDecl(subject.OwnedMintInputV4, "openCanonicalBytes"))
            @compileError("path-free V4 mint admission disappeared");
        _ = typecheckPathFree;
    }
    try std.testing.expect(!subject.PRODUCTION_ACTIVE);
    try std.testing.expect(!subject.VM_REEXECUTION_REQUIRED);
    try std.testing.expect(subject.RETAINED_ROOT_REUSE_REQUIRED);
}

fn typecheckPathFree(
    allocator: std.mem.Allocator,
    execution_authority: publication.ExecutionAuthorityV4,
    source: *const leaf_support.source_wire.Source,
    elf: []const u8,
    input: []const u8,
    output: []const u8,
    compact: []const u8,
    wire: []const u8,
) !void {
    var owned = try subject.OwnedMintInputV4.openCanonicalBytes(
        allocator,
        execution_authority,
        elf,
        input,
        output,
        source,
        compact,
        wire,
    );
    defer owned.deinit();
}

fn expectIdentityMismatch(
    execution_authority: publication.ExecutionAuthorityV4,
    elf: []const u8,
    input: []const u8,
    output: []const u8,
    source: *const leaf_support.source_wire.Source,
    compact: []const u8,
    wire: []const u8,
) !void {
    try std.testing.expectError(
        error.IncrementalPostprocessCanonicalBytesMismatchV4,
        subject.OwnedMintInputV4.openCanonicalBytes(
            std.testing.allocator,
            execution_authority,
            elf,
            input,
            output,
            source,
            compact,
            wire,
        ),
    );
}

fn execution(
    elf: []const u8,
    input: []const u8,
    output: []const u8,
) publication.ExecutionAuthorityV4 {
    return .{
        .elf = identity(elf),
        .input = identity(input),
        .expected_output = identity(output),
        .execution_profile_semantic_sha256 = frontend.isa.execution_profile
            .ethereum_semantic_digest,
        .segment_count = 2,
        .segment_step_budget = 100,
    };
}

fn identity(bytes: []const u8) publication.ArtifactIdentityV4 {
    return publication.ArtifactIdentityV4.fromBytes(bytes);
}

fn retainedSource(
    source: frontend.recursion.segment_statement_v2.SourceV2,
) leaf_support.source_wire.Source {
    const statement = source.statement() catch unreachable;
    const base = source.base_statement.canonicalWords() catch unreachable;
    return .{
        .journal_record_sha256 = [_]u8{9} ** 32,
        .metadata = .{
            .base_statement_words = base,
            .segment_index = source.segment_index,
            .segment_count = source.base_statement.job.segment_count,
            .global_cycle_start = 0,
            .global_cycle_end = @intCast(source.cycle_count),
            .local_cycle_count = @intCast(source.cycle_count),
            .entry = .{
                .snapshot_id = statement.entry_snapshot_id,
                .snapshot_count = statement.entry_snapshot_count,
                .continuation_root = statement.entry_continuation_root,
                .register_clocks = statement.entry_register_clocks,
                .memory_clock_id = statement.entry_memory_clock_id,
                .memory_clock_count = statement.entry_memory_clock_count,
            },
            .exit = .{
                .snapshot_id = statement.exit_snapshot_id,
                .snapshot_count = statement.exit_snapshot_count,
                .continuation_root = statement.exit_continuation_root,
                .register_clocks = statement.exit_register_clocks,
                .memory_clock_id = statement.exit_memory_clock_id,
                .memory_clock_count = statement.exit_memory_clock_count,
            },
            .completion = statement.completion,
        },
    };
}
