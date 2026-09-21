//! Focused mutation matrix for Ethereum SegmentV2 admission.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const segment_v2 = frontend.recursion.segment_statement_v2;

pub fn assertBoundaries(
    allocator: std.mem.Allocator,
    output: anytype,
    source: *const segment_v2.SourceV2,
    words: []M31,
) !void {
    const admission = frontend.air.guest_precompile.ethereum_proof_admission;
    try admission.validateV2(&output.statement, &output.extension, .proof);
    var v1_rejected = false;
    admission.validate(
        &output.statement.core,
        &output.extension,
        .proof,
    ) catch {
        v1_rejected = true;
    };
    try std.testing.expect(v1_rejected);

    var wrong_terms = output.extension;
    wrong_terms.admission.memory_relation_terms += 1;
    try std.testing.expectError(
        error.AdmissionCertificateMismatch,
        admission.validateV2(&output.statement, &wrong_terms, .proof),
    );

    if (source.memory_words.len != 0 and
        source.exit_memory_clocks.len != 0)
    {
        try rejectStalePublicTermAuthority(allocator, output, source);
    }

    var wrong_clock = output.statement;
    wrong_clock.core.public_data.clock += 1;
    try std.testing.expectError(
        error.InvalidSegmentV2Boundary,
        admission.validateV2(&wrong_clock, &output.extension, .proof),
    );

    var wrong_completion = output.statement;
    wrong_completion.core.public_data.completion =
        frontend.air.public_data.Completion.canonicalSelfLoop(
            wrong_completion.core.public_data.final_pc,
        );
    try std.testing.expectError(
        error.InvalidSegmentV2Boundary,
        admission.validateV2(
            &wrong_completion,
            &output.extension,
            .proof,
        ),
    );

    {
        const original = words[0];
        defer words[0] = original;
        words[0] = words[0].add(M31.one());
        try std.testing.expectError(
            error.InvalidSegmentV2Boundary,
            admission.validateV2(&output.statement, &output.extension, .proof),
        );
    }
}

fn rejectStalePublicTermAuthority(
    allocator: std.mem.Allocator,
    output: anytype,
    source: *const segment_v2.SourceV2,
) !void {
    const Word = @TypeOf(source.memory_words[0]);
    const Clock = @TypeOf(source.exit_memory_clocks[0]);
    const changed_words = try allocator.alloc(Word, source.memory_words.len + 1);
    defer allocator.free(changed_words);
    @memcpy(changed_words[0..source.memory_words.len], source.memory_words);
    const changed_clocks = try allocator.alloc(
        Clock,
        source.exit_memory_clocks.len + 1,
    );
    defer allocator.free(changed_clocks);
    @memcpy(
        changed_clocks[0..source.exit_memory_clocks.len],
        source.exit_memory_clocks,
    );
    const address = try std.math.add(
        u32,
        source.memory_words[source.memory_words.len - 1].addr,
        4,
    );
    const clock = source.exit_memory_clocks[
        source.exit_memory_clocks.len - 1
    ].clock;
    changed_words[changed_words.len - 1] = .{
        .addr = address,
        .initial_word = 0,
        .final_word = 0,
        .final_clock = clock,
    };
    changed_clocks[changed_clocks.len - 1] = .{
        .addr = address,
        .clock = clock,
    };
    var changed_source = source.*;
    changed_source.memory_words = changed_words;
    changed_source.exit_memory_clocks = changed_clocks;
    const changed_wire = try encodeSegment(allocator, &changed_source);
    defer allocator.free(changed_wire);
    const changed_public = try frontend.air.public_data_v2.PublicDataV2
        .authenticate(changed_wire);
    var changed_core = output.statement.core;
    changed_core.public_data = try frontend.air.statement_v2
        .canonicalCorePublicData(&changed_public);
    const changed_statement = try frontend.air.statement_v2
        .RiscVStatementV2.init(changed_core, changed_public);
    try changed_statement.validate();
    try std.testing.expectError(
        error.AdmissionCertificateMismatch,
        frontend.air.guest_precompile.ethereum_proof_admission.validateV2(
            &changed_statement,
            &output.extension,
            .proof,
        ),
    );
}

fn encodeSegment(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}
