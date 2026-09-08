const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("recursive_common_ethereum_incremental_leaf_child_statement_v4.zig");
const child_public = @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");
const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const RawWords = [@typeInfo(frontend.recursion.span_statement.StatementWords).array.len]u32;

test "Ethereum child statement owns source snapshots and rejects changed prepared rows" {
    const words = try executedWords(0);
    try subject.testing.exercise(Engine, std.testing.allocator, words, fixtureBinding(words));
}

test "Ethereum child statement constructor unwinds every allocation failure" {
    const words = try executedWords(0);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, construct, .{ words, fixtureBinding(words) });
}

fn construct(allocator: std.mem.Allocator, words: RawWords, binding: child_public.ChildPublicBindingV4) !void {
    try subject.testing.construct(Engine, allocator, words, binding);
}

fn fixtureBinding(words: RawWords) child_public.ChildPublicBindingV4 {
    return child_public.testing.resealBinding(.{
        .stage101_capability_identity_sha256 = [_]u8{11} ** 32,
        .role_io_identity_sha256 = [_]u8{43} ** 32,
        .field_source_digest = digest(59),
        .statement_words_identity_sha256 = subject.testing.statementIdentity(words),
        .claim_words_identity_sha256 = [_]u8{83} ** 32,
        .claim_digest = digest(101),
        .public_input_digest = digest(211),
        .public_output_digest = digest(307),
        .io_hash_output_digests = .{ digest(211), digest(307) },
        .child_io_hash_call_count = 67,
        .identity_sha256 = undefined,
    });
}

fn executedWords(index: u32) !RawWords {
    const span = frontend.recursion.span_statement;
    const initial = try span.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(1),
        digest(2),
    );
    const final = try span.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest(3),
        digest(4),
    );
    const input_digest = digest(5);
    const output_digest = digest(6);
    const complete = try span.CompleteExecution.init(
        frontend.recursion.protocol.protocolId(),
        digest(7),
        initial,
        final,
        input_digest,
        output_digest,
        8,
    );
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(
        0,
        1,
        0,
        8,
        initial,
        final,
        try span.EdgeClaim.present(input_digest),
        try span.EdgeClaim.present(output_digest),
    );
    const statement = try span.SpanStatement.segmentLeaf(job, index, executed);
    const canonical = try statement.canonicalWords();
    var result: RawWords = undefined;
    for (&result, canonical) |*destination, word|
        destination.* = word.toU32();
    return result;
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
