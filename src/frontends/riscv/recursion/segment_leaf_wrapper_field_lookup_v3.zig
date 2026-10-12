//! Exact cold tuple closure for staged ProgramV2/provider word-to-hash pairs.
//! This checks the relation schedule before proof integration; the wrapper
//! must still prove the source/hash interactions under its own challenges.

const std = @import("std");
const core = @import("stwo_core");
const word_air = @import("air/transcript_program_v2_field_source_v1.zig");
const word_witness = @import("transcript_program_v2_field_word_witness_v1.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const hash_witness = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const relation = @import("../air/lang/relation.zig");
const interaction = @import("air/relation_interaction.zig");

const M31 = core.fields.m31.M31;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WORD_DOMAIN = relation.Domain.recursion_vm_public_claim_word;
pub const WORD_DOMAIN_MASK: u64 = @as(u64, 1) << @intFromEnum(WORD_DOMAIN);

pub fn verifyExact(
    allocator: std.mem.Allocator,
    words: *const word_witness.WordsV1,
    hash: *const hash_witness.HashV1,
) !interaction.TupleClosureReport {
    if (words.scope != hash.scope or words.word_count != hash.word_count)
        return error.FieldWordHashScopeMismatch;
    var word_definition = try word_air.build(allocator);
    defer word_definition.deinit();
    const word_plan = try word_air.authenticate(&word_definition);
    var hash_definition = try hash_air.build(allocator);
    defer hash_definition.deinit();
    const hash_plan = try hash_relation.authenticate(&hash_definition);

    const hash_rows = try allocator.alloc(
        hash_relation.Row,
        @as(usize, 1) << @intCast(hash.log_size),
    );
    defer allocator.free(hash_rows);
    for (hash_rows, 0..) |*row, index| {
        row.* = if (index < hash.main.len)
            try hash.logicalRow(index)
        else
            [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
    }
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try word_plan.appendPreparedTupleContributions(&ledger, 0, words.rows, WORD_DOMAIN_MASK);
    try hash_plan.appendPreparedTupleContributions(&ledger, 1, hash_rows, WORD_DOMAIN_MASK);
    const report = ledger.classify();
    if (report.unmatched_by_domain[@intFromEnum(WORD_DOMAIN)] != 0 or
        report.contribution_count != 2 * words.word_count)
        return error.FieldWordHashLookupNotClosed;
    return report;
}

test "field word-to-hash lookup closes exact tuples and rejects scope mutation" {
    const source = @import("air/transcript_program_v2_field_source_v1.zig");
    const channel = @import("poseidon2_channel.zig");
    const values = [_]M31{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(65535) };
    var words = try word_witness.WordsV1.init(std.testing.allocator, &values, source.PROGRAM_WORD_SCOPE);
    defer words.deinit();
    const domain: u32 = 0x5450_5632;
    var hash = try hash_witness.HashV1.init(
        std.testing.allocator,
        &values,
        domain,
        source.PROGRAM_WORD_SCOPE,
        0x5052_4731,
        hash_witness.PROGRAM_STEP_BASE,
        channel.hashCanonicalWords(&values, domain),
    );
    defer hash.deinit();
    const report = try verifyExact(std.testing.allocator, &words, &hash);
    try std.testing.expectEqual(@as(usize, 6), report.contribution_count);
    try std.testing.expectEqual(@as(usize, 0), report.unmatched_by_domain[@intFromEnum(WORD_DOMAIN)]);
    hash.scope ^= 1;
    try std.testing.expectError(
        error.FieldWordHashScopeMismatch,
        verifyExact(std.testing.allocator, &words, &hash),
    );
}
