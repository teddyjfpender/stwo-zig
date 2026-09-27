//! Nonproving original join equation/admission fixtures. Synthetic scalars
//! exercise algebra only and are never supplied as fresh proof receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Join = @import("block_v5_memory_source_page_join_algebra_v1.zig");
const Owner = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
fn admission() !Batch.Admission {
    const empty = Tree.TreeHasher.init(.memory).defaults[0].bytes;
    const sha = Initial.sha256("");
    const source = try Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
        .initial_rw_root = empty,
        .initial_registers = @splat(0),
        .public_input_sha256 = sha,
        .public_input_len = 0,
        .input_words = .{ .sha256 = sha, .records = 0 },
        .rw_words = .{ .sha256 = sha, .records = 0 },
        .first_touches = .{ .sha256 = sha, .records = 0 },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = empty, .endpoints = .{ .sha256 = sha, .records = 0 } }, @splat(8), .{});
    return Batch.Admission.init(source, .{});
}
fn zeroTotals() Join.Totals {
    var totals = Join.Totals{};
    totals.fold.roots = Q.one();
    return totals;
}
test "source PAGE join: empty source still requires one original fold root and every raw chain zero" {
    const admitted = try admission();
    const correct = zeroTotals();
    try Join.close(&admitted, correct);
    var missing = correct;
    missing.fold.roots = Q.zero();
    try std.testing.expectError(error.UnclosedSourcePageJoin, Join.close(&admitted, missing));
    inline for (.{ "bytes", "input", "route", "roots", "ordering", "sha_chain" }) |field| {
        var changed = correct;
        @field(changed.raw, field) = Q.one();
        try std.testing.expectError(error.UnclosedSourcePageJoin, Join.close(&admitted, changed));
    }
}
test "source PAGE join: indexed insertion before after and RAM endpoint signs close independently" {
    const admitted = try admission();
    var correct = zeroTotals();
    const value = Q.fromU32Unchecked(3, 5, 7, 11);
    correct.indexed = value;
    correct.fold.indexed = value.neg();
    inline for (.{ "insertion", "before", "after" }) |field| {
        @field(correct.raw, field) = value;
        @field(correct.fold, field) = value.neg();
    }
    correct.raw.initial = value;
    correct.initial = value.neg();
    correct.raw.endpoint = value;
    correct.endpoint = value;
    try Join.close(&admitted, correct);
    inline for (.{ "initial", "endpoint", "predecessor", "indexed" }) |field| {
        var changed = correct;
        @field(changed, field) = @field(changed, field).add(Q.one());
        try std.testing.expectError(error.UnclosedSourcePageJoin, Join.close(&admitted, changed));
    }
    inline for (.{ "insertion", "before", "after", "route", "hash", "input", "rw", "touches", "roots" }) |field| {
        var changed = correct;
        @field(changed.fold, field) = @field(changed.fold, field).add(Q.one());
        try std.testing.expectError(error.UnclosedSourcePageJoin, Join.close(&admitted, changed));
    }
}
test "source PAGE join: malformed raw field cannot cancel against opposite noncanonical proposal" {
    const admitted = try admission();
    var changed = zeroTotals();
    // Corrupt raw wire storage, never invoke a canonical constructor outside
    // its assertion contract.
    changed.raw.initial.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalSourcePageJoin, Join.close(&admitted, changed));
}
test "source PAGE join: source pins and complete source plan remain independent admission authority" {
    const admitted = try admission();
    var context: @import("block_v5_memory_source_unified_page_proof_v1.zig").Context = undefined;
    context.admitted = admitted;
    context.base.digest = admitted.source.sealed_digest;
    var memory: @import("block_v5_ram_lanes_receiver_v1.zig").Pins = undefined;
    memory.source = admitted.source.pins;
    memory.expected_seal_digest = admitted.source.sealed_digest;
    memory.pins = &.{};
    try Owner.testing.requireAuthority(&context, memory);
    memory.source.initial.public_input_sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageJoinAuthority, Owner.testing.requireAuthority(&context, memory));
    memory.source = admitted.source.pins;
    memory.source.memory_plan_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageJoinAuthority, Owner.testing.requireAuthority(&context, memory));
    memory.source = admitted.source.pins;
    memory.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageJoinAuthority, Owner.testing.requireAuthority(&context, memory));
}
test "source PAGE join: resource admission and consumed lifecycle reject before touching original receipts" {
    try std.testing.expectError(error.SourcePageJoinResourceLimit, Owner.Owner.create(std.testing.allocator, undefined, undefined, .{ .max_setup_bytes = 0 }));
    var consumed: Owner.Owner = undefined;
    consumed.consumed = true;
    try std.testing.expectError(error.SourcePageJoinAlreadyConsumed, consumed.verify(std.testing.allocator, undefined));
    try std.testing.expect(!Owner.Open.complete_block_authority);
}
test "source PAGE join: batch resource rejection cannot take or accept any original proof" {
    const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
    const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const Page = Pages.ForKind(kind);
        const Loader = struct {
            calls: usize = 0,
            pub fn take(self: *@This(), _: std.mem.Allocator, _: u32) !Page.Proof {
                self.calls += 1;
                return error.FixtureCannotProduceProof;
            }
            pub fn rows(self: *@This(), _: std.mem.Allocator, _: u32, _: u32) ![]Semantic.FoldRow {
                self.calls += 1;
                return error.FixtureCannotProduceProof;
            }
            pub fn accept(self: *@This(), _: Page.VerifiedPage) !void {
                self.calls += 1;
                return error.FixtureCannotProduceProof;
            }
        };
        var loader = Loader{};
        try std.testing.expectError(error.SourcePageReceiverResourceLimit, Page.verifyRosterOwned(std.testing.allocator, undefined, undefined, undefined, .{ .max_receiver_heap_bytes = 0 }, &loader));
        try std.testing.expectEqual(@as(usize, 0), loader.calls);
    }
}
