//! Synchronous publication-policy projection. No Job or fresh claim scalar is
//! serialized as proof authority. Version 2 pins actual pre-proof semantic
//! proposals alongside normative pins and file integrity proposals. Policy.read independently rebuilds original Globals admissions.
const std = @import("std");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const FoldStore = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Files = struct { raw: []const Policy.Artifact, fold: []const Policy.Artifact, fold_operands: []const FoldStore.Pin, raw_claims: []const Semantic.Claims = &.{}, fold_claims: []const Semantic.Claims = &.{} };
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, globals: Global.Pins, context: *const Page.Context, files: Files, limits: Policy.Limits) !Policy.Pin {
    try limits.validate();
    if (files.raw_claims.len != context.raw.len or files.fold_claims.len != context.fold.len or files.raw.len != context.raw.len or files.fold.len != context.fold.len or files.fold_operands.len != context.fold.len or
        try std.math.add(usize, context.raw.len, context.fold.len) > limits.max_pages or try Policy.metadataBytes(context.raw.len, context.fold.len) > limits.max_metadata_bytes) return error.UntrustedSourcePagePolicyFiles;
    const budget = try Budget.createRetainingParent(a, limits.max_owned_bytes);
    defer budget.destroy();
    const bounded = budget.allocator();
    // Original context admission stays independent of file pins. Published
    // artifacts must later be freshly verified, regardless of this check.
    try context.require(bounded, limits.pages);
    const raw = try bounded.alloc(Policy.RawRecord, context.raw.len);
    defer bounded.free(raw);
    const fold = try bounded.alloc(Policy.FoldRecord, context.fold.len);
    defer bounded.free(fold);
    for (raw, context.raw, files.raw, files.raw_claims) |*record, pin, artifact, claims| record.* = .{ .pin = pin, .artifact = artifact, .expected_claims = try Policy.expectedClaims(.raw, claims) };
    for (fold, context.fold, files.fold, files.fold_operands, files.fold_claims) |*record, pin, artifact, operands, claims| record.* = .{ .pin = pin, .artifact = artifact, .operands = operands, .expected_claims = try Policy.expectedClaims(.fold, claims) };
    return Policy.write(bounded, dir, globals, .{ .config = globals.tables.seal.config, .raw_plan = context.raw_plan, .fold_plan = context.fold_plan, .raw = raw, .fold = fold, .sealed = context.sealed }, limits);
}
