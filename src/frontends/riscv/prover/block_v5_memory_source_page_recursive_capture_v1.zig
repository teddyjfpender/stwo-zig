//! Actual original PAGE capture with bounded independently owned storage.
//! Mutation integrity never replaces fresh verification or original admission.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = Page.ForKind(kind);
    const Policy = Admission.ForKind(kind).Prepared;
    return struct {
        pub const VerifiedCapture = struct {
            allocator: std.mem.Allocator,
            budget: *engine.host_budget_allocator.SharedHostBudget,
            original: Original.Captured,
            // Immutable borrowed views; only original owns capture vectors.
            proof: @FieldType(Original.Captured, "proof"),
            relations: @FieldType(Original.Captured, "relations"),
            final_channel: @FieldType(Original.Captured, "final_channel"),
            receipt: Original.VerifiedPage,
            seal: [32]u8,
            pub fn deinit(self: *VerifiedCapture) void {
                self.original.deinit(self.allocator);
                self.budget.destroy();
                self.* = undefined;
            }
            pub fn validate(self: *const VerifiedCapture, admitted: *const Policy, expected: [32]u8) !void {
                try admitted.validate(expected);
                try self.original.requireIntegrity();
                if (!std.meta.eql(self.original.pin, admitted.pin) or !std.meta.eql(self.original.config, admitted.config) or
                    !std.meta.eql(self.original.receipt.admission_id, admitted.context.admitted.identity) or !std.meta.eql(self.original.receipt.source_seal, admitted.context.sealed.digest) or
                    !std.meta.eql(self.receipt, self.original.receipt) or !std.meta.eql(self.relations, self.original.relations) or !std.meta.eql(self.final_channel, self.original.final_channel) or
                    !std.meta.eql(@import("proof_capture_sha256.zig").compute(&self.proof), @import("proof_capture_sha256.zig").compute(&self.original.proof)) or !std.meta.eql(self.seal, self.original.identity())) return error.InvalidSourcePageRecursiveCapture;
                const recipe = try admitted.reconstruct(self.allocator, &self.original.frame, self.original.relations);
                defer recipe.deinit();
                try self.original.frame.requireCaptured(self.allocator, &self.original.proof, admitted.config, recipe.owner);
            }
        };
        pub fn verifyBorrowed(backing: std.mem.Allocator, proof: *const Original.Proof, admitted: *const Policy) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            var fresh = try Original.verifyCaptureBorrowed(a, proof, admitted.context, admitted.pin, admitted.fold_rows, admitted.core_setup, admitted.arithmetic_setup, admitted.limits.page);
            errdefer fresh.deinit(a);
            return .{ .allocator = a, .budget = budget, .original = fresh, .proof = fresh.proof, .relations = fresh.relations, .final_channel = fresh.final_channel, .receipt = fresh.receipt, .seal = fresh.identity() };
        }
        pub fn verifyOwned(backing: std.mem.Allocator, proof: Original.Proof, admitted: *const Policy) !VerifiedCapture {
            var received = proof;
            defer received.deinit(backing);
            return verifyBorrowed(backing, &received, admitted);
        }
    };
}
