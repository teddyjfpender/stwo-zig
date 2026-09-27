//! Real borrowed range verifier capture. A mutation seal is a consistency
//! check only; it never replaces fixed-root/AIR/PCS cryptographic verification.
const std = @import("std");
const core = @import("stwo_core");
const Range = @import("block_v5_range16_v1.zig");
const Native = @import("block_v5_range16_proof_v1.zig");
const Component = @import("block_v5_range16_component_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const suite = core.proof_suites.Blake3;
pub fn ForAdmission(comptime Admission: type) type {
    return struct {
        pub const VerifiedCapture = struct {
            allocator: std.mem.Allocator,
            budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
            proof: core.verifier.ProofCapture(suite.Hasher),
            challenges: Word.Challenges,
            final_channel: suite.Channel,
            receipt: Native.OpenReceipt,
            seal: [32]u8,
            pub fn deinit(self: *VerifiedCapture) void {
                self.proof.deinit(self.allocator);
                self.budget.destroy();
                self.* = undefined;
            }
            pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
                var channel = suite.Channel{};
                channel.mixU32s(&.{ 0x42355243, Admission.VERSION }); // B5RC
                channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
                channel.mixRoot(admitted.template_id);
                channel.mixRoot(self.receipt.sealed_digest);
                channel.mixRoot(admitted.plan_digest);
                Native.mixShard(&channel, self.receipt.shard, admitted.plan_digest);
                for (self.receipt.roots) |root| channel.mixRoot(root);
                channel.mixU64(self.receipt.claim.count);
                channel.mixFelts(&.{self.receipt.claim.sum});
                for (self.challenges.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
                inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
                    const element = @field(self.challenges, field);
                    channel.mixFelts(&.{ element.z, element.alpha });
                }
                channel.mixRoot(self.final_channel.digestBytes());
                channel.mixU64(self.final_channel.n_draws);
                return channel.digestBytes();
            }
            pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
                try admitted.validate(expected);
                if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or
                    !std.meta.eql(self.receipt.shard, admitted.shard) or !std.meta.eql(self.receipt.roots, admitted.roots) or
                    !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or self.receipt.claim.count != admitted.shard.request_count or
                    !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&self.receipt.claim.sum) or
                    !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidRangeRecursiveCapture;
                const actual = try Word.Challenges.draw(self.allocator, admitted.sealed);
                if (!std.meta.eql(self.challenges, actual)) return error.InvalidRangeRecursiveCapture;
            }
        };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
                    try admitted.validate(admitted.template_id);
                    if (received.claim.count != admitted.shard.request_count or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&received.claim.sum)) return error.InvalidV5Range16Claim;
                    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(a, admitted.limits.max_capture_bytes);
                    errdefer budget.destroy();
                    const bounded = budget.allocator();
                    const fixed = try Range.valueColumn(bounded);
                    defer bounded.free(fixed);
                    const challenges = try Word.Challenges.draw(bounded, admitted.sealed);
                    const spec = Component.Spec{ .claim = received.claim, .challenges = &challenges };
                    const Api = @import("block_v5_word_pcs_v1.zig").For(Backend, Component.Spec);
                    var captured = try Api.verifyCaptureBorrowed(bounded, &received.stark, spec, Range.TABLE_LOG, &.{.{ .log_size = Range.TABLE_LOG, .values = fixed }}, admitted.roots, admitted.config, Native.firstChannel(admitted.shard, admitted.plan_digest), try Native.proofChannel(bounded, admitted.sealed, admitted.shard, admitted.plan_digest, received.claim));
                    errdefer captured.deinit(bounded);
                    var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = captured.proof, .challenges = challenges, .final_channel = captured.final_channel, .receipt = .{ .claim = received.claim, .shard = admitted.shard, .roots = admitted.roots, .sealed_digest = admitted.sealed.digest }, .seal = undefined };
                    result.seal = result.identity(admitted);
                    return result;
                }
            };
        }
    };
}
