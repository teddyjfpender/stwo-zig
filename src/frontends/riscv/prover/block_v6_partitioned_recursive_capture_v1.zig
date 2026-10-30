//! Fresh complete joint-verifier capture. Custody hashes are mutation guards,
//! never substitutes for the recursively constrained verifier equations.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("block_v6_partitioned_native_proof_v1.zig");
const Admission = @import("block_v6_partitioned_recursive_admission_v1.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    original: Protocol.Capture,
    proof: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher),
    metadata: struct { claims: []const Fused.Claim, memory_claims: []const Memory.Claim },
    word_challenges: Word.Challenges,
    challenges: Bus.Challenges,
    relations: @import("../recursion/air/universal_challenges.zig").UniversalRelations,
    final_channel: core.proof_suites.Blake3.Channel,
    receipt: Protocol.Receipt,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.original.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        if (!std.meta.eql(self.seal, self.original.identity()) or !std.meta.eql(self.seal, self.original.seal) or !std.meta.eql(self.receipt, self.original.receipt) or !std.meta.eql(self.final_channel, self.original.final_channel) or !std.meta.eql(@import("proof_capture_sha256.zig").compute(&self.proof), @import("proof_capture_sha256.zig").compute(&self.original.proof)) or (self.metadata.claims.ptr != self.original.claims.ptr or self.metadata.claims.len != self.original.claims.len) or !std.meta.eql(self.metadata.memory_claims.ptr, self.original.memory_claims.ptr) or self.metadata.memory_claims.len != self.original.memory_claims.len) return error.UntrustedPartitionedCapture;
        if (!std.meta.eql(self.receipt.template_id, admitted.binding.template_id) or !std.meta.eql(self.receipt.instance_id, admitted.binding.instance_id) or !std.meta.eql(self.receipt.first_roots, admitted.binding.first_roots) or !std.meta.eql(self.receipt.sealed_digest, admitted.native.sealed.digest) or !std.meta.eql(self.receipt.layout_digest, admitted.layout_digest)) return error.UntrustedPartitionedCapture;
        if (!std.meta.eql(self.word_challenges, try Word.Challenges.draw(self.allocator, admitted.native.sealed)) or !std.meta.eql(self.challenges, try Bus.Challenges.draw(self.allocator, admitted.native.sealed)) or !std.meta.eql(self.relations, self.word_challenges.universal_prefix)) return error.UntrustedPartitionedCaptureChallenges;
        if (self.proof.commitments.len != admitted.tree_count + 1 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.binding.first_roots) or (admitted.slots.len != 0 and !std.meta.eql(self.proof.commitments[2], admitted.witness_root))) return error.UntrustedPartitionedCaptureRoots;
        if (self.proof.column_log_sizes.len != admitted.tree_count + 1) return error.UntrustedPartitionedCaptureGeometry;
        for (admitted.logs[0..admitted.tree_count], self.proof.column_log_sizes[0..admitted.tree_count]) |logs, captured| {
            if (logs.len != captured.len) return error.UntrustedPartitionedCaptureGeometry;
            for (logs, captured) |log, got| if (got != try std.math.add(u32, log, admitted.config.fri_config.log_blowup_factor)) return error.UntrustedPartitionedCaptureGeometry;
        }
        var channel = core.proof_suites.Blake3.Channel{};
        try Fused.mixClaims(&channel, admitted.binding.template_id, admitted.binding.instance_id, admitted.native.index, admitted.projections, admitted.slots, self.metadata.claims, self.metadata.memory_claims);
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyOwned(a: std.mem.Allocator, proof: Protocol.Proof, admitted: *const Admission.Prepared, expected: [32]u8) !VerifiedCapture {
            var owned = proof;
            defer owned.deinit(a);
            return verifyBorrowed(a, &owned, admitted, expected);
        }
        /// Keeps caller ownership on either outcome. The canonical copy and
        /// original verifier still run inside the bounded capture allocator;
        /// publication callbacks need no additional encode/decode copy merely
        /// to preserve their success-only ownership-transfer contract.
        pub fn verifyBorrowed(a: std.mem.Allocator, proof: *const Protocol.Proof, admitted: *const Admission.Prepared, expected: [32]u8) !VerifiedCapture {
            try admitted.validate(expected);
            const budget = try Budget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            const Codec = @import("block_v6_partitioned_native_codec_v1.zig");
            const policy = Codec.Expected{ .shape = admitted.native.shape, .external_retirements = admitted.native.template.external_retirements, .template_id = admitted.binding.template_id, .native_instance_id = admitted.binding.instance_id, .fused_instance_id = Fused.instanceId(admitted.binding.template_id, admitted.binding.instance_id, admitted.binding.first_roots, admitted.witness_root, admitted.native.index, admitted.frame, admitted.projections, admitted.slots), .native_roots = admitted.binding.first_roots, .witness_root = admitted.witness_root, .sealed_digest = admitted.native.sealed.digest, .index = admitted.native.index, .frame = admitted.frame, .register_custody_mode = admitted.native.sealed.register_custody_mode, .config = admitted.config };
            const wire = try Codec.encode(bounded, proof, policy, .{});
            defer bounded.free(wire);
            const copy = try Codec.decode(bounded, wire, policy, .{});
            var capture: Protocol.Capture = undefined;
            var result = try Protocol.ForBackend(Backend).verifyOwnedCapture(bounded, copy, admitted.native.index, Admission.instancePin(admitted.native), admitted.memory, admitted.native.sealed, admitted.native.pins, admitted.native.entries, admitted.native.catalog.?, &capture);
            defer result.deinit(bounded);
            errdefer capture.deinit();
            const word = try Word.Challenges.draw(bounded, admitted.native.sealed);
            const value = VerifiedCapture{ .allocator = bounded, .budget = budget, .original = capture, .proof = capture.proof, .metadata = .{ .claims = capture.claims, .memory_claims = capture.memory_claims }, .word_challenges = word, .challenges = try Bus.Challenges.draw(bounded, admitted.native.sealed), .relations = word.universal_prefix, .final_channel = capture.final_channel, .receipt = capture.receipt, .seal = capture.seal };
            try value.validate(admitted, expected);
            return value;
        }
    };
}
