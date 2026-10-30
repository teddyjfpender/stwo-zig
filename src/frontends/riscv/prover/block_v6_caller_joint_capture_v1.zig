//! Actual six-commitment original verification boundary. Capture consistency
//! is checked against independent equations, roots and exact OODS masks. This
//! does not claim that a recursive parent/key factory has been qualified.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Admission = @import("block_v6_caller_joint_admission_v1.zig");
const Joint = @import("block_v6_caller_joint_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
pub const VerifiedCapture = struct {
    budget: *Budget,
    original: Joint.VerifiedCapture,
    template_id: [32]u8,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.original.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    /// Transport checksum only, never a replacement for a proof or key policy.
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) ![32]u8 {
        var channel = try Joint.proofChannel(admitted.allocator, admitted.policy(), &admitted.relations.schedule, &self.original.arithmetic, &self.original.claims);
        channel.mixRoot(self.template_id);
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.original.proof));
        channel.mixRoot(self.original.final_channel.digestBytes());
        channel.mixU64(self.original.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected_template: [32]u8) !void {
        const a = self.budget.allocator();
        if (!std.meta.eql(expected_template, admitted.template_id)) return error.UntrustedJointCallerGeometry;
        try admitted.validate();
        if (!std.meta.eql(self.template_id, admitted.template_id) or !std.meta.eql(self.seal, try self.identity(admitted)) or !std.meta.eql(self.original.receipt.binding, admitted.arithmetic.binding) or !self.original.receipt.arithmetic_sum.eql(self.original.arithmetic.componentSum())) return error.InvalidJointCallerCapture;
        const captured = &self.original.proof;
        if (captured.commitments.len != 6 or captured.column_log_sizes.len != 6 or captured.sampled_points.len != 6 or !std.meta.eql(captured.commitments[0..3].*, .{ admitted.arithmetic.roots[0], admitted.arithmetic.roots[1], admitted.relations.witness_root })) return error.InvalidJointCallerCapture;
        for (admitted.logs(), captured.column_log_sizes[0..5]) |expected, actual| try @import("proof_capture_geometry_v1.zig").requireExtendedLogs(error.InvalidJointCallerCapture, expected, actual, admitted.arithmetic.config.fri_config.log_blowup_factor);
        const columns = core.verifier_types.compositionColumnCount(admitted.composition_split, 4) orelse return error.InvalidJointCallerCapture;
        if (captured.column_log_sizes[5].len != columns) return error.InvalidJointCallerCapture;
        for (captured.column_log_sizes[5]) |log| if (log != admitted.mask_log + admitted.arithmetic.config.fri_config.log_blowup_factor) return error.InvalidJointCallerCapture;
        const equations = try Admission.EquationOwner.create(a, admitted, &self.original.arithmetic, &self.original.claims);
        defer equations.destroy();
        if (equations.joint.bound != admitted.composition_log or equations.joint.split != admitted.composition_split or equations.joint.constraints != admitted.constraint_count) return error.InvalidJointCallerCapture;
        const point = core.circle.secureFieldPointFromRandomSeed(captured.oods_seed);
        var masks = try equations.joint.maskPoints(a, point, admitted.mask_log);
        defer masks.deinitDeep(a);
        var total: usize = 0;
        for (masks.items, captured.sampled_points[0..5]) |expected, actual| {
            if (expected.len != actual.len) return error.InvalidJointCallerCapture;
            for (expected, actual) |wanted, received| {
                if (wanted.len != received.len) return error.InvalidJointCallerCapture;
                for (wanted, received) |w, r| if (!w.eql(r)) return error.InvalidJointCallerCapture;
                total = try std.math.add(usize, total, received.len);
            }
        }
        if (captured.sampled_points[5].len != columns) return error.InvalidJointCallerCapture;
        for (captured.sampled_points[5]) |samples| if (samples.len != 1 or !samples[0].eql(point)) return error.InvalidJointCallerCapture;
        total = try std.math.add(usize, total, columns);
        if (total != captured.sampled_values.len or total > admitted.limits.max_samples) return error.InvalidJointCallerCapture;
        var expected = try Fused.deriveOpenReceipts(a, &self.original.claims, &admitted.relations.schedule, admitted.arithmetic.binding, admitted.relations.witness_root, admitted.arithmetic.sealed);
        const ranges = expected.memory.range_claims;
        defer a.free(ranges);
        if (ranges.len != self.original.receipt.relations.memory.range_claims.len) return error.InvalidJointCallerCapture;
        for (ranges, self.original.receipt.relations.memory.range_claims) |want, got| if (!std.meta.eql(want, got)) return error.InvalidJointCallerCapture;
        expected.memory.range_claims = self.original.receipt.relations.memory.range_claims;
        if (!std.meta.eql(expected, self.original.receipt.relations)) return error.InvalidJointCallerCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verify(a: std.mem.Allocator, proof: *const Joint.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate();
            const budget = try Budget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            var original = try Joint.ForBackend(Backend).verifyCapture(budget.allocator(), proof, admitted.policy());
            errdefer original.deinit();
            var result = VerifiedCapture{ .budget = budget, .original = original, .template_id = admitted.template_id, .seal = undefined };
            result.seal = try result.identity(admitted);
            try result.validate(admitted, admitted.template_id);
            return result;
        }
    };
}
