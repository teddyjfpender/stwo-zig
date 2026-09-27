//! Shared owned PCS lifetime for word memory and independently sized range16.
//! Caller derives fixed columns and trusted first roots before this verifier.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
pub const Column = engine.pcs.ColumnEvaluation;
pub fn For(comptime Backend: type, comptime Spec: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
        pub const First = struct {
            scheme: Scheme,
            roots: [2][32]u8,
            owns_scheme: bool = true,
            pub fn deinit(self: *First, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
        };
        pub fn commit(a: std.mem.Allocator, fixed: []const Column, main: []const Column, first_channel: suite.Channel, config: core.pcs.PcsConfig, retain: bool) !First {
            if (fixed.len != Spec.FIXED_COUNT or main.len != Spec.MAIN_COUNT) return error.InvalidV5WordColumns;
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(if (retain) .always else .never);
            var channel = first_channel;
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidV5WordFirstRound;
            return .{ .scheme = scheme, .roots = roots.items[0..2].* };
        }
        pub fn prove(a: std.mem.Allocator, first: *First, spec: Spec, log: u32, columns: []const Column, channel_value: suite.Channel) !suite.Proof {
            if (!first.owns_scheme or columns.len != Spec.INTERACTION_COUNT) return error.InvalidV5WordPhase;
            var channel = channel_value;
            try first.scheme.commitBorrowedStreaming(a, columns, 8, &channel);
            return proveCommitted(a, first, spec, log, channel);
        }
        fn proveCommitted(a: std.mem.Allocator, first: *First, spec: Spec, log: u32, channel_value: suite.Channel) !suite.Proof {
            var channel = channel_value;
            const component = Component{ .spec = spec, .log_size = log };
            first.owns_scheme = false;
            return engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, first.scheme);
        }
        /// Device-only commitments. A backend decline fails closed, never
        /// selecting the generic CPU transform or interaction route.
        pub fn commitResident(a: std.mem.Allocator, session: anytype, witness: anytype, log: u32, first_channel: suite.Channel, config: core.pcs.PcsConfig, other_live: usize) !First {
            if (log > 24 or witness.rows != (@as(usize, 1) << @intCast(log)) or witness.columns != Spec.FIXED_COUNT + Spec.MAIN_COUNT) return error.InvalidV5WordPhase;
            const lane = comptime Spec.FIXED_COUNT == 24 and Spec.MAIN_COUNT == 54 and Spec.INTERACTION_COUNT == 92;
            const provider = comptime Spec.FIXED_COUNT == 1 and Spec.MAIN_COUNT == 1 and Spec.INTERACTION_COUNT == 8;
            if (comptime !lane and !provider) return error.UnsupportedSecureResidentSpec;
            var channel = first_channel;
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            const Resident = Backend.RamLaneResident;
            const fixed_role: Resident.Role = if (lane) .lane_fixed else .range_fixed;
            const main_role: Resident.Role = if (lane) .lane_main else .range_main;
            try session.commit(suite.Hasher, a, &scheme, &witness.resident, 0, fixed_role, log, other_live, &channel);
            try session.commit(suite.Hasher, a, &scheme, &witness.resident, Spec.FIXED_COUNT, main_role, log, try std.math.add(usize, other_live, try Resident.retainedBytes(fixed_role, log)), &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidV5WordFirstRound;
            return .{ .scheme = scheme, .roots = roots.items[0..2].* };
        }
        pub fn proveResident(a: std.mem.Allocator, first: *First, spec: Spec, log: u32, session: anytype, owned_interaction: anytype, other_live: usize, channel_value: suite.Channel) !suite.Proof {
            var interaction = owned_interaction;
            var owns_interaction = true;
            defer if (owns_interaction) interaction.deinit();
            if (log > 24 or !first.owns_scheme or interaction.rows != (@as(usize, 1) << @intCast(log)) or interaction.batches * 4 != Spec.INTERACTION_COUNT or interaction.claim_count != interaction.batches) return error.InvalidV5WordPhase;
            const Resident = Backend.RamLaneResident;
            const role: Resident.Role = if (comptime Spec.INTERACTION_COUNT == 92) .lane_interaction else if (comptime Spec.INTERACTION_COUNT == 8) .range_interaction else return error.UnsupportedSecureResidentSpec;
            var channel = channel_value;
            try session.commit(suite.Hasher, a, &first.scheme, &interaction.resident, 0, role, log, other_live, &channel);
            interaction.deinit();
            owns_interaction = false;
            return proveCommitted(a, first, spec, log, channel);
        }
        pub const Captured = struct {
            proof: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.proof.deinit(a);
                self.* = undefined;
            }
        };
        pub fn verifyOwned(a: std.mem.Allocator, received: suite.Proof, spec: Spec, log: u32, fixed: []const Column, roots: [2][32]u8, config: core.pcs.PcsConfig, first_channel: suite.Channel, channel_value: suite.Channel) !void {
            _ = try verifyInternal(true, false, a, &received, spec, log, fixed, roots, config, first_channel, channel_value, null);
        }
        /// Owns the real core capture while the received proof remains borrowed.
        /// It performs the identical fixed-root, component and PCS checks.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const suite.Proof, spec: Spec, log: u32, fixed: []const Column, roots: [2][32]u8, config: core.pcs.PcsConfig, first_channel: suite.Channel, channel_value: suite.Channel) !Captured {
            var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
            const channel = try verifyInternal(false, true, a, received, spec, log, fixed, roots, config, first_channel, channel_value, &captured);
            return .{ .proof = captured, .final_channel = channel };
        }
        fn verifyInternal(comptime take: bool, comptime capture: bool, a: std.mem.Allocator, received: *const suite.Proof, spec: Spec, log: u32, fixed: []const Column, roots: [2][32]u8, config: core.pcs.PcsConfig, first_channel: suite.Channel, channel_value: suite.Channel, output: ?*core.verifier.ProofCapture(suite.Hasher)) !suite.Channel {
            var proof = received.*;
            var owns = take;
            defer if (owns) proof.deinit(a);
            if (!std.meta.eql(proof.commitment_scheme_proof.config, config) or fixed.len != Spec.FIXED_COUNT) return error.InvalidV5WordConfig;
            const proof_roots = proof.commitment_scheme_proof.commitments.items;
            if (proof_roots.len != 4 or !std.meta.eql(proof_roots[0..2].*, roots)) return error.UntrustedV5WordFirstRound;
            var trusted = try Scheme.init(a, config);
            defer trusted.deinit(a);
            trusted.setCoefficientRetentionPolicy(.never);
            var fixed_channel = first_channel;
            try trusted.commitBorrowedStreaming(a, fixed, 16, &fixed_channel);
            var fixed_roots = try trusted.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], roots[0])) return error.UntrustedV5WordFixedRoot;
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            var channel = first_channel;
            try verifier.commit(a, roots[0], &([_]u32{log} ** Spec.FIXED_COUNT), &channel);
            try verifier.commit(a, roots[1], &([_]u32{log} ** Spec.MAIN_COUNT), &channel);
            channel = channel_value;
            try verifier.commit(a, proof_roots[2], &([_]u32{log} ** Spec.INTERACTION_COUNT), &channel);
            const component = Component{ .spec = spec, .log_size = log };
            if (capture) {
                try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, received, output.?);
            } else {
                owns = false;
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof);
            }
            return channel;
        }
    };
}
