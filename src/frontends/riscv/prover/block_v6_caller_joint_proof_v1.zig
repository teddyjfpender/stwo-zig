//! Experimental B6CJ1 original caller STARK: arithmetic and every typed
//! projection/access relation share one composition and FRI proof. Global bus
//! sums remain OPEN. This is not a complete block receipt or recursive root.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Joint = @import("block_v6_caller_joint_components_v1.zig");
const Interaction = @import("block_v6_caller_joint_interaction_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const TAG: u32 = 0x4236434a;
pub const VERSION: u32 = 1;
pub const Policy = struct {
    statement: *const Profile.admission.Statement,
    total_steps: u32,
    binding: Protocol.CallerBinding,
    witness_root: [32]u8,
    frame: Frame,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    pub fn admit(self: Policy, a: std.mem.Allocator, schedule: *const Schedule) !void {
        if (self.statement.ethereum.localZeroCustody()) return error.UnqualifiedJointCallerLocalZeroRecipe;
        try Protocol.validate(self.statement, self.total_steps, self.pins.config);
        try Witness.validateAdmission(a, self.statement);
        if (!std.meta.eql(self.binding.caller_key_id, try Protocol.keyId(self.statement, self.total_steps, self.pins.config, self.binding.first_roots[0]))) return error.UntrustedJointCallerKey;
        try Fused.admit(self.binding, self.witness_root, self.frame, schedule, self.sealed, self.pins, self.entries);
    }
};
pub const Proof = struct {
    stark: suite.Proof,
    arithmetic: Profile.ExtensionClaim,
    relations: Fused.ClaimFrames,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.relations.deinit(a);
        self.* = undefined;
    }
};
pub const Verified = struct {
    binding: Protocol.CallerBinding,
    arithmetic_sum: core.fields.qm31.QM31,
    relations: Fused.Verified,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.relations.deinit(a);
        self.* = undefined;
    }
};
/// Exact original verifier capture for the new six-commitment family. A host
/// capture structure or its checksum is not a verified recursive child.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    arithmetic: Profile.ExtensionClaim,
    claims: Fused.ClaimFrames,
    final_channel: suite.Channel,
    receipt: Verified,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.claims.deinit(self.allocator);
        self.receipt.deinit(self.allocator);
        self.* = undefined;
    }
};
/// Every physical claim is absorbed BEFORE either interaction commitment.
/// Original shared challenge derivation, ordered roots, geometry and source
/// group are all bound. No reset to a separately proving family's channel.
pub fn proofChannel(a: std.mem.Allocator, policy: Policy, schedule: *const Schedule, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !suite.Channel {
    try arithmetic.validate(policy.statement);
    var channel = try Protocol.pcsChannel(a, policy.sealed, policy.binding);
    try mixAfterChallenges(&channel, policy, schedule, arithmetic, relations);
    return channel;
}
/// One framing authority for native hashing and recursive public routing.
pub fn mixAfterChallenges(channel: anytype, policy: Policy, schedule: *const Schedule, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !void {
    try arithmetic.validate(policy.statement);
    channel.mixU32s(&.{ TAG, VERSION, 5, 6 });
    policy.pins.config.mixInto(channel);
    channel.mixRoot(policy.sealed.digest);
    Family.mixBinding(channel, policy.binding);
    Fused.mixFirst(channel, policy.binding, policy.witness_root, policy.frame, policy.sealed.register_custody_mode, schedule);
    arithmetic.mixInto(channel);
    try Fused.mixClaims(channel, policy.binding, schedule, relations.program_claims, relations.state_claims, relations.table_claims, relations.memory_claims);
}
fn fusedProvers(a: std.mem.Allocator, owner: *Fused.Components) ![]engine.air.component_prover.ComponentProver {
    const out = try a.alloc(engine.air.component_prover.ComponentProver, owner.memory.len + owner.program.len + owner.tables.len);
    var i: usize = 0;
    inline for (.{ owner.memory, owner.program, owner.tables }) |partition| for (partition) |*component| {
        out[i] = component.asProverComponent();
        i += 1;
    };
    return out;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        /// Consumes the access lease only. The original arithmetic prefix is
        /// retained by the caller for independent comparisons, not reproved.
        pub fn prove(a: std.mem.Allocator, first: *External.ForPackedBackend(Backend).FirstRound, caller: *Family.ForBackend(Backend).FirstRound, inputs: []const External.Input, policy: Policy, pool: *engine.work_pool.WorkPool) !Proof {
            if (!first.owns_scheme or !caller.owns_scheme or first.scheme.trees.items.len != 3 or caller.scheme.trees.items.len != 2 or !std.meta.eql(caller.binding(policy.sealed), policy.binding) or !std.meta.eql(caller.witness.statement, policy.statement.*) or caller.total_steps != policy.total_steps or !std.meta.eql(first.scheme.config, policy.pins.config) or !std.meta.eql(caller.config, policy.pins.config)) return error.UntrustedJointCallerPhase;
            var schedule = try Schedule.init(a, policy.statement, policy.total_steps, policy.frame, policy.sealed.register_custody_mode);
            defer schedule.deinit();
            try policy.admit(a, &schedule);
            if (!std.mem.eql(u32, first.fixed_logs, schedule.fixed) or !std.mem.eql(u32, first.main_logs, schedule.main) or !std.meta.eql(first.roots, .{ policy.binding.first_roots[0], policy.binding.first_roots[1], policy.witness_root })) return error.UntrustedJointCallerPrefix;
            try Selected.validateTrees(&caller.scheme, schedule.fixed, schedule.main);
            for (0..2) |t| {
                const original = caller.scheme.trees.items[t].columns;
                const leased = first.scheme.trees.items[t].columns;
                if (original.len != leased.len) return error.UnsharedJointCallerPrefix;
                for (original, leased) |left, right| if (left.values.ptr != right.values.ptr or left.values.len != right.values.len or left.log_size != right.log_size) return error.UnsharedJointCallerPrefix;
            }
            var roots = try first.scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3 or !std.meta.eql(roots.items[0..3].*, first.roots)) return error.UntrustedJointCallerPrefix;
            const ranges = try schedule.projectionRanges();
            defer a.free(ranges);
            var columns = try Selected.Columns.init(a, &caller.scheme, schedule.fixed, schedule.main, ranges);
            defer columns.deinit(a);
            const relations = try Protocol.drawRelations(a, policy.sealed);
            const word = try Word.Challenges.draw(a, policy.sealed);
            const memory = try Bus.Challenges.draw(a, policy.sealed);
            var arithmetic = try Profile.interactions(a, caller.witness, &relations, pool);
            defer arithmetic.deinit(a);
            var fused = try Interaction.generate(a, &columns, &schedule, inputs, first.snapshots, &relations, &word);
            defer fused.deinit(a);
            const arithmetic_owner = try Profile.Assembly(.prover).createBlockV5Standalone(a, policy.statement, policy.total_steps, &relations, &arithmetic.claim);
            defer arithmetic_owner.destroy(a);
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const access_logs = try schedule.witnessLogs();
            defer a.free(access_logs);
            var fused_owner = try Fused.Components.init(a, &schedule, &fused.claims, &relations, &memory, &word, logs, access_logs, policy.sealed.register_custody_mode);
            defer fused_owner.deinit();
            const handles = try fusedProvers(a, &fused_owner);
            defer a.free(handles);
            const arithmetic_logs = try Protocol.columnLogs(a, policy.statement, .interaction);
            defer a.free(arithmetic_logs);
            const joint = try Joint.Owner(true).create(a, arithmetic_owner.active(), handles, .{ schedule.fixed, schedule.main, access_logs, arithmetic_logs, logs }, fused_owner.memory.len);
            defer joint.destroy();
            var channel = try proofChannel(a, policy, &schedule, &arithmetic.claim, &fused.claims);
            try first.scheme.commitBorrowedStreaming(a, arithmetic.columns, 8, &channel);
            try first.scheme.commitBorrowedStreaming(a, fused.columns, 8, &channel);
            first.owns_scheme = false;
            var stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{joint.asProverComponent()}, &channel, first.scheme);
            errdefer stark.deinit(a);
            return .{ .stark = stark, .arithmetic = arithmetic.claim, .relations = try Fused.ClaimFrames.clone(a, &fused.claims) };
        }
        /// Full fresh verification, with no earlier arithmetic receipt and no
        /// authority taken from producer-selected roots/statement/security.
        pub fn verify(a: std.mem.Allocator, proof: *const Proof, policy: Policy) !Verified {
            return verifyInternal(false, a, proof, policy);
        }
        pub fn verifyCapture(a: std.mem.Allocator, proof: *const Proof, policy: Policy) !VerifiedCapture {
            return verifyInternal(true, a, proof, policy);
        }
        fn verifyInternal(comptime capture_requested: bool, a: std.mem.Allocator, proof: *const Proof, policy: Policy) !(if (capture_requested) VerifiedCapture else Verified) {
            var schedule = try Schedule.init(a, policy.statement, policy.total_steps, policy.frame, policy.sealed.register_custody_mode);
            defer schedule.deinit();
            try policy.admit(a, &schedule);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 6 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.pins.config) or !std.meta.eql(roots[0..3].*, .{ policy.binding.first_roots[0], policy.binding.first_roots[1], policy.witness_root })) return error.UntrustedJointCallerRoots;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const fixed = try Profile.preprocessed(scratch, policy.statement);
            var fixed_scheme = try Scheme.init(a, policy.pins.config);
            defer fixed_scheme.deinit(a);
            fixed_scheme.setCoefficientRetentionPolicy(.never);
            var fixed_channel = suite.Channel{};
            try fixed_scheme.commitBorrowedStreaming(a, fixed, 8, &fixed_channel);
            var fixed_roots = try fixed_scheme.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], policy.binding.first_roots[0])) return error.UntrustedJointCallerFixedRoot;
            var channel = try proofChannel(a, policy, &schedule, &proof.arithmetic, &proof.relations);
            const relations = try Protocol.drawRelations(a, policy.sealed);
            const word = try Word.Challenges.draw(a, policy.sealed);
            const memory = try Bus.Challenges.draw(a, policy.sealed);
            const arithmetic_owner = try Profile.Assembly(.verifier).createBlockV5Standalone(a, policy.statement, policy.total_steps, &relations, &proof.arithmetic);
            defer arithmetic_owner.destroy(a);
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const access_logs = try schedule.witnessLogs();
            defer a.free(access_logs);
            var fused_owner = try Fused.Components.init(a, &schedule, &proof.relations, &relations, &memory, &word, logs, access_logs, policy.sealed.register_custody_mode);
            defer fused_owner.deinit();
            const handles = try fused_owner.verifier();
            defer a.free(handles);
            const arithmetic_logs = try Protocol.columnLogs(a, policy.statement, .interaction);
            defer a.free(arithmetic_logs);
            const joint = try Joint.Owner(false).create(a, arithmetic_owner.active(), handles, .{ schedule.fixed, schedule.main, access_logs, arithmetic_logs, logs }, fused_owner.memory.len);
            defer joint.destroy();
            var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, policy.pins.config);
            defer verifier.deinit(a);
            var first_channel = suite.Channel{};
            for (0..3) |t| try verifier.commit(a, roots[t], joint.logs.items[t], &first_channel);
            for (3..5) |t| try verifier.commit(a, roots[t], joint.logs.items[t], &channel);
            var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{joint.asVerifierComponent()}, &channel, &verifier, &proof.stark, &capture);
            var owns_capture = true;
            defer if (owns_capture) capture.deinit(a);
            var receipt = Verified{ .binding = policy.binding, .arithmetic_sum = proof.arithmetic.componentSum(), .relations = try Fused.deriveOpenReceipts(a, &proof.relations, &schedule, policy.binding, policy.witness_root, policy.sealed) };
            errdefer receipt.deinit(a);
            if (capture_requested) {
                const claims = try Fused.ClaimFrames.clone(a, &proof.relations);
                owns_capture = false;
                return .{ .allocator = a, .proof = capture, .arithmetic = proof.arithmetic, .claims = claims, .final_channel = channel, .receipt = receipt };
            } else return receipt;
        }
    };
}
