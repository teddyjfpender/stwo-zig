//! Independently sized typed precompile arithmetic. Its VM claims remain open
//! until the native, ROM, memory and lookup providers close under B5SS.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const profile = @import("blake3_ethereum_sha_profile.zig");
const protocol = @import("block_v5_precompile_protocol_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Statement = profile.admission.Statement;
const Digest = [32]u8;
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
pub const CallerBinding = protocol.CallerBinding;

pub const Proof = struct {
    stark: suite.Proof,
    claims: profile.ExtensionClaim,
    key_id: Digest,
    instance_id: Digest,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenReceipt = struct {
    binding: CallerBinding,
    open_sum: core.fields.qm31.QM31,
};

/// Every vector is owned independently of the source proof. This transport
/// seal detects mutations only; callers must freshly verify original bytes.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    claims: profile.ExtensionClaim,
    relations: profile.Relations,
    final_channel: suite.Channel,
    config: core.pcs.PcsConfig,
    receipt: OpenReceipt,
    seal: Digest,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture) Digest {
        var channel = suite.Channel{};
        channel.mixRoot(captureDomain());
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        self.config.mixInto(&channel);
        mixBinding(&channel, self.receipt.binding);
        self.claims.mixInto(&channel);
        channel.mixFelts(&.{self.receipt.open_sum});
        for (self.relations.sha.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        const extension_draws = self.relations.draws();
        channel.mixFelts(&extension_draws);
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    /// Independent statement/binding/seal policy is still mandatory. A
    /// checksum-valid host construction is never a verification receipt.
    pub fn validate(self: *const VerifiedCapture, a: std.mem.Allocator, statement: *const Statement, total_steps: u32, expected: CallerBinding, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
        try protocol.validate(statement, total_steps, pins.config);
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
        try self.claims.validate(statement);
        try protocol.admit(expected, sealed, pins, entries);
        if (!std.meta.eql(self.config, pins.config) or self.proof.commitments.len != 4 or
            !std.meta.eql(self.proof.commitments[0..2].*, expected.first_roots) or
            !std.meta.eql(self.receipt.binding, expected) or !self.receipt.open_sum.eql(self.claims.componentSum()) or
            !std.meta.eql(expected.caller_key_id, try protocol.keyId(statement, total_steps, pins.config, expected.first_roots[0])) or
            !std.meta.eql(self.seal, self.identity()) or
            !std.meta.eql(self.relations, try protocol.drawRelations(a, sealed))) return error.InvalidV5CallerArithmeticCapture;
        inline for (.{ .fixed, .main, .interaction }, 0..) |tree, i| {
            const logs = try protocol.columnLogs(a, statement, tree);
            defer a.free(logs);
            if (self.proof.column_log_sizes.len != 4 or !std.mem.eql(u32, self.proof.column_log_sizes[i], logs)) return error.InvalidV5CallerArithmeticCapture;
        }
    }
};
fn captureDomain() Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash("stwo-zig/block-v5/caller-arithmetic-capture/v1\x00", &result, .{});
    return result;
}
pub fn mixBinding(channel: *suite.Channel, binding: CallerBinding) void {
    channel.mixU32s(&.{ binding.execution_index, binding.caller_entry_index });
    channel.mixRoot(binding.execution_instance_id);
    channel.mixRoot(binding.caller_instance_id);
    channel.mixRoot(binding.caller_key_id);
    for (binding.first_roots) |root| channel.mixRoot(root);
    channel.mixRoot(binding.sealed_digest);
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub const FirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            key_id: Digest,
            instance_id: Digest,
            execution_instance_id: Digest,
            index: u32,
            total_steps: u32,
            config: core.pcs.PcsConfig,
            witness: *const Witness,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
            pub fn entry(self: *const FirstRound) seal.Entry {
                return .{ .family = .precompile, .index = self.index, .instance_id = self.instance_id, .roots = self.roots };
            }
            pub fn binding(self: *const FirstRound, sealed: seal.Sealed) CallerBinding {
                return .{ .execution_index = self.index, .execution_instance_id = self.execution_instance_id, .caller_entry_index = self.index, .caller_instance_id = self.instance_id, .caller_key_id = self.key_id, .first_roots = self.roots, .sealed_digest = sealed.digest };
            }
        };

        /// Physical setup has no execution-instance authority. Its trees are
        /// identical to the existing bound route and remain caller-owned.
        pub const PhysicalFirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            key_id: Digest,
            total_steps: u32,
            config: core.pcs.PcsConfig,
            witness: *const Witness,
            owns_scheme: bool = true,
            pub fn deinit(self: *PhysicalFirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
            pub fn bind(self: *PhysicalFirstRound, index: u32, execution_instance_id: Digest) !FirstRound {
                if (!self.owns_scheme) return error.ConsumedV5PhysicalCaller;
                self.owns_scheme = false;
                return .{ .scheme = self.scheme, .roots = self.roots, .key_id = self.key_id, .instance_id = protocol.instanceId(self.key_id, execution_instance_id, index, self.roots), .execution_instance_id = execution_instance_id, .index = index, .total_steps = self.total_steps, .config = self.config, .witness = self.witness };
            }
        };

        pub fn commitFirstRound(a: std.mem.Allocator, witness: *const Witness, total_steps: u32, config: core.pcs.PcsConfig, index: u32, execution_instance_id: Digest) !FirstRound {
            var physical = try commitPhysicalFirstRound(a, witness, total_steps, config);
            defer physical.deinit(a);
            return physical.bind(index, execution_instance_id);
        }
        pub fn commitPhysicalFirstRound(a: std.mem.Allocator, witness: *const Witness, total_steps: u32, config: core.pcs.PcsConfig) !PhysicalFirstRound {
            try protocol.validate(&witness.statement, total_steps, config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &witness.statement);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = suite.Channel{};
            const fixed = try profile.preprocessed(a, &witness.statement);
            defer {
                for (fixed) |column| a.free(column.values);
                a.free(fixed);
            }
            try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
            var main = try profile.mainWitness(a, witness);
            defer main.deinit(a);
            try scheme.commitBorrowedStreaming(a, main.columns, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidBlockV5PrecompileFirstRound;
            const first_roots: seal.Roots = roots.items[0..2].*;
            const key_id = try protocol.keyId(&witness.statement, total_steps, config, first_roots[0]);
            return .{ .scheme = scheme, .roots = first_roots, .key_id = key_id, .total_steps = total_steps, .config = config, .witness = witness };
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, pool: *engine.work_pool.WorkPool) !Proof {
            const binding = first.binding(sealed);
            try protocol.admit(binding, sealed, pins, entries);
            if (!std.meta.eql(first.config, pins.config) or !std.meta.eql(first.key_id, try protocol.keyId(&first.witness.statement, first.total_steps, pins.config, first.roots[0])))
                return error.UntrustedBlockV5PrecompileKey;
            const relations = try protocol.drawRelations(a, sealed);
            var interaction = try profile.interactions(a, first.witness, &relations, pool);
            defer interaction.deinit(a);
            const assembly = try profile.Assembly(.prover).createBlockV5Standalone(a, &first.witness.statement, first.total_steps, &relations, &interaction.claim);
            defer assembly.destroy(a);
            var channel = try protocol.pcsChannel(a, sealed, binding);
            interaction.claim.mixInto(&channel);
            try first.scheme.commitBorrowedStreaming(a, interaction.columns, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, assembly.active(), &channel, first.scheme), .claims = interaction.claim, .key_id = first.key_id, .instance_id = first.instance_id };
        }

        /// The statement, key and native execution identity come from receiver
        /// policy; neither proof metadata nor a sidecar can admit its own key.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, statement: *const Statement, total_steps: u32, expected_key: Digest, execution_instance_id: Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !OpenReceipt {
            return verifyInternal(false, true, a, &received, statement, total_steps, expected_key, execution_instance_id, index, sealed, pins, entries);
        }
        pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, statement: *const Statement, total_steps: u32, expected_key: Digest, execution_instance_id: Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !VerifiedCapture {
            return verifyInternal(true, true, a, &received, statement, total_steps, expected_key, execution_instance_id, index, sealed, pins, entries);
        }
        /// Source proof and its immutable arrays remain caller-owned on every
        /// path. It must stay alive and unchanged only until this call returns.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, statement: *const Statement, total_steps: u32, expected_key: Digest, execution_instance_id: Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !VerifiedCapture {
            return verifyInternal(true, false, a, received, statement, total_steps, expected_key, execution_instance_id, index, sealed, pins, entries);
        }
        fn verifyInternal(comptime capture: bool, comptime take: bool, a: std.mem.Allocator, received: *const Proof, statement: *const Statement, total_steps: u32, expected_key: Digest, execution_instance_id: Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !(if (capture) VerifiedCapture else OpenReceipt) {
            var proof = received.*;
            var owns_stark = take;
            defer if (owns_stark) proof.deinit(a);
            try protocol.validate(statement, total_steps, pins.config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
            try proof.claims.validate(statement);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config))
                return error.InvalidBlockV5PrecompileProofShape;
            const first_roots: seal.Roots = roots[0..2].*;
            const key_id = try protocol.keyId(statement, total_steps, pins.config, first_roots[0]);
            if (!std.meta.eql(key_id, expected_key) or !std.meta.eql(proof.key_id, expected_key))
                return error.UntrustedBlockV5PrecompileKey;
            const binding = CallerBinding{ .execution_index = index, .execution_instance_id = execution_instance_id, .caller_entry_index = index, .caller_instance_id = proof.instance_id, .caller_key_id = key_id, .first_roots = first_roots, .sealed_digest = sealed.digest };
            try protocol.admit(binding, sealed, pins, entries);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const fixed = try profile.preprocessed(scratch, statement);
            var fixed_scheme = try Scheme.init(a, pins.config);
            defer fixed_scheme.deinit(a);
            fixed_scheme.setCoefficientRetentionPolicy(.never);
            var fixed_channel = suite.Channel{};
            try fixed_scheme.commitBorrowedStreaming(a, fixed, 8, &fixed_channel);
            var fixed_roots = try fixed_scheme.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], first_roots[0]))
                return error.UntrustedBlockV5PrecompileFixedRoot;
            const relations = try protocol.drawRelations(a, sealed);
            const assembly = try profile.Assembly(.verifier).createBlockV5Standalone(a, statement, total_steps, &relations, &proof.claims);
            defer assembly.destroy(a);
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            var first_channel = suite.Channel{};
            try verifier.commit(a, first_roots[0], try protocol.columnLogs(scratch, statement, .fixed), &first_channel);
            try verifier.commit(a, first_roots[1], try protocol.columnLogs(scratch, statement, .main), &first_channel);
            var channel = try protocol.pcsChannel(a, sealed, binding);
            proof.claims.mixInto(&channel);
            try verifier.commit(a, roots[2], try protocol.columnLogs(scratch, statement, .interaction), &channel);
            const sum = proof.claims.componentSum();
            const receipt = OpenReceipt{ .binding = binding, .open_sum = sum };
            if (capture) {
                var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
                if (take) {
                    owns_stark = false;
                    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, assembly.active(), &channel, &verifier, proof.stark, &captured);
                } else {
                    try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, assembly.active(), &channel, &verifier, &proof.stark, &captured);
                }
                var result = VerifiedCapture{ .allocator = a, .proof = captured, .claims = proof.claims, .relations = relations, .final_channel = channel, .config = pins.config, .receipt = receipt, .seal = undefined };
                result.seal = result.identity();
                return result;
            } else {
                owns_stark = false;
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, assembly.active(), &channel, &verifier, proof.stark);
                return receipt;
            }
        }
    };
}
