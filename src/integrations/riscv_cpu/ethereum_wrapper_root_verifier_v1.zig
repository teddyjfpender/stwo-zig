//! Ethereum wrapper verification from an independently admitted fixed circuit.
//! The caller authenticates the key separately from the proof. Public inputs
//! and claims are untrusted until STARK verification succeeds; no native leaf,
//! capture, witness row or producer owner enters this endpoint.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const components_mod = @import("ethereum_wrapper_verifier_components_v1.zig");
const field_transcript = @import("ethereum_wrapper_field_transcript_v1.zig");
const public_mod = @import("recursive_field_node_public_v2.zig");
const public_boundary = @import("recursive_common_ethereum_incremental_leaf_public_statement_boundary_v4.zig");
const codec = @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const lowering = recursion.air.verifier_arithmetic_lowering;
const Relations = recursion.air.universal_challenges.UniversalRelations;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const Scheme = core.pcs.verifier.CommitmentSchemeVerifier(recursion.engine.Hasher, recursion.engine.MerkleChannel);
const ROOT_VERSION: u16 = 2;
pub const VERSION = ROOT_VERSION;
pub const Ordinary = Types(manifest_mod);
pub const Initial38 = Types(recursion.air.ethereum_initial_input_manifest_v1);
pub const ClaimsV1 = Ordinary.ClaimsV1;
pub const KeyV1 = Ordinary.KeyV1;
pub const verify = Ordinary.verify;
pub const verifyWithCapture = Ordinary.verifyWithCapture;
const Capture = core.pcs.verifier.VerifiedProofCapture(recursion.engine.Hasher);
pub const ProofCapture = Capture;

pub fn Types(comptime ManifestMod: type) type {
    const Components = components_mod.Types(ManifestMod);
    return struct {
        const Selected = @This();
        pub const VERSION = ROOT_VERSION;
        pub const ProofCapture = Capture;
        pub const ClaimsV1 = Components.ClaimsV1;

        /// Fixed circuit data only. The wire anchors are copied from the authenticated
        /// lowering plan, not reconstructed from observed proof claims or evaluations.
        /// Structural validation does not substitute for independent key admission.
        pub const KeyV1 = struct {
            version: u16 = Selected.VERSION,
            transcript_version: u32 = field_transcript.VERSION,
            manifest_schema: u16 = ManifestMod.SCHEMA_VERSION,
            manifest: ManifestMod.Manifest,
            session_fields: field_transcript.SessionFieldsV1,
            preprocessed_root: Digest,
            parameters: Components.AdmissionParametersV1,
            wire_terms: []const lowering.PublicWireTerm,

            pub fn validate(self: *const Selected.KeyV1) !void {
                if (self.version != Selected.VERSION or self.transcript_version != field_transcript.VERSION or self.manifest_schema != ManifestMod.SCHEMA_VERSION)
                    return error.InvalidEthereumRootKeyVersion;
                try self.session_fields.validate();
                _ = try self.parameters.validate(&self.manifest);
                if (std.mem.allEqual(u32, &self.preprocessed_root, 0)) return error.InvalidEthereumRootKey;
                for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus) return error.InvalidEthereumRootKey;
                if (self.wire_terms.len == 0 or self.wire_terms.len >= core.fields.m31.Modulus) return error.InvalidEthereumRootKey;
                for (self.wire_terms) |term| {
                    if (term.active_in != .segment or term.role == .request or term.circuit_id >= core.fields.m31.Modulus or
                        term.node_id >= core.fields.m31.Modulus or term.multiplicity == 0 or term.multiplicity >= core.fields.m31.Modulus)
                        return error.InvalidEthereumRootKey;
                    for (term.value.toM31Array()) |word| if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidEthereumRootKey;
                }
                if (!std.meta.eql(self.session_fields, try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFieldsFromValidatedKey(self)))
                    return error.InvalidEthereumRootFixedNamespace;
            }

            pub fn wireClaim(self: *const Selected.KeyV1, relations: *const Relations) !QM31 {
                const challenge = try relations.getExact(.recursion_wire);
                var claim = QM31.zero();
                for (self.wire_terms) |term| claim = claim.add(try lowering.publicTermClaim(challenge, term));
                return claim;
            }
        };

        /// Returns the verified transcript identity. This proves the published leaf
        /// execution under the selected field circuit; a whole-block root additionally
        /// needs the fold's exact coverage and continuation relation.
        pub fn verify(
            allocator: std.mem.Allocator,
            key: *const Selected.KeyV1,
            node: *const public_mod.NodePublicV2,
            claims: Selected.ClaimsV1,
            interaction_pow_nonce: u64,
            proof_bytes: []const u8,
        ) !Digest {
            return verifyImpl(allocator, key, node, claims, interaction_pow_nonce, proof_bytes, null);
        }

        /// The same verification, retaining the core's authenticated opening/FRI data
        /// for recursive witness generation. Capture is caller-owned only on success;
        /// it is witness data and does not admit a fold circuit or parent proof.
        pub fn verifyWithCapture(
            allocator: std.mem.Allocator,
            key: *const Selected.KeyV1,
            node: *const public_mod.NodePublicV2,
            claims: Selected.ClaimsV1,
            interaction_pow_nonce: u64,
            proof_bytes: []const u8,
            capture: *Selected.ProofCapture,
        ) !Digest {
            return verifyImpl(allocator, key, node, claims, interaction_pow_nonce, proof_bytes, capture);
        }

        fn verifyImpl(
            allocator: std.mem.Allocator,
            key: *const Selected.KeyV1,
            node: *const public_mod.NodePublicV2,
            claims: Selected.ClaimsV1,
            interaction_pow_nonce: u64,
            proof_bytes: []const u8,
            capture: ?*Selected.ProofCapture,
        ) !Digest {
            try key.validate();
            const words = try node.canonicalAirWords();
            if (node.coordinate.height != 0 or node.node_kind != .real) return error.InvalidEthereumRootPublicInputs;
            const claim_vector = try claims.vector(&key.manifest);
            const protocol = key.session_fields.protocol;
            var proof = try codec.deserializeProtocolProof(allocator, protocol, proof_bytes);
            var proof_owned = true;
            defer if (proof_owned) proof.deinit(allocator);
            const commitments = proof.commitment_scheme_proof.commitments.items;
            if (commitments.len != ManifestMod.TREE_COUNT + 1 or !std.meta.eql(commitments[0], key.preprocessed_root))
                return error.InvalidEthereumRootPreprocessedCommitment;
            var scheme = try Scheme.init(allocator, try protocol.pcsConfig());
            defer scheme.deinit(allocator);
            var channel = recursion.poseidon2_channel.Channel{};
            for (0..2) |tree| try recursion.verifier_tree.commitVerifierTreeForManifest(ManifestMod, allocator, &scheme, &key.manifest, tree, commitments[tree], &channel);
            try key.manifest.mixStatementPrefix(&channel);
            try field_transcript.mixAuthority(&channel, &words);
            try field_transcript.mixSessionFields(&channel, key.session_fields);
            if (!channel.verifyPowNonce(protocol.interaction_pow_bits, interaction_pow_nonce)) return error.InvalidEthereumRootInteractionPow;
            channel.mixU64(interaction_pow_nonce);
            const relations = try Relations.draw(allocator, &channel);
            const wire_claim = try key.wireClaim(&relations);
            var total = wire_claim.add((try public_boundary.PublicStatementBoundaryV4.derive(node, &relations)).claimed_sum);
            for (claims.values) |claim| total = total.add(claim);
            if (!total.isZero()) return error.InvalidEthereumRootClaimClosure;
            try field_transcript.mixClaims(&channel, &key.manifest, &claim_vector);
            try field_transcript.mixBoundaryFields(&channel, @intCast(key.wire_terms.len), wire_claim, &claims.poseidon_partials);
            try recursion.verifier_tree.commitVerifierTreeForManifest(ManifestMod, allocator, &scheme, &key.manifest, 2, commitments[2], &channel);
            const components = try Components.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &relations, claims);
            defer components.deinit();
            const moved = recursion.verifier_tree.moveOwnedForVerifier(recursion.engine.Proof, &proof, &proof_owned);
            if (capture) |output|
                try core.verifier.verifyWithProofCapture(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try components.verifierComponents(), &channel, &scheme, moved, output)
            else
                try core.verifier.verify(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try components.verifierComponents(), &channel, &scheme, moved);
            return recursion.protocol.transcriptId(channel.digestWords(), channel.n_draws);
        }
    };
}
