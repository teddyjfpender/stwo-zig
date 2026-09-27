//! Explicit full-width BLAKE3 execution proof API. Not a production default.
//! Verification consumes the proof and requires caller-admitted public execution
//! geometry, commitment schedules and security parameters. No proof-supplied key
//! or preprocessing root becomes an authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const stage_profile = engine.stage_profile;
const suite = core.proof_suites.Blake3;
const universal = @import("../recursion/air/universal_challenges.zig");
const providers = @import("../recursion/air/universal_provider_relations.zig");
const statement_mod = @import("../air/statement.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const Native = @import("blake3_execution_trace.zig").Owner;
pub const Hashes = @import("blake3_commitment_columns.zig").Owner;
const Joined = @import("blake3_execution_components.zig").Owner;
pub const Admission = @import("blake3_commitment_plan.zig").Admission;
pub const commitment_witness = @import("blake3_commitment_witness.zig");
pub const codec = @import("blake3_execution_codec.zig");
pub const commitment_plan = @import("blake3_commitment_plan.zig");
pub const Statement = statement_mod.Blake3ExecutionStatement;
const N_HASHES = @import("blake3_commitment_components.zig").Airs.len;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Proof = struct {
    stark: suite.Proof,
    key_id: [32]u8,
    native_claims: *statement_mod.RiscVInteractionClaim,
    hash_claims: [N_HASHES]Q,
    compact: bool = false,
    compact_claims: [3]Q = @splat(Q.zero()),
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.native_claims);
        self.* = undefined;
    }
};
pub const Verified = @import("blake3_execution_capture.zig").Verified;
pub const Proved = struct { proof: Proof, transcript_digest: [32]u8 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        pub const PreparedVerifier = @import("blake3_execution_prepared.zig").ForBackend(Backend);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        /// Non-consuming admission shared by one-shot and paired proving.
        pub fn validateForProving(native: *const Native, hashes: *const Hashes, pin: Admission) !void {
            if (!native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
            if (native.compact_ranges != null) return error.CompactRangeProtocolNotAdmitted;
            if (!std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedCommitmentPlan;
        }
        /// Borrows prepared owners, generating their interactions exactly once.
        /// On an error after interaction generation, rebuild the native owner.
        pub fn prove(a: std.mem.Allocator, native: *Native, hashes: *Hashes, pin: Admission, config: core.pcs.PcsConfig) !Proved {
            try validateForProving(native, hashes, pin);
            return proveInternal(a, native, hashes, pin, config);
        }
        pub fn proveCompact(a: std.mem.Allocator, native: *Native, hashes: *Hashes, pin: Admission, config: core.pcs.PcsConfig) !Proved {
            try validateCompactForProving(native, hashes, pin);
            return proveInternal(a, native, hashes, pin, config);
        }
        pub fn validateCompactForProving(native: *const Native, hashes: *const Hashes, pin: Admission) !void {
            if (native.compact_ranges == null or !native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
            try native.compact_ranges.?.plan.admit(native.compact_ranges.?.identity);
            if (!std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedCommitmentPlan;
        }
        fn proveInternal(a: std.mem.Allocator, native: *Native, hashes: *Hashes, pin: Admission, config: core.pcs.PcsConfig) !Proved {
            var recorder = stage_profile.Recorder.initWithOptions(a, "native", "blake3-execution", .{ .capture_tasks = false });
            defer recorder.deinit();
            const diagnostic: ?*stage_profile.Recorder = if (std.process.hasEnvVarConstant("STWO_RISCV_EXECUTION_PROFILE")) &recorder else null;
            var phase = try stage_profile.StageScope.begin(diagnostic, "execution.fixed", "Admission and fixed commitment");
            const range_plan = if (native.compact_ranges) |ranges| ranges.plan else null;
            var channel = suite.Channel{};
            try mixExecution(&channel, config, &native.statement, pin, range_plan);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var scheme = try Scheme.init(a, config);
            // Bound coefficient retention across all three trace commitments; larger trees use LDE openings.
            scheme.setCoefficientRetentionPolicy(.never);
            var coefficient_budget: @import("blake3_coefficient_retention.zig").Budget = .{};
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            var columns: std.ArrayList(Column) = .empty;
            try columns.appendSlice(scratch, native.preprocessed.items);
            try columns.appendSlice(scratch, hashes.preprocessed());
            coefficient_budget.configure(&scheme, columns.items);
            try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            const key = @import("blake3_execution_key.zig").Key{ .preprocessed_root = roots.items[0], .hash_logs = hashes.logs };
            const key_id = if (range_plan) |ranges| try key.identityCompact(&native.statement, pin, config, ranges) else try key.identity(&native.statement, pin, config);
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "execution.main", "Main commitment");
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.main.items);
            if (native.compact_ranges) |ranges| try columns.appendSlice(scratch, &ranges.columns);
            try columns.appendSlice(scratch, try hashes.main());
            coefficient_budget.configure(&scheme, columns.items);
            try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "execution.native_interaction", "Native interaction generation");
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const shared = try providers.SharedProviderRelations.init(&relations);
            if (range_plan != null) try native.generateCompactNativeInteractions(&shared.native) else try native.generateInteractions(&shared.native);
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "execution.hash_interaction", "Hash interaction generation");
            var hash_interaction = try hashes.interactionsForBackend(Backend, a, &relations);
            defer hash_interaction.deinit();
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "execution.interaction_commit", "Interaction closure and commitment");
            const joined = try Joined.init(a, &native.statement, &native.claims, relations, pin);
            defer joined.deinit();
            var range_owner: ?*@import("compact_range_assembly.zig").Owner = null;
            defer if (range_owner) |owner| owner.deinit();
            var range_columns: std.ArrayList(Column) = .empty;
            defer {
                for (range_columns.items) |column| a.free(column.values);
                range_columns.deinit(a);
            }
            var range_claims: [3]Q = @splat(Q.zero());
            if (native.compact_ranges) |ranges| {
                range_owner = try @import("compact_range_assembly.zig").Owner.init(a, ranges.plan, ranges.identity, .{ .columns = joined.origin.columns, .claimed_sum_index = joined.origin.claimed_sum_index }, true);
                try range_columns.ensureTotalCapacity(a, 12);
                inline for (0..3) |i| {
                    const generated = try range_owner.?.prepared[i].generate(&ranges.witnesses[i], &relations);
                    range_claims[i] = generated.claimed_sum;
                    for (generated.columns) |values| range_columns.appendAssumeCapacity(.{ .log_size = ranges.plan.shapes[i].log_size, .values = values });
                }
                try joined.bindCompactCommitments(hashes, hash_interaction.claims, range_owner.?, range_claims);
            } else try joined.bindCommitments(hashes, hash_interaction.claims);
            try requireClosedWithExternal(joined, hash_interaction.claims, range_claims[0].add(range_claims[1]).add(range_claims[2]));
            try mixExecutionClaims(&channel, &native.statement, &native.claims, &hash_interaction.claims, range_plan, range_claims);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.interaction.items);
            try columns.appendSlice(scratch, range_columns.items);
            try columns.appendSlice(scratch, hash_interaction.columns.items);
            coefficient_budget.configure(&scheme, columns.items);
            try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
            phase.end();
            phase = try stage_profile.StageScope.begin(diagnostic, "execution.core", "Core STARK proof");
            var components: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
            try components.appendSlice(scratch, joined.proving.components.active());
            try components.appendSlice(scratch, &(try hashes.provers()));
            const claims = try a.create(statement_mod.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = native.claims;
            coefficient_budget.configureComposition(&scheme, components.items);
            owns_scheme = false;
            var extended = try engine.prove.proveExWithRecorder(Backend, suite.Hasher, suite.MerkleChannel, a, components.items, &channel, scheme, false, diagnostic);
            extended.aux.deinit(a);
            errdefer extended.proof.deinit(a);
            phase.end();
            if (diagnostic != null) {
                var snapshot = try recorder.snapshot(a);
                defer snapshot.deinit(a);
                const json = try std.json.Stringify.valueAlloc(a, snapshot, .{});
                defer a.free(json);
                std.debug.print("BLAKE3_EXECUTION_STAGE_PROFILE {s}\n", .{json});
            }
            const stark = extended.proof;
            return .{ .proof = .{ .stark = stark, .key_id = key_id, .native_claims = claims, .hash_claims = hash_interaction.claims, .compact = range_plan != null, .compact_claims = range_claims }, .transcript_digest = channel.digestBytes() };
        }
        /// Consumes proof on every path. Expected shape/pin/config must come from
        /// verifier admission, independently of the received proof bundle.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shape: *const statement_mod.Blake3ExecutionStatement, pin: Admission, config: core.pcs.PcsConfig) ![32]u8 {
            var proof = received;
            const prepared = PreparedVerifier.init(a, shape, pin, config) catch |err| {
                proof.deinit(a);
                return err;
            };
            defer prepared.deinit();
            return verifyPreparedOwned(a, proof, prepared, prepared.id);
        }
        /// Reuses authenticated plans and geometry without rebuilding fixed
        /// trace columns. The caller supplies the expected ID independently.
        pub fn verifyPreparedOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) ![32]u8 {
            return verifyPreparedInternal(false, a, received, prepared, expected_id);
        }
        pub fn verifyPreparedCaptureOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) !Verified {
            return verifyPreparedInternal(true, a, received, prepared, expected_id);
        }
        fn verifyPreparedInternal(comptime capture_mode: bool, a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) !(if (capture_mode) Verified else [32]u8) {
            var proof = received;
            var owns_claims = true;
            defer if (owns_claims) a.destroy(proof.native_claims);
            var owns_stark = true;
            defer if (owns_stark) proof.stark.deinit(a);
            try prepared.validate(expected_id);
            if (proof.compact != (prepared.ranges != null)) return error.InvalidExecutionProof;

            if (!proof.compact) for (proof.compact_claims) |claim| {
                if (!claim.isZero()) return error.InvalidInteractionClaim;
            };
            if (!std.mem.eql(u8, &proof.key_id, &expected_id)) return error.UntrustedExecutionKey;
            const shape = &prepared.shape;
            const pin = prepared.admission();
            const config = prepared.config;
            if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidExecutionConfig;
            if (proof.native_claims.n_components != shape.n_components or proof.native_claims.n_infra != shape.n_infra) return error.InvalidInteractionClaim;
            var channel = suite.Channel{};
            try mixExecution(&channel, config, shape, pin, prepared.ranges);
            const hashes = prepared.hashes.?;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const expected_root = prepared.key.preprocessed_root;
            try admitPreprocessedRoot(expected_root, proof.stark.commitment_scheme_proof.commitments.items[0]);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, expected_root, prepared.logs[0], &channel);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[1], prepared.logs[1], &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const joined = try Joined.init(a, shape, proof.native_claims, relations, pin);
            defer joined.deinit();
            if (prepared.range_components) |ranges| {
                try joined.bindCompactCommitments(hashes, proof.hash_claims, ranges, proof.compact_claims);
            } else try joined.bindCommitments(hashes, proof.hash_claims);
            try requireClosedWithExternal(joined, proof.hash_claims, proof.compact_claims[0].add(proof.compact_claims[1]).add(proof.compact_claims[2]));
            try mixExecutionClaims(&channel, shape, proof.native_claims, &proof.hash_claims, prepared.ranges, proof.compact_claims);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[2], prepared.logs[2], &channel);
            var components: std.ArrayList(core.air.components.Component) = .empty;
            try components.appendSlice(scratch, joined.verifying.components.active());
            try components.appendSlice(scratch, &(try hashes.verifiers()));
            owns_stark = false;
            if (capture_mode) {
                var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, components.items, &channel, &verifier, proof.stark, &capture);
                errdefer capture.deinit(a);
                var result = Verified{ .allocator = a, .key_id = expected_id, .proof = capture, .native_claims = proof.native_claims, .hash_claims = proof.hash_claims, .ranges = prepared.ranges, .compact_claims = proof.compact_claims, .relations = relations, .final_channel = channel, .seal = undefined };
                result.seal = try result.identity(shape);
                owns_claims = false;
                return result;
            } else {
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, components.items, &channel, &verifier, proof.stark);
                return channel.digestBytes();
            }
        }
    };
}
pub fn admitPreprocessedRoot(expected: suite.Hasher.Hash, supplied: suite.Hasher.Hash) !void {
    if (!std.mem.eql(u8, &expected, &supplied)) return error.UntrustedBlake3Preprocessing;
}
fn requireClosed(joined: *const Joined, hashes: [N_HASHES]Q) !void {
    return requireClosedWithExternal(joined, hashes, Q.zero());
}
pub fn requireClosedWithExternal(joined: *const Joined, hashes: [N_HASHES]Q, external_sum: Q) !void {
    if (joined.claims.n_components != joined.statement.n_components or joined.claims.n_infra != joined.statement.n_infra) return error.InvalidInteractionClaim;
    var total = (try joined.publicCompensation()).add(external_sum);
    for (joined.statement.component_descs[0..joined.statement.n_components], 0..) |desc, i| total = total.add(try joined.claims.opcodeClaimTotal(desc.family, i));
    for (joined.statement.infra_descs[0..joined.statement.n_infra], 0..) |desc, i| total = total.add(try joined.claims.infraClaimTotal(desc.kind, i));
    for (hashes) |claim| total = total.add(claim);
    if (!total.isZero()) return error.UnclosedExecutionRelations;
}

fn mixExecution(channel: anytype, config: core.pcs.PcsConfig, shape: *const Statement, pin: Admission, ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan) !void {
    if (ranges) |plan| try (@import("compact_execution_contract.zig").Contract{ .native = shape, .ranges = plan }).mix(channel, config, pin, 0) else try protocol.mix(channel, config, shape, pin);
}
fn mixExecutionClaims(channel: anytype, shape: *const Statement, claims: *const statement_mod.RiscVInteractionClaim, hashes: []const Q, ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan, range_claims: [3]Q) !void {
    if (ranges) |plan| try (@import("compact_execution_contract.zig").Contract{ .native = shape, .ranges = plan }).mixClaims(channel, claims, range_claims, hashes, 0) else try protocol.mixClaims(channel, shape, claims, hashes);
}
