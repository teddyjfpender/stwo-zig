//! Shared full-width extension proof pipeline, specialized by typed profile.
pub fn ForProfile(comptime Profile: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const engine = @import("stwo_prover_engine");
        const stage_profile = engine.stage_profile;
        const suite = core.proof_suites.Blake3;
        const Q = core.fields.qm31.QM31;
        const Column = engine.pcs.ColumnEvaluation;
        const native_mod = @import("../air/statement.zig");
        const protocol = Profile.protocol;
        const base_protocol = @import("blake3_execution_protocol.zig");
        const execution = @import("blake3_execution_proof.zig");
        const Joined = @import("blake3_execution_components.zig").Owner;
        const Witness = Profile.Witness;
        const universal = @import("../recursion/air/universal_challenges.zig");
        const shared = @import("../recursion/air/universal_provider_relations.zig");
        const Relations = Profile.Relations;
        const Assembly = Profile.Assembly;
        const ExtensionClaim = Profile.ExtensionClaim;
        const N_HASHES = @import("blake3_commitment_components.zig").Airs.len;
        pub const Proof = struct {
            stark: suite.Proof,
            key_id: [32]u8,
            native_claims: *native_mod.RiscVInteractionClaim,
            hash_claims: [N_HASHES]Q,
            extension_claims: ExtensionClaim,
            compact: bool = false,
            compact_claims: [3]Q = @splat(Q.zero()),
            pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
                self.stark.deinit(a);
                a.destroy(self.native_claims);
                self.* = undefined;
            }
        };
        pub const Verified = @import("blake3_extension_capture.zig").ForProfile(Profile);
        pub const codec = @import("blake3_extension_codec.zig").ForProfile(Profile, @This());
        pub const Proved = struct { proof: Proof, transcript_digest: [32]u8 };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub const PreparedVerifier = @import("blake3_extension_prepared.zig").ForBackend(Profile, Backend);
                const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
                const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
                /// Non-consuming admission shared with paired-segment orchestration.
                /// Both children must pass this before either generates interactions.
                pub fn validateForProving(owner: *const Witness, prepared: *const PreparedVerifier, expected: [32]u8) !void {
                    try prepared.validate(expected);
                    const native = owner.native;
                    const hashes = owner.hashes;
                    const pin = try owner.admission();
                    if (!native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
                    if ((native.compact_ranges != null) != (prepared.ranges != null)) return error.CompactRangeProtocolNotAdmitted;
                    const actual = if (native.compact_ranges) |ranges| blk: {
                        try ranges.plan.admit(ranges.identity);
                        break :blk try (@import("compact_extension_contract.zig").ForProfile(Profile){ .native = &native.statement, .extension = &owner.statement, .ranges = ranges.plan }).identity(prepared.config, pin, hashes.logs, prepared.root);
                    } else try protocol.identity(prepared.config, &native.statement, &owner.statement, pin, hashes.logs, prepared.root);
                    if (!std.mem.eql(u8, &actual, &expected) or !std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedExecutionKey;
                }
                /// Owner is single-use after interaction generation. Prepared admission
                /// is reusable and must come from independently selected source inputs.
                pub fn prove(a: std.mem.Allocator, owner: *Witness, prepared: *PreparedVerifier, expected: [32]u8, pool: *engine.work_pool.WorkPool) !Proved {
                    var recorder = stage_profile.Recorder.initWithOptions(a, "native", "blake3-extension", .{ .capture_tasks = false });
                    defer recorder.deinit();
                    const diagnostic: ?*stage_profile.Recorder = if (std.process.hasEnvVarConstant("STWO_RISCV_EXECUTION_PROFILE")) &recorder else null;
                    var phase = try stage_profile.StageScope.begin(diagnostic, "execution.fixed", "Admission and fixed commitment");
                    defer phase.end();
                    try validateForProving(owner, prepared, expected);
                    const native = owner.native;
                    const hashes = owner.hashes;
                    const pin = try owner.admission();
                    var arena = std.heap.ArenaAllocator.init(a);
                    defer arena.deinit();
                    const scratch = arena.allocator();
                    var channel = suite.Channel{};
                    try mixStatement(&channel, prepared.config, &native.statement, &owner.statement, pin, hashes.logs, prepared.ranges);
                    var scheme = try Scheme.init(a, prepared.config);
                    // Bound coefficient retention across all three trace commitments; larger trees use LDE openings.
                    scheme.setCoefficientRetentionPolicy(.never);
                    var coefficient_budget: @import("blake3_coefficient_retention.zig").Budget = .{};
                    var owns_scheme = true;
                    defer if (owns_scheme) scheme.deinit(a);
                    var columns: std.ArrayList(Column) = .empty;
                    try columns.appendSlice(scratch, native.preprocessed.items);
                    try columns.appendSlice(scratch, hashes.preprocessed());
                    try columns.appendSlice(scratch, try Profile.preprocessed(scratch, &owner.statement));
                    coefficient_budget.configure(&scheme, columns.items);
                    try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
                    var roots = try scheme.roots(a);
                    defer roots.deinit(a);
                    try execution.admitPreprocessedRoot(prepared.root, roots.items[0]);
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.main", "Main commitment");
                    var main = try Profile.main(a, &owner.extension);
                    defer main.deinit(a);
                    columns.clearRetainingCapacity();
                    try columns.appendSlice(scratch, native.main.items);
                    if (native.compact_ranges) |ranges| try columns.appendSlice(scratch, &ranges.columns);
                    try columns.appendSlice(scratch, try hashes.main());
                    try columns.appendSlice(scratch, main.columns);
                    coefficient_budget.configure(&scheme, columns.items);
                    try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.native_interaction", "Native interaction generation");
                    const relations = try universal.UniversalRelations.draw(a, &channel);
                    const providers = try shared.SharedProviderRelations.init(&relations);
                    const extension_relations = try Relations.drawAfterBase(a, &channel, providers.native);
                    if (prepared.ranges != null) try native.generateCompactNativeInteractions(&providers.native) else try native.generateInteractions(&providers.native);
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.hash_interaction", "Hash interaction generation");
                    var hash_interaction = try hashes.interactionsForBackend(Backend, a, &relations);
                    defer hash_interaction.deinit();
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.extension_interaction", "Precompile interaction generation");
                    var extension = try Profile.interactions(a, owner, &extension_relations, pool);
                    defer extension.deinit(a);
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.interaction_commit", "Interaction closure and commitment");
                    const joined = try Joined.initWithExternal(a, &native.statement, &native.claims, relations, pin, Profile.externalCount(&owner.statement));
                    defer joined.deinit();
                    var range_owner: ?*@import("compact_range_assembly.zig").Owner = null;
                    defer if (range_owner) |owner_ranges| owner_ranges.deinit();
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
                    try execution.requireClosedWithExternal(joined, hash_interaction.claims, extension.claim.componentSum().add(rangeSum(range_claims)));
                    try mixClaims(&channel, &native.statement, &native.claims, &hash_interaction.claims, &extension.claim, prepared.ranges, range_claims, Profile.externalCount(&owner.statement));
                    columns.clearRetainingCapacity();
                    try columns.appendSlice(scratch, native.interaction.items);
                    try columns.appendSlice(scratch, range_columns.items);
                    try columns.appendSlice(scratch, hash_interaction.columns.items);
                    try columns.appendSlice(scratch, extension.columns);
                    coefficient_budget.configure(&scheme, columns.items);
                    try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
                    phase.end();
                    phase = try stage_profile.StageScope.begin(diagnostic, "execution.core", "Core STARK proof");
                    var prefix: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
                    try prefix.appendSlice(scratch, joined.proving.components.active());
                    try prefix.appendSlice(scratch, &(try hashes.provers()));
                    const components = try Assembly(.prover).createBlake3WithRanges(a, &native.statement, &owner.statement, pin, hashes.logs, &extension_relations, prefix.items, &extension.claim, prepared.ranges);
                    defer components.destroy(a);
                    const claims = try a.create(native_mod.RiscVInteractionClaim);
                    errdefer a.destroy(claims);
                    claims.* = native.claims;
                    coefficient_budget.configureComposition(&scheme, components.active());
                    owns_scheme = false;
                    var extended = try engine.prove.proveExWithRecorder(Backend, suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, scheme, false, diagnostic);
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
                    return .{ .proof = .{ .stark = stark, .key_id = expected, .native_claims = claims, .hash_claims = hash_interaction.claims, .extension_claims = extension.claim, .compact = prepared.ranges != null, .compact_claims = range_claims }, .transcript_digest = channel.digestBytes() };
                }
                /// Consumes proof on every path. No received claim selects its own key.
                pub fn verifyOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) ![32]u8 {
                    return verifyInternal(false, a, received, prepared, expected);
                }
                pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) !Verified {
                    return verifyInternal(true, a, received, prepared, expected);
                }
                fn verifyInternal(comptime capture_mode: bool, a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) !(if (capture_mode) Verified else [32]u8) {
                    var proof = received;
                    var owns_claims = true;
                    defer if (owns_claims) a.destroy(proof.native_claims);
                    var owns_stark = true;
                    defer if (owns_stark) proof.stark.deinit(a);
                    try prepared.validate(expected);
                    if (proof.compact != (prepared.ranges != null)) return error.InvalidExecutionProof;

                    if (!proof.compact) for (proof.compact_claims) |claim| {
                        if (!claim.isZero()) return error.InvalidInteractionClaim;
                    };
                    if (!std.mem.eql(u8, &proof.key_id, &expected)) return error.UntrustedExecutionKey;
                    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, prepared.config) or proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
                    try proof.extension_claims.validateCanonicalFields();
                    try proof.extension_claims.validate(&prepared.extension);
                    try execution.admitPreprocessedRoot(prepared.root, proof.stark.commitment_scheme_proof.commitments.items[0]);
                    var arena = std.heap.ArenaAllocator.init(a);
                    defer arena.deinit();
                    const scratch = arena.allocator();
                    const pin = prepared.admission();
                    const hashes = prepared.hashes.?;
                    var channel = suite.Channel{};
                    try mixStatement(&channel, prepared.config, &prepared.native, &prepared.extension, pin, hashes.logs, prepared.ranges);
                    var verifier = try Verifier.init(a, prepared.config);
                    defer verifier.deinit(a);
                    try verifier.commit(a, prepared.root, prepared.logs[0], &channel);
                    try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[1], prepared.logs[1], &channel);
                    const relations = try universal.UniversalRelations.draw(a, &channel);
                    const providers = try shared.SharedProviderRelations.init(&relations);
                    const extension_relations = try Relations.drawAfterBase(a, &channel, providers.native);
                    const joined = try Joined.initWithExternal(a, &prepared.native, proof.native_claims, relations, pin, Profile.externalCount(&prepared.extension));
                    defer joined.deinit();
                    if (prepared.range_components) |ranges| {
                        try joined.bindCompactCommitments(hashes, proof.hash_claims, ranges, proof.compact_claims);
                    } else try joined.bindCommitments(hashes, proof.hash_claims);
                    try execution.requireClosedWithExternal(joined, proof.hash_claims, proof.extension_claims.componentSum().add(rangeSum(proof.compact_claims)));
                    try mixClaims(&channel, &prepared.native, proof.native_claims, &proof.hash_claims, &proof.extension_claims, prepared.ranges, proof.compact_claims, Profile.externalCount(&prepared.extension));
                    try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[2], prepared.logs[2], &channel);
                    var prefix: std.ArrayList(core.air.components.Component) = .empty;
                    try prefix.appendSlice(scratch, joined.verifying.components.active());
                    try prefix.appendSlice(scratch, &(try hashes.verifiers()));
                    const components = try Assembly(.verifier).createBlake3WithRanges(a, &prepared.native, &prepared.extension, pin, hashes.logs, &extension_relations, prefix.items, &proof.extension_claims, prepared.ranges);
                    defer components.destroy(a);
                    owns_stark = false;
                    if (capture_mode) {
                        var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                        try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, &verifier, proof.stark, &capture);
                        errdefer capture.deinit(a);
                        var result = Verified{ .allocator = a, .key_id = expected, .proof = capture, .native_claims = proof.native_claims, .hash_claims = proof.hash_claims, .extension_claims = proof.extension_claims, .ranges = prepared.ranges, .compact_claims = proof.compact_claims, .relations = relations, .extension_draws = extension_relations.draws(), .extension_placements = components.extensionPlacements(), .final_channel = channel, .seal = undefined };
                        result.seal = try result.identity(&prepared.native);
                        owns_claims = false;
                        return result;
                    }
                    try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, &verifier, proof.stark);
                    return channel.digestBytes();
                }
            };
        }
        fn rangeSum(claims: [3]Q) Q {
            return claims[0].add(claims[1]).add(claims[2]);
        }
        fn mixStatement(channel: anytype, config: core.pcs.PcsConfig, native: *const native_mod.Blake3ExecutionStatement, extension: *const Profile.admission.Statement, pin: @import("blake3_commitment_plan.zig").Admission, logs: Profile.admission.HashLogs, ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan) !void {
            if (ranges) |compact| try (@import("compact_extension_contract.zig").ForProfile(Profile){ .native = native, .extension = extension, .ranges = compact }).mix(channel, config, pin, logs) else try protocol.mix(channel, config, native, extension, pin, logs);
        }
        fn mixClaims(channel: anytype, shape: *const native_mod.Blake3ExecutionStatement, claims: *const native_mod.RiscVInteractionClaim, hashes: []const Q, extension: *const ExtensionClaim, ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan, range_claims: [3]Q, external_count: u32) !void {
            if (ranges) |compact| try (@import("compact_execution_contract.zig").Contract{ .native = shape, .ranges = compact }).mixClaims(channel, claims, range_claims, hashes, external_count) else try base_protocol.mixClaims(channel, shape, claims, hashes);
            extension.mixInto(channel);
        }
    };
}
