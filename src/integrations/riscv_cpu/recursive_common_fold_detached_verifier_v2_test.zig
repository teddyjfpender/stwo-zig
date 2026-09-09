const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("recursive_common_fold_q193_bootstrap_v2.zig");
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");

/// Rebuild setup using children 212/213 and compare all public key bytes with
/// the saved 210/211 bootstrap key. No parent proof or capture supplies setup.
/// This checks instance invariance for these cases, not production admission.
pub fn exerciseSetup(live: *const subject.BootstrapLiveV2) !void {
    const allocator = std.testing.allocator;
    const recursion = @import("stwo_riscv_frontend").recursion;
    const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Tree = @import("recursive_binary_outer_support.zig").TreeStorageForManifest(manifest_mod);
    var cohort = try subject.SecureCohort.init(allocator, .{ .live = live });
    defer cohort.deinit();
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const generated = try cohort.rebuildGeneratedInteractions(&relations, &providers);
    var components = try cohort.initComponents(&generated, &relations, &providers);
    defer components.deinit();
    const protocol = @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1.secureParent();
    var scheme = try Engine.init(allocator, try protocol.pcsConfig());
    defer Engine.deinit(&scheme, allocator);
    var transcript = Engine.Channel{};
    var tree = try Tree.init(allocator, cohort.manifest(), manifest_mod.PREPROCESSED_TREE_INDEX);
    defer tree.deinit();
    try cohort.fillPreprocessedInto(cohort.manifest(), tree.columns);
    try tree.commit(&scheme, &transcript);
    try Engine.flushPendingCommit(&scheme, allocator, &transcript);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), roots.items.len);
    var key = verifier.Key{ .manifest = cohort.manifest().*, .preprocessed_root = roots.items[0], .parameters = undefined, .poseidon_rows = components.suffix.poseidon2.component.n_rows };
    inline for (0..18) |index| key.parameters[index] = components.logical[index].parameters;
    inline for (std.meta.fields(@TypeOf(components.suffix))[0..16], 18..) |field, index|
        key.parameters[index] = @field(components.suffix, field.name).parameters;
    _ = try key.validate();
    const transport = @import("recursive_common_fold_verifier_command_v2.zig");
    const bytes = try std.json.Stringify.valueAlloc(allocator, transport.KeyFile{ .format_version = 1, .common_fold_schema = @import("recursive_common_fold_secure_cohort_v2.zig").SCHEMA_VERSION, .key = key }, .{});
    defer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37");
    std.debug.print("COMMON_FOLD_SETUP rebuilt_children=212,213 baseline_children=210,211 key_sha256={s} parent_proof_used=false independent_key_admission=false\n", .{std.fmt.bytesToHex(actual, .lower)});
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

/// Setup is deliberately explicit and test-only. Snapshot the already verified
/// cohort's public parameters, then destroy it before entering the new verifier.
/// This tests verifier independence, not independent admission of the key.
pub fn exercise(cold: *const subject.OwnedBootstrapProofV2) !void {
    const allocator = std.testing.allocator;
    const replay = &cold.transcript.replay;
    var key: verifier.Key = undefined;
    const claims = verifier.Claims{ .values = cold.claims.values, .poseidon_partials = replay.generated.suffix.claims.poseidon2_partials };
    {
        var cohort = try subject.SecureCohort.init(allocator, .{ .live = cold.live });
        defer cohort.deinit();
        const generated = try cohort.rebuildGeneratedInteractions(&replay.relations, &replay.provider_relations);
        var components = try cohort.initComponents(&generated, &replay.relations, &replay.provider_relations);
        defer components.deinit();
        key = .{ .manifest = cohort.manifest().*, .preprocessed_root = cold.fresh.capture.commitments[0], .parameters = undefined, .poseidon_rows = components.suffix.poseidon2.component.n_rows };
        inline for (0..18) |index| key.parameters[index] = components.logical[index].parameters;
        inline for (std.meta.fields(@TypeOf(components.suffix))[0..16], 18..) |field, index|
            key.parameters[index] = @field(components.suffix, field.name).parameters;
    }
    const node = cold.live.input.outputNodePublic().*;
    const nonce = cold.artifact_value.statement.interaction_pow_nonce;
    const bytes = cold.artifact_value.proof_bytes;
    var timer = try std.time.Timer.start();
    const terminal = try verifier.verify(allocator, &key, &node, &claims, nonce, bytes);
    const verify_ns = timer.read();
    if (std.process.getEnvVarOwned(allocator, "STWO_RECURSION_VERIFIER_EXPORT_DIR")) |path| {
        defer allocator.free(path);
        const digest = try @import("recursive_common_fold_verifier_command_v2.zig").writeBundle(allocator, path, key, node, claims, nonce, bytes);
        std.debug.print("COMMON_FOLD_VERIFIER_EXPORT key_sha256={s} independent_key_admission=false\n", .{std.fmt.bytesToHex(digest, .lower)});
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }
    try std.testing.expectEqualDeep(cold.fresh.statement.transcript_id, terminal);
    var capture: verifier.ProofCapture = undefined;
    const captured_terminal = try verifier.verifyWithCapture(allocator, &key, &node, &claims, nonce, bytes, &capture);
    defer capture.deinit(allocator);
    const publication = @import("recursive_segment_v2_verified_publication.zig");
    try std.testing.expectEqualDeep(terminal, captured_terminal);
    try std.testing.expectEqualDeep(publication.captureIdentity(&cold.fresh.capture), publication.captureIdentity(&capture));
    std.debug.print("COMMON_FOLD_DETACHED_CAPTURE native_capture_matches=true rebuilt_child_cohort=false\n", .{});
    const detached = @import("recursive_common_fold_detached_transcript_v2.zig");
    var witness = try detached.Owned.init(allocator, &key, &node, &claims, nonce, bytes);
    defer witness.deinit();
    try std.testing.expectEqualDeep(cold.transcript.program.identity, witness.program.identity);
    try std.testing.expectEqualDeep(cold.transcript.execution.identity_sha256, witness.execution.identity_sha256);
    try std.testing.expectEqualDeep(cold.transcript.replay.relations, witness.relations);
    try std.testing.expectEqualDeep(cold.query_authority.query_words, witness.query_words);
    var composition = try detached.Composition.init(allocator, &witness);
    defer composition.deinit();
    try std.testing.expectEqualDeep(cold.composition_capture.circuit.identity_digest, composition.program.circuit.identity_digest);
    try std.testing.expectEqualDeep(cold.composition_capture.layout.identity, composition.layout.identity);
    try std.testing.expectEqualDeep(cold.composition_capture.bindings, composition.program.bindings);
    try std.testing.expectEqualDeep(cold.composition_capture.input_values, composition.inputs);
    try std.testing.expectEqualDeep(cold.composition_capture.node_values, composition.values);
    std.debug.print("COMMON_FOLD_DETACHED_CHILD native_transcript_graph_inputs_values_match=true grandchild_inputs=false\n", .{});
    var changed_key = key;
    changed_key.preprocessed_root[0] ^= 1;
    try std.testing.expectError(error.InvalidCommonFoldVerifierKey, verifier.verify(allocator, &changed_key, &node, &claims, nonce, bytes));
    var changed_claims = claims;
    changed_claims.values[0] = changed_claims.values[0].add(QM31.one());
    try std.testing.expectError(error.InvalidCommonFoldVerifierClosure, verifier.verify(allocator, &key, &node, &changed_claims, nonce, bytes));
    changed_claims = claims;
    changed_claims.poseidon_partials[0] = changed_claims.poseidon_partials[0].add(QM31.one());
    changed_claims.poseidon_partials[1] = changed_claims.poseidon_partials[1].sub(QM31.one());
    if (verifier.verify(allocator, &key, &node, &changed_claims, nonce, bytes)) |_| {
        return error.ChangedProviderPartialsAccepted;
    } else |_| {}
    std.debug.print("COMMON_FOLD_DETACHED_VERIFIER verify_ns={d} rebuilt_child_cohort=false transcript_matches=true changed_root_or_claims_rejected=true independent_key_admission=false\n", .{verify_ns});
}
