//! Native CPU proof evidence for authenticated resumable V2 segments.

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const M31 = stwo_core.fields.m31.M31;
const pcs_core = stwo_core.pcs;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const detached = @import("recursive_segment_v2_detached_proof.zig");
const detached_command = @import("recursive_segment_v2_detached_command.zig");
const detached_verifier = @import("recursive_segment_v2_detached_verifier.zig");
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const verified_link_v3 = frontend.recursion.segment_leaf_local_verified_link_v3;
const span = frontend.recursion.span_statement;
const Engine = prover.ProverEngineForBackend(CpuBackend);

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 1,
    },
};

test "native V2 proves and independently verifies real nonfinal and final segments" {
    try nativeSegments(Engine, "blake2s-default");
}
test "native q193 re-proves an AIR-valid hostile Tree0 and rejects its root" {
    try nativeSegmentsMode(frontend.recursion.engine.ProverEngineForBackend(CpuBackend), "poseidon-q193", false);
}
test "BLAKE3 V2 segment proofs verify nonfinal capture and final completion" {
    try nativeSegments(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1");
}
test "native BLAKE3 arithmetic fusion census" {
    try nativeSegmentsMode(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1", true);
}
fn nativeSegments(comptime ProofEngine: type, comptime suite_name: []const u8) !void {
    return nativeSegmentsMode(ProofEngine, suite_name, false);
}
fn nativeSegmentsMode(comptime ProofEngine: type, comptime suite_name: []const u8, comptime audit_only: bool) !void {
    const allocator = std.testing.allocator;
    const pcs_config = if (comptime ProofEngine.Hasher == frontend.recursion.engine.Hasher)
        protocol.PCS_CONFIG
    else
        test_config;
    std.debug.print("\nV2_NATIVE_PROOF_SUITE suite={s} queries={d} pow_bits={d}\n", .{ suite_name, pcs_config.fri_config.n_queries, pcs_config.pow_bits });
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-segment-v2-poseidon-witness",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    // This repository-owned ELF carries exact __text_start/__text_len symbols,
    // so every segment commits the same complete declared program rather than
    // a segment-local fetch subset.  No CUSTOM-0 call is retired here.
    const elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );

    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    const left_result = &left_profile.base;
    var right_profile = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_profile.deinit();
    const right_result = &right_profile.base;

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        left_result.execution_trace.rows.items,
        left_result.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const public_input = digest("native-v2-input");
    const public_output = digest("native-v2-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        digest("native-v2-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        digest("native-v2-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        digest("native-v2-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const left_span = try leafStatement(
        job,
        left_result,
        initial_state,
        shared_state,
        try span.EdgeClaim.present(public_input),
        span.EdgeClaim.absent(),
    );
    const right_span = try leafStatement(
        job,
        right_result,
        shared_state,
        final_state,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(public_output),
    );
    const session_id = digest("native-v2-session");
    const left_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        left_span,
        left_result,
    );
    const right_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        right_span,
        right_result,
    );
    try segment_v2.requireAdjacentSources(&left_source, &right_source);

    const left_words = try encode(allocator, &left_source);
    defer allocator.free(left_words);
    const right_words = try encode(allocator, &right_source);
    defer allocator.free(right_words);
    const left_public = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        left_words,
    );
    const right_public = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        right_words,
    );
    _ = try frontend.air.public_data_v2.PublicDataV2.authenticateAdjacent(
        &left_public,
        &right_public,
    );

    // Keep deterministic ingress mutations before the first expensive proof.
    // The authenticated wire owns this rejection; the V2 statement envelope
    // subsequently consumes only a validated `PublicDataV2`.
    const saved_word = left_words[segment_v2.fixed_layout.position_id];
    left_words[segment_v2.fixed_layout.position_id] = M31.fromCanonical(
        saved_word.toU32() ^ 1,
    );
    try std.testing.expectError(error.DigestMismatch, left_public.validate());
    left_words[segment_v2.fixed_layout.position_id] = saved_word;
    try left_public.validate();

    var left_prove_timer = try std.time.Timer.start();
    var left_output = try prover.proveRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        pcs_config,
        left_result,
        &recorder,
        left_public,
    );
    const left_prove_ns = left_prove_timer.read();
    const left_proof_size = left_output.proof.sizeEstimate();
    var left_proof_moved = false;
    defer if (left_proof_moved)
        left_output.deinitAfterProofMoved(allocator)
    else
        left_output.deinit(allocator);
    try left_output.statement.validateSegmentResult(left_result);
    try std.testing.expect(!(try left_output.statement.metadata()).is_final);
    if (comptime !audit_only) {
        // This is a genuinely re-proved Tree 0, not a mutation of serialized
        // proof bytes. The bitwise row with operation 3 is never requested by
        // this guest, so changing its fixed tuple preserves native AIR
        // satisfaction while changing the canonical table commitment.
        const core_statement = &left_output.statement.core;
        var bitwise_rows: ?u32 = null;
        for (core_statement.infra_descs[0..core_statement.n_infra]) |desc| {
            if (desc.kind == .bitwise) bitwise_rows = desc.n_rows;
        }
        const bitwise_row = (bitwise_rows orelse return error.MissingBitwiseTable) - 1;
        var hostile_channel = ProofEngine.Channel{};
        var hostile = try prover.proveRiscVSegmentV2WithEngineUsingChannelAndExecution(
            ProofEngine,
            allocator,
            pcs_config,
            left_result,
            null,
            left_public,
            &hostile_channel,
            .{ .test_preprocessed_mutation = .{ .preprocessed = .{
                .target = .{ .infrastructure = .{ .kind = .bitwise } },
                .column = 1,
                .logical_row = bitwise_row,
            } } },
        );
        var hostile_proof_moved = false;
        defer if (hostile_proof_moved)
            hostile.deinitAfterProofMoved(allocator)
        else
            hostile.deinit(allocator);
        const honest_root = left_output.proof.commitment_scheme_proof.commitments.items[0];
        const hostile_root = hostile.proof.commitment_scheme_proof.commitments.items[0];
        try std.testing.expect(!std.meta.eql(honest_root, hostile_root));
        try std.testing.expectEqualDeep(left_output.statement, hostile.statement);
        if (comptime ProofEngine.Hasher == frontend.recursion.engine.Hasher) {
            // Copy through canonical serialization. Only the test verifier
            // omits the independent Tree 0 comparison; every remaining native
            // AIR/PCS/FRI check runs against this separately decoded proof.
            var hostile_bytes: std.ArrayList(u8) = .empty;
            defer hostile_bytes.deinit(allocator);
            try postcard.serializeProof(
                ProofEngine.Hasher,
                hostile_bytes.writer(allocator),
                hostile.proof,
            );
            var hostile_stream = std.io.fixedBufferStream(hostile_bytes.items);
            var hostile_copy = try postcard.deserializeProof(
                ProofEngine.Hasher,
                allocator,
                hostile_stream.reader(),
            );
            var hostile_copy_moved = false;
            defer if (!hostile_copy_moved) hostile_copy.deinit(allocator);
            try std.testing.expectEqual(hostile_bytes.items.len, hostile_stream.pos);
            var captured: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
            var capture_channel = ProofEngine.Channel{};
            hostile_copy_moved = true;
            try frontend.testing.verifySegmentV2HostileTree0CaptureForTest(
                ProofEngine,
                allocator,
                pcs_config,
                hostile.statement,
                hostile_copy,
                hostile.interaction_claim,
                &capture_channel,
                &captured,
            );
            var captured_moved = false;
            defer if (!captured_moved) captured.deinit(allocator);
            try captured.validate();
            try std.testing.expectEqualDeep(hostile_root, captured.proof.commitments[0]);
            const canonical_root = try prover.preprocessed.rootForDescriptors(
                ProofEngine,
                allocator,
                pcs_config,
                core_statement.component_descs[0..core_statement.n_components],
                core_statement.infra_descs[0..core_statement.n_infra],
            );
            try std.testing.expectEqualDeep(honest_root, canonical_root);
            try std.testing.expectError(
                error.InvalidNativePreprocessedCommitment,
                leaf_outer.validateNativeTree0(
                    &captured,
                    canonical_root,
                ),
            );
            // The test-only native capture bypasses native Tree-0 admission
            // after all other native checks. The ordinary recursive leaf
            // preparation must still reject it against the independent
            // canonical root before it can construct an outer proof. The
            // plans are intentionally never dereferenced on this path.
            const keys = try frontend.recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
                digest("hostile-tree0-segment-key"),
                digest("hostile-tree0-parent-key"),
            );
            try std.testing.expectError(
                error.InvalidNativePreprocessedCommitment,
                leaf_outer.PreparedNativeV2LeafOuter.init(
                    allocator,
                    allocator,
                    &captured,
                    pcs_config,
                    hostile.interaction_claim.interaction_pow,
                    keys,
                    canonical_root,
                    frontend.recursion.air.universal_challenges.UniversalRelations.dummy(),
                    .{ .vm = undefined, .recursion = undefined },
                ),
            );
            // An optional test export carries the *fully re-proved* hostile
            // native capture through outer proving under its own Tree-0 root.
            // Production key admission must reject the resulting outer
            // candidate after independently rebuilding the native root from
            // descriptors. The retained bundle can also be replayed by the
            // standalone verifier in a separate process.
            const export_dir: ?[]u8 = std.process.getEnvVarOwned(
                allocator,
                "STWO_RISCV_HOSTILE_TREE0_EXPORT_DIR",
            ) catch |err| switch (err) {
                error.EnvironmentVariableNotFound => null,
                else => return err,
            };
            if (export_dir) |directory| {
                defer allocator.free(directory);
                var prepared = try prepareHostileCapture(
                    allocator,
                    &captured,
                    pcs_config,
                    hostile.interaction_claim.interaction_pow,
                    keys,
                    hostile_root,
                );
                captured_moved = true;
                defer prepared.deinit();
                var candidate = try detached.produceWithProfile(
                    allocator,
                    &prepared,
                    null,
                    .recursive_q193_v1,
                );
                defer candidate.deinit();
                // The outer proof itself must be internally valid. Only this
                // test uses a self-pinned key without canonical-root admission.
                const candidate_pin = detached_command.hash(candidate.key_json);
                var self_pinned = try detached_command.OwnedKeyV1.admit(
                    allocator,
                    candidate.key_json,
                    candidate_pin,
                );
                defer self_pinned.deinit();
                _ = try detached_verifier.verify(
                    allocator,
                    self_pinned.key(),
                    &prepared.capture.public_data.data,
                    candidate.claims,
                    candidate.proof_bytes,
                );
                const hashes = try detached_command.retainCandidate(
                    allocator,
                    directory,
                    candidate.key_json,
                    candidate.claims,
                    candidate.proof_bytes,
                );
                const expected_json = try detached_command.encodeExpected(
                    allocator,
                    &prepared.capture.public_data.data,
                );
                defer allocator.free(expected_json);
                var export_directory = try std.fs.cwd().openDir(directory, .{});
                defer export_directory.close();
                var expected_file = try export_directory.createFile(
                    "expected-wire.json",
                    .{ .exclusive = true },
                );
                defer expected_file.close();
                try expected_file.writeAll(expected_json);
                const native_statement_json = try std.json.Stringify.valueAlloc(
                    allocator,
                    .{
                        .format_version = hostile.statement.format_version,
                        .schema_version = hostile.statement.schema_version,
                        .core = .{
                            .n_components = hostile.statement.core.n_components,
                            .component_descs = hostile.statement.core.component_descs[0..hostile.statement.core.n_components],
                            .initial_pc = hostile.statement.core.initial_pc,
                            .final_pc = hostile.statement.core.final_pc,
                            .total_steps = hostile.statement.core.total_steps,
                            .public_data = hostile.statement.core.public_data,
                            .x0_local_custody_version = hostile.statement.core.x0_local_custody_version,
                            .n_infra = hostile.statement.core.n_infra,
                            .infra_descs = hostile.statement.core.infra_descs[0..hostile.statement.core.n_infra],
                        },
                        .authority_id = hostile.statement.authority_id,
                        .expected_wire_sha256 = detached_command.hash(expected_json),
                    },
                    .{},
                );
                defer allocator.free(native_statement_json);
                const native_claim_json = try std.json.Stringify.valueAlloc(
                    allocator,
                    hostile.interaction_claim.*,
                    .{},
                );
                defer allocator.free(native_claim_json);
                for ([_]struct { name: []const u8, bytes: []const u8 }{
                    .{ .name = "hostile-native-proof.bin", .bytes = hostile_bytes.items },
                    .{ .name = "hostile-native-statement.json", .bytes = native_statement_json },
                    .{ .name = "hostile-native-claim.json", .bytes = native_claim_json },
                }) |artifact| {
                    var file = try export_directory.createFile(artifact.name, .{ .exclusive = true });
                    defer file.close();
                    try file.writeAll(artifact.bytes);
                }
                try std.testing.expectError(
                    error.InvalidNativePreprocessedCommitment,
                    detached_command.OwnedKeyV1.admitWithNativeRoot(
                        ProofEngine,
                        allocator,
                        candidate.key_json,
                        hashes.key_sha256,
                    ),
                );
                std.debug.print(
                    "HOSTILE_TREE0_OUTER_CANDIDATE directory={s} key_sha256={s} proof_sha256={s} native_proof_sha256={s} proof_bytes={d} self_pinned_outer_verified=true\n",
                    .{ directory, std.fmt.bytesToHex(hashes.key_sha256, .lower), std.fmt.bytesToHex(hashes.proof_sha256, .lower), std.fmt.bytesToHex(detached_command.hash(hostile_bytes.items), .lower), hashes.proof_bytes },
                );
            }
        }
        hostile_proof_moved = true;
        try std.testing.expectError(
            error.InvalidPreprocessedCommitment,
            prover.verifyRiscVSegmentV2WithEngine(
                ProofEngine,
                allocator,
                pcs_config,
                hostile.statement,
                hostile.proof,
                hostile.interaction_claim,
            ),
        );
    }
    // The focused q193 gate verifies its honest control before exiting. The
    // remaining checks below exercise the separate two-segment fixture.
    if (comptime ProofEngine.Hasher == frontend.recursion.engine.Hasher) {
        left_proof_moved = true;
        try prover.verifyRiscVSegmentV2WithEngine(
            ProofEngine,
            allocator,
            pcs_config,
            left_output.statement,
            left_output.proof,
            left_output.interaction_claim,
        );
        return;
    }
    const work = recorder.workCaptureRecorder() orelse unreachable;
    const poseidon_site = @intFromEnum(
        prover_api.work_profile.Site.sparse_memory_and_guest_poseidon_witness,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[poseidon_site]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[poseidon_site]);
    const work_snapshot = try recorder.workSnapshot();
    try work_snapshot.validate();

    // Preserve a real proof for the failure-atomic mutation gate without
    // proving twice: canonical postcard decoding owns an independent copy.
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        ProofEngine.Hasher,
        proof_bytes.writer(allocator),
        left_output.proof,
    );
    if (comptime ProofEngine.Hasher != prover.Hasher and
        ProofEngine.Hasher != frontend.recursion.engine.Hasher)
    {
        var wrong_stream = std.io.fixedBufferStream(proof_bytes.items);
        const wrong_suite_proof = try postcard.deserializeProof(prover.Hasher, allocator, wrong_stream.reader());
        try std.testing.expectError(error.InvalidPreprocessedCommitment, prover.verifyRiscVSegmentV2WithEngine(Engine, allocator, pcs_config, left_output.statement, wrong_suite_proof, left_output.interaction_claim));
    }
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var mutated_proof = try postcard.deserializeProof(
        ProofEngine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var mutated_proof_moved = false;
    defer if (!mutated_proof_moved) mutated_proof.deinit(allocator);
    try std.testing.expectEqual(proof_bytes.items.len, proof_stream.pos);

    var bad_version = left_output.statement;
    bad_version.format_version +%= 1;
    var capture_sentinel: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
    @memset(std.mem.asBytes(&capture_sentinel), 0xa5);
    var before: [@sizeOf(@TypeOf(capture_sentinel))]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&capture_sentinel));
    var rejected_channel = ProofEngine.Channel{};
    mutated_proof_moved = true;
    try std.testing.expectError(
        error.InvalidStatement,
        prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
            ProofEngine,
            allocator,
            pcs_config,
            bad_version,
            mutated_proof,
            left_output.interaction_claim,
            &rejected_channel,
            &capture_sentinel,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&capture_sentinel),
    );

    // F1 regression: shifting mass between two batch claims of one opcode
    // component keeps every canonical aggregate (and the global LogUp
    // cancellation) unchanged. The per-batch transcript frame mixed before
    // Tree 2 must still reject the proof on its own.
    {
        const QM31 = stwo_core.fields.qm31.QM31;
        const manifest = frontend.air.lookup_physical_manifest_v2.Manifest.native();
        const core_statement = &left_output.statement.core;
        var shifted_component: ?usize = null;
        for (core_statement.component_descs[0..core_statement.n_components], 0..) |desc, index| {
            if (manifest.entryForFamily(desc.family).detailed_claim_count >= 2) {
                shifted_component = index;
                break;
            }
        }
        const component_index = shifted_component orelse return error.NoMultiBatchComponent;
        const shifted = try allocator.create(prover.RiscVInteractionClaim);
        defer allocator.destroy(shifted);
        shifted.* = left_output.interaction_claim.*;
        const delta = QM31.fromU32Unchecked(0x1234_5678, 0x0f0f_0f0f, 7, 11);
        shifted.opcode_claims[component_index][0] =
            shifted.opcode_claims[component_index][0].add(delta);
        shifted.opcode_claims[component_index][1] =
            shifted.opcode_claims[component_index][1].sub(delta);
        const honest_canonical = try allocator.create(frontend.air.statement.CanonicalInteractionClaim);
        defer allocator.destroy(honest_canonical);
        honest_canonical.* = try left_output.interaction_claim.canonical(core_statement);
        const shifted_canonical = try allocator.create(frontend.air.statement.CanonicalInteractionClaim);
        defer allocator.destroy(shifted_canonical);
        shifted_canonical.* = try shifted.canonical(core_statement);
        try std.testing.expectEqual(honest_canonical.claimed_sums, shifted_canonical.claimed_sums);

        var shifted_stream = std.io.fixedBufferStream(proof_bytes.items);
        const shifted_proof = try postcard.deserializeProof(
            ProofEngine.Hasher,
            allocator,
            shifted_stream.reader(),
        );
        try std.testing.expectEqual(proof_bytes.items.len, shifted_stream.pos);
        if (prover.verifyRiscVSegmentV2WithEngine(
            ProofEngine,
            allocator,
            pcs_config,
            left_output.statement,
            shifted_proof,
            shifted,
        )) |_| {
            return error.ExpectedShiftedBatchClaimRejection;
        } else |err| {
            std.debug.print(
                "V2_NATIVE_PROOF_SUITE shifted batch claim rejected component={d} err={s}\n",
                .{ component_index, @errorName(err) },
            );
        }
    }

    var left_capture: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
    var left_channel = ProofEngine.Channel{};
    left_proof_moved = true;
    var left_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        ProofEngine,
        allocator,
        pcs_config,
        left_output.statement,
        left_output.proof,
        left_output.interaction_claim,
        &left_channel,
        &left_capture,
    );
    const left_verify_ns = left_verify_timer.read();
    defer left_capture.deinit(allocator);
    try left_capture.validate();
    try std.testing.expectEqual(left_public.wireId(), left_capture.receipt.wire_id);
    try std.testing.expectEqual(
        left_output.statement.authority_id,
        left_capture.receipt.authority_id,
    );
    try std.testing.expect(!left_capture.receipt.is_final);
    try std.testing.expect(
        left_capture.public_data.canonical_words.ptr != left_words.ptr,
    );
    // The BLAKE3 native-parent transcript/preparation/pipeline leg was retired
    // with the archived recursion exports (recursion.blake3_native_parent_*).
    try left_capture.vm_air.validate();
    try left_capture.public_data.data.validate();
    const captured_relations = frontend.air.relation_challenges.Relations
        .fromDrawSequence(&left_capture.vm_air.relation_draws);
    try left_capture.native_public_sums.validateAgainst(
        &left_capture.public_data.data,
        &captured_relations,
    );
    const saved_sums_identity = left_capture.native_public_sums.identity[0];
    left_capture.native_public_sums.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidNativePublicSums,
        left_capture.native_public_sums.validateAgainst(
            &left_capture.public_data.data,
            &captured_relations,
        ),
    );
    left_capture.native_public_sums.identity[0] = saved_sums_identity;
    try left_capture.validate();
    const saved_receipt_identity = left_capture.receipt.identity[0];
    left_capture.receipt.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifiedReceipt,
        left_capture.validate(),
    );
    left_capture.receipt.identity[0] = saved_receipt_identity;
    try left_capture.validate();

    var right_prove_timer = try std.time.Timer.start();
    var right_output = try prover.proveRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        pcs_config,
        right_result,
        null,
        right_public,
    );
    const right_prove_ns = right_prove_timer.read();
    const right_proof_size = right_output.proof.sizeEstimate();
    var right_proof_moved = false;
    defer if (right_proof_moved)
        right_output.deinitAfterProofMoved(allocator)
    else
        right_output.deinit(allocator);
    try right_output.statement.validateSegmentResult(right_result);
    // A resumed V2 segment authenticates its nonzero origin through the
    // statement. A self-consistent local trace range cannot replace it.
    const trace = &right_profile.base.execution_trace;
    const saved_origin = trace.clock_origin;
    const saved_last = trace.last_retirement_clock;
    try std.testing.expect(saved_origin > 0);
    try trace.bindExtractedClockRange(0, @intCast(right_result.cycle_count), 0);
    try std.testing.expectError(
        error.SegmentResultMismatch,
        right_output.statement.validateSegmentResult(right_result),
    );
    try trace.bindExtractedClockRange(saved_origin, saved_last, 0);
    const saved_first_row_clock = trace.rows.items[0].clk;
    trace.rows.items[0].clk = 1;
    try std.testing.expectError(
        error.SegmentResultMismatch,
        right_output.statement.validateSegmentResult(right_result),
    );
    trace.rows.items[0].clk = saved_first_row_clock;
    try right_output.statement.validateSegmentResult(right_result);
    const right_metadata = try right_output.statement.metadata();
    try std.testing.expect(right_metadata.is_final);
    try std.testing.expect(right_metadata.completion != null);
    right_proof_moved = true;
    var right_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        pcs_config,
        right_output.statement,
        right_output.proof,
        right_output.interaction_claim,
    );
    const right_verify_ns = right_verify_timer.read();

    std.debug.print(
        "\nV2_NATIVE_PROOF nonfinal cycles={d} proof_estimate={d} " ++
            "wire_bytes={d} prove_ms={d:.3} verify_capture_ms={d:.3}\n",
        .{
            left_result.cycle_count,
            left_proof_size,
            proof_bytes.items.len,
            milliseconds(left_prove_ns),
            milliseconds(left_verify_ns),
        },
    );
    printDigest("nonfinal_wire_id", left_capture.receipt.wire_id);
    printDigest("nonfinal_authority_id", left_capture.receipt.authority_id);
    printDigest(
        "nonfinal_relation_context_id",
        left_capture.native_public_sums.relation_context_id,
    );
    printDigest("nonfinal_native_sums_id", left_capture.native_public_sums.identity);
    std.debug.print(
        "V2_NATIVE_PROOF final cycles={d} proof_estimate={d} " ++
            "prove_ms={d:.3} verify_ms={d:.3}\n",
        .{
            right_result.cycle_count,
            right_proof_size,
            milliseconds(right_prove_ns),
            milliseconds(right_verify_ns),
        },
    );
    printDigest("final_wire_id", right_public.wireId());
    printDigest("final_authority_id", right_output.statement.authority_id);
}

test "native V2 proves a rebased leaf-local V3 segment without widening the AIR" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    var right_profile = try session.resumeSegment(
        left_profile.base.continuation.?,
        16,
    );
    defer right_profile.deinit();
    const left_result = &left_profile.base;
    const right_result = &right_profile.base;

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        right_result.execution_trace.rows.items,
        right_result.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
    const public_input = digest("native-local-v3-input");
    const public_output = digest("native-local-v3-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        digest("native-local-v3-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const right_global_statement = try leafStatement(
        job,
        right_result,
        shared_state,
        final_state,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(public_output),
    );
    const right_global = try global_v3.SourceV3.fromSegmentResult(
        right_global_statement,
        right_result,
    );
    var projection = try projection_v3.ProjectionV3.init(&right_global);
    const local_source = try projection.sourceV2(
        &right_global,
        digest("native-local-v3-session"),
    );
    const words = try encode(allocator, &local_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );
    const global_metadata = try right_global.metadata();
    const local_metadata = try public_data.metadata();
    try std.testing.expect(global_metadata.global_cycle_start > 0);
    try std.testing.expectEqual(@as(u32, 0), local_metadata.global_cycle_start);
    try std.testing.expectEqual(
        global_metadata.local_cycle_count,
        local_metadata.global_cycle_end,
    );

    var output = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        &projection.local_result,
        null,
        public_data,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);
    try output.statement.validateSegmentResult(&projection.local_result);
    try std.testing.expectError(
        error.ClockFrameMismatch,
        output.statement.validateSegmentResult(right_result),
    );
    var capture: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.proof,
        output.interaction_claim,
        &verify_channel,
        &capture,
    );
    defer capture.deinit(allocator);
    try capture.validate();
    const link = try verified_link_v3.VerifiedLinkV3.init(
        &global_metadata,
        &capture.public_data.data,
        &capture.receipt,
    );
    try link.validateAgainst(
        &global_metadata,
        &capture.public_data.data,
        &capture.receipt,
    );
    var forged_link = link;
    forged_link.global_cycle_start += 1;
    try std.testing.expectError(
        error.InvalidVerifiedLink,
        forged_link.validateAgainst(
            &global_metadata,
            &capture.public_data.data,
            &capture.receipt,
        ),
    );
    // Reuse the same immutable cold-wire admission in the real global link.
    // Unleased public values keep their full authentication behavior.
    const Public = frontend.air.public_data_v2.PublicDataV2;
    const owned_words = try allocator.dupe(M31, capture.public_data.data.words());
    var counters = Public.ValidationCountersV2{};
    var lease = Public.OwnedValidatedLeaseV2.adoptCold(allocator, owned_words, &counters) catch |err| {
        allocator.free(owned_words);
        return err;
    };
    defer lease.deinit();
    const leased_link = try verified_link_v3.VerifiedLinkV3.init(&global_metadata, lease.data(), &capture.receipt);
    try std.testing.expectEqualDeep(link, leased_link);
    const before = counters.snapshot();
    for (0..8) |_| try leased_link.validateAgainst(&global_metadata, lease.data(), &capture.receipt);
    const after = counters.snapshot();
    // Each link validation checks local data, receipt metadata and the actual
    // projected view through the existing owner. A raw-wire bypass loses the
    // third reuse and repeats sparse root authentication instead.
    try std.testing.expectEqual(before.cached_view_reuses + 24, after.cached_view_reuses);
    try std.testing.expectEqual(@as(u64, 1), after.legacy_full_authentications);
    var substituted = lease.data().*;
    substituted.canonical_words = capture.public_data.data.words();
    try std.testing.expectError(error.SourceMutation, leased_link.validateAgainst(&global_metadata, &substituted, &capture.receipt));
    substituted = lease.data().*;
    substituted.authenticated_wire_id[0] ^= 1;
    try std.testing.expectError(error.SourceMutation, leased_link.validateAgainst(&global_metadata, &substituted, &capture.receipt));
    try projection.validateAgainst(&right_global);
}

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    if (result.global_first_cycle == 0) return error.InvalidGlobalCycle;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            input,
            output,
        ),
    );
}

fn prepareHostileCapture(
    allocator: std.mem.Allocator,
    captured: *leaf_outer.NativeCapture,
    pcs_config: pcs_core.PcsConfig,
    interaction_pow: u64,
    keys: frontend.recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
    hostile_root: leaf_outer.Digest,
) !leaf_outer.PreparedNativeV2LeafOuter {
    const recursion = frontend.recursion;
    const schedule = recursion.air.verifier_schedule;
    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(pcs_config),
        &captured.proof,
    );
    defer profile.deinit();
    if (profile.trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT)
        return error.InvalidProofShape;
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .physical_claimed_sum_count = @intCast(captured.vm_air.detailed_claims.len),
            .physical_component_count = @intCast(captured.vm_air.component_descs.len),
            .physical_infra_count = @intCast(captured.vm_air.infra_descs.len),
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    defer recursion_plan.deinit();
    return leaf_outer.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        captured,
        pcs_config,
        interaction_pow,
        keys,
        hostile_root,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
}

fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4e56_3250); // "NV2P"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn printDigest(label: []const u8, value: channel.Digest) void {
    std.debug.print("  {s}=", .{label});
    for (value) |word| std.debug.print("{x:0>8}", .{word});
    std.debug.print("\n", .{});
}
