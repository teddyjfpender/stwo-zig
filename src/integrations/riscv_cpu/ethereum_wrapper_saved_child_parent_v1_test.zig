//! Actual saved wrapper children 2/3 -> existing Ethereum common-fold proof.
//! A tiny generated test root calls run with the measured fixed dimensions.
//! The dimensions select storage only: separately pinned child keys and full
//! child verification remain mandatory. No native leaf inputs are loaded.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const adapter_mod = @import("ethereum_wrapper_detached_fold_v1.zig");
const child_transport = @import("ethereum_wrapper_root_command_v1.zig");
const child_shape = @import("ethereum_wrapper_child_shape_v1.zig");
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const transport = @import("recursive_common_fold_verifier_command_v2.zig");
const public = @import("recursive_field_node_public_v2.zig");
const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
const cohort_mod = @import("recursive_common_fold_secure_cohort_v2.zig");
const engine = @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const runtime = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
const native_scope = @import("ethereum_native_verification_scope_v1.zig");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");

pub fn run(comptime dimensions: recursion.fixed_wire.Dimensions) !void {
    @setEvalBranchQuota(50_000_000);
    const Adapter = adapter_mod.Types(dimensions);
    const Kernel = engine.EngineKernelForManifest(Adapter.Cohort, manifest, .common_fold_field_v2);
    const allocator = std.testing.allocator;
    const left_dir = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PARENT_LEFT_DIR");
    defer allocator.free(left_dir);
    const right_dir = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PARENT_RIGHT_DIR");
    defer allocator.free(right_dir);
    const output = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PARENT_OUTPUT_DIR");
    defer allocator.free(output);
    const left_pin = try keyPin(allocator, "STWO_ETHEREUM_PARENT_LEFT_KEY_SHA256");
    const right_pin = try keyPin(allocator, "STWO_ETHEREUM_PARENT_RIGHT_KEY_SHA256");
    const left_proof_pin = try keyPin(allocator, "STWO_ETHEREUM_PARENT_LEFT_PROOF_SHA256");
    const right_proof_pin = try keyPin(allocator, "STWO_ETHEREUM_PARENT_RIGHT_PROOF_SHA256");
    var producer = runtime.TrackedSmpAllocatorV4{};
    defer producer.requireEmpty() catch @panic("saved-child parent producer ownership leak");
    var parent_pin: [32]u8 = undefined;
    var expected_terminal: [8]u32 = undefined;
    var expected_node: public.NodePublicV2 = undefined;
    var child_nodes: [2]public.NodePublicV2 = undefined;
    var timer = try std.time.Timer.start();
    {
        const owned_allocator = producer.allocator();
        const left = try loadChild(Adapter, dimensions, owned_allocator, left_dir, left_pin, left_proof_pin, 2, &child_nodes[0]);
        defer left.deinit();
        const right = try loadChild(Adapter, dimensions, owned_allocator, right_dir, right_pin, right_proof_pin, 3, &child_nodes[1]);
        defer right.deinit();
        const live = try Adapter.Live.init(.{ left, right });
        expected_node = live.input.node;
        try std.testing.expectEqual(@as(u8, 1), expected_node.coordinate.height);
        try std.testing.expectEqual(@as(u32, 1), expected_node.coordinate.index);
        try std.testing.expectError(error.CommonFoldPublicInputMismatch, Adapter.Live.init(.{ right, left }));
        try std.testing.expectError(error.CommonFoldPublicInputMismatch, Adapter.Live.init(.{ left, left }));
        try rejectChangedChildBoundaries(&child_nodes, expected_node.coordinate);
        var cohort = blk: {
            var scope: native_scope.ScopeV1 = undefined;
            try scope.initInPlace(1);
            defer scope.deinit();
            break :blk try Adapter.Cohort.initEthereumDetachedFold(owned_allocator, .{ .live = &live });
        };
        defer cohort.deinit();
        const key = try cohort.ethereumDetachedVerifierKey();
        const session = try cohort.session();
        // The cohort has already derived its admitted Tree0. Report the
        // full proving PCS floor before allocating any of that request's trees.
        try @import("ethereum_wrapper_resources_v1.zig").reportPlan(manifest, cohort.manifest(), session.protocol.fri_log_blowup_factor, .never);
        // Freeze the independently prepared AIR key before any candidate
        // commitment exists, using the existing verifier transport encoding.
        const key_json = try std.json.Stringify.valueAlloc(owned_allocator, transport.EthereumKeyFile{ .format_version = 1, .common_fold_schema = cohort_mod.SCHEMA_VERSION, .key = key }, .{});
        defer owned_allocator.free(key_json);
        parent_pin = child_transport.hash(key_json);
        // Admit the exact serialized key through the consumer before proving;
        // transport limits or schema mismatches must fail before expensive work.
        _ = try transport.decodeEthereumKey(owned_allocator, key_json, parent_pin);
        try std.fs.cwd().makePath(output);
        var output_dir = try std.fs.cwd().openDir(output, .{});
        defer output_dir.close();
        try runtime.writeReplayFile(output_dir, "admitted-key.json", key_json);
        const pins_json = try std.json.Stringify.valueAlloc(owned_allocator, .{ .version = @as(u32, 1), .left_key_sha256 = left_pin, .right_key_sha256 = right_pin, .left_proof_sha256 = left_proof_pin, .right_proof_sha256 = right_proof_pin, .parent_key_sha256 = parent_pin, .left_index = @as(u32, 2), .right_index = @as(u32, 3), .dimensions = dimensions }, .{});
        defer owned_allocator.free(pins_json);
        try runtime.writeReplayFile(output_dir, "admission.json", pins_json);
        std.debug.print("ETHEREUM_SAVED_CHILD_PARENT_ADMITTED coordinate=1/1 child_coordinates=0/2,0/3 native_inputs=false worker_count=1 key_sha256={x} preparation_ns={d}\n", .{ parent_pin, timer.read() });
        var transaction = try Kernel.proveAndColdVerifyWithReplay(owned_allocator, &cohort, session, .{ .worker_count = 1 });
        defer transaction.deinit();
        const result = &transaction.result;
        const replay = &transaction.replay;
        const claims: verifier.Claims = .{ .values = replay.claims.values, .poseidon_partials = replay.generated.suffix.claims.poseidon2_partials };
        expected_terminal = result.fresh.statement.transcript_id;
        const written_pin = try transport.writeEthereumBundle(owned_allocator, output, key, expected_node, claims, result.artifact.statement.interaction_pow_nonce, result.artifact.proof_bytes);
        try std.testing.expectEqualDeep(parent_pin, written_pin);
        std.debug.print("ETHEREUM_SAVED_CHILD_PARENT_PROVED prove_ns={d} cold_verify_ns={d} proof_bytes={d}\n", .{ result.receipt.prove_ns, result.receipt.cold_verify_ns, result.artifact.proof_bytes.len });
    }
    // Every producer and child allocation is gone. Reopen only durable bytes
    // and the key hash admitted before proving; no old capture can be reused.
    try producer.requireEmpty();
    var dir = try std.fs.cwd().openDir(output, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", 1024 * 1024);
    defer allocator.free(key_json);
    const fresh_key = try transport.decodeEthereumKey(allocator, key_json, parent_pin);
    const inputs_json = try dir.readFileAlloc(allocator, "inputs.json", 1024 * 1024);
    defer allocator.free(inputs_json);
    const inputs = try transport.decodeInputs(allocator, inputs_json);
    try std.testing.expectEqualDeep(expected_node, inputs.node);
    const proof = try dir.readFileAlloc(allocator, "proof.bin", artifact.MAX_CANONICAL_PROOF_BYTES);
    defer allocator.free(proof);
    if (proof.len != inputs.proof_bytes or !std.meta.eql(child_transport.hash(proof), inputs.proof_sha256)) return error.VerifierProofIdentityMismatch;
    var scope: native_scope.ScopeV1 = undefined;
    try scope.initInPlace(1);
    defer scope.deinit();
    const terminal = try fresh_key.verify(allocator, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof);
    try std.testing.expectEqualDeep(expected_terminal, terminal);
    const M31 = @import("stwo_core").fields.m31.M31;
    var malformed = inputs.node;
    malformed.output_digest[0] = M31.fromCanonical(malformed.output_digest[0]).add(M31.one()).toU32();
    try std.testing.expectError(error.InvalidFieldNodePublic, fresh_key.verify(allocator, &malformed, &inputs.claims, inputs.interaction_pow_nonce, proof));
    // Derive a canonical parent from an altered saved child's source. Its
    // coverage and continuation still agree, so the same parent proof must
    // reject through cryptographic binding, not malformed public inputs.
    var changed_source = child_nodes[1].source_digest;
    changed_source[0] = M31.fromCanonical(changed_source[0]).add(M31.one()).toU32();
    const changed_right = try public.NodePublicV2.initLeaf(child_nodes[1].coordinate, child_nodes[1].statement_words, changed_source);
    const changed = try public.NodePublicV2.initParent(&child_nodes[0], &changed_right, expected_node.coordinate);
    try changed.validate();
    try std.testing.expect(!std.meta.eql(inputs.node, changed));
    if (fresh_key.verify(allocator, &changed, &inputs.claims, inputs.interaction_pow_nonce, proof)) |_| {
        return error.ChangedEthereumParentAccepted;
    } else |err| switch (err) {
        error.InvalidCommonFoldVerifierPow, error.InvalidCommonFoldVerifierClosure, error.OodsNotMatching => std.debug.print("ETHEREUM_SAVED_CHILD_PARENT_MUTATION public_input_well_formed=true changed_source_rejected=true derived_from_changed_child=true reason={s}\n", .{@errorName(err)}),
        // Allocation, malformed-input and unrelated operational failures must
        // fail this acceptance test, never count as cryptographic rejection.
        else => return err,
    }
    std.debug.print("ETHEREUM_SAVED_CHILD_PARENT_VERIFIED coordinate=1/1 producer_destroyed=true children_destroyed=true from_disk=true native_inputs=false key_sha256={x} proof_sha256={x} proof_bytes={d} request_ns={d} producer_peak_bytes={d}\n", .{ parent_pin, inputs.proof_sha256, proof.len, timer.read(), producer.peakBytes() });
}

fn keyPin(allocator: std.mem.Allocator, name: []const u8) ![32]u8 {
    const encoded = try std.process.getEnvVarOwned(allocator, name);
    defer allocator.free(encoded);
    if (encoded.len != 64) return error.InvalidEthereumChildKeyPin;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, encoded);
    return result;
}

fn rejectChangedChildBoundaries(children: *const [2]public.NodePublicV2, parent_coordinate: @import("recursive_node_artifact_v2.zig").TaskCoordinateV1) !void {
    const span = recursion.span_statement;
    const M31 = @import("stwo_core").fields.m31.M31;
    var words: span.StatementWords = undefined;
    for (&words, children[1].statement_words) |*word, value| word.* = M31.fromCanonical(value);
    const right = try span.SpanStatement.fromCanonicalWords(&words);

    var changed = right;
    changed.body.executed.entry.pc +%= 4;
    var changed_node = try leafWithStatement(&children[1], changed);
    try std.testing.expectError(error.StateDiscontinuity, public.NodePublicV2.initParent(&children[0], &changed_node, parent_coordinate));

    changed = right;
    try std.testing.expect(changed.body.executed.cycle_count > 1);
    changed.body.executed.first_cycle += 1;
    changed.body.executed.cycle_count -= 1;
    changed_node = try leafWithStatement(&children[1], changed);
    try std.testing.expectError(error.CycleDiscontinuity, public.NodePublicV2.initParent(&children[0], &changed_node, parent_coordinate));

    changed = right;
    changed.slots.first += 1;
    changed.body.executed.first_segment += 1;
    changed_node = try leafWithStatement(&children[1], changed);
    try std.testing.expectError(error.ChildCoordinateMismatch, public.NodePublicV2.initParent(&children[0], &changed_node, parent_coordinate));
    for (&words, children[0].statement_words) |*word, value| word.* = M31.fromCanonical(value);
    const left = try span.SpanStatement.fromCanonicalWords(&words);
    try std.testing.expectError(error.SlotsNotAdjacent, span.SpanStatement.fold(left, changed));
    std.debug.print("ETHEREUM_SAVED_CHILD_PARENT_BOUNDARIES canonical=true changed_state_rejected=true changed_clock_rejected=true changed_coverage_rejected=true\n", .{});
}

fn leafWithStatement(original: *const public.NodePublicV2, statement: recursion.span_statement.SpanStatement) !public.NodePublicV2 {
    const coordinate = try @import("recursive_node_artifact_v2.zig").TaskCoordinateV1.init(0, @intCast(statement.slots.nodeIndex()));
    const canonical = try statement.canonicalWords();
    var words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&words, canonical) |*word, value| word.* = value.toU32();
    return public.NodePublicV2.initLeaf(coordinate, words, original.source_digest);
}

fn loadChild(comptime Adapter: type, comptime dimensions: recursion.fixed_wire.Dimensions, allocator: std.mem.Allocator, path: []const u8, expected_key: [32]u8, expected_proof: [32]u8, expected_index: u32, node: *public.NodePublicV2) !*Adapter.Child {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", 64 * 1024 * 1024);
    defer allocator.free(key_json);
    const key = try child_transport.OwnedKeyV1.admit(allocator, key_json, expected_key);
    defer key.deinit();
    try std.testing.expectEqualDeep(dimensions, try child_shape.dimensionsForManifest(&key.key().manifest));
    const input_json = try dir.readFileAlloc(allocator, "inputs.json", 128 * 1024);
    defer allocator.free(input_json);
    const inputs = try child_transport.decodeInputs(allocator, input_json);
    if (!std.meta.eql(inputs.proof_sha256, expected_proof)) return error.EthereumSavedChildProofPinMismatch;
    if (inputs.node.coordinate.height != 0 or inputs.node.coordinate.index != expected_index) return error.EthereumSavedChildCoordinateMismatch;
    const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
    defer allocator.free(proof);
    if (proof.len != inputs.proof_bytes or !std.meta.eql(child_transport.hash(proof), inputs.proof_sha256)) return error.VerifierProofIdentityMismatch;
    var scope: native_scope.ScopeV1 = undefined;
    try scope.initInPlace(1);
    defer scope.deinit();
    const child = try Adapter.Child.init(allocator, key.key(), &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof);
    node.* = inputs.node;
    return child;
}
