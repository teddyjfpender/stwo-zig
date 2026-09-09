//! Owned witness for the next recursive consumer of a detached SegmentV2 proof.
//! The sole verifier flow runs with the canonical recording channel. Native
//! replay validates its complete sponge execution; no legacy prefix is forged.
//! These projections are witness data, not admission of a parent circuit.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const command = @import("recursive_segment_v2_detached_command.zig");
const components = @import("recursive_segment_v2_verifier_components.zig");
const recording = recursion.recording_poseidon_channel_v4;
const universal = recursion.air.universal_challenges;
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const CirclePoint = core.circle.CirclePointQM31;

/// All slices are const, including nested capture views returned individually.
/// They remain valid until the owner is destroyed.
pub const CaptureViewV1 = struct {
    commitments: []const Digest,
    sampled_values: []const QM31,
    queried_values: []const M31,
    deep_answers: []const QM31,
    raw_queries: []const usize,
    unique_queries: []const usize,
    last_layer_coefficients: []const QM31,
    proof_of_work: u64,
    composition_randomness: QM31,
    oods_seed: QM31,
    deep_randomness: QM31,
    trace_count: usize,
    fri_layer_count: usize,
};
pub const FriLayerViewV1 = struct {
    commitment: Digest,
    folding_alpha: QM31,
    fold_step: u32,
    fold_width: u32,
    path_depth: u32,
    query_count: usize,
    positions: []const usize,
    values: []const QM31,
    siblings: []const Digest,
};
pub const TracePathViewV1 = struct { positions: []const usize, path_depth: u32, siblings: []const Digest };
pub const RecordingViewV1 = struct {
    trace: recording.TranscriptTrace,
    operations: []const recording.OperationV4,
    final_digest: Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,
};

pub const Family = enum { segment, parent };
pub const OwnedV1 = OwnedFor(.segment);
pub const ParentOwnedV1 = OwnedFor(.parent);

/// Capture ownership is shared; key, public statement and verifier stay typed.
pub fn OwnedFor(comptime family: Family) type {
    const Verifier = if (family == .segment) verifier else @import("recursive_segment_v2_detached_parent_verifier.zig");
    const Command = if (family == .segment) command else @import("recursive_segment_v2_detached_parent_command.zig");
    const Expected = if (family == .segment) PublicData else Verifier.ExpectedV1;
    const OwnedExpected = if (family == .segment) command.OwnedExpectedV1 else Expected;
    return opaque {
        const Self = @This();
        pub const FAMILY = family;
        const Storage = struct {
            allocator: std.mem.Allocator,
            key: *Command.OwnedKeyV1,
            expected: OwnedExpected,
            claims: Verifier.ClaimsV1,
            capture: Verifier.ProofCapture,
            execution: recording.ExecutionV4,
            relations: components.Relations,
            terminal: Digest,
            key_sha256: [32]u8,
            proof_sha256: [32]u8,
        };

        /// Independently supplied key hash is mandatory. No pointer into caller
        /// key, statement, claims or serialized proof survives this transaction.
        pub fn init(allocator: std.mem.Allocator, key_json: []const u8, independent_key_sha256: [32]u8, expected_input: *const Expected, input_claims: Verifier.ClaimsV1, proof_bytes: []const u8) !*Self {
            const owned_key = try Command.OwnedKeyV1.admit(allocator, key_json, independent_key_sha256);
            errdefer owned_key.deinit();
            const owned_expected: OwnedExpected = if (family == .segment) blk: {
                _ = try expected_input.metadata();
                const words = try allocator.dupe(M31, expected_input.words());
                errdefer allocator.free(words);
                const admitted_expected = try PublicData.authenticate(words);
                if (!std.meta.eql(admitted_expected.wireId(), expected_input.wireId())) return error.DetachedChildExpectedWireChanged;
                break :blk .{ .allocator = allocator, .words = words, .data = admitted_expected };
            } else expected_input.*;
            errdefer if (family == .segment) allocator.free(owned_expected.words);
            var channel = recording.Channel.init(allocator);
            defer channel.deinit();
            var capture: Verifier.ProofCapture = undefined;
            const result = try Verifier.verifyWithCaptureRecording(allocator, owned_key.key(), expectedData(&owned_expected), input_claims, proof_bytes, &channel, &capture);
            errdefer capture.deinit(allocator);
            // finish validates every recorded hash, PoW and draw against the native
            // channel, including the whole PCS/FRI suffix used by the real verifier.
            var execution = try channel.finish();
            errdefer execution.deinit();
            if (!std.meta.eql(result.terminal, recursion.protocol.transcriptId(execution.final_digest, execution.final_draw_count))) return error.DetachedChildTerminalMismatch;
            try @import("recursive_detached_recording_draws.zig").validate(&execution, &capture, &result.relations, owned_key.key().pcs_config.fri_config.n_queries);
            const owned_storage = try allocator.create(Storage);
            owned_storage.* = .{ .allocator = allocator, .key = owned_key, .expected = owned_expected, .claims = input_claims, .capture = capture, .execution = execution, .relations = result.relations, .terminal = result.terminal, .key_sha256 = independent_key_sha256, .proof_sha256 = command.hash(proof_bytes) };
            return @ptrCast(owned_storage);
        }

        pub fn deinit(self: *Self) void {
            const value: *Storage = @ptrCast(@alignCast(self));
            const allocator = value.allocator;
            value.execution.deinit();
            value.capture.deinit(allocator);
            if (family == .segment) value.expected.deinit();
            value.key.deinit();
            allocator.destroy(value);
        }
        fn storage(self: *const Self) *const Storage {
            return @ptrCast(@alignCast(self));
        }
        pub fn key(self: *const Self) *const Verifier.KeyV1 {
            return self.storage().key.key();
        }
        fn expectedData(value: *const OwnedExpected) *const Expected {
            return if (family == .segment) &value.data else value;
        }
        pub fn expected(self: *const Self) *const Expected {
            return expectedData(&self.storage().expected);
        }
        pub fn expectedWords(self: *const Self) []const M31 {
            return if (family == .segment) self.expected().words() else self.expected();
        }
        pub fn claims(self: *const Self) Verifier.ClaimsV1 {
            return self.storage().claims;
        }
        pub fn relations(self: *const Self) *const components.Relations {
            return &self.storage().relations;
        }
        pub fn terminal(self: *const Self) Digest {
            return self.storage().terminal;
        }
        pub fn keySha256(self: *const Self) [32]u8 {
            return self.storage().key_sha256;
        }
        pub fn proofSha256(self: *const Self) [32]u8 {
            return self.storage().proof_sha256;
        }
        pub fn recordingView(self: *const Self) RecordingViewV1 {
            const execution = &self.storage().execution;
            return .{ .trace = execution.trace(), .operations = execution.operations, .final_digest = execution.final_digest, .final_draw_count = execution.final_draw_count, .identity_sha256 = execution.identity_sha256 };
        }
        pub fn captureView(self: *const Self) CaptureViewV1 {
            const value = &self.storage().capture;
            return .{ .commitments = value.commitments, .sampled_values = value.sampled_values, .queried_values = value.queried_values, .deep_answers = value.deep_answers, .raw_queries = value.queries.raw, .unique_queries = value.queries.unique, .last_layer_coefficients = value.last_layer_coefficients, .proof_of_work = value.proof_of_work, .composition_randomness = value.composition_randomness, .oods_seed = value.oods_seed, .deep_randomness = value.deep_randomness, .trace_count = value.trace_paths.len, .fri_layer_count = value.fri.layers.len };
        }
        pub fn friLayer(self: *const Self, index: usize) FriLayerViewV1 {
            const value = &self.storage().capture.fri.layers[index];
            return .{ .commitment = value.commitment, .folding_alpha = value.folding_alpha, .fold_step = value.fold_step, .fold_width = value.fold_width, .path_depth = value.path_depth, .query_count = value.query_count, .positions = value.positions, .values = value.values, .siblings = value.siblings };
        }
        pub fn tracePath(self: *const Self, index: usize) TracePathViewV1 {
            const value = &self.storage().capture.trace_paths[index];
            return .{ .positions = value.positions, .path_depth = value.path_depth, .siblings = value.siblings };
        }
        /// Build the canonical composition projection without exposing mutable
        /// nested capture storage. The returned layout owns its allocations.
        pub fn compositionLayout(self: *const Self, allocator: std.mem.Allocator) !recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3 {
            const Layout = recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3;
            return if (family == .segment)
                Layout.initSegment(allocator, &self.key().manifest, &self.storage().capture)
            else
                Layout.initAuthenticatedBinaryWithProviderRow(allocator, .detached_segment_parent_v1, 34, &self.key().manifest, &self.storage().capture);
        }
        pub fn writeCompositionInputs(self: *const Self, profile: recursion.recursion_air_composition_circuit_v3.InputProfileV3, destination: []QM31) !void {
            const v3 = recursion.recursion_air_composition_circuit_v3;
            const kind: recursion.air.composition_circuit.ProofKind = if (family == .segment) .segment_leaf else .binary_node;
            const key_value = self.key();
            const claims_value = self.claims();
            var claim_inputs: [v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
            try v3.writeClaimInputs(kind, &claims_value.values, &claims_value.poseidon_partials, &claim_inputs);
            const words: recursion.span_statement.StatementWords = if (family == .segment)
                (try self.expected().authenticatedView()).statement.base_statement_words
            else
                self.expected()[0..recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS].*;
            const boundary = if (family == .segment) blk: {
                const hash_boundary = try @import("recursive_segment_v2_authority_boundary.zig").derive(self.expected(), key_value.native_descriptors, self.relations());
                break :blk (try key_value.wireClaim(self.relations())).add(hash_boundary.claimed_sum);
            } else try @import("recursive_segment_v2_detached_parent_protocol.zig").publicBoundary(self.expected(), self.relations());
            const capture = self.captureView();
            try v3.writeInputsFromValidatedProfile(profile, .{
                .parent_binary_selector = true,
                .proof_kind = kind,
                .statement_words = &words,
                .sampled_values = capture.sampled_values,
                .claim_inputs = &claim_inputs,
                .public_wire_boundary = boundary,
                .relations = self.relations(),
                .composition_randomness = capture.composition_randomness,
                .oods_seed = capture.oods_seed,
            }, destination);
        }
        /// Explicit preparation of the shared PCS/FRI arithmetic. This copies the
        /// admitted capture once into caller-owned storage and evaluates both
        /// circuits. Cheap capture reads above never initiate this construction.
        pub fn preparePcs(self: *const Self, allocator: std.mem.Allocator) !recursion.captured_fri.Owned {
            const pcs = self.key().pcs_config;
            return recursion.captured_fri.Owned.init(allocator, .{
                .log_blowup_factor = pcs.fri_config.log_blowup_factor,
                .log_last_layer_degree_bound = pcs.fri_config.log_last_layer_degree_bound,
                .interaction_pow_bits = self.key().profile.interactionPowBits(),
                .pcs_pow_bits = pcs.pow_bits,
                .claimed_sum_count = @intCast(self.claims().values.len),
            }, &self.storage().capture);
        }
        /// Copy the full canonical transcript draws, before the native query mask.
        /// Query-bit AIR must prove that reduction; a masked index is insufficient
        /// to authenticate the original randomness word. No replay or hashing here.
        pub fn writeRawQueryDraws(self: *const Self, destination: []M31) !void {
            const value = self.storage();
            if (destination.len != value.capture.queries.raw.len) return error.DetachedChildQueryMismatch;
            const first_query_draw = universal.RELATION_COUNT + 3 + value.capture.fri.layers.len;
            var draw: usize = 0;
            var cursor: usize = 0;
            for (value.execution.operations) |operation| {
                if (operation.effect != .draw) continue;
                if (draw >= first_query_draw) {
                    const count = @min(recording.RATE, destination.len - cursor);
                    const frame = value.execution.hash_frames[operation.first_hash_id];
                    @memcpy(destination[cursor..][0..count], frame.output[0..count]);
                    cursor += count;
                }
                draw += 1;
            }
            if (cursor != destination.len) return error.DetachedChildQueryMismatch;
        }
        pub fn columnLogSizes(self: *const Self, tree: usize) []const u32 {
            return self.storage().capture.column_log_sizes[tree];
        }
        pub fn sampledPoints(self: *const Self, tree: usize, column: usize) []const CirclePoint {
            return self.storage().capture.sampled_points[tree][column];
        }
    };
}

// Required real inputs; absence is a gate failure, never a skipped test.
// The key pin is supplied independently, not read from the candidate bundle.
test "SegmentV2 detached child owns genuine capture and exact recorded transcript" {
    const allocator = std.testing.allocator;
    const directory = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_BUNDLE");
    defer allocator.free(directory);
    const pin_hex = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_KEY_SHA256");
    defer allocator.free(pin_hex);
    const expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_EXPECTED_WIRE");
    defer allocator.free(expected_path);
    const args = try command.parseArguments(&.{ directory, pin_hex, expected_path });
    var dir = try std.fs.cwd().openDir(args.directory, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", command.MAX_KEY_BYTES);
    defer allocator.free(key_json);
    const expected_json = try std.fs.cwd().readFileAlloc(allocator, args.expected_wire_path, command.MAX_INPUT_BYTES);
    defer allocator.free(expected_json);
    var expected = try command.OwnedExpectedV1.decode(allocator, expected_json);
    defer expected.deinit();
    const claims_json = try dir.readFileAlloc(allocator, "claims.json", command.MAX_INPUT_BYTES);
    defer allocator.free(claims_json);
    const input = try command.decodeClaims(allocator, claims_json);
    const proof_bytes = try dir.readFileAlloc(allocator, "proof.bin", input.proof_bytes);
    defer allocator.free(proof_bytes);
    try std.testing.expectEqual(input.proof_bytes, proof_bytes.len);
    try std.testing.expectEqual(input.proof_sha256, command.hash(proof_bytes));
    const key = try command.OwnedKeyV1.admit(allocator, key_json, args.independent_key_sha256);
    defer key.deinit();
    var ordinary_capture: verifier.ProofCapture = undefined;
    const ordinary_terminal = try verifier.verifyWithCapture(allocator, key.key(), &expected.data, input.claims, proof_bytes, &ordinary_capture);
    defer ordinary_capture.deinit(allocator);

    // The owner must survive both hostile writes and destruction of every
    // supplied dynamic allocation. No native producer exists in this test.
    const owner = blk: {
        const caller_key = try allocator.dupe(u8, key_json);
        defer allocator.free(caller_key);
        const caller_proof = try allocator.dupe(u8, proof_bytes);
        defer allocator.free(caller_proof);
        var caller_expected = try command.OwnedExpectedV1.decode(allocator, expected_json);
        defer caller_expected.deinit();
        var caller_claims = input.claims;
        const value = try OwnedV1.init(allocator, caller_key, args.independent_key_sha256, &caller_expected.data, caller_claims, caller_proof);
        @memset(caller_key, 0);
        @memset(caller_proof, 0);
        @memset(caller_expected.words, M31.zero());
        caller_claims.values = @splat(QM31.zero());
        break :blk value;
    };
    defer owner.deinit();
    try std.testing.expectEqual(ordinary_terminal, owner.terminal());
    try std.testing.expectEqualDeep(ordinary_capture, owner.storage().capture);
    try std.testing.expectEqualDeep(key.key().*, owner.key().*);
    try std.testing.expectEqualDeep(input.claims, owner.claims());
    try std.testing.expectEqualSlices(M31, expected.data.words(), owner.expected().words());
    try std.testing.expectEqual(input.proof_sha256, owner.proofSha256());
    try std.testing.expectEqual(args.independent_key_sha256, owner.keySha256());
    // Replaying this retained recording is a diagnostic, not an operational
    // getter. Its closure is checked once at owner admission above.
    try owner.storage().execution.validate();
    const before = owner.recordingView();
    for (0..3) |_| {
        _ = owner.key();
        _ = owner.expected();
        _ = owner.claims();
        _ = owner.relations();
        _ = owner.captureView();
        for (0..ordinary_capture.trace_paths.len) |tree| {
            _ = owner.tracePath(tree);
            for (0..owner.columnLogSizes(tree).len) |column| _ = owner.sampledPoints(tree, column);
        }
        for (0..ordinary_capture.fri.layers.len) |layer| _ = owner.friLayer(layer);
    }
    try std.testing.expectEqual(before.identity_sha256, owner.recordingView().identity_sha256);
    try @import("recursive_segment_v2_detached_composition.zig").testFromVerifiedChild(allocator, owner);
    try @import("recursive_segment_v2_detached_prefix.zig").testFromVerifiedChild(allocator, owner);
    try @import("recursive_segment_v2_detached_pcs_rows.zig").testFromVerifiedChild(allocator, owner);
    try @import("recursive_segment_v2_detached_pcs_checks.zig").testFromVerifiedChild(allocator, owner);
    // Independently reviewed one-address seed13 first-child profile. This is
    // fixture admission, not a section layout inferred from a candidate proof.
    try @import("recursive_segment_v2_detached_boundary.zig").testFromVerifiedChild(allocator, owner, .{ .counts = .{ 1, 1, 0, 1 } }, .{ .entry_addresses = &.{1048832}, .exit_addresses = &.{1048832} });
    {
        var pcs = try owner.preparePcs(allocator);
        defer pcs.deinit();
        try std.testing.expectEqualSlices(QM31, ordinary_capture.deep_answers, pcs.deep_answers);
        const changed_answers = try allocator.dupe(QM31, pcs.deep_answers);
        defer allocator.free(changed_answers);
        for (changed_answers, 0..) |original, query| {
            changed_answers[query] = original.add(QM31.one());
            var witness = pcs.witness();
            witness.deep_answers = changed_answers;
            try std.testing.expectError(error.UnsatisfiedCircuit, pcs.circuit.evaluate(allocator, witness));
            try std.testing.expectError(error.UnsatisfiedCircuit, pcs.pcs_circuit.evaluateFrozen(allocator, .{
                .active = true,
                .sampled_values = pcs.sampled_values,
                .queried_values = pcs.queried_values,
                .oods_seed = pcs.oods_seed,
                .deep_randomness = pcs.deep_randomness,
                .raw_queries = pcs.raw_queries,
                .answers = changed_answers,
            }));
            changed_answers[query] = original;
        }
        std.debug.print("SEGMENT_V2_DETACHED_PCS samples={d} queried_values={d} layers={d} rejected_deep_answers={d} parent_proof_verified=false\n", .{
            pcs.sampled_values.len, pcs.queried_values.len, pcs.fold_widths.len, changed_answers.len,
        });
    }

    var wrong_pin = args.independent_key_sha256;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.DetachedKeyHashMismatch, OwnedV1.init(allocator, key_json, wrong_pin, &expected.data, input.claims, proof_bytes));
    try std.testing.expectError(error.EndOfStream, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, proof_bytes[0 .. proof_bytes.len - 1]));
    const trailing = try allocator.alloc(u8, proof_bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..proof_bytes.len], proof_bytes);
    trailing[proof_bytes.len] = 0;
    try std.testing.expectError(error.TrailingProofBytes, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, trailing));
    var wrong_claims = input.claims;
    wrong_claims.values[36] = wrong_claims.values[36].add(QM31.one());
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, wrong_claims, proof_bytes));

    // Use a second genuine, canonically authenticated statement. A raw
    // register edit would fail Span/job/lineage admission before the verifier.
    const other_expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_OTHER_EXPECTED_WIRE");
    defer allocator.free(other_expected_path);
    const other_expected_json = try std.fs.cwd().readFileAlloc(allocator, other_expected_path, command.MAX_INPUT_BYTES);
    defer allocator.free(other_expected_json);
    var other_expected = try command.OwnedExpectedV1.decode(allocator, other_expected_json);
    defer other_expected.deinit();
    try std.testing.expectEqual(expected.words.len, other_expected.words.len);
    try std.testing.expect(!std.meta.eql(expected.data.wireId(), other_expected.data.wireId()));
    try std.testing.expectError(if (key.key().profile.interactionPowBits() > 0) error.InvalidDetachedInteractionPow else error.SegmentV2PublicInputClaimMismatch, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &other_expected.data, input.claims, proof_bytes));

    // Change an actual sampled opening and canonically serialize it. Decoder
    // shape acceptance must not mask the required cryptographic rejection.
    const postcard = @import("interop_postcard");
    var stream = std.io.fixedBufferStream(proof_bytes);
    var changed_proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
    defer changed_proof.deinit(allocator);
    const sampled = changed_proof.commitment_scheme_proof.sampled_values.items;
    const opening = &sampled[sampled.len - 1][0][0];
    opening.* = opening.add(QM31.one());
    var changed_bytes: std.ArrayList(u8) = .empty;
    defer changed_bytes.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, changed_bytes.writer(allocator), changed_proof);
    try std.testing.expectError(error.OodsNotMatching, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, changed_bytes.items));
    const captured = owner.captureView();
    std.debug.print("SEGMENT_V2_DETACHED_CHILD transcript_operations={d} poseidon_calls={d} sampled_values={d} queried_values={d} fri_layers={d} raw_queries={d} input_bytes={d} caller_destroyed=true\n", .{
        before.operations.len, before.trace.poseidon_calls.len, captured.sampled_values.len, captured.queried_values.len, captured.fri_layer_count, captured.raw_queries.len, proof_bytes.len,
    });
}
