//! Field9 child witness reconstructed from a separately admitted fixed key and
//! a real wrapper proof. No native child or producer cohort enters this path.
//! This owner is not a fold capability: the parent still needs the symbolic
//! Ethereum composition equation, fixed child shape and complete AIR closure.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const field = @import("ethereum_wrapper_field_transcript_v1.zig");
const public = @import("recursive_field_node_public_v2.zig");
const program_mod = @import("recursive_secure_transcript_program_v1.zig");
const rows = @import("recursive_secure_transcript_rows_v1.zig");
const recording = recursion.recording_poseidon_channel_v4;
const universal = recursion.air.universal_challenges;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
pub const VERSION: u16 = 1;
pub const FOLD_ADMISSION_AVAILABLE = false;
const QUERY_COUNT = recursion.protocol.FRI_QUERY_COUNT;

pub const Ordinary = Types(@import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig"));
pub const Initial38 = Types(recursion.air.ethereum_initial_input_manifest_v1);
pub const OwnedV1 = Ordinary.OwnedV1;

/// Selection comes from the admitted circuit profile, never candidate bytes.
pub fn Types(comptime ManifestMod: type) type {
    const Verifier = verifier.Types(ManifestMod);
    return struct {
        const Selected = @This();
        pub const OwnedV1 = opaque {
            const Storage = struct {
                allocator: std.mem.Allocator,
                key: Verifier.KeyV1,
                node: public.NodePublicV2,
                claims: Verifier.ClaimsV1,
                nonce: u64,
                capture: Verifier.ProofCapture,
                program: program_mod.Program,
                replay: Replay,
                terminal: Digest,
            };

            /// Key authenticity is the caller's responsibility, as at root verify.
            /// All retained data is copied or transferred from successful verification.
            pub fn init(allocator: std.mem.Allocator, key: *const Verifier.KeyV1, node: *const public.NodePublicV2, claims: Verifier.ClaimsV1, nonce: u64, proof: []const u8) !*Selected.OwnedV1 {
                var capture: Verifier.ProofCapture = undefined;
                const terminal = try Verifier.verifyWithCapture(allocator, key, node, claims, nonce, proof, &capture);
                errdefer capture.deinit(allocator);
                const anchors = try allocator.dupe(recursion.air.verifier_arithmetic_lowering.PublicWireTerm, key.wire_terms);
                errdefer allocator.free(anchors);
                var owned_key = key.*;
                owned_key.wire_terms = anchors;
                var program = if (ManifestMod == recursion.air.ethereum_initial_input_manifest_v1)
                    try program_mod.Program.initEthereumInitialFieldFieldsV1(allocator, &owned_key.manifest, &capture, try admission(&owned_key))
                else
                    try program_mod.Program.initEthereumFieldFieldsV1(allocator, &owned_key.manifest, &capture, try admission(&owned_key));
                errdefer program.deinit();
                var replay = try Replay.init(allocator, &owned_key, node, &claims, nonce, &capture, &program);
                errdefer replay.execution.deinit();
                if (!std.meta.eql(terminal, recursion.protocol.transcriptId(replay.execution.final_digest, replay.execution.final_draw_count)))
                    return error.InvalidEthereumDetachedTranscript;
                const value = try allocator.create(Storage);
                value.* = .{ .allocator = allocator, .key = owned_key, .node = node.*, .claims = claims, .nonce = nonce, .capture = capture, .program = program, .replay = replay, .terminal = terminal };
                return @ptrCast(value);
            }

            fn storage(self: *const Selected.OwnedV1) *const Storage {
                return @ptrCast(@alignCast(self));
            }

            pub fn deinit(self: *Selected.OwnedV1) void {
                const value: *Storage = @ptrCast(@alignCast(self));
                const allocator = value.allocator;
                value.replay.execution.deinit();
                value.program.deinit();
                value.capture.deinit(allocator);
                allocator.free(value.key.wire_terms);
                allocator.destroy(value);
            }

            pub fn admittedKey(self: *const Selected.OwnedV1) *const Verifier.KeyV1 {
                return &self.storage().key;
            }
            pub fn publicNode(self: *const Selected.OwnedV1) *const public.NodePublicV2 {
                return &self.storage().node;
            }
            pub fn claimValues(self: *const Selected.OwnedV1) *const Verifier.ClaimsV1 {
                return &self.storage().claims;
            }
            pub fn proofCapture(self: *const Selected.OwnedV1) *const Verifier.ProofCapture {
                return &self.storage().capture;
            }
            pub fn relations(self: *const Selected.OwnedV1) *const universal.UniversalRelations {
                return &self.storage().replay.relations;
            }
            pub fn queryWords(self: *const Selected.OwnedV1) *const [QUERY_COUNT]M31 {
                return &self.storage().replay.query_words;
            }
            pub fn queryLogSize(self: *const Selected.OwnedV1) u32 {
                return self.storage().replay.query_log_size;
            }
            pub fn wireClaim(self: *const Selected.OwnedV1) QM31 {
                return self.storage().replay.wire_claim;
            }
            pub fn interactionPowNonce(self: *const Selected.OwnedV1) u64 {
                return self.storage().nonce;
            }
            pub fn terminalIdentity(self: *const Selected.OwnedV1) Digest {
                return self.storage().terminal;
            }
            pub fn transcriptView(self: *const Selected.OwnedV1) rows.View {
                const value = self.storage();
                return .{ .program = &value.program, .execution = &value.replay.execution };
            }
        };

        fn admission(key: *const Verifier.KeyV1) !field.FieldAdmissionV1 {
            try key.validate();
            return .{ .session_fields = key.session_fields, .preprocessed_root = key.preprocessed_root, .wire_term_count = @intCast(key.wire_terms.len) };
        }

        const Replay = struct {
            execution: recording.ExecutionV4,
            relations: universal.UniversalRelations,
            query_words: [QUERY_COUNT]M31,
            query_log_size: u32,
            wire_claim: QM31,

            fn init(allocator: std.mem.Allocator, key: *const Verifier.KeyV1, node: *const public.NodePublicV2, claims: *const Verifier.ClaimsV1, nonce: u64, capture: *const Verifier.ProofCapture, program: *const program_mod.Program) !Replay {
                if (program.kind != .ethereum_incremental_field_v1) return error.InvalidEthereumDetachedTranscript;
                const query_log_size = try @import("recursive_common_wrapper_authority_v2.zig").queryLogSizeFromCapture(capture);
                const query_mask = (@as(u32, 1) << @intCast(query_log_size)) - 1;
                var channel = recording.Channel.init(allocator);
                defer channel.deinit();
                var draws: [universal.DRAW_COUNT]QM31 = undefined;
                var relation_at: usize = 0;
                var query_words: [QUERY_COUNT]M31 = undefined;
                var query_at: usize = 0;
                var wire_claim: ?QM31 = null;
                for (program.operations) |op| {
                    channel.setContextTag(@intFromEnum(op.context));
                    switch (op.effect) {
                        .mix => {
                            if (op.source == .canonical_wire_boundary) {
                                if (relation_at != draws.len or wire_claim != null) return error.InvalidEthereumDetachedTranscript;
                                const relations = universal.UniversalRelations.fromDraws(&draws);
                                wire_claim = try key.wireClaim(&relations);
                            }
                            try mix(&channel, op, node, claims, capture, wire_claim);
                        },
                        .pow => {
                            const value = switch (op.item) {
                                0 => nonce,
                                1 => capture.proof_of_work,
                                else => return error.InvalidEthereumDetachedTranscript,
                            };
                            if (!channel.verifyPowNonce(op.pow_bits, value)) return error.InvalidEthereumDetachedTranscript;
                            channel.mixU64(value);
                        },
                        .draw => {
                            const words = channel.drawU32s();
                            const value = secure(words[0..4].*);
                            switch (op.draw) {
                                .relation => {
                                    if (op.item * 2 != relation_at or relation_at + 2 > draws.len) return error.InvalidEthereumDetachedTranscript;
                                    draws[relation_at] = value;
                                    draws[relation_at + 1] = secure(words[4..8].*);
                                    relation_at += 2;
                                },
                                .queries => {
                                    if (op.item != query_at or query_at + op.draw_word_count > query_words.len or capture.queries.raw.len != query_words.len) return error.InvalidEthereumDetachedTranscript;
                                    for (words[0..op.draw_word_count]) |word| {
                                        if (word >= core.fields.m31.Modulus or (word & query_mask) != capture.queries.raw[query_at]) return error.InvalidEthereumDetachedTranscript;
                                        query_words[query_at] = M31.fromCanonical(word);
                                        query_at += 1;
                                    }
                                },
                                .composition => try same(value, capture.composition_randomness),
                                .oods => try same(value, capture.oods_seed),
                                .deep => try same(value, capture.deep_randomness),
                                .fri_alpha => try same(value, capture.fri.layers[op.item].folding_alpha),
                                .none => return error.InvalidEthereumDetachedTranscript,
                            }
                        },
                    }
                }
                if (relation_at != draws.len or query_at != query_words.len or wire_claim == null) return error.InvalidEthereumDetachedTranscript;
                var execution = try channel.finish();
                errdefer execution.deinit();
                try program.validateRecording(&execution);
                const relations = universal.UniversalRelations.fromDraws(&draws);
                try relations.validate();
                return .{ .execution = execution, .relations = relations, .query_words = query_words, .query_log_size = query_log_size, .wire_claim = wire_claim.? };
            }
        };
    };
}

fn mix(channel: *recording.Channel, op: program_mod.Operation, node: *const public.NodePublicV2, claims: anytype, capture: *const verifier.ProofCapture, wire_claim: ?QM31) !void {
    if (op.source.isConstantPayload()) {
        if (op.payload_words > op.constant_words.len) return error.InvalidEthereumDetachedTranscript;
        var words: [16]M31 = undefined;
        for (op.constant_words[0..op.payload_words], words[0..op.payload_words]) |word, *out| out.* = M31.fromCanonical(word);
        channel.mixCanonicalM31Words(words[0..op.payload_words]);
        return;
    }
    switch (op.source) {
        .commitment => mixRoot(channel, capture.commitments[op.item]),
        .statement => channel.mixU32s(&try node.canonicalAirWords()),
        .claim_value => channel.mixFelts(&.{claims.values[op.item]}),
        .canonical_wire_boundary => channel.mixFelts(&.{wire_claim orelse return error.InvalidEthereumDetachedTranscript}),
        .provider_partial => channel.mixFelts(&claims.poseidon_partials),
        .sampled_values => channel.mixFelts(capture.sampled_values),
        .fri_commitment => mixRoot(channel, capture.fri.layers[op.item].commitment),
        .last_layer => channel.mixFelts(capture.last_layer_coefficients),
        else => return error.InvalidEthereumDetachedTranscript,
    }
}
fn mixRoot(channel: *recording.Channel, root: Digest) void {
    var words: [8]M31 = undefined;
    for (root, &words) |word, *out| out.* = M31.fromCanonical(word);
    channel.mixCanonicalM31Words(&words);
}
fn secure(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}
fn same(actual: QM31, expected: QM31) !void {
    if (!actual.eql(expected)) return error.InvalidEthereumDetachedTranscript;
}

test "Ethereum detached field admission preserves session projection without custody" {
    const fixture = @import("ethereum_wrapper_root_verifier_v1_test.zig");
    const key = try fixture.testKey();
    const session = try fixture.testSession(key.session_fields);
    const native = field.AdmissionV1{ .session = &session, .preprocessed_root = key.preprocessed_root, .wire_term_count = @intCast(key.wire_terms.len) };
    try std.testing.expectEqualDeep(try native.fieldProjection(), try Ordinary.admission(&key));
    var changed = try Ordinary.admission(&key);
    changed.preprocessed_root[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, changed.validate());
    changed = try Ordinary.admission(&key);
    changed.session_fields.air_program_id = @splat(0);
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, changed.validate());
    changed = try Ordinary.admission(&key);
    changed.wire_term_count = 0;
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, changed.validate());
    try std.testing.expect(!FOLD_ADMISSION_AVAILABLE);
}

test "Ethereum detached transcript dynamic frames match public wire and provider emitters" {
    const allocator = std.testing.allocator;
    const fixture = @import("ethereum_wrapper_root_verifier_v1_test.zig");
    const key = try fixture.testKey();
    const session = try fixture.testSession(key.session_fields);
    var words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (session.parent_statement_words, &words) |word, *out| out.* = word.toU32();
    const node = try public.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0), words, [_]u32{9} ** 8);
    const claims: verifier.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = .{ QM31.one(), QM31.fromU32Unchecked(2, 3, 4, 5) } };
    const relations = universal.UniversalRelations.dummy();
    const wire = try key.wireClaim(&relations);
    var native = recording.Channel.init(allocator);
    defer native.deinit();
    native.setContextTag(@intFromEnum(program_mod.Context.authority));
    try field.mixAuthority(&native, &try node.canonicalAirWords());
    native.setContextTag(@intFromEnum(program_mod.Context.boundary));
    try field.mixBoundaryFields(&native, @intCast(key.wire_terms.len), wire, &claims.poseidon_partials);
    var expected = try native.finish();
    defer expected.deinit();
    // Selected frame kinds do not access PCS capture fields in this encoding
    // fixture. The real-artifact test below exercises the complete capture.
    const unused_capture: verifier.ProofCapture = undefined;
    for (0..4) |mutation| {
        var actual_node = node;
        var actual_claims = claims;
        var actual_wire = wire;
        if (mutation == 1) actual_node = try public.NodePublicV2.initLeaf(node.coordinate, words, [_]u32{10} ** 8);
        if (mutation == 2) actual_wire = actual_wire.add(QM31.one());
        if (mutation == 3) actual_claims.poseidon_partials[1] = actual_claims.poseidon_partials[1].add(QM31.one());
        var channel = recording.Channel.init(allocator);
        defer channel.deinit();
        channel.setContextTag(@intFromEnum(program_mod.Context.authority));
        try mix(&channel, testHeader(.authority, .authority_header, &field.AUTHORITY_HEADER), &actual_node, &actual_claims, &unused_capture, actual_wire);
        try mix(&channel, .{ .context = .authority, .effect = .mix, .source = .statement }, &actual_node, &actual_claims, &unused_capture, actual_wire);
        channel.setContextTag(@intFromEnum(program_mod.Context.boundary));
        try mix(&channel, testHeader(.boundary, .canonical_boundary_header, &try field.boundaryHeader(@intCast(key.wire_terms.len))), &actual_node, &actual_claims, &unused_capture, actual_wire);
        try mix(&channel, .{ .context = .boundary, .effect = .mix, .source = .canonical_wire_boundary }, &actual_node, &actual_claims, &unused_capture, actual_wire);
        try mix(&channel, .{ .context = .boundary, .effect = .mix, .source = .provider_partial }, &actual_node, &actual_claims, &unused_capture, actual_wire);
        var actual = try channel.finish();
        defer actual.deinit();
        try actual.validate();
        if (mutation == 0) {
            try std.testing.expectEqualDeep(expected.hash_frames, actual.hash_frames);
            try std.testing.expectEqualDeep(expected.final_digest, actual.final_digest);
        } else try std.testing.expect(!std.meta.eql(expected.final_digest, actual.final_digest));
    }
}

fn testHeader(context: program_mod.Context, source: program_mod.Source, words: []const u32) program_mod.Operation {
    var op = program_mod.Operation{ .context = context, .effect = .mix, .source = source, .payload_words = @intCast(2 * words.len) };
    for (words, 0..) |word, index| {
        op.constant_words[2 * index] = word & 0xffff;
        op.constant_words[2 * index + 1] = word >> 16;
    }
    return op;
}

test "Ethereum initial detached transcript admits38 claims with native frame parity" {
    @setEvalBranchQuota(50_000_000);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const key = try @import("ethereum_wrapper_root_verifier_v1_test.zig").testInitialKey();
    const admitted = try Initial38.admission(&key);
    var capture = try initialProgramCapture(allocator, &key);
    var program = try program_mod.Program.initEthereumInitialFieldFieldsV1(allocator, &key.manifest, &capture, admitted);
    defer program.deinit();
    var bad = admitted;
    bad.preprocessed_root[0] += 1;
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, program_mod.Program.initEthereumInitialFieldFieldsV1(allocator, &key.manifest, &capture, bad));
    var changed_manifest = key.manifest;
    changed_manifest.input_capacity += 1;
    try std.testing.expectError(error.ManifestSealMismatch, program_mod.Program.initEthereumInitialFieldFieldsV1(allocator, &changed_manifest, &capture, admitted));
    // The ordinary entry still rejects the appended geometry.
    try std.testing.expectError(error.InvalidSampleGeometry, program_mod.Program.initEthereumFieldFieldsV1(allocator, &key.manifest.ordinary, &capture, admitted));
    capture.sampled_values[0] = QM31.one();
    var changed_program = try program_mod.Program.initEthereumInitialFieldFieldsV1(allocator, &key.manifest, &capture, admitted);
    defer changed_program.deinit();
    try std.testing.expectEqualDeep(program.identity, changed_program.identity);

    var claims: verifier.Initial38.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    claims.values[36] = QM31.one();
    claims.values[37] = QM31.fromU32Unchecked(2, 3, 4, 5);
    const vector = try claims.vector(&key.manifest);
    const wire = try key.wireClaim(&universal.UniversalRelations.dummy());
    var native = recording.Channel.init(allocator);
    defer native.deinit();
    native.setContextTag(@intFromEnum(program_mod.Context.claims));
    try field.mixClaims(&native, &key.manifest, &vector);
    native.setContextTag(@intFromEnum(program_mod.Context.boundary));
    try field.mixBoundaryFields(&native, admitted.wire_term_count, wire, &claims.poseidon_partials);
    var expected = try native.finish();
    defer expected.deinit();
    // These operations read claims and boundary only, never a node or PCS value.
    const unused_node: public.NodePublicV2 = undefined;
    for (0..3) |mutation| {
        var actual_claims = claims;
        if (mutation != 0) actual_claims.values[35 + mutation] = actual_claims.values[35 + mutation].add(QM31.one());
        var channel = recording.Channel.init(allocator);
        defer channel.deinit();
        var claim_count: usize = 0;
        for (program.operations) |op| {
            if (op.context != .claims and op.context != .boundary) continue;
            channel.setContextTag(@intFromEnum(op.context));
            if (op.source == .claim_value) {
                try std.testing.expectEqual(claim_count, op.item);
                claim_count += 1;
            }
            if (op.source == .provider_partial) try std.testing.expectEqual(@as(u32, 39), op.item);
            if (op.source == .canonical_wire_boundary) try std.testing.expectEqual(@as(u32, 41), op.item);
            try mix(&channel, op, &unused_node, &actual_claims, &capture, wire);
        }
        try std.testing.expectEqual(@as(usize, 38), claim_count);
        var actual = try channel.finish();
        defer actual.deinit();
        if (mutation == 0) {
            try std.testing.expectEqualDeep(expected.hash_frames, actual.hash_frames);
            try std.testing.expectEqualDeep(expected.final_digest, actual.final_digest);
        } else try std.testing.expect(!std.meta.eql(expected.final_digest, actual.final_digest));
    }
}

/// Constructor-only geometry fixture. Actual component masks determine sample
/// counts; no proof, query, or FRI value in this fixture is verified.
fn initialProgramCapture(allocator: std.mem.Allocator, key: *const verifier.Initial38.KeyV1) !verifier.ProofCapture {
    const claims: verifier.Initial38.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const owner = try @import("ethereum_wrapper_verifier_components_v1.zig").Initial38.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &universal.UniversalRelations.dummy(), claims);
    defer owner.deinit();
    const components = core.air.components.Components{ .components = try owner.verifierComponents(), .n_preprocessed_columns = key.manifest.total_preprocessed_columns };
    const geometry = try recursion.recursion_air_composition_circuit_v3.capture_layout_v3.ethereumInitialWrapperFixedGeometryV1(&key.manifest, recursion.protocol.FRI_LOG_BLOWUP_FACTOR);
    const point = core.circle.secureFieldPointFromRandomSeed(QM31.fromU32Unchecked(3, 5, 7, 11));
    const masks = try components.maskPoints(allocator, point, geometry.composition_chunk_log_degree, false);
    // The caller's arena owns this whole synthetic capture and its nested masks.
    var capture = std.mem.zeroes(verifier.ProofCapture);
    capture.commitments = try allocator.alloc(Digest, 4);
    @memset(capture.commitments, @splat(0));
    capture.commitments[0] = key.preprocessed_root;
    capture.sampled_points = try allocator.alloc([][]core.circle.CirclePointQM31, 4);
    @memcpy(capture.sampled_points[0..3], masks.items);
    capture.sampled_points[3] = try allocator.alloc([]core.circle.CirclePointQM31, 16);
    for (capture.sampled_points[3]) |*column| column.* = try allocator.dupe(core.circle.CirclePointQM31, &.{point});
    capture.column_log_sizes = try allocator.alloc([]u32, 4);
    for (geometry.tree_column_counts, capture.column_log_sizes) |count, *logs| logs.* = try allocator.alloc(u32, count);
    for (key.manifest.placements) |placement| {
        const p = placement.?;
        const offsets = [_]usize{ p.preprocessed_offset, p.main_offset, p.interaction_offset };
        const counts = [_]usize{ p.geometry.preprocessed_columns, p.geometry.main_columns, p.geometry.interaction_columns };
        for (offsets, counts, capture.column_log_sizes[0..3]) |offset, count, logs| @memset(logs[offset..][0..count], p.geometry.log_size + recursion.protocol.FRI_LOG_BLOWUP_FACTOR);
    }
    @memset(capture.column_log_sizes[3], geometry.composition_chunk_log_degree + recursion.protocol.FRI_LOG_BLOWUP_FACTOR);
    capture.sampled_values = try allocator.alloc(QM31, geometry.sampled_value_count);
    @memset(capture.sampled_values, QM31.zero());
    capture.fri.layers = try allocator.alloc(std.meta.Child(@TypeOf(capture.fri.layers)), 1);
    capture.last_layer_coefficients = try allocator.alloc(QM31, 1);
    capture.queries.raw = try allocator.alloc(usize, QUERY_COUNT);
    return capture;
}

test "Ethereum detached transcript replays independently pinned field9 proof after input destruction" {
    try testSavedArtifact(@import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig"));
}

test "Ethereum initial detached transcript replays independently pinned field9 proof after input destruction" {
    try testSavedArtifact(recursion.air.ethereum_initial_input_manifest_v1);
}

fn testSavedArtifact(comptime ManifestMod: type) !void {
    const initial = ManifestMod == recursion.air.ethereum_initial_input_manifest_v1;
    const Selected = Types(ManifestMod);
    const Verifier = verifier.Types(ManifestMod);
    const allocator = std.testing.allocator;
    const transport = @import("ethereum_wrapper_root_command_v1.zig").Types(ManifestMod);
    const directory = try std.process.getEnvVarOwned(allocator, if (initial) "STWO_ETHEREUM_INITIAL_ROOT_REPLAY_DIR" else "STWO_ETHEREUM_ROOT_REPLAY_DIR");
    defer allocator.free(directory);
    const pin_hex = try std.process.getEnvVarOwned(allocator, if (initial) "STWO_ETHEREUM_INITIAL_ROOT_KEY_SHA256" else "STWO_ETHEREUM_ROOT_KEY_SHA256");
    defer allocator.free(pin_hex);
    if (pin_hex.len != 64) return error.InvalidEthereumDetachedKeyPin;
    var pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pin, pin_hex);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    var witness: *Selected.OwnedV1 = undefined;
    {
        const key_bytes = try dir.readFileAlloc(allocator, "key.json", 64 * 1024 * 1024);
        defer allocator.free(key_bytes);
        const key = try transport.OwnedKeyV1.admit(allocator, key_bytes, pin);
        defer key.deinit();
        const input_bytes = try dir.readFileAlloc(allocator, "inputs.json", 128 * 1024);
        defer allocator.free(input_bytes);
        const inputs = try transport.decodeInputs(allocator, input_bytes);
        const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
        defer allocator.free(proof);
        try std.testing.expectEqual(inputs.proof_bytes, proof.len);
        try std.testing.expectEqualDeep(inputs.proof_sha256, @import("ethereum_wrapper_root_command_v1.zig").hash(proof));
        const terminal = try Verifier.verify(allocator, key.key(), &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof);
        witness = try Selected.OwnedV1.init(allocator, key.key(), &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof);
        errdefer witness.deinit();
        try std.testing.expectEqualDeep(terminal, witness.terminalIdentity());
        const mutated_rows = if (initial) &[_]usize{ 0, 36, 37 } else &[_]usize{0};
        for (mutated_rows) |row| {
            var wrong_claims = inputs.claims;
            wrong_claims.values[row] = wrong_claims.values[row].add(QM31.one());
            try std.testing.expectError(error.InvalidEthereumRootClaimClosure, Selected.OwnedV1.init(allocator, key.key(), &inputs.node, wrong_claims, inputs.interaction_pow_nonce, proof));
        }
        // Recomputed fixed namespace cannot authorize another proof's Tree0.
        var wrong_key = key.key().*;
        wrong_key.preprocessed_root[0] = (wrong_key.preprocessed_root[0] + 1) % core.fields.m31.Modulus;
        wrong_key.session_fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&wrong_key);
        try std.testing.expectError(error.InvalidEthereumRootPreprocessedCommitment, Selected.OwnedV1.init(allocator, &wrong_key, &inputs.node, inputs.claims, inputs.interaction_pow_nonce, proof));
    }
    defer witness.deinit();
    try witness.admittedKey().validate();
    const child_shape = try @import("ethereum_wrapper_child_shape_v1.zig").Types(ManifestMod).OwnedV1.create(allocator, witness.admittedKey());
    defer child_shape.deinit();
    try child_shape.validateCaptureShape(allocator, witness.proofCapture());
    const view = witness.transcriptView();
    try view.program.validateRecording(view.execution);
    try view.execution.validate();
    var prepared = try view.prepareTranscriptRows(allocator, 1);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, ManifestMod.COMPONENT_COUNT), prepared.physical_claim_count);
    try std.testing.expectEqual(@as(usize, 193), witness.queryWords().len);
    try std.testing.expectEqual(@as(usize, 47), prepared.challenges.len);
    try std.testing.expectEqualDeep(witness.wireClaim(), try witness.admittedKey().wireClaim(witness.relations()));
    for (prepared.payload[0..8], witness.admittedKey().preprocessed_root) |row, word| {
        try std.testing.expectEqual(@as(u32, 1), row.preprocessing.constant_mask);
        try std.testing.expectEqual(word, row.preprocessing.constant_value);
    }
    const air_check = @import("recursive_secure_transcript_rows_v1_test.zig");
    try air_check.validate(&prepared, view.program, view.execution);
    const original_root_word = prepared.payload[0].value;
    prepared.payload[0].value = original_root_word.add(M31.one());
    try std.testing.expectError(error.TranscriptConstraintMismatch, air_check.validate(&prepared, view.program, view.execution));
    prepared.payload[0].value = original_root_word;
    try @import("ethereum_wrapper_detached_composition_v1.zig").Types(ManifestMod).testFromVerifiedTranscript(allocator, witness);
    if (initial)
        std.debug.print("ETHEREUM_INITIAL_DETACHED_TRANSCRIPT field9_verified=true manifest_components=38 native_capture_parity=true native_inputs_used=false input_buffers_destroyed=true queries=193 fold_admitted=false\n", .{})
    else
        std.debug.print("ETHEREUM_DETACHED_TRANSCRIPT field9_verified=true ordinary_capture_parity=true native_inputs_used=false input_buffers_destroyed=true queries=193 fold_admitted=false\n", .{});
}
