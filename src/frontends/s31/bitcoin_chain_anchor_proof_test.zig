//! Expensive, opt-in native proof test for the real checkpoint anchor layout.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const anchor = @import("bitcoin_chain_anchor.zig");
const fold = @import("bitcoin_chain_fold.zig");
const chain_verifier = @import("bitcoin_chain_verifier.zig");
const native = @import("native_verifier.zig");
const s31 = @import("stwo_s31_prototype");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
const targets: circuit.common.finalize.ComponentSizes = .{
    .eq = 32768,
    .qm31_ops = 2097152,
    .m31_to_u32 = 262144,
    .triple_xor = 131072,
    .blake_g_gate = 2097152,
};

const AnchorResult = struct {
    captured: cpu.verifier_proof.VerifierProof,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    root: [32]u8,
    hash: [32]u8,
    proof_bytes: usize,
    prove_ns: u64,
};

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}

fn proveAnchor(allocator: std.mem.Allocator, bundle: *const cpu.air.Bundle) !AnchorResult {
    var values = try anchor.build(core.fields.qm31.QM31, allocator, checkpoint, targets);
    defer values.deinit();
    try std.testing.expect(try values.isCircuitValid());
    var topology = try anchor.build(circuit.builder.NoValue, allocator, checkpoint, targets);
    defer topology.deinit();
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer pp.deinit(allocator);
    const layout = pp.layout();
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        layout.traceLogSize(),
    );
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );
    values.circuit.deinit(allocator);
    values.circuit = .{};
    var timer = try std.time.Timer.start();
    var proof = try cpu.Internal.prove(allocator, values.values(), &pp, bundle, pcs, .{ .evaluations_only = true }, {});
    defer proof.deinit();
    const elapsed = timer.read();
    try std.testing.expectEqual(@as(usize, 8), proof.output_values.len);
    for (proof.output_values, checkpoint) |value, word|
        try std.testing.expectEqual(word, circuit.builder.ivalue.unpackU32(core.fields.qm31.QM31, value));
    const bytes = try native.serialize(allocator, &proof);
    defer allocator.free(bytes);
    const captured = try native.verifyAndCapture(allocator, &layout, bundle, pcs, root, hash, checkpoint, bytes);
    return .{ .captured = captured, .layout = layout, .pcs = pcs, .root = root, .hash = hash, .proof_bytes = bytes.len, .prove_ns = elapsed };
}

fn headerHash(words: [40]u32) [32]u8 {
    var bytes: [80]u8 = undefined;
    for (words, 0..) |word, i|
        std.mem.writeInt(u16, bytes[2 * i ..][0..2], @intCast(word), .little);
    var once: [32]u8 = undefined;
    var twice: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &once, .{});
    std.crypto.hash.sha2.Sha256.hash(&once, &twice, .{});
    return twice;
}

fn hashRoot(hash: [32]u8) [8]u32 {
    var limbs: [16]M31 = undefined;
    for (&limbs, 0..) |*limb, i|
        limb.* = M31.fromCanonical(std.mem.readInt(u16, hash[2 * i ..][0..2], .little));
    const root = s31.poseidon2.leafWords(&limbs);
    var words: [8]u32 = undefined;
    for (root, &words) |value, *word| word.* = value.toU32();
    return words;
}

const FoldResult = struct {
    captured: cpu.verifier_proof.VerifierProof,
    public_words: [8]u32,
    encoded: []u8,
    proof_bytes: usize,
    prove_ns: u64,

    fn deinit(self: *FoldResult, allocator: std.mem.Allocator) void {
        self.captured.deinit();
        allocator.free(self.encoded);
    }
};

fn proveFoldStep(
    allocator: std.mem.Allocator,
    bundle: *const cpu.air.Bundle,
    pp: *const circuit.common.preprocessed.PreprocessedCircuit,
    table: *const circuit.air_eval.component_table.Table,
    layout: circuit.common.preprocessed.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    base_root: [32]u8,
    fold_root: [32]u8,
    fold_hash: [32]u8,
    child: *const cpu.verifier_proof.VerifierProof,
    prior_root_words: [8]u32,
    old_hash_words: [16]u32,
    header_words: [40]u32,
    step: u32,
) !FoldResult {
    var old_hash: [16]QM31 = undefined;
    var header: [40]QM31 = undefined;
    var prior_root: [8]QM31 = undefined;
    for (old_hash_words, &old_hash) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    for (header_words, &header) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    for (prior_root_words, &prior_root) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = pcs,
        .preprocessed_column_log_sizes = layout,
    };
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const proof_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &child.proof, child.config);
    var values = try fold.buildCircuit(
        QM31,
        allocator,
        table,
        &config,
        base_root,
        checkpoint,
        circuit.builder.blake.hashValue(QM31, wordsFromBytes(fold_root)),
        prior_root,
        old_hash,
        header,
        step,
        &proof_values,
        circuit.stark_verifier.verify.NoStages{},
    );
    defer values.deinit();
    if (!try values.isCircuitValid()) return error.InvalidBitcoinFoldCircuit;
    try circuit.common.finalize.padContext(QM31, &values);
    if (!try values.isCircuitValid()) return error.InvalidPaddedBitcoinFoldCircuit;
    var value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &values.circuit);
    defer value_pp.deinit(allocator);
    const value_root = try value_pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    if (!std.mem.eql(u8, &fold_root, &value_root)) return error.ValueDependentBitcoinFoldAir;
    values.circuit.deinit(allocator);
    values.circuit = .{};

    var timer = try std.time.Timer.start();
    var proof = try cpu.Internal.prove(allocator, values.values(), pp, bundle, pcs, .{ .evaluations_only = true }, {});
    defer proof.deinit();
    const prove_ns = timer.read();
    const new_root = hashRoot(headerHash(header_words));
    const expected = try s31.bitcoin_fold_digest.statementDigest(fold_root, step, checkpoint, new_root);
    try std.testing.expectEqual(@as(usize, 8), proof.output_values.len);
    for (proof.output_values, expected) |value, word|
        try std.testing.expectEqual(word, circuit.builder.ivalue.unpackU32(QM31, value));
    const bytes = try native.serialize(allocator, &proof);
    errdefer allocator.free(bytes);
    const captured = try native.verifyAndCapture(allocator, &layout, bundle, pcs, fold_root, fold_hash, expected, bytes);
    var changed = expected;
    changed[0] ^= 1;
    if (native.verify(allocator, &layout, bundle, pcs, fold_root, fold_hash, changed, bytes)) |_| {
        return error.AcceptedChangedBitcoinFoldStatement;
    } else |_| {}
    return .{ .captured = captured, .public_words = expected, .encoded = bytes, .proof_bytes = bytes.len, .prove_ns = prove_ns };
}

test "Bitcoin checkpoint anchor proves and verifies under the fold child layout" {
    const allocator = std.heap.page_allocator;
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var base = try proveAnchor(allocator, &bundle);
    defer base.captured.deinit();
    std.debug.print("Bitcoin checkpoint anchor: proof_bytes={d} prove_seconds={d:.3} root={s}\n", .{
        base.proof_bytes,                       @as(f64, @floatFromInt(base.prove_ns)) / std.time.ns_per_s,
        &std.fmt.bytesToHex(base.root, .lower),
    });
}

test "Bitcoin chain fold proves two changing headers over a verified checkpoint anchor" {
    const allocator = std.heap.page_allocator;
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var base = try proveAnchor(allocator, &bundle);
    defer base.captured.deinit();
    std.debug.print("Bitcoin checkpoint anchor: proof_bytes={d} prove_seconds={d:.3} root={s}\n", .{
        base.proof_bytes,                       @as(f64, @floatFromInt(base.prove_ns)) / std.time.ns_per_s,
        &std.fmt.bytesToHex(base.root, .lower),
    });

    var topology = try fold.topology(
        allocator,
        @embedFile("s31_air_projection"),
        base.layout,
        base.pcs,
        base.root,
        checkpoint,
        0,
    );
    defer topology.deinit();
    try circuit.common.finalize.padContext(circuit.builder.NoValue, &topology);
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer pp.deinit(allocator);
    if (!pp.layout().eql(&base.layout)) return error.FoldGeometryMismatch;
    const fold_root = try pp.preprocessedRoot(allocator, base.pcs.fri_config.log_blowup_factor);
    const fold_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&base.layout),
        base.pcs.fri_config.log_blowup_factor,
        fold_root,
    );

    const Fixture = struct { private_inputs: struct { prior_hash: [16]u32, child: [40]u32 } };
    var parsed = try std.json.parseFromSlice(Fixture, allocator, @embedFile("s31_bitcoin_fixture"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var projection = try circuit.air_eval.projection.parse(allocator, @embedFile("s31_air_projection"));
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    const new_root = [8]u32{ 1230097977, 338045265, 582454319, 1194138423, 159136005, 2049036807, 17165835, 883545160 };
    try std.testing.expectEqualDeep(new_root, hashRoot(headerHash(parsed.value.private_inputs.child)));
    var fold0 = try proveFoldStep(
        allocator,
        &bundle,
        &pp,
        &table,
        base.layout,
        base.pcs,
        base.root,
        fold_root,
        fold_hash,
        &base.captured,
        checkpoint,
        parsed.value.private_inputs.prior_hash,
        parsed.value.private_inputs.child,
        0,
    );
    defer fold0.deinit(allocator);
    std.debug.print("Bitcoin chain fold step 0: proof_bytes={d} prove_seconds={d:.3} root={s}\n", .{
        fold0.proof_bytes,                      @as(f64, @floatFromInt(fold0.prove_ns)) / std.time.ns_per_s,
        &std.fmt.bytesToHex(fold_root, .lower),
    });

    const Block2 = struct {
        header_hex: []const u8,
        display_hash: []const u8,
        previous_display_hash: []const u8,
    };
    var block2 = try std.json.parseFromSlice(Block2, allocator, @embedFile("s31_bitcoin_block2_fixture"), .{ .ignore_unknown_fields = true });
    defer block2.deinit();
    var block2_bytes: [80]u8 = undefined;
    _ = try std.fmt.hexToBytes(&block2_bytes, block2.value.header_hex);
    var block2_words: [40]u32 = undefined;
    for (&block2_words, 0..) |*word, i| word.* = std.mem.readInt(u16, block2_bytes[2 * i ..][0..2], .little);
    const block1_hash = headerHash(parsed.value.private_inputs.child);
    if (!std.mem.eql(u8, block2_bytes[4..36], &block1_hash)) return error.InvalidBlockTwoPreviousHash;
    var display_block1 = block1_hash;
    std.mem.reverse(u8, &display_block1);
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(display_block1, .lower), block2.value.previous_display_hash))
        return error.InvalidBlockOneDisplayHash;
    const block2_hash = headerHash(block2_words);
    var display_block2 = block2_hash;
    std.mem.reverse(u8, &display_block2);
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(display_block2, .lower), block2.value.display_hash))
        return error.InvalidBlockTwoDisplayHash;
    var block1_hash_words: [16]u32 = undefined;
    for (&block1_hash_words, 0..) |*word, i| word.* = std.mem.readInt(u16, block1_hash[2 * i ..][0..2], .little);
    var fold1 = try proveFoldStep(
        allocator,
        &bundle,
        &pp,
        &table,
        base.layout,
        base.pcs,
        base.root,
        fold_root,
        fold_hash,
        &fold0.captured,
        new_root,
        block1_hash_words,
        block2_words,
        1,
    );
    defer fold1.deinit(allocator);
    if (std.meta.eql(fold0.public_words, fold1.public_words)) return error.FoldDidNotAdvance;
    std.debug.print("Bitcoin chain fold step 1: proof_bytes={d} prove_seconds={d:.3} root={s}\n", .{
        fold1.proof_bytes,                      @as(f64, @floatFromInt(fold1.prove_ns)) / std.time.ns_per_s,
        &std.fmt.bytesToHex(fold_root, .lower),
    });

    var genesis_raw: [32]u8 = undefined;
    for (parsed.value.private_inputs.prior_hash, 0..) |word, i|
        std.mem.writeInt(u16, genesis_raw[2 * i ..][0..2], @intCast(word), .little);
    std.mem.reverse(u8, &genesis_raw);
    const genesis_display = std.fmt.bytesToHex(genesis_raw, .lower);
    const key_bytes = try chain_verifier.generateKeyJson(allocator, &genesis_display, 1);
    defer allocator.free(key_bytes);
    try std.testing.expectError(error.FirstEpochRetargetUnsupported,
        chain_verifier.generateKeyJson(allocator, &genesis_display, 2015));
    try std.testing.expectError(error.FirstEpochRequiresGenesisCheckpoint,
        chain_verifier.generateKeyJson(allocator, block2.value.display_hash, 1));
    const key_digest = chain_verifier.sha256(key_bytes);
    const key = try chain_verifier.validateKey(allocator, key_bytes, key_digest);
    try std.testing.expectEqualDeep(checkpoint, key.material.checkpoint_root);
    try std.testing.expectEqualDeep(base.root, key.material.anchor_root);
    try std.testing.expectEqualDeep(fold_root, key.material.fold_root);
    var wrong_digest = key_digest;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.WrongVerificationKeyDigest, chain_verifier.validateKey(allocator, key_bytes, wrong_digest));
    try std.testing.expectError(error.BitcoinChainStepExceedsKeyLimit, chain_verifier.generateStatementJson(allocator, key, 2, block2.value.display_hash));
    const first_statement = try chain_verifier.generateStatementJson(allocator, key, 0, block2.value.previous_display_hash);
    defer allocator.free(first_statement);
    const second_statement = try chain_verifier.generateStatementJson(allocator, key, 1, block2.value.display_hash);
    defer allocator.free(second_statement);
    try chain_verifier.verifyProof(allocator, key, first_statement, fold0.encoded);
    try chain_verifier.verifyProof(allocator, key, second_statement, fold1.encoded);
    if (chain_verifier.verifyProof(allocator, key, second_statement, fold0.encoded)) |_| {
        return error.BitcoinChainVerifierAcceptedWrongStepProof;
    } else |_| {}
    var parsed_statement = try std.json.parseFromSlice(chain_verifier.Statement, allocator, second_statement, .{ .ignore_unknown_fields = false });
    defer parsed_statement.deinit();
    parsed_statement.value.public_words[0] ^= 1;
    const changed_statement = try std.json.Stringify.valueAlloc(allocator, parsed_statement.value, .{});
    defer allocator.free(changed_statement);
    try std.testing.expectError(error.InvalidBitcoinChainStatement, chain_verifier.verifyProof(allocator, key, changed_statement, fold1.encoded));
    std.debug.print("Bitcoin chain verifier: key_sha256={s} step_1_accepted=true replay_rejected=true\n", .{
        &std.fmt.bytesToHex(key_digest, .lower),
    });
    const artifact_dir = "zig-out/s31/bitcoin-chain-two-step";
    try std.fs.cwd().makePath(artifact_dir);
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/verification-key.json", .data = key_bytes });
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/fold0.statement.json", .data = first_statement });
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/fold0.proof", .data = fold0.encoded });
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/fold1.statement.json", .data = second_statement });
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/fold1.proof", .data = fold1.encoded });
    const digest_line = try std.fmt.allocPrint(allocator, "{s}\n", .{&std.fmt.bytesToHex(key_digest, .lower)});
    defer allocator.free(digest_line);
    try std.fs.cwd().writeFile(.{ .sub_path = artifact_dir ++ "/verification-key.sha256", .data = digest_line });

    // The child proof and header remain valid; only the claimed prior state
    // changes. The child-output digest must make the outer circuit invalid.
    var forged_root = new_root;
    forged_root[0] ^= 1;
    var forged_root_values: [8]QM31 = undefined;
    var old_hash_values: [16]QM31 = undefined;
    var block2_values: [40]QM31 = undefined;
    for (forged_root, &forged_root_values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    for (block1_hash_words, &old_hash_values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    for (block2_words, &block2_values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    const config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = base.pcs,
        .preprocessed_column_log_sizes = base.layout,
    };
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const child_values = try cpu.verifier_proof.circuitVerifierValues(
        scratch.allocator(),
        &fold0.captured.proof,
        fold0.captured.config,
    );
    var forged = try fold.buildCircuit(
        QM31,
        allocator,
        &table,
        &config,
        base.root,
        checkpoint,
        circuit.builder.blake.hashValue(QM31, wordsFromBytes(fold_root)),
        forged_root_values,
        old_hash_values,
        block2_values,
        1,
        &child_values,
        circuit.stark_verifier.verify.NoStages{},
    );
    defer forged.deinit();
    if (try forged.isCircuitValid()) return error.AcceptedForgedPriorBitcoinState;
    std.debug.print("Bitcoin chain fold: forged prior state rejected\n", .{});
}
