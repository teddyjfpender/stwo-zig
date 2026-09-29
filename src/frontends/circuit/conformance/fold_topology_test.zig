//! R6 fold topology rung, oracle-free part (design §8.2).
//!
//! Checks the fold circuit's identity data that does not need the built
//! multiverifier circuit:
//!
//! - the 45-column preprocessed layout of `layout_from_component_sizes`
//!   against `multiverifier_preprocessed_column_log_sizes` in
//!   `crates/circuit_multiverifier/src/test_utils.rs`;
//! - every committed registry's `circuit_hash` from its `preprocessed_root`,
//!   config and target sizes (`CanonicalCircuit::build` steps 1 and 4);
//! - the R0 circuit-hash vectors (`config_words` and the host hash);
//! - `ProofInfo::total_bytes` against the length of the multiverifier
//!   `proof.bin` fixture (182,884 bytes, `LOG_BLOWUP_FACTOR` 3).
//!
//! Upstream: https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. The multiverifier's own
//! `preprocessed_root` (`MULTIVERIFIER_PREPROCESSED_ROOT`, and the registry
//! roots) needs the built multiverifier circuit and is not checked here.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("circuit_frontend");

const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const component_list = circuit.common.component_list;
const ComponentSizes = circuit.common.finalize.ComponentSizes;
const multiverifier = circuit.statements.multiverifier;
const circuit_statement = circuit.statements.circuit_statement;
const ProofInfo = circuit.stark_verifier.proof.ProofInfo;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

/// `TARGET_PADDING_SIZES` of `circuit_multiverifier/src/test_utils.rs`.
const TARGET_PADDING_SIZES: ComponentSizes = .{
    .eq = 1 << 17,
    .qm31_ops = 1 << 21,
    .m31_to_u32 = 1 << 18,
    .triple_xor = 1 << 17,
    .blake_g_gate = 1 << 20,
};

/// `multiverifier_preprocessed_column_log_sizes()`.
const MULTIVERIFIER_LAYOUT = [_]preprocessed.LayoutEntry{
    .{ .id = "bitwise_xor_4_0", .log_size = 8 },
    .{ .id = "bitwise_xor_4_1", .log_size = 8 },
    .{ .id = "bitwise_xor_4_2", .log_size = 8 },
    .{ .id = "bitwise_xor_7_0", .log_size = 14 },
    .{ .id = "bitwise_xor_7_1", .log_size = 14 },
    .{ .id = "bitwise_xor_7_2", .log_size = 14 },
    .{ .id = "seq_16", .log_size = 16 },
    .{ .id = "bitwise_xor_8_0", .log_size = 16 },
    .{ .id = "bitwise_xor_8_1", .log_size = 16 },
    .{ .id = "bitwise_xor_8_2", .log_size = 16 },
    .{ .id = "eq_in0_address", .log_size = 17 },
    .{ .id = "eq_in1_address", .log_size = 17 },
    .{ .id = "triple_xor_input_addr_0", .log_size = 17 },
    .{ .id = "triple_xor_input_addr_1", .log_size = 17 },
    .{ .id = "triple_xor_input_addr_2", .log_size = 17 },
    .{ .id = "triple_xor_output_addr", .log_size = 17 },
    .{ .id = "triple_xor_multiplicity", .log_size = 17 },
    .{ .id = "m31_to_u32_input_addr", .log_size = 18 },
    .{ .id = "m31_to_u32_output_addr", .log_size = 18 },
    .{ .id = "m31_to_u32_multiplicity", .log_size = 18 },
    .{ .id = "bitwise_xor_9_0", .log_size = 18 },
    .{ .id = "bitwise_xor_9_1", .log_size = 18 },
    .{ .id = "bitwise_xor_9_2", .log_size = 18 },
    .{ .id = "blake_g_gate_input_addr_a", .log_size = 20 },
    .{ .id = "blake_g_gate_input_addr_b", .log_size = 20 },
    .{ .id = "blake_g_gate_input_addr_c", .log_size = 20 },
    .{ .id = "blake_g_gate_input_addr_d", .log_size = 20 },
    .{ .id = "blake_g_gate_input_addr_f0", .log_size = 20 },
    .{ .id = "blake_g_gate_input_addr_f1", .log_size = 20 },
    .{ .id = "blake_g_gate_output_addr_a", .log_size = 20 },
    .{ .id = "blake_g_gate_output_addr_b", .log_size = 20 },
    .{ .id = "blake_g_gate_output_addr_c", .log_size = 20 },
    .{ .id = "blake_g_gate_output_addr_d", .log_size = 20 },
    .{ .id = "blake_g_gate_multiplicity", .log_size = 20 },
    .{ .id = "bitwise_xor_10_0", .log_size = 20 },
    .{ .id = "bitwise_xor_10_1", .log_size = 20 },
    .{ .id = "bitwise_xor_10_2", .log_size = 20 },
    .{ .id = "qm31_ops_add_flag", .log_size = 21 },
    .{ .id = "qm31_ops_sub_flag", .log_size = 21 },
    .{ .id = "qm31_ops_mul_flag", .log_size = 21 },
    .{ .id = "qm31_ops_pointwise_mul_flag", .log_size = 21 },
    .{ .id = "qm31_ops_in0_address", .log_size = 21 },
    .{ .id = "qm31_ops_in1_address", .log_size = 21 },
    .{ .id = "qm31_ops_out_address", .log_size = 21 },
    .{ .id = "qm31_ops_mults", .log_size = 21 },
};

/// `get_pcs_config(PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE = 21,
/// LOG_BLOWUP_FACTOR = 3)` of `cairo_verifier/src/privacy.rs`.
fn multiverifierTestPcsConfig() !PcsConfigV2 {
    const fri = try FriConfigV2.init(27, 0, 3, 23, 4);
    return PcsConfigV2.fromFriAndTraceSize(fri, 21);
}

const MULTIVERIFIER_PROOF_BIN_BYTES: usize = 182_884;

test "r6 fold: layout_from_component_sizes reproduces the 45-column multiverifier layout" {
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(TARGET_PADDING_SIZES);
    try std.testing.expectEqual(MULTIVERIFIER_LAYOUT.len, layout.entries.len);
    for (MULTIVERIFIER_LAYOUT, layout.entries) |want, got| {
        try std.testing.expectEqualStrings(want.id, got.id);
        try std.testing.expectEqual(want.log_size, got.log_size);
    }
    try std.testing.expectEqual(@as(u32, 21), layout.traceLogSize());
}

test "r6 fold: ProofInfo total bytes equal the multiverifier proof.bin length" {
    const allocator = std.testing.allocator;
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(TARGET_PADDING_SIZES);
    var shared = try multiverifier.sharedConfig(allocator, layout, try multiverifierTestPcsConfig());
    defer shared.deinit(allocator);
    const config = shared.proof_config;
    try std.testing.expectEqual(@as(usize, 45), config.n_preprocessed_columns);
    try std.testing.expectEqual(@as(usize, 114), config.n_trace_columns);
    try std.testing.expectEqual(@as(usize, 152), config.n_interaction_columns);
    try std.testing.expectEqual(@as(usize, 6), config.nFriLayers());
    const info = ProofInfo.fromConfig(config);
    try std.testing.expectEqual(MULTIVERIFIER_PROOF_BIN_BYTES, info.totalBytes());
}

const DigestWords = [8][]const u8;

const RegistryFriConfig = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,
};

const RegistryLogSizes = struct {
    eq: u32,
    qm31_ops: u32,
    m31_to_u32: u32,
    triple_xor: u32,
    blake_g_gate: u32,
};

const RegistryCircuitConfig = struct {
    fri_config: RegistryFriConfig,
    component_log_sizes: RegistryLogSizes,
};

const RegistryEntry = struct {
    config: []const u8,
    preprocessed_root: DigestWords,
    circuit_hash: DigestWords,
};

/// Test-only reader for the fields R6 needs. The interop registry codec
/// (M3 `registry.zig`) replaces it once it lands.
const Registry = struct {
    circuit_proof_configs: std.json.ArrayHashMap(RegistryCircuitConfig),
    leaf_verifiers: []const RegistryEntry,
    multiverifiers: []const RegistryEntry,
};

fn parseDigest(words: DigestWords) ![32]u8 {
    var out: [8]u32 = undefined;
    for (words, &out) |text, *word| {
        if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidDigestWord;
        word.* = try std.fmt.parseInt(u32, text[2..], 16);
    }
    return circuit_hash.bytesFromLeU32s(8, out);
}

fn checkRegistry(path: []const u8) !usize {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 1 << 20);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Registry, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var checked: usize = 0;
    for ([_][]const RegistryEntry{ parsed.value.leaf_verifiers, parsed.value.multiverifiers }) |entries| {
        for (entries) |entry| {
            const config = parsed.value.circuit_proof_configs.map.get(entry.config) orelse return error.MissingConfig;
            const fri = config.fri_config;
            const target_sizes = ComponentSizes.fromLogSizes(config.component_log_sizes);
            var shared = try multiverifier.foldSharedConfig(
                allocator,
                target_sizes,
                try FriConfigV2.init(fri.pow_bits, fri.log_last_layer_degree_bound, fri.log_blowup_factor, fri.n_queries, fri.fold_step),
            );
            defer shared.deinit(allocator);
            const log_sizes = try circuit_statement.circuitComponentLogSizes(&shared.preprocessed_column_log_sizes);
            const got = try circuit_hash.hostCircuitHash(
                log_sizes,
                shared.pcs_config.fri_config.log_blowup_factor,
                try parseDigest(entry.preprocessed_root),
            );
            try std.testing.expectEqualSlices(u8, &(try parseDigest(entry.circuit_hash)), &got);
            checked += 1;
        }
    }
    return checked;
}

test "r6 fold: registry circuit hashes follow from target sizes, FRI config and root" {
    // Leaf verifiers and multiverifiers share the registry's padding target,
    // so both hash through the same layout.
    try std.testing.expectEqual(@as(usize, 2), try checkRegistry("vectors/circuit/official/registries/recursive_tree_test.json"));
    try std.testing.expectEqual(@as(usize, 2), try checkRegistry("vectors/circuit/official/registries/leaf_prover_canonical_small.json"));
}

const R0CircuitHash = struct {
    name: []const u8,
    log_blowup_factor: u32,
    component_log_sizes: [component_list.N_COMPONENTS]u32,
    config_words: [circuit_hash.CONFIG_N_WORDS]u32,
    preprocessed_root: []const u8,
    circuit_hash: []const u8,
};

const R0Checkpoint = struct {
    body: struct {
        hashing: struct {
            circuit_hash: []const R0CircuitHash,
        },
    },
};

test "r6 fold: R0 config words and circuit hashes" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/r0/primitives.json", 8 << 20);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(R0Checkpoint, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const cases = parsed.value.body.hashing.circuit_hash;
    try std.testing.expect(cases.len >= 5);
    for (cases) |case| {
        const sizes = component_list.PerComponent(u32).fromArray(case.component_log_sizes);
        const words = try circuit_hash.configWords(case.log_blowup_factor, sizes);
        try std.testing.expectEqualSlices(u32, &case.config_words, &words);
        var root: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&root, case.preprocessed_root);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.circuit_hash);
        const got = try circuit_hash.hostCircuitHash(sizes, case.log_blowup_factor, root);
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}

const R3Checkpoint = struct {
    body: struct {
        evaluators: []const struct {
            air: []const u8,
            name: []const u8,
            trace_columns: usize,
            interaction_columns: usize,
            relation_uses_per_row: []const struct { relation_id: []const u8, uses: u64 },
        },
    },
};

test "r6 fold: static component facts agree with the R3 evaluator fixture" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/circuit/r3/components.json", 64 << 20);
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(R3Checkpoint, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var seen: usize = 0;
    for (parsed.value.body.evaluators) |evaluator| {
        if (!std.mem.eql(u8, evaluator.air, "circuit")) continue;
        const component = std.meta.stringToEnum(component_list.ComponentList, evaluator.name) orelse
            return error.UnknownCircuitComponent;
        try std.testing.expectEqual(seen, component.idx());
        const facts = component_list.component_facts.get(component);
        try std.testing.expectEqual(evaluator.trace_columns, facts.trace_columns);
        try std.testing.expectEqual(evaluator.interaction_columns, facts.interaction_columns);
        try std.testing.expectEqual(evaluator.relation_uses_per_row.len, facts.relation_uses_per_row.len);
        for (evaluator.relation_uses_per_row, facts.relation_uses_per_row) |want, got| {
            try std.testing.expectEqualStrings(want.relation_id, got.relation_id);
            try std.testing.expectEqual(want.uses, got.uses);
        }
        seen += 1;
    }
    try std.testing.expectEqual(component_list.N_COMPONENTS, seen);
}
