//! R10c: the Zig Cairo leaf lane against upstream `prove_cairo`.
//!
//! Proves `all_opcodes` and `all_builtins` (stwo-cairo 82f2125
//! `test_prove_verify_all_opcode_components` / `..._all_builtins`) under the
//! canonical_small leaf registry's `cairo_prover_params` on the CPU binding of
//! `prove_cairo::<Blake2sM31MerkleChannel>` and compares each serialized proof
//! with `vectors/circuit/r10/<name>.prove_cairo.json`,
//! emitted by `stwo-circuit-oracle prove-cairo` at
//! https://github.com/starkware-libs/proving 5a7c5ede4299c91a61df19a07cba4f7502c14230
//! (which verified the proof with `verify_cairo_ex` first).
//!
//! - `binary`: `bincode(CairoProofForRustVerifier)`, every byte fixed by the protocol;
//! - `extended_binary`: `bincode(CairoProof)` with aux maps in ascending key order.
//!
//! On a mismatch the per-stage checkpoint values localise the first
//! divergent transcript step.

const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const leaf = @import("stwo_cairo_cpu_integration").prover.leaf_transaction;
const registry_format = @import("stwo_circuit_recursion_wire").registry;

const registry_path = "vectors/circuit/official/registries/leaf_prover_canonical_small.json";

const ByteRecord = struct { bytes: u64, sha256: []const u8 };
const U64Record = struct { value: []const u8, hi: u32, lo: u32 };
const Stages = struct {
    config: struct {
        pow_bits: u32,
        log_blowup_factor: u32,
        log_last_layer_degree_bound: u32,
        n_queries: u64,
        fold_step: u32,
        trace_lifting_log_size: u32,
        preprocessed_lifting_log_size: u32,
    },
    interaction_pow: U64Record,
    commitments: []const []const u8,
    proof_of_work: U64Record,
    fri_inner_layer_roots: []const []const u8,
};
const Checkpoint = struct {
    body: struct {
        binary: ByteRecord,
        extended_binary: ByteRecord,
        stages: Stages,
    },
};

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
}

fn expectSha256(expected: ByteRecord, bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (expected.bytes != bytes.len or !std.mem.eql(u8, expected.sha256, &actual)) {
        std.debug.print("bytes {d} sha256 {s}; oracle bytes {d} sha256 {s}\n", .{
            bytes.len, &actual, expected.bytes, expected.sha256,
        });
        return error.LeafProofBytesDiffer;
    }
}

fn hex(bytes: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

/// Reports every stage that differs; the first one is where the transcripts fork.
fn compareStages(expected: Stages, result: *const leaf.Result) !void {
    const proof = result.proof.proof.commitment_scheme_proof;
    var diverged = false;
    const config = proof.revision_config orelse return error.MissingRevisionConfig;
    if (config.trace_lifting_log_size != expected.config.trace_lifting_log_size or
        config.preprocessed_lifting_log_size != expected.config.preprocessed_lifting_log_size or
        config.fri_config.pow_bits != expected.config.pow_bits)
    {
        std.debug.print("config: heights {d}/{d}, oracle {d}/{d}\n", .{
            config.trace_lifting_log_size,               config.preprocessed_lifting_log_size,
            expected.config.trace_lifting_log_size, expected.config.preprocessed_lifting_log_size,
        });
        diverged = true;
    }
    for (proof.commitments.items, 0..) |root, tree| {
        const actual = hex(root);
        if (tree >= expected.commitments.len or !std.mem.eql(u8, expected.commitments[tree], &actual)) {
            std.debug.print("commitment {d}: {s}, oracle {s}\n", .{
                tree, &actual, if (tree < expected.commitments.len) expected.commitments[tree] else "-",
            });
            diverged = true;
        }
    }
    var buffer: [24]u8 = undefined;
    const interaction = try std.fmt.bufPrint(&buffer, "{d}", .{result.interaction_pow});
    if (!std.mem.eql(u8, interaction, expected.interaction_pow.value)) {
        std.debug.print("interaction pow {s}, oracle {s}\n", .{ interaction, expected.interaction_pow.value });
        diverged = true;
    }
    const fri_pow = try std.fmt.bufPrint(&buffer, "{d}", .{proof.proof_of_work});
    if (!std.mem.eql(u8, fri_pow, expected.proof_of_work.value)) {
        std.debug.print("FRI pow {s}, oracle {s}\n", .{ fri_pow, expected.proof_of_work.value });
        diverged = true;
    }
    for (proof.fri_proof.inner_layers, 0..) |layer, index| {
        const actual = hex(layer.commitment);
        if (index >= expected.fri_inner_layer_roots.len or
            !std.mem.eql(u8, expected.fri_inner_layer_roots[index], &actual))
        {
            std.debug.print("FRI layer {d}: {s}\n", .{ index, &actual });
            diverged = true;
            break;
        }
    }
    if (diverged) return error.LeafProofStagesDiffer;
}

test "R10c: leaf Cairo proofs match proving@5a7c5ed prove_cairo" {
    // The last field overrides the registry's lifting policy: under
    // AtLeastPreprocessed these programs commit every tree at its own height
    // (their 2^20-row tables fill the preprocessed domain), and `Fixed(22)`
    // lifts every tree, the pruned preprocessed one included.
    const Policy = registry_format.LiftingSizePolicy;
    inline for (.{
        .{ "all_opcodes", "vectors/cairo/official/all_opcodes.prover_input.json", @as(?Policy, null) },
        .{ "all_builtins", "vectors/cairo/official/all_builtins.prover_input.json", @as(?Policy, null) },
        .{ "use_all_opcodes_and_builtins", "vectors/circuit/r10/use_all_opcodes_and_builtins.prover_input.json", @as(?Policy, null) },
        .{ "all_opcodes.fixed_22", "vectors/cairo/official/all_opcodes.prover_input.json", @as(?Policy, .{ .fixed = 22 }) },
    }) |case| {
        const name = case[0];
        proveAndCompare(case[1], "vectors/circuit/r10/" ++ name ++ ".prove_cairo.json", case[2]) catch |err| {
            std.debug.print("R10c case {s} failed\n", .{name});
            return err;
        };
    }
}

fn proveAndCompare(input_path: []const u8, checkpoint_path: []const u8, policy: ?registry_format.LiftingSizePolicy) !void {
    const allocator = std.testing.allocator;

    const checkpoint_bytes = try readFile(allocator, checkpoint_path);
    defer allocator.free(checkpoint_bytes);
    const checkpoint = try std.json.parseFromSlice(Checkpoint, allocator, checkpoint_bytes, .{ .ignore_unknown_fields = true });
    defer checkpoint.deinit();

    // The registry's `cairo_prover_params`, as the leaf prover reads them.
    const registry_bytes = try readFile(allocator, registry_path);
    defer allocator.free(registry_bytes);
    var registry = try registry_format.parseRegistry(allocator, registry_bytes);
    defer registry.deinit();
    var params = registry.registry.cairo_prover_params;
    if (policy) |override| params.lifting_size_policy = override;

    var input = try cairo.adapter.official_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var programs = try cairo.witness.bundle.Bundle.readFile(allocator, "vectors/cairo/official/witness_programs_v1.bin");
    defer programs.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
    defer topology.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, "vectors/cairo/cairo_fixed_tables.bin");
    defer fixed.deinit();
    var relations = try cairo.witness.relation_bundle.Bundle.readFile(allocator, "vectors/cairo/cairo_relation_templates.bin");
    defer relations.deinit();
    var air_templates = try cairo.air.template_library.Library.readFile(allocator, "vectors/cairo/official/air_template_library_v1.json");
    defer air_templates.deinit();

    var result = try leaf.proveLeafCairo(allocator, .{
        .input = &input,
        .programs = &programs,
        .topology = topology,
        .fixed = &fixed,
        .relations = &relations,
        .air_templates = &air_templates,
    }, params, null);
    defer result.deinit();

    compareStages(checkpoint.value.body.stages, &result) catch |err| {
        std.debug.print("R10c leaf proof diverges from the oracle\n", .{});
        return err;
    };

    var binary = std.Io.Writer.Allocating.init(allocator);
    defer binary.deinit();
    try cairo.proof.binary.writeDocument(
        &binary.writer,
        &input,
        &result.composition,
        result.claimed_sums,
        result.interaction_pow,
        result.channel_salt,
        result.preprocessed_variant,
        &result.proof.proof,
    );
    try expectSha256(checkpoint.value.body.binary, binary.written());

    var extended = std.Io.Writer.Allocating.init(allocator);
    defer extended.deinit();
    try cairo.proof.binary.writeExtendedDocument(
        allocator,
        &extended.writer,
        &input,
        &result.composition,
        result.claimed_sums,
        result.interaction_pow,
        result.channel_salt,
        result.preprocessed_variant,
        &result.proof,
    );
    try expectSha256(checkpoint.value.body.extended_binary, extended.written());
}

test "R10b: canonical_small preprocessed roots at log blowup 1, 2 and 3" {
    // `get_preprocessed_root` (crates/cairo_verifier/src/verify.rs at
    // proving@5a7c5ed), generated by
    // `export_circuit_cairo_verifier_preprocessed_roots`: the canonical_small
    // preprocessed trace under `Blake2sM31MerkleChannel`, extended by
    // `log_blowup_factor` and committed at `20 + log_blowup_factor`, as the
    // little-endian words of its Blake2s digest.
    const expected = [_]struct { log_blowup_factor: u32, words: [8]u32 }{
        .{ .log_blowup_factor = 1, .words = .{ 1712426246, 3975215561, 3393287716, 971513401, 2481352801, 3435847491, 949366627, 3962244455 } },
        .{ .log_blowup_factor = 2, .words = .{ 1339935525, 1265118357, 1284994137, 2854722301, 3594581873, 3353940013, 4006659842, 3223691736 } },
        .{ .log_blowup_factor = 3, .words = .{ 2271225220, 1855536874, 1802924152, 654143153, 3715309987, 1517124483, 206973071, 750452746 } },
    };
    const allocator = std.testing.allocator;
    const preprocessed = cairo.preprocessed;
    var spec = try preprocessed.trace.Spec.init(allocator, .canonical_small);
    defer spec.deinit();
    var pedersen = try preprocessed.pedersen_table.Table.init(allocator, .small);
    defer pedersen.deinit();
    for (expected) |case| {
        const fri = try cairo.proving.leaf_lane.FriConfigV2.init(16, 0, case.log_blowup_factor, 70, 1);
        const binding = preprocessed.product_cache.Binding{
            .variant = .canonical_small,
            .spec_digest = preprocessed.product_cache.specDigest(spec),
            .pcs_digest = preprocessed.product_cache.pcsDigestRevision(fri),
        };
        const height = spec.variant.maxLogSize() + case.log_blowup_factor;
        const config = cairo.proving.leaf_lane.PcsConfigV2.fromFriAndLiftingSize(fri, height);
        var scheme = try leaf.Engine.initRevision(allocator, config);
        defer scheme.deinit(allocator);
        var channel = leaf.Channel{};
        try cairo.proving.preprocessed_commit.commit(leaf.Engine, allocator, &spec, &pedersen, binding, &scheme, &channel, null);
        var roots = try scheme.roots(allocator);
        defer roots.deinit(allocator);
        var expected_bytes: [32]u8 = undefined;
        for (case.words, 0..) |word, index| std.mem.writeInt(u32, expected_bytes[index * 4 ..][0..4], word, .little);
        if (!std.mem.eql(u8, &expected_bytes, &roots.items[0])) {
            std.debug.print("preprocessed root at blowup {d}: {s}, upstream {s}\n", .{
                case.log_blowup_factor, &hex(roots.items[0]), &hex(expected_bytes),
            });
            return error.PreprocessedRootDiffers;
        }
    }
}

/// Upstream `FrameworkComponent` semantics for the example AIR: the OODS
/// vanishing polynomial is over `CanonicCoset(max_log_degree_bound)`, which a
/// lifted proof raises above the component's rows. The example component
/// fixes it at its own rows (the a8fcf4b native lane), so this wrapper
/// replaces that one term and delegates everything else.
const LiftedWideFibonacci = struct {
    inner: @import("stwo_native_examples").wide_fibonacci.Component,

    const core = @import("stwo_core");
    const prover_air = @import("stwo_prover_engine").air;
    const Adapter = core.air.derive.ComponentAdapter(
        @This(),
        prover_air.component_prover.ComponentProver,
        prover_air.component_prover.Trace,
        prover_air.accumulation.DomainEvaluationAccumulator,
    );

    fn asProverComponent(self: *const @This()) prover_air.component_prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.inner.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.inner.maxConstraintLogDegreeBound();
    }
    pub fn traceLogDegreeBounds(self: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        return self.inner.traceLogDegreeBounds(allocator);
    }
    pub fn maskPoints(self: *const @This(), allocator: std.mem.Allocator, point: core.circle.CirclePointQM31, bound: u32) !core.air.components.MaskPoints {
        // Every mask offset is 0, so the points do not depend on the bound.
        return self.inner.maskPoints(allocator, point, bound);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        return self.inner.preprocessedColumnIndices(allocator);
    }
    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
    ) !void {
        return self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }
    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: core.circle.CirclePointQM31,
        mask: *const core.air.components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        // The lifted proof's OODS quotient divides by the committed domain.
        return self.inner.evaluateConstraintQuotientsAtPointOver(point, mask, accumulator, max_log_degree_bound);
    }
};

const LiftedCheckpoint = struct {
    body: struct {
        fri_config: [5]u32,
        cases: []const struct {
            log_n_rows: u32,
            sequence_len: u32,
            trace_lifting_log_size: u32,
            preprocessed_lifting_log_size: u32,
            commitments: []const []const u8,
            proof_of_work: U64Record,
            fri_inner_layer_roots: []const []const u8,
            sampled_values_sha256: []const u8,
            stark_proof_bytes: u64,
            stark_proof_sha256: []const u8,
        },
    },
};

test "R10 lift: trace trees committed above their columns match proving@5a7c5ed" {
    // `stwo-circuit-oracle prove-lifted-example`: upstream's wide-Fibonacci
    // prover test with the trace tree lifted 0, 1 and 3 levels above its
    // columns. The small Cairo programs never lift (their 2^20-row tables fill
    // the preprocessed domain), so this is the end-to-end check of the prover's
    // lifted commitments, queries, sampled points and FRI domain.
    const allocator = std.testing.allocator;
    const core = @import("stwo_core");
    const wide_fibonacci = @import("stwo_native_examples").wide_fibonacci;
    const bytes = try readFile(allocator, "vectors/circuit/r10/prove_lifted_example.json");
    defer allocator.free(bytes);
    const checkpoint = try std.json.parseFromSlice(LiftedCheckpoint, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer checkpoint.deinit();
    const fri_words = checkpoint.value.body.fri_config;
    const fri = try core.pcs.config_v2.FriConfigV2.init(fri_words[0], fri_words[2], fri_words[1], fri_words[3], fri_words[4]);

    for (checkpoint.value.body.cases) |case| {
        const config = core.pcs.config_v2.PcsConfigV2{
            .fri_config = fri,
            .trace_lifting_log_size = case.trace_lifting_log_size,
            .preprocessed_lifting_log_size = case.preprocessed_lifting_log_size,
        };
        var scheme = try leaf.Engine.initRevision(allocator, config);
        var scheme_owned = true;
        errdefer if (scheme_owned) scheme.deinit(allocator);
        var channel = leaf.Channel{};
        try leaf.Engine.commit(&scheme, allocator, try allocator.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, 0), null, &channel);
        const statement = wide_fibonacci.Statement{ .log_n_rows = case.log_n_rows, .sequence_len = case.sequence_len };
        // Upstream `generate_trace` writes input `i` at storage index `i` of the
        // bit-reversed evaluation; the Zig example (`genTrace`) writes it at
        // the circle bit-reversed row, the a8fcf4b layout. Only the AIR is shared.
        const M31 = core.fields.m31.M31;
        const rows = @as(usize, 1) << @intCast(case.log_n_rows);
        const values = try allocator.alloc([]M31, case.sequence_len);
        defer allocator.free(values);
        for (values) |*column| column.* = try allocator.alloc(M31, rows);
        for (0..rows) |row| {
            var a = M31.one();
            var b = M31.fromCanonical(@intCast(row));
            values[0][row] = a;
            values[1][row] = b;
            for (values[2..]) |column| {
                const next = a.square().add(b.square());
                a = b;
                b = next;
                column[row] = b;
            }
        }
        const columns = try allocator.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, values.len);
        for (values, columns) |column_values, *column| column.* = .{ .log_size = case.log_n_rows, .values = column_values };
        try leaf.Engine.commit(&scheme, allocator, columns, null, &channel);
        const component = LiftedWideFibonacci{ .inner = .{ .statement = statement } };
        scheme_owned = false;
        var proof = leaf.Engine.prove(allocator, &.{component.asProverComponent()}, &channel, scheme, .{}) catch |err| {
            std.debug.print("lifted example at height {d}: {s}\n", .{ case.trace_lifting_log_size, @errorName(err) });
            return err;
        };
        defer proof.deinit(allocator);

        const pcs_proof = proof.proof.commitment_scheme_proof;
        for (pcs_proof.commitments.items, case.commitments) |root, expected|
            try std.testing.expectEqualStrings(expected, &hex(root));
        var buffer: [24]u8 = undefined;
        try std.testing.expectEqualStrings(case.proof_of_work.value, try std.fmt.bufPrint(&buffer, "{d}", .{pcs_proof.proof_of_work}));
        var encoded = std.Io.Writer.Allocating.init(allocator);
        defer encoded.deinit();
        try cairo.proof.binary.pcs.write(&encoded.writer, pcs_proof);
        expectSha256(.{ .bytes = case.stark_proof_bytes, .sha256 = case.stark_proof_sha256 }, encoded.written()) catch |err| {
            std.debug.print("lifted example at height {d} differs\n", .{case.trace_lifting_log_size});
            return err;
        };
    }
}
