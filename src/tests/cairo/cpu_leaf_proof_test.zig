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
const parameters = cairo.proving.transaction.leaf_lane.parameters;

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
    inline for (.{ "all_opcodes", "all_builtins" }) |name| {
        proveAndCompare(
            "vectors/cairo/official/" ++ name ++ ".prover_input.json",
            "vectors/circuit/r10/" ++ name ++ ".prove_cairo.json",
        ) catch |err| {
            std.debug.print("R10c case {s} failed\n", .{name});
            return err;
        };
    }
}

fn proveAndCompare(input_path: []const u8, checkpoint_path: []const u8) !void {
    const allocator = std.testing.allocator;

    const checkpoint_bytes = try readFile(allocator, checkpoint_path);
    defer allocator.free(checkpoint_bytes);
    const checkpoint = try std.json.parseFromSlice(Checkpoint, allocator, checkpoint_bytes, .{ .ignore_unknown_fields = true });
    defer checkpoint.deinit();

    // The registry's `cairo_prover_params`, as the leaf prover reads them.
    const registry_bytes = try readFile(allocator, registry_path);
    defer allocator.free(registry_bytes);
    const registry = try std.json.parseFromSlice(std.json.Value, allocator, registry_bytes, .{});
    defer registry.deinit();
    const params = try parameters.fromValue(allocator, registry.value.object.get("cairo_prover_params") orelse
        return error.MissingProverParameters);

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
