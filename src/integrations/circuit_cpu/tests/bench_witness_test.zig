//! Witness and prove benchmark on the R9 workload (not a parity rung).
//!
//! Builds the multiverifier over two copies of the upstream golden leaf
//! (`four_leaves/leaf.json`) exactly as one pair reduction of the recursive
//! tree does, padded to the recursive-tree test registry's canonical target
//! (2^23-row blake_g_gate and qm31_ops), then:
//!
//! - times `writeTrace` and `writeInteractionTrace` (`STWO_BENCH_REPS`
//!   repetitions, fixed lookup elements) and prints a SHA-256 over every
//!   column they write, so two builds can be compared for identical bytes;
//! - proves the node once on the internal profile with a stage recorder and
//!   prints the stage tree and the SHA-256 of the `CircuitSerialize` proof.
//!
//! `zig build circuit-bench-witness --build-file src/integrations/circuit_cpu/build.zig
//! -Doptimize=ReleaseFast`. Large: several GB.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const recursion = circuit_cpu.recursion;
const multiverifier = circuit.statements.multiverifier;
const finalize = circuit.common.finalize;
const witness = circuit.witness.trace;

const registry_path = "vectors/circuit/official/registries/recursive_tree_test.json";
const leaf_path = "vectors/circuit/official/recursive_tree/four_leaves/leaf.json";
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

fn envUsize(name: []const u8, default: usize) usize {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, name) catch return default;
    defer std.heap.page_allocator.free(value);
    return std.fmt.parseInt(usize, value, 10) catch default;
}

fn hashColumns(hasher: *std.crypto.hash.sha2.Sha256, columns: []const prover.pcs.ColumnEvaluation) void {
    for (columns) |column| hasher.update(std.mem.sliceAsBytes(column.values));
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}

fn printStage(stage: prover.stage_profile.StageNode, depth: usize) void {
    std.debug.print("{s: >[3]}{s} {d:.3} s\n", .{ "", stage.id, stage.seconds, depth * 2 });
    if (stage.children) |children| for (children) |child| printStage(child, depth + 1);
}

test "bench: multiverifier witness and prove" {
    const gpa = std.heap.smp_allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    var registry = try wire.registry.parseRegistry(gpa, try std.fs.cwd().readFileAlloc(a, registry_path, 1 << 20));
    defer registry.deinit();
    var projection = try circuit.air_eval.projection.parse(gpa, try std.fs.cwd().readFileAlloc(a, projection_path, 8 << 20));
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer table.deinit();
    var bundle = try circuit_cpu.air.parse(gpa, try std.fs.cwd().readFileAlloc(a, circuit_cpu.air.bundle_path, 1 << 20));
    defer bundle.deinit();
    var canonical = try recursion.CanonicalCircuit.build(gpa, &table, registry.registry);
    defer canonical.deinit(gpa);
    var leaf = try wire.leaf_proof_json.parseLeafInput(gpa, try std.fs.cwd().readFileAlloc(a, leaf_path, 8 << 20));
    defer leaf.deinit();

    var packed_arena = std.heap.ArenaAllocator.init(gpa);
    defer packed_arena.deinit();
    const fold: recursion.Fold = .{
        .canonical = &canonical,
        .table = &table,
        .bundle = &bundle,
        .options = .{ .compact_polynomial_min_log = 18 },
        .packed_allocator = packed_arena.allocator(),
    };
    var left = try recursion.LayerEntry.fromLeaf(gpa, &fold, leaf.value);
    defer left.deinit();

    var timer = try std.time.Timer.start();
    const values = blk: {
        var inputs_arena = std.heap.ArenaAllocator.init(gpa);
        defer inputs_arena.deinit();
        const config = canonical.proofConfig();
        const child_proof = try circuit_cpu.verifier_proof.circuitVerifierValues(inputs_arena.allocator(), &left.proof.circuit, config);
        var proofs = [2]@TypeOf(child_proof){ child_proof, child_proof };
        var inputs: [2]multiverifier.MultiverifierInput(QM31) = undefined;
        for (&inputs, &proofs) |*input, *proof| input.* = .{
            .proof = proof,
            .preprocessed_root = circuit.builder.blake.hashValue(QM31, left.preprocessed_root),
            .output_digest = circuit.builder.blake.hashValue(QM31, left.output_digest),
        };
        var ctx = try multiverifier.buildMultiverifierCircuit(QM31, gpa, &table, &inputs, &canonical.shared, circuit.stark_verifier.verify.NoStages{});
        defer ctx.deinit();
        try finalize.padToTargets(QM31, &ctx, canonical.target_sizes);
        try std.testing.expect(try ctx.isCircuitValid());
        break :blk try gpa.dupe(QM31, ctx.values());
    };
    defer gpa.free(values);
    std.debug.print("BENCH build_values_ms {d:.1}\n", .{ms(timer.lap())});

    // The CUDA fold rebuilds only values against the authenticated topology.
    // This local path checks every padded value, not merely the output digest,
    // while timing the exact-capacity, gate-free handoff used by the GPU path.
    if (envUsize("STWO_BENCH_VALUE_REPLAY", 0) != 0) {
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(values), &expected, .{});
        for (0..2) |variant| {
            timer.reset();
            const replay = blk: {
                var inputs_arena = std.heap.ArenaAllocator.init(gpa);
                defer inputs_arena.deinit();
                const config = canonical.proofConfig();
                const child_proof = try circuit_cpu.verifier_proof.circuitVerifierValues(inputs_arena.allocator(), &left.proof.circuit, config);
                var proofs = [2]@TypeOf(child_proof){ child_proof, child_proof };
                var inputs: [2]multiverifier.MultiverifierInput(QM31) = undefined;
                for (&inputs, &proofs) |*input, *proof| input.* = .{
                    .proof = proof,
                    .preprocessed_root = circuit.builder.blake.hashValue(QM31, left.preprocessed_root),
                    .output_digest = circuit.builder.blake.hashValue(QM31, left.output_digest),
                };
                var ctx = try multiverifier.buildMultiverifierCircuitWithGateRecordingAndCapacity(
                    QM31,
                    gpa,
                    &table,
                    &inputs,
                    &canonical.shared,
                    false,
                    if (variant == 0) null else canonical.n_vars,
                    circuit.stark_verifier.verify.NoStages{},
                );
                var ctx_owned = true;
                defer if (ctx_owned) ctx.deinit();
                try finalize.padToTargets(QM31, &ctx, canonical.target_sizes);
                try std.testing.expectEqual(canonical.n_vars, ctx.circuit.n_vars);
                if (variant == 0) break :blk try gpa.dupe(QM31, ctx.values());
                const owned = try ctx.intoValues();
                ctx_owned = false;
                break :blk owned;
            };
            defer gpa.free(replay);
            const replay_ns = timer.lap();
            var actual: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(replay), &actual, .{});
            try std.testing.expectEqualSlices(u8, &expected, &actual);
            std.debug.print("BENCH replay_{s}_ms {d:.1} values_sha256 {s}\n", .{
                if (variant == 0) "copy" else "owned", ms(replay_ns),
                std.fmt.bytesToHex(actual, .lower),
            });
        }
        return;
    }

    const reps = envUsize("STWO_BENCH_REPS", 3);
    const pp = &canonical.preprocessed;
    const z = QM31.fromU32Unchecked(12345, 678, 91011, 1213);
    const alpha = QM31.fromU32Unchecked(1415, 161718, 1920, 212223);
    var base_digest: [32]u8 = undefined;
    var interaction_digest: [32]u8 = undefined;
    for (0..reps) |rep| {
        timer.reset();
        var base = try witness.writeTrace(gpa, values, pp);
        defer base.deinit();
        const base_ns = timer.lap();
        var interaction = try witness.writeInteractionTrace(gpa, base.columns, base.log_sizes, pp, z, alpha);
        defer interaction.deinit();
        const interaction_ns = timer.lap();
        if (rep == 0) {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hashColumns(&hasher, base.columns);
            hasher.final(&base_digest);
            hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hashColumns(&hasher, interaction.columns);
            for (interaction.claimed_sums.toArray()) |sum| hasher.update(std.mem.asBytes(&sum.toM31Array()));
            hasher.final(&interaction_digest);
        }
        std.debug.print("BENCH rep {d} base_witness_ms {d:.1} interaction_witness_ms {d:.1}\n", .{ rep, ms(base_ns), ms(interaction_ns) });
    }
    std.debug.print("BENCH base_sha256 {s}\nBENCH interaction_sha256 {s}\n", .{ std.fmt.bytesToHex(base_digest, .lower), std.fmt.bytesToHex(interaction_digest, .lower) });

    if (envUsize("STWO_BENCH_PROVE", 1) == 0) return;
    var recorder = prover.stage_profile.Recorder.init(gpa, "cpu", "circuit-bench");
    defer recorder.deinit();
    var options = fold.options;
    options.recorder = &recorder;
    if (envUsize("STWO_BENCH_NATIVE", 1) == 0) options.composition_executor = null;
    timer.reset();
    var proof = try circuit_cpu.Internal.prove(gpa, values, pp, &bundle, canonical.shared.pcs_config, options, {});
    defer proof.deinit();
    const prove_ns = timer.lap();
    var converted = try circuit_cpu.verifier_proof.prepare(gpa, &proof);
    defer converted.deinit();
    const bytes = try converted.serialize(gpa);
    defer gpa.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    std.debug.print("BENCH prove_ms {d:.1}\nBENCH proof_bytes {d} proof_sha256 {s}\n", .{ ms(prove_ns), bytes.len, std.fmt.bytesToHex(digest, .lower) });
    var profile = try recorder.snapshot(gpa);
    defer profile.deinit(gpa);
    for (profile.stages) |stage| printStage(stage, 0);
}
