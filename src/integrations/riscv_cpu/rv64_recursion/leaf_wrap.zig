//! Wrapping one RV64 Ethereum batch proof into a circuit leaf: verify it
//! natively with proof capture, build the leaf circuit with values around
//! the native-protocol verifier and the batch statement, pad it to the
//! production registry's shared target, prove it with the circuit prover,
//! and serialize the leaf with the statement words that its output digest
//! binds.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const core = @import("stwo_core");
const A = @import("../rv64_authenticated_execution.zig");
const Key = @import("../rv64_execution_verifier_key.zig");
const native_capture = @import("native_capture.zig");
const leaf_statement = @import("leaf_statement.zig");
const walk = @import("transcript_walk.zig");
const fold_root = @import("fold_root.zig");
const point_eval = @import("../rv64_point_evaluation.zig");

const Q = core.fields.qm31.QM31;
const P = A.P;
const builder = circuit.builder;
const Context = builder.Context(Q);
const nv = circuit.native_verifier;
const blake2_hash = core.vcs.blake2_hash;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

fn stage(name: []const u8, err: anyerror) anyerror {
    std.log.err("rv64 recursion wrap failed at {s}: {s}", .{ name, @errorName(err) });
    return err;
}

pub const Timings = struct {
    native_verify_ns: u64,
    build_ns: u64,
    pad_ns: u64,
    preprocess_ns: u64,
    prove_ns: u64,
    serialize_ns: u64,
    gate_counts: builder.context.GateCounts,
    n_vars: u32,
};

pub const Wrapped = struct {
    leaf: fold_root.LeafFile,
    proof_bytes: []u8,
    timings: Timings,
};

/// Wraps the batch (`public`, `claims`, `proof`) verified under `key`.
pub fn wrap(gpa: std.mem.Allocator, arena: std.mem.Allocator, assets: *fold_root.Assets, key: *const Key.ReceiverKey, index: u32, public: A.Public, claims: A.Claims, proof: *const P.Proof) !Wrapped {
    var timer = try std.time.Timer.start();
    const verified = try native_capture.verify(gpa, key, public, claims, proof);
    defer verified.deinit();
    const native_verify_ns = timer.lap();

    // The shape of this batch's proof and the fixed-width witness.
    const roster = try point_eval.Roster.init(key, verified.roster());
    var described = try point_eval.describeShape(gpa, &roster);
    defer described.deinit();
    // The AIR trees as described, then the composition tree: one column per
    // QM31 coordinate of every composition chunk, all at the global log and
    // sampled once at the OODS point.
    const n_air_trees = described.tree_column_log_sizes.len;
    const n_composition_columns = core.verifier_types.compositionColumnCount(described.composition_log_split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidRv64CompositionGeometry;
    const tree_logs = try arena.alloc([]const u32, n_air_trees + 1);
    for (tree_logs[0..n_air_trees], described.tree_column_log_sizes) |*out, tree| out.* = tree;
    const composition_logs = try arena.alloc(u32, n_composition_columns);
    @memset(composition_logs, described.global_log);
    tree_logs[n_air_trees] = composition_logs;
    const offsets = try arena.alloc([]const []const i32, n_air_trees + 1);
    for (offsets[0..n_air_trees], described.mask_offsets) |*out, tree| {
        const columns = try arena.alloc([]const i32, tree.len);
        for (columns, tree) |*column, source| column.* = source;
        out.* = columns;
    }
    const composition_offsets = try arena.alloc([]const i32, n_composition_columns);
    @memset(composition_offsets, &[_]i32{0});
    offsets[n_air_trees] = composition_offsets;
    const shape = nv.shape.Shape{
        .tree_column_log_sizes = tree_logs,
        .mask_offsets = offsets,
        .global_log = described.global_log,
        .composition_log_split = described.composition_log_split,
        .pcs = P.config(),
    };
    shape.validate() catch |err| return stage("shape.validate", err);
    const proof_values = nv.proof.fromNative(arena, P.Hasher, proof, &verified.capture, &shape) catch |err| return stage("proof.fromNative", err);

    var ctx = try Context.init(gpa, circuit.common.component_list.N_RESERVED);
    var ctx_owned = true;
    defer if (ctx_owned) ctx.deinit();
    const proof_wires = try nv.proof.guess(Q, &ctx, &proof_values);
    var statement = try leaf_statement.Statement.init(arena, key.view(), public, claims, &roster);
    const outcome = nv.verify.verify(Q, &ctx, &shape, &proof_wires, &statement) catch |err| return stage("native_verifier.verify", err);
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) {
        const circuit_digest = outcome.channel.debugDigest(&ctx);
        const native_digest = verified.session.channel.digest;
        std.log.info("diagnose: channel digest {s}; circuit valid after verify: {}", .{ if (std.mem.eql(u8, &circuit_digest, &native_digest)) "matches native" else "DIFFERS from native", ctx.isCircuitValid() catch false });
        const native_composition = proof.extractCompositionOodsEvalWithSplit(core.circle.secureFieldPointFromRandomSeed(verified.capture.oods_seed), described.global_log + described.composition_log_split, described.composition_log_split) orelse Q.zero();
        std.log.info("diagnose: native composition at OODS {any}; circuit oods seed matches: {}", .{ native_composition.toM31Array(), ctx.get(outcome.oods_point.x).eql(core.circle.secureFieldPointFromRandomSeed(verified.capture.oods_seed).x) });
    }
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) {
        const native_target = public.cpu.statement.expectedStateWithProfile(verified.session.challenges.cpu.cpu.state, public.cpu.execution_profile) catch Q.zero();
        var native_effect = A.CS.effect(claims.cpu);
        if (claims.ram) |*ram| {
            const debt = A.I.closeWithoutByte(public.before, public.after, public.geometry, &ram.callers, ram.provider, ram.policy, &verified.session.challenges.ram.?) catch null;
            if (debt) |d| native_effect = native_effect.add(d.state).add(d.bytes);
        }
        std.log.info("diagnose native: effect {any} target {any}", .{ native_effect.toM31Array(), native_target.toM31Array() });
        if (verified.session.challenges.ram) |*ram| {
            var before: [9]Q = undefined;
            for (&before, public.before) |*b, x| b.* = Q.fromBase(core.fields.m31.M31.fromCanonical(x));
            const depth = Q.fromBase(core.fields.m31.M31.fromCanonical(public.geometry.depth()));
            std.log.info("diagnose native: node den[0] {any} c1 {any} c2 {any} c10 {any} depth {any} word8 {any}", .{ ram.ram.node(Q.zero(), depth, @splat(Q.zero()), before).toM31Array(), ram.ram.coefficients[1].toM31Array(), ram.ram.coefficients[2].toM31Array(), ram.ram.coefficients[10].toM31Array(), depth.toM31Array(), before[8].toM31Array() });
        }
    }
    _ = statement.finish(&ctx) catch |err| return stage("statement.finish", err);
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose: circuit valid after closure: {}", .{ctx.isCircuitValid() catch false});
    try ctx.finalize(false);
    const build_ns = timer.lap();
    const raw_counts = ctx.gate_counts;
    const target = try assets.target();
    try circuit.common.finalize.padToTargets(Q, &ctx, target);
    if (!try ctx.isCircuitValid()) return error.CircuitRejectsProof;
    const pad_ns = timer.lap();
    const statement_words = try statement.statementWords(&ctx);

    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
    defer pp.deinit(gpa);
    const circuit_fri = try assets.circuitFri();
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(circuit_fri, pp.traceLogSize());
    const n_vars = ctx.circuit.n_vars;
    const values = try ctx.intoValues();
    ctx_owned = false;
    defer gpa.free(values);
    const preprocess_ns = timer.lap();

    var circuit_proof = try circuit_cpu.prove.cpu_provers.internal(gpa, values, &pp, &assets.bundle, pcs_config, circuit_cpu.recursion.fold.default_options);
    defer circuit_proof.deinit();
    const prove_ns = timer.lap();
    const preprocessed_root = blake2_hash.digestToU32s(circuit_proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0]);
    const circuit_hash = blake2_hash.digestToU32s(circuit_proof.circuit_hash);
    var prepared = try circuit_cpu.verifier_proof.prepare(gpa, &circuit_proof);
    defer prepared.deinit();
    const bytes = try prepared.serialize(gpa);
    errdefer gpa.free(bytes);
    const serialize_ns = timer.lap();

    var narrow = public;
    narrow.cpu.statement.program = .{ .base = 0, .words = &.{}, .addresses = &.{} };
    return .{
        .leaf = .{
            .batch_index = index,
            .circuit_hash = circuit_hash,
            .preprocessed_root = preprocessed_root,
            .output_digest = walk.statementDigest(statement_words),
            .statement_words = statement_words,
            .public = narrow,
            .proof_file = try std.fmt.allocPrint(arena, "leaf-{d:0>6}.proof", .{index}),
        },
        .proof_bytes = bytes,
        .timings = .{ .native_verify_ns = native_verify_ns, .build_ns = build_ns, .pad_ns = pad_ns, .preprocess_ns = preprocess_ns, .prove_ns = prove_ns, .serialize_ns = serialize_ns, .gate_counts = raw_counts, .n_vars = n_vars },
    };
}
