//! Native proof gate for the compact typed secp256k1 ECDSA precompile.
//!
//! One retained CSP verification transaction is decomposed into ten typed
//! components: base/scalar products, base/scalar linear operations, affine
//! transitions, GLV splits, the scalar program, signed tables, the ECDSA
//! transaction row, and an extension-local byte table.  The proof supplies
//! only the public ECDSA call counterpart and is reconstructed by a fresh
//! verifier transcript.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const core_verifier = stwo_core.verifier;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const pcs_core = stwo_core.pcs;

const guest_air = frontend.air.guest_precompile;
const affine = guest_air.secp256k1_affine;
const bundle_mod = guest_air.secp256k1_component_bundle;
const component_mod = guest_air.secp256k1_component;
const config = guest_air.secp256k1_component_config;
const ecdsa = guest_air.secp256k1_ecdsa;
const interaction_mod = guest_air.secp256k1_component_interaction;
const relations_mod = guest_air.secp256k1_relations;
const trace_mod = guest_air.secp256k1_component_trace;
const recursion_engine = frontend.recursion.engine;

const Engine = recursion_engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion_engine.Hasher,
    recursion_engine.MerkleChannel,
);

const component_count: usize = 10;
const pp_count: usize = component_count * trace_mod.preprocessed_column_count;
const main_count: usize = 3_654;
const interaction_count: usize = 2_240;
const Configs = .{
    bundle_mod.ProductBase,
    bundle_mod.ProductScalar,
    bundle_mod.LinearBase,
    bundle_mod.LinearScalar,
    config.Point,
    config.Split,
    config.ScalarProgram,
    config.Table,
    config.Ecdsa,
    config.ByteTable,
};
const placements = makePlacements();

test "secp256k1 typed ECDSA bundle proves and independently verifies" {
    const allocator = std.testing.allocator;
    var timer = try std.time.Timer.start();
    var tape = affine.Tape.init(allocator);
    defer tape.deinit();
    if (!try ecdsa.verify(
        &tape,
        csp_input[0..32].*,
        csp_input[32..97].*,
        csp_input[97..129].*,
        csp_input[129..161].*,
    )) return error.InvalidFixture;
    var bundle = try bundle_mod.generate(allocator, &tape);
    defer bundle.deinit();
    const witness_ns = timer.lap();

    const pcs_config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};

    var pp_logs: [pp_count]u32 = undefined;
    fillLogs(&bundle, .preprocessed, &pp_logs);
    var pp_tree = try OwnedTree.init(allocator, &pp_logs);
    defer pp_tree.deinit();
    var column: usize = 0;
    appendPreprocessed(bundle_mod.ProductBase, &bundle.product_base, &pp_tree, &column);
    appendPreprocessed(bundle_mod.ProductScalar, &bundle.product_scalar, &pp_tree, &column);
    appendPreprocessed(bundle_mod.LinearBase, &bundle.linear_base, &pp_tree, &column);
    appendPreprocessed(bundle_mod.LinearScalar, &bundle.linear_scalar, &pp_tree, &column);
    appendPreprocessed(config.Point, &bundle.point, &pp_tree, &column);
    appendPreprocessed(config.Split, &bundle.split, &pp_tree, &column);
    appendPreprocessed(config.ScalarProgram, &bundle.scalar, &pp_tree, &column);
    appendPreprocessed(config.Table, &bundle.table, &pp_tree, &column);
    appendPreprocessed(config.Ecdsa, &bundle.ecdsa, &pp_tree, &column);
    appendPreprocessed(config.ByteTable, &bundle.byte, &pp_tree, &column);
    try std.testing.expectEqual(pp_count, column);
    try pp_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const pp_commit_ns = timer.lap();

    var main_logs: [main_count]u32 = undefined;
    fillLogs(&bundle, .main, &main_logs);
    var main_tree = try OwnedTree.init(allocator, &main_logs);
    defer main_tree.deinit();
    column = 0;
    appendMain(bundle_mod.ProductBase, &bundle.product_base, &main_tree, &column);
    appendMain(bundle_mod.ProductScalar, &bundle.product_scalar, &main_tree, &column);
    appendMain(bundle_mod.LinearBase, &bundle.linear_base, &main_tree, &column);
    appendMain(bundle_mod.LinearScalar, &bundle.linear_scalar, &main_tree, &column);
    appendMain(config.Point, &bundle.point, &main_tree, &column);
    appendMain(config.Split, &bundle.split, &main_tree, &column);
    appendMain(config.ScalarProgram, &bundle.scalar, &main_tree, &column);
    appendMain(config.Table, &bundle.table, &main_tree, &column);
    appendMain(config.Ecdsa, &bundle.ecdsa, &main_tree, &column);
    appendMain(config.ByteTable, &bundle.byte, &main_tree, &column);
    try std.testing.expectEqual(main_count, column);
    try main_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    try mixMainStatement(&channel, &bundle);
    const main_commit_ns = timer.lap();

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var pool: prover_engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var ix0 = try interaction_mod.generate(bundle_mod.ProductBase, allocator, &bundle.product_base, &relations, &pool);
    defer ix0.deinit(allocator);
    var ix1 = try interaction_mod.generate(bundle_mod.ProductScalar, allocator, &bundle.product_scalar, &relations, &pool);
    defer ix1.deinit(allocator);
    var ix2 = try interaction_mod.generate(bundle_mod.LinearBase, allocator, &bundle.linear_base, &relations, &pool);
    defer ix2.deinit(allocator);
    var ix3 = try interaction_mod.generate(bundle_mod.LinearScalar, allocator, &bundle.linear_scalar, &relations, &pool);
    defer ix3.deinit(allocator);
    var ix4 = try interaction_mod.generate(config.Point, allocator, &bundle.point, &relations, &pool);
    defer ix4.deinit(allocator);
    var ix5 = try interaction_mod.generate(config.Split, allocator, &bundle.split, &relations, &pool);
    defer ix5.deinit(allocator);
    var ix6 = try interaction_mod.generate(config.ScalarProgram, allocator, &bundle.scalar, &relations, &pool);
    defer ix6.deinit(allocator);
    var ix7 = try interaction_mod.generate(config.Table, allocator, &bundle.table, &relations, &pool);
    defer ix7.deinit(allocator);
    var ix8 = try interaction_mod.generate(config.Ecdsa, allocator, &bundle.ecdsa, &relations, &pool);
    defer ix8.deinit(allocator);
    var ix9 = try interaction_mod.generate(config.ByteTable, allocator, &bundle.byte, &relations, &pool);
    defer ix9.deinit(allocator);

    const c0 = try component_mod.Claim(bundle_mod.ProductBase).canonical(&bundle.product_base, ix0.claims);
    const c1 = try component_mod.Claim(bundle_mod.ProductScalar).canonical(&bundle.product_scalar, ix1.claims);
    const c2 = try component_mod.Claim(bundle_mod.LinearBase).canonical(&bundle.linear_base, ix2.claims);
    const c3 = try component_mod.Claim(bundle_mod.LinearScalar).canonical(&bundle.linear_scalar, ix3.claims);
    const c4 = try component_mod.Claim(config.Point).canonical(&bundle.point, ix4.claims);
    const c5 = try component_mod.Claim(config.Split).canonical(&bundle.split, ix5.claims);
    const c6 = try component_mod.Claim(config.ScalarProgram).canonical(&bundle.scalar, ix6.claims);
    const c7 = try component_mod.Claim(config.Table).canonical(&bundle.table, ix7.claims);
    const c8 = try component_mod.Claim(config.Ecdsa).canonical(&bundle.ecdsa, ix8.claims);
    const c9 = try component_mod.Claim(config.ByteTable).canonical(&bundle.byte, ix9.claims);
    const public_call = try relations_mod.combineEcdsa(
        M31,
        relations.ecdsa,
        relations_mod.ecdsaTupleForRecord(&tape.ecdsa.items[0]),
    ).inv();
    const claims = .{ c0, c1, c2, c3, c4, c5, c6, c7, c8, c9 };
    var closure = public_call.neg();
    inline for (claims) |claim| closure = closure.add(claim.component_sum);
    try std.testing.expect(closure.isZero());
    mixInteractionClaims(&channel, claims, public_call.neg());
    const interaction_gen_ns = timer.lap();

    var interaction_logs: [interaction_count]u32 = undefined;
    fillLogs(&bundle, .interaction, &interaction_logs);
    var interaction_tree = try OwnedTree.init(allocator, &interaction_logs);
    defer interaction_tree.deinit();
    column = 0;
    appendInteraction(&ix0, &interaction_tree, &column);
    appendInteraction(&ix1, &interaction_tree, &column);
    appendInteraction(&ix2, &interaction_tree, &column);
    appendInteraction(&ix3, &interaction_tree, &column);
    appendInteraction(&ix4, &interaction_tree, &column);
    appendInteraction(&ix5, &interaction_tree, &column);
    appendInteraction(&ix6, &interaction_tree, &column);
    appendInteraction(&ix7, &interaction_tree, &column);
    appendInteraction(&ix8, &interaction_tree, &column);
    appendInteraction(&ix9, &interaction_tree, &column);
    try std.testing.expectEqual(interaction_count, column);
    try interaction_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const interaction_commit_ns = timer.lap();

    var p0 = try component_mod.Component(bundle_mod.ProductBase).init(c0, placements[0], &relations);
    var p1 = try component_mod.Component(bundle_mod.ProductScalar).init(c1, placements[1], &relations);
    var p2 = try component_mod.Component(bundle_mod.LinearBase).init(c2, placements[2], &relations);
    var p3 = try component_mod.Component(bundle_mod.LinearScalar).init(c3, placements[3], &relations);
    var p4 = try component_mod.Component(config.Point).init(c4, placements[4], &relations);
    var p5 = try component_mod.Component(config.Split).init(c5, placements[5], &relations);
    var p6 = try component_mod.Component(config.ScalarProgram).init(c6, placements[6], &relations);
    var p7 = try component_mod.Component(config.Table).init(c7, placements[7], &relations);
    var p8 = try component_mod.Component(config.Ecdsa).init(c8, placements[8], &relations);
    var p9 = try component_mod.Component(config.ByteTable).init(c9, placements[9], &relations);
    const prover_components = [_]prover_engine.air.component_prover.ComponentProver{
        p0.asProverComponent(), p1.asProverComponent(), p2.asProverComponent(),
        p3.asProverComponent(), p4.asProverComponent(), p5.asProverComponent(),
        p6.asProverComponent(), p7.asProverComponent(), p8.asProverComponent(),
        p9.asProverComponent(),
    };
    scheme_moved = true;
    var extended = Engine.prove(
        allocator,
        &prover_components,
        &channel,
        scheme,
        .{},
    ) catch |err| {
        std.debug.print("secp256k1 proof failed in prover: {s}\n", .{@errorName(err)});
        return err;
    };
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);
    const prove_ns = timer.lap();

    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expect(commitments.len >= 4);
    var verifier_scheme = try VerifierScheme.init(allocator, pcs_config);
    defer verifier_scheme.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    try verifier_scheme.commit(allocator, commitments[0], &pp_logs, &verifier_channel);
    try verifier_scheme.commit(allocator, commitments[1], &main_logs, &verifier_channel);
    try mixMainStatement(&verifier_channel, &bundle);
    const verifier_relations = try relations_mod.Relations.draw(allocator, &verifier_channel);
    mixInteractionClaims(&verifier_channel, claims, public_call.neg());
    try verifier_scheme.commit(allocator, commitments[2], &interaction_logs, &verifier_channel);

    var v0 = try component_mod.Component(bundle_mod.ProductBase).init(c0, placements[0], &verifier_relations);
    var v1 = try component_mod.Component(bundle_mod.ProductScalar).init(c1, placements[1], &verifier_relations);
    var v2 = try component_mod.Component(bundle_mod.LinearBase).init(c2, placements[2], &verifier_relations);
    var v3 = try component_mod.Component(bundle_mod.LinearScalar).init(c3, placements[3], &verifier_relations);
    var v4 = try component_mod.Component(config.Point).init(c4, placements[4], &verifier_relations);
    var v5 = try component_mod.Component(config.Split).init(c5, placements[5], &verifier_relations);
    var v6 = try component_mod.Component(config.ScalarProgram).init(c6, placements[6], &verifier_relations);
    var v7 = try component_mod.Component(config.Table).init(c7, placements[7], &verifier_relations);
    var v8 = try component_mod.Component(config.Ecdsa).init(c8, placements[8], &verifier_relations);
    var v9 = try component_mod.Component(config.ByteTable).init(c9, placements[9], &verifier_relations);
    const verifier_components = [_]stwo_core.air.components.Component{
        v0.asVerifierComponent(), v1.asVerifierComponent(), v2.asVerifierComponent(),
        v3.asVerifierComponent(), v4.asVerifierComponent(), v5.asVerifierComponent(),
        v6.asVerifierComponent(), v7.asVerifierComponent(), v8.asVerifierComponent(),
        v9.asVerifierComponent(),
    };
    proof_moved = true;
    core_verifier.verify(
        recursion_engine.Hasher,
        recursion_engine.MerkleChannel,
        allocator,
        &verifier_components,
        &verifier_channel,
        &verifier_scheme,
        extended.proof,
    ) catch |err| {
        std.debug.print("secp256k1 proof failed in fresh verifier: {s}\n", .{@errorName(err)});
        return err;
    };
    const verify_ns = timer.lap();

    std.debug.print(
        "secp256k1 proof timings: witness={d:.3}ms pp={d:.3}ms main={d:.3}ms " ++
            "interaction-gen={d:.3}ms interaction-commit={d:.3}ms prove={d:.3}ms verify={d:.3}ms\n",
        .{
            ms(witness_ns),         ms(pp_commit_ns),          ms(main_commit_ns),
            ms(interaction_gen_ns), ms(interaction_commit_ns), ms(prove_ns),
            ms(verify_ns),
        },
    );
}

const TreeKind = enum { preprocessed, main, interaction };

fn fillLogs(bundle: *const bundle_mod.Bundle, kind: TreeKind, logs: []u32) void {
    var cursor: usize = 0;
    appendLogs(bundle_mod.ProductBase, &bundle.product_base, kind, logs, &cursor);
    appendLogs(bundle_mod.ProductScalar, &bundle.product_scalar, kind, logs, &cursor);
    appendLogs(bundle_mod.LinearBase, &bundle.linear_base, kind, logs, &cursor);
    appendLogs(bundle_mod.LinearScalar, &bundle.linear_scalar, kind, logs, &cursor);
    appendLogs(config.Point, &bundle.point, kind, logs, &cursor);
    appendLogs(config.Split, &bundle.split, kind, logs, &cursor);
    appendLogs(config.ScalarProgram, &bundle.scalar, kind, logs, &cursor);
    appendLogs(config.Table, &bundle.table, kind, logs, &cursor);
    appendLogs(config.Ecdsa, &bundle.ecdsa, kind, logs, &cursor);
    appendLogs(config.ByteTable, &bundle.byte, kind, logs, &cursor);
    std.debug.assert(cursor == logs.len);
}

fn appendLogs(comptime Config: type, trace: *const trace_mod.Trace(Config), kind: TreeKind, logs: []u32, cursor: *usize) void {
    const count = switch (kind) {
        .preprocessed => trace_mod.preprocessed_column_count,
        .main => Config.main_column_count,
        .interaction => 4 * Config.batch_count,
    };
    @memset(logs[cursor.*..][0..count], trace.log_size);
    cursor.* += count;
}

fn appendPreprocessed(comptime Config: type, trace: *const trace_mod.Trace(Config), tree: *OwnedTree, cursor: *usize) void {
    for (0..trace_mod.preprocessed_column_count) |source| {
        @memcpy(tree.column(cursor.*), trace.preprocessedColumn(source));
        cursor.* += 1;
    }
}

fn appendMain(comptime Config: type, trace: *const trace_mod.Trace(Config), tree: *OwnedTree, cursor: *usize) void {
    for (0..Config.main_column_count) |source| {
        @memcpy(tree.column(cursor.*), trace.mainColumn(source));
        cursor.* += 1;
    }
}

fn appendInteraction(interaction: anytype, tree: *OwnedTree, cursor: *usize) void {
    for (interaction.columns) |source| {
        @memcpy(tree.column(cursor.*), source);
        cursor.* += 1;
    }
}

fn makePlacements() [component_count]component_mod.Placement {
    var result: [component_count]component_mod.Placement = undefined;
    var pp: usize = 0;
    var main: usize = 0;
    var interaction: usize = 0;
    inline for (Configs, 0..) |Config, index| {
        result[index] = .{
            .preprocessed_offset = pp,
            .main_offset = main,
            .interaction_offset = interaction,
        };
        pp += trace_mod.preprocessed_column_count;
        main += Config.main_column_count;
        interaction += 4 * Config.batch_count;
    }
    std.debug.assert(pp == pp_count and main == main_count and interaction == interaction_count);
    return result;
}

fn mixMainStatement(channel: anytype, bundle: *const bundle_mod.Bundle) !void {
    channel.mixU64(0x53_45_43_50_32_35_36_31); // "SECP2561"
    var offset: usize = 0;
    while (offset < csp_input.len) : (offset += 8) {
        var word: u64 = 0;
        for (csp_input[offset..@min(csp_input.len, offset + 8)], 0..) |byte, index| {
            word |= @as(u64, byte) << @intCast(8 * index);
        }
        channel.mixU64(word);
    }
    inline for (.{
        &bundle.product_base,  &bundle.product_scalar, &bundle.linear_base,
        &bundle.linear_scalar, &bundle.point,          &bundle.split,
        &bundle.scalar,        &bundle.table,          &bundle.ecdsa,
        &bundle.byte,
    }) |trace| {
        channel.mixU64(trace.log_size);
        channel.mixU64(trace.n_rows);
    }
}

fn mixInteractionClaims(channel: anytype, claims: anytype, public_sum: QM31) void {
    channel.mixU64(0x53_45_43_50_49_4e_54_31); // "SECPINT1"
    inline for (claims) |claim| {
        channel.mixFelts(&claim.batch_sums);
        channel.mixFelts(&.{claim.component_sum});
    }
    channel.mixFelts(&.{public_sum});
}

const OwnedTree = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    evaluations: []prover_pcs.ColumnEvaluation,
    columns: [][]M31,
    moved: bool = false,

    fn init(allocator: std.mem.Allocator, logs: []const u32) !OwnedTree {
        var cells: usize = 0;
        for (logs) |log_size| cells = try std.math.add(usize, cells, @as(usize, 1) << @intCast(log_size));
        const storage = try allocator.alloc(M31, cells);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        const evaluations = try allocator.alloc(prover_pcs.ColumnEvaluation, logs.len);
        errdefer allocator.free(evaluations);
        const columns = try allocator.alloc([]M31, logs.len);
        errdefer allocator.free(columns);
        var offset: usize = 0;
        for (evaluations, columns, logs) |*evaluation, *view, log_size| {
            const size = @as(usize, 1) << @intCast(log_size);
            view.* = storage[offset..][0..size];
            evaluation.* = .{ .log_size = log_size, .values = view.* };
            offset += size;
        }
        return .{ .allocator = allocator, .storage = storage, .evaluations = evaluations, .columns = columns };
    }

    fn deinit(self: *OwnedTree) void {
        if (self.columns.len != 0) self.allocator.free(self.columns);
        if (!self.moved) {
            self.allocator.free(self.evaluations);
            self.allocator.free(self.storage);
        }
        self.* = undefined;
    }

    fn column(self: *OwnedTree, index: usize) []M31 {
        return self.columns[index];
    }

    fn commit(self: *OwnedTree, scheme: *Engine.Scheme, channel: *Engine.Channel) !void {
        const backing = try self.allocator.alloc([]M31, 1);
        backing[0] = self.storage;
        self.allocator.free(self.columns);
        self.columns = &.{};
        self.moved = true;
        try Engine.commitWithBacking(scheme, self.allocator, self.evaluations, backing, null, channel);
    }
};

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}

const csp_input = [_]u8{
    0xe4, 0x95, 0xc7, 0x07, 0xf9, 0x13, 0x9a, 0x49, 0x9b, 0xa2, 0x6b, 0xb8,
    0xe8, 0x53, 0xe7, 0x7e, 0x3b, 0x29, 0xea, 0xd1, 0xf6, 0x26, 0x9e, 0x93,
    0xa8, 0xb7, 0x8d, 0x08, 0x50, 0x79, 0xee, 0xd5, 0x04, 0x05, 0xb3, 0x04,
    0x75, 0xaf, 0x82, 0xde, 0x72, 0xca, 0x14, 0x45, 0x99, 0x79, 0xe2, 0xc4,
    0x2a, 0x82, 0xa0, 0x79, 0xbb, 0x8e, 0x75, 0x42, 0x04, 0xbb, 0xfb, 0xbc,
    0x46, 0xf1, 0x96, 0x1b, 0x62, 0x04, 0xdd, 0xf4, 0x75, 0x99, 0xc8, 0x3b,
    0x4d, 0xd3, 0x85, 0x7f, 0x53, 0xdf, 0xa0, 0x89, 0xc1, 0x8c, 0xd5, 0x2a,
    0x3a, 0x79, 0xa3, 0xc0, 0x34, 0xd4, 0xc3, 0xce, 0xb2, 0x8f, 0x0c, 0x52,
    0x87, 0x97, 0x4a, 0x99, 0xc1, 0x96, 0x65, 0x05, 0x41, 0x1c, 0xc2, 0x06,
    0x2a, 0xb5, 0x1a, 0x44, 0xae, 0x6e, 0x47, 0x9d, 0xc5, 0x74, 0xc7, 0x34,
    0x1a, 0x2f, 0x65, 0x48, 0x89, 0xd3, 0xd0, 0x7b, 0x3d, 0x19, 0x13, 0xa0,
    0x4f, 0xd6, 0x5d, 0x1d, 0x07, 0xc3, 0x87, 0xb4, 0x1f, 0x7b, 0x11, 0x30,
    0xdc, 0x6b, 0x8b, 0x64, 0x22, 0xdd, 0xe0, 0xe4, 0xcb, 0xc5, 0x31, 0x30,
    0x90, 0xf4, 0x04, 0xdd, 0x0d,
};

comptime {
    if (csp_input.len != 161 or pp_count != 30 or main_count != 3_654 or
        interaction_count != 2_240)
    {
        @compileError("secp256k1 isolated proof geometry drifted");
    }
}
