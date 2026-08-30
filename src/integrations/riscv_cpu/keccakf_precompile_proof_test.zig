//! Native CPU proof gate for the candidate typed Keccak-f profile.
//!
//! This is deliberately isolated from production routing. It proves one
//! paired Keccak shard together with the complete chi/xor5 multiplicity
//! tables, supplies the public packed-I/O boundary, and then reconstructs the
//! transcript in a fresh verifier scheme. The heterogeneous log-5/log-10/
//! log-13 commitment trees exercise the same placement and prepared-domain
//! surfaces needed by the eventual guest profile.

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
const guest_runner = frontend.runner.guest_precompile;
const authority = guest_air.keccakf_authority;
const component_mod = guest_air.keccakf_component;
const counters_mod = guest_air.keccakf_multiplicities;
const interaction_mod = guest_air.keccakf_interaction;
const relations_mod = guest_air.keccakf_relations;
const table_component_mod = guest_air.keccakf_table_component;
const table_interaction_mod = guest_air.keccakf_table_interaction;
const tables = guest_air.keccakf_tables;
const trace_mod = guest_air.keccakf_trace;
const call_buffer = guest_runner.keccakf_call_buffer;
const recursion_engine = frontend.recursion.engine;

const Engine = recursion_engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion_engine.Hasher,
    recursion_engine.MerkleChannel,
);

const pp_count = component_mod.preprocessed_column_count +
    2 * table_component_mod.preprocessed_column_count;
const main_count = component_mod.main_column_count +
    2 * table_component_mod.main_column_count;
const interaction_count = component_mod.interaction_column_count +
    2 * table_component_mod.interaction_column_count;

const shard_placement = component_mod.Placement{
    .preprocessed_offset = 0,
    .main_offset = 0,
    .interaction_offset = 0,
};
const chi_placement = tablePlacement(
    component_mod.preprocessed_column_count,
    component_mod.main_column_count,
    component_mod.interaction_column_count,
);
const xor5_placement = tablePlacement(
    component_mod.preprocessed_column_count +
        table_component_mod.preprocessed_column_count,
    component_mod.main_column_count + table_component_mod.main_column_count,
    component_mod.interaction_column_count +
        table_component_mod.interaction_column_count,
);

test "Keccak-f typed shard and lookup tables prove and independently verify" {
    const allocator = std.testing.allocator;
    var timer = try std.time.Timer.start();
    const records = [_]call_buffer.Record{makeRecord(11)};
    var counters = try counters_mod.Counters.init(allocator);
    defer counters.deinit();
    var shard = try trace_mod.generateShard(allocator, &records, 0, &counters);
    defer shard.deinit();
    try counters.validateTotals();
    const witness_ns = timer.lap();

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};

    var pp_logs: [pp_count]u32 = undefined;
    fillLogs(&pp_logs, shard.log_size, tables.logSize(.chi), tables.logSize(.xor5));
    var pp_tree = try OwnedTree.init(allocator, &pp_logs);
    defer pp_tree.deinit();
    var column: usize = 0;
    for (0..component_mod.preprocessed_column_count) |source| {
        @memcpy(pp_tree.column(column), shard.preprocessedColumn(source));
        column += 1;
    }
    try appendTablePreprocessed(allocator, &pp_tree, &column, .chi);
    try appendTablePreprocessed(allocator, &pp_tree, &column, .xor5);
    try std.testing.expectEqual(pp_count, column);
    try pp_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const pp_commit_ns = timer.lap();

    var main_logs: [main_count]u32 = undefined;
    fillLogs(&main_logs, shard.log_size, tables.logSize(.chi), tables.logSize(.xor5));
    var main_tree = try OwnedTree.init(allocator, &main_logs);
    defer main_tree.deinit();
    column = 0;
    for (0..component_mod.main_column_count) |source| {
        @memcpy(main_tree.column(column), shard.mainColumn(source));
        column += 1;
    }
    const chi_main = try counters.committedColumn(allocator, .chi);
    defer allocator.free(chi_main);
    @memcpy(main_tree.column(column), chi_main);
    column += 1;
    const xor5_main = try counters.committedColumn(allocator, .xor5);
    defer allocator.free(xor5_main);
    @memcpy(main_tree.column(column), xor5_main);
    column += 1;
    try std.testing.expectEqual(main_count, column);
    try main_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const main_commit_ns = timer.lap();

    try mixMainStatement(&channel, &records, &shard);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var pool: prover_engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var shard_interaction = try interaction_mod.generate(
        allocator,
        &shard,
        &relations,
        &pool,
    );
    defer shard_interaction.deinit(allocator);
    var chi_interaction = try table_interaction_mod.generate(
        allocator,
        .chi,
        &counters,
        &relations,
        &pool,
    );
    defer chi_interaction.deinit(allocator);
    var xor5_interaction = try table_interaction_mod.generate(
        allocator,
        .xor5,
        &counters,
        &relations,
        &pool,
    );
    defer xor5_interaction.deinit(allocator);
    const shard_claim = try component_mod.Claim.canonical(
        &shard,
        shard_interaction.claims,
    );
    const public_io_sum = try publicIoSum(&records, 0, &relations);
    try std.testing.expect(shard_claim.component_sum
        .add(chi_interaction.claim)
        .add(xor5_interaction.claim)
        .add(public_io_sum)
        .isZero());
    mixInteractionClaims(
        &channel,
        shard_claim,
        chi_interaction.claim,
        xor5_interaction.claim,
        public_io_sum,
    );
    const interaction_gen_ns = timer.lap();

    var interaction_logs: [interaction_count]u32 = undefined;
    fillLogs(
        &interaction_logs,
        shard.log_size,
        tables.logSize(.chi),
        tables.logSize(.xor5),
    );
    var interaction_tree = try OwnedTree.init(allocator, &interaction_logs);
    defer interaction_tree.deinit();
    column = 0;
    for (shard_interaction.columns) |source| {
        @memcpy(interaction_tree.column(column), source);
        column += 1;
    }
    for (chi_interaction.columns) |source| {
        @memcpy(interaction_tree.column(column), source);
        column += 1;
    }
    for (xor5_interaction.columns) |source| {
        @memcpy(interaction_tree.column(column), source);
        column += 1;
    }
    try std.testing.expectEqual(interaction_count, column);
    try interaction_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const interaction_commit_ns = timer.lap();

    var shard_component = try component_mod.KeccakShardComponent.initProver(
        shard_claim,
        shard_placement,
        &relations,
    );
    var chi_component = try table_component_mod.KeccakTableComponent.initProver(
        .chi,
        chi_placement,
        &relations,
        chi_interaction.claim,
    );
    var xor5_component = try table_component_mod.KeccakTableComponent.initProver(
        .xor5,
        xor5_placement,
        &relations,
        xor5_interaction.claim,
    );
    const prover_components = [_]prover_engine.air.component_prover.ComponentProver{
        shard_component.asProverComponent(),
        chi_component.asProverComponent(),
        xor5_component.asProverComponent(),
    };
    scheme_moved = true;
    var extended = Engine.prove(
        allocator,
        &prover_components,
        &channel,
        scheme,
        .{},
    ) catch |err| {
        std.debug.print("Keccak-f proof failed in prover: {s}\n", .{@errorName(err)});
        return err;
    };
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);
    const prove_ns = timer.lap();

    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expect(commitments.len >= 4);
    var verifier_scheme = try VerifierScheme.init(allocator, config);
    defer verifier_scheme.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    try verifier_scheme.commit(allocator, commitments[0], &pp_logs, &verifier_channel);
    try verifier_scheme.commit(allocator, commitments[1], &main_logs, &verifier_channel);
    try mixMainStatement(&verifier_channel, &records, &shard);
    const verifier_relations = try relations_mod.Relations.draw(
        allocator,
        &verifier_channel,
    );
    mixInteractionClaims(
        &verifier_channel,
        shard_claim,
        chi_interaction.claim,
        xor5_interaction.claim,
        public_io_sum,
    );
    try verifier_scheme.commit(
        allocator,
        commitments[2],
        &interaction_logs,
        &verifier_channel,
    );
    var verifier_shard = try component_mod.KeccakShardComponent.initVerifier(
        shard_claim,
        shard_placement,
        &verifier_relations,
    );
    var verifier_chi = try table_component_mod.KeccakTableComponent.initVerifier(
        .chi,
        chi_placement,
        &verifier_relations,
        chi_interaction.claim,
    );
    var verifier_xor5 = try table_component_mod.KeccakTableComponent.initVerifier(
        .xor5,
        xor5_placement,
        &verifier_relations,
        xor5_interaction.claim,
    );
    const verifier_components = [_]stwo_core.air.components.Component{
        verifier_shard.asVerifierComponent(),
        verifier_chi.asVerifierComponent(),
        verifier_xor5.asVerifierComponent(),
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
        std.debug.print("Keccak-f proof failed in fresh verifier: {s}\n", .{@errorName(err)});
        return err;
    };
    const verify_ns = timer.lap();

    std.debug.print(
        "Keccak-f proof timings: witness={d:.3}ms pp={d:.3}ms main={d:.3}ms " ++
            "interaction-gen={d:.3}ms interaction-commit={d:.3}ms prove={d:.3}ms verify={d:.3}ms\n",
        .{
            ms(witness_ns),
            ms(pp_commit_ns),
            ms(main_commit_ns),
            ms(interaction_gen_ns),
            ms(interaction_commit_ns),
            ms(prove_ns),
            ms(verify_ns),
        },
    );
}

const OwnedTree = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    evaluations: []prover_pcs.ColumnEvaluation,
    columns: [][]M31,
    moved: bool = false,

    fn init(allocator: std.mem.Allocator, logs: []const u32) !OwnedTree {
        var cells: usize = 0;
        for (logs) |log_size| cells = try std.math.add(
            usize,
            cells,
            @as(usize, 1) << @intCast(log_size),
        );
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
            evaluation.* = .{
                .log_size = log_size,
                .values = view.*,
            };
            offset += size;
        }
        return .{
            .allocator = allocator,
            .storage = storage,
            .evaluations = evaluations,
            .columns = columns,
        };
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

    fn commit(
        self: *OwnedTree,
        scheme: *Engine.Scheme,
        channel: *Engine.Channel,
    ) !void {
        const backing = try self.allocator.alloc([]M31, 1);
        backing[0] = self.storage;
        self.allocator.free(self.columns);
        self.columns = &.{};
        self.moved = true;
        try Engine.commitWithBacking(
            scheme,
            self.allocator,
            self.evaluations,
            backing,
            null,
            channel,
        );
    }
};

fn appendTablePreprocessed(
    allocator: std.mem.Allocator,
    tree: *OwnedTree,
    column: *usize,
    kind: tables.Kind,
) !void {
    const log_size = tables.logSize(kind);
    tree.column(column.*)[trace_mod.committedRow(0, log_size)] = M31.one();
    column.* += 1;
    var generated = try tables.generatePreprocessed(allocator, kind);
    defer generated.deinit(allocator);
    for (generated.columns) |source| {
        @memcpy(tree.column(column.*), source);
        column.* += 1;
    }
}

fn fillLogs(logs: []u32, shard_log: u32, chi_log: u32, xor5_log: u32) void {
    const shard_columns = logs.len -
        2 * (logs.len - switch (logs.len) {
            pp_count => component_mod.preprocessed_column_count,
            main_count => component_mod.main_column_count,
            interaction_count => component_mod.interaction_column_count,
            else => unreachable,
        }) / 2;
    @memset(logs[0..shard_columns], shard_log);
    const per_table = (logs.len - shard_columns) / 2;
    @memset(logs[shard_columns..][0..per_table], chi_log);
    @memset(logs[shard_columns + per_table ..], xor5_log);
}

fn tablePlacement(
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
) table_component_mod.Placement {
    var tuple_indices: [tables.arity]usize = undefined;
    for (&tuple_indices, 0..) |*value, index| value.* =
        preprocessed_offset + 1 + index;
    return .{
        .is_first_col_idx = preprocessed_offset,
        .tuple_col_indices = tuple_indices,
        .main_col_offset = main_offset,
        .interaction_col_offset = interaction_offset,
    };
}

fn makeRecord(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* =
        seed +% @as(u32, @intCast(index * 0x101));
    var state = trace_mod.stateFromWords(input);
    authority.permute(&state);
    var output: [call_buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, index| {
        output[2 * index] = @truncate(lane);
        output[2 * index + 1] = @truncate(lane >> 32);
    }
    return .{
        .execution_clock = seed + 1,
        .pc = seed + 4,
        .state_ptr = 0x4000,
        .pointer_register = 7,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

fn mixMainStatement(
    channel: anytype,
    records: []const call_buffer.Record,
    shard: *const trace_mod.Shard,
) !void {
    channel.mixU64(0x4b_45_43_43_41_4b_46_31); // "KECCAKF1"
    channel.mixU64(shard.log_size);
    channel.mixU64(shard.n_rows);
    channel.mixU64(shard.first_call_index);
    channel.mixU64(shard.call_count);
    for (records, 0..) |record, index| {
        const tuple = try relations_mod.ioTuple(
            shard.first_call_index + index,
            trace_mod.stateFromWords(record.input),
            trace_mod.stateFromWords(record.output),
        );
        var secure: [relations_mod.io_arity]QM31 = undefined;
        for (&secure, tuple) |*destination, value| destination.* = QM31.fromBase(value);
        channel.mixFelts(&secure);
    }
}

fn mixInteractionClaims(
    channel: anytype,
    shard: component_mod.Claim,
    chi: QM31,
    xor5: QM31,
    public_io: QM31,
) void {
    channel.mixU64(0x4b_45_43_43_41_4b_49_31); // "KECCAKI1"
    channel.mixFelts(&shard.batch_sums);
    channel.mixFelts(&.{ shard.component_sum, chi, xor5, public_io });
}

fn publicIoSum(
    records: []const call_buffer.Record,
    first_call_index: usize,
    relations: *const relations_mod.Relations,
) !QM31 {
    var result = QM31.zero();
    for (records, 0..) |record, index| {
        const tuple = try relations_mod.ioTuple(
            first_call_index + index,
            trace_mod.stateFromWords(record.input),
            trace_mod.stateFromWords(record.output),
        );
        result = result.add(try relations_mod.IoEvent.unitEmit(tuple).term(&relations.io));
    }
    return result;
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}

comptime {
    if (pp_count != 45 or main_count != 2142 or interaction_count != 3852)
        @compileError("Keccak-f isolated proof tree geometry drifted");
}
