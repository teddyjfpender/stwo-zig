//! RISC-V STARK proving orchestration.
//!
//! Proves execution of a RISC-V RV32IM program by:
//! 1. Running the program (ELF) to produce an execution trace
//! 2. Splitting the trace by opcode family
//! 3. Creating per-family components, each at its own log_size
//! 4. Committing and proving via the stwo STARK backend
//! 5. Verification of the produced proof
//!
//! ## Architecture
//!
//! Instead of one monolithic component with all trace rows, the trace is split
//! by opcode family. Each active family gets its own component with its own
//! `log_size = ceil(log2(count))`. This gives smaller FFTs per-component and
//! better cache behavior.
//!
//! ## Usage
//! ```zig
//! const result = try proveRiscVWithEngine(
//!     Engine, allocator, config, &exec_trace, &state_chain, &rw_memory, null,
//! );
//! try verifyRiscVWithEngine(Engine, allocator, config, result.statement, result.proof, result.interaction_claim);
//! ```

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_impl").engine;
const prover_pcs = @import("stwo_prover_impl").pcs;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const trace_mod = @import("../runner/trace.zig");
const component_order = @import("../air/component_order.zig");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const interaction_gen = @import("../air/interaction_gen.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const opcode_memory = @import("../air/opcode_memory.zig");
const public_data_mod = @import("../air/public_data.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const program_table = @import("../air/program/table.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const proof_transcript = @import("../proof_transcript.zig");
const lookup_sources = @import("lookup_sources.zig");
const opcode_trace = @import("opcode_trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const proof_finalize = @import("proof_finalize.zig");
const statement_validation = @import("statement_validation.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const types = @import("types.zig");
const state_chain = @import("../runner/state_chain.zig");
const memory_state = @import("../runner/memory_state.zig");

const M31 = m31.M31;
const PublicData = types.PublicData;
const ProveOutput = types.ProveOutput;
const ProverError = types.ProverError;
const RelationDiagnostic = types.RelationDiagnostic;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RiscVStatement = types.RiscVStatement;
const RunMode = types.RunMode;
const RunOutput = types.RunOutput;
const MAX_COMPONENTS = types.MAX_COMPONENTS;
const MAX_INFRA_COMPONENTS = types.MAX_INFRA_COMPONENTS;
const MAX_OPCODE_SHARD_ROWS: usize = 1 << 16;
const MAX_MEMORY_SHARD_ROWS: usize = 1 << 16;
const computeLogSize = statement_validation.computeLogSize;
const computeOpcodeLogSize = statement_validation.computeOpcodeLogSize;
pub const TestWitnessMutation = test_witness_hook.Mutation;
pub fn runRiscVWithEngineAndPublicData(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
) !RunOutput(mode) {
    var channel = Engine.Channel{};
    return runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
        null,
    );
}

/// Runs the production proving transaction against a caller-owned channel.
///
/// The ordinary entrypoint above instantiates `Engine.Channel` directly. This
/// substitution point lets conformance tests observe the exact production
/// transcript without replaying statement or commitment events.
pub fn runRiscVWithEngineAndPublicDataUsingChannel(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
) !RunOutput(mode) {
    comptime prover_engine.assertProverEngine(Engine);
    if (exec_trace.step_count == 0) return ProverError.EmptyTrace;

    var bound_public_data = public_data;
    if (bound_public_data.completion == null) {
        bound_public_data.completion =
            public_data_mod.Completion.canonicalSelfLoop(exec_trace.final_pc);
    }
    try validateCompletionWitness(&bound_public_data, opt_memory);

    var boundary_claims: ?memory_boundary.Claims = if (opt_memory) |snapshot|
        try memory_boundary.build(allocator, snapshot.words)
    else
        null;
    defer if (boundary_claims) |*claims| claims.deinit(allocator);
    if (boundary_claims) |claims| try claims.validate(allocator);

    const has_public_fetch =
        bound_public_data.completion.?.kind == .unretired_self_loop;
    const fetches = try allocator.alloc(
        program_table.Fetch,
        exec_trace.rows.items.len + @intFromBool(has_public_fetch),
    );
    defer allocator.free(fetches);
    for (exec_trace.rows.items, fetches[0..exec_trace.rows.items.len]) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    if (has_public_fetch) {
        const completion = bound_public_data.completion.?;
        fetches[fetches.len - 1] = .{
            .pc = completion.address,
            .word = completion.value,
        };
    }
    var program = try program_commitment.build(
        allocator,
        fetches,
        if (opt_memory) |snapshot| snapshot.program_words else &.{},
    );
    defer program.deinit(allocator);

    // Pinned Stark-V visits Poseidon calls program -> initial RW -> final RW,
    // while its Merkle table visits initial RW -> final RW -> program.
    var poseidon_calls_list: std.ArrayList(poseidon2_air.Call) = .{};
    defer poseidon_calls_list.deinit(allocator);
    for (program.tree.nodes) |node| {
        const row = merkle_node.NodeRow.fromNode(node, program.tree.root);
        try poseidon_calls_list.append(allocator, row.poseidonCall());
    }
    if (boundary_claims) |claims| {
        if (claims.initial_tree) |tree| {
            for (tree.nodes) |node| {
                const row = merkle_node.NodeRow.fromNode(node, tree.root);
                try poseidon_calls_list.append(allocator, row.poseidonCall());
            }
        }
        if (claims.final_tree) |tree| {
            for (tree.nodes) |node| {
                const row = merkle_node.NodeRow.fromNode(node, tree.root);
                try poseidon_calls_list.append(allocator, row.poseidonCall());
            }
        }
    }
    const poseidon_calls = poseidon_calls_list.items;

    var merkle_rows_list: std.ArrayList(merkle_node.NodeRow) = .{};
    defer merkle_rows_list.deinit(allocator);
    if (boundary_claims) |claims| {
        if (claims.initial_tree) |tree| {
            for (tree.nodes) |node| {
                try merkle_rows_list.append(allocator, merkle_node.NodeRow.fromNode(node, tree.root));
            }
        }
        if (claims.final_tree) |tree| {
            for (tree.nodes) |node| {
                try merkle_rows_list.append(allocator, merkle_node.NodeRow.fromNode(node, tree.root));
            }
        }
    }
    for (program.tree.nodes) |node| {
        try merkle_rows_list.append(allocator, merkle_node.NodeRow.fromNode(node, program.tree.root));
    }
    const merkle_rows = merkle_rows_list.items;

    // -- Step 1: Count rows per opcode family. --
    const counts = try exec_trace.groupByOpcodeFamily(allocator);

    // -- Step 2: Build statement with per-family descriptors. --
    var statement: RiscVStatement = .{
        .n_components = 0,
        .component_descs = undefined,
        .initial_pc = exec_trace.initial_pc,
        .final_pc = exec_trace.final_pc,
        .total_steps = @intCast(exec_trace.step_count),
        .public_data = bound_public_data,
    };

    for (component_order.opcodeFamilies()) |family| {
        const count = counts.get(family);
        if (count == 0) continue;

        var remaining = count;
        while (remaining > 0) {
            if (statement.n_components >= MAX_COMPONENTS) return ProverError.TooManyOpcodeComponents;
            const shard_len = @min(remaining, MAX_OPCODE_SHARD_ROWS);
            statement.component_descs[statement.n_components] = .{
                .family = family,
                .log_size = computeOpcodeLogSize(shard_len),
                .n_rows = @intCast(shard_len),
                .n_columns = trace_mod.nColumnsForFamily(family),
            };
            statement.n_components += 1;
            remaining -= shard_len;
        }
    }

    if (statement.n_components == 0) return ProverError.EmptyTrace;

    // -- Step 2b: Build infrastructure component descriptors. --
    statement.n_infra = 0;

    // Exact sparse decoded-program commitment, including canonical aligned
    // address limbs (10 columns).
    const program_log_size = computeLogSize(program.rows.len);
    statement.infra_descs[statement.n_infra] = .{
        .kind = .program,
        .log_size = program_log_size,
        .n_rows = @intCast(program.rows.len),
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;

    // Ordinary RW-memory boundary rows, sharded without changing relation
    // placement. Opcode-side accesses close this bus in a later soundness slice.
    var memory_shard_count: usize = 0;
    var memory_shard_lengths: [MAX_INFRA_COMPONENTS]usize = undefined;
    if (boundary_claims) |claims| {
        var remaining = claims.rows.len;
        while (remaining > 0) {
            if (statement.n_infra + 3 >= MAX_INFRA_COMPONENTS)
                return ProverError.TooManyInfrastructureComponents;
            const shard_len = @min(remaining, MAX_MEMORY_SHARD_ROWS);
            const shard_log_size = @max(computeLogSize(shard_len), 4);
            statement.infra_descs[statement.n_infra] = .{
                .kind = .memory,
                .log_size = shard_log_size,
                .n_rows = @intCast(shard_len),
                .n_columns = memory_trace.N_COLUMNS,
            };
            statement.n_infra += 1;
            memory_shard_lengths[memory_shard_count] = shard_len;
            memory_shard_count += 1;
            remaining -= shard_len;
        }
    }

    if (statement.public_data.program_root) |root| {
        if (root != program.tree.root) return ProverError.InvalidStatement;
    }
    statement.public_data.program_root = program.tree.root;

    if (boundary_claims) |claims| {
        const initial_root = if (claims.initial_tree) |tree| tree.root else null;
        const final_root = if (claims.final_tree) |tree| tree.root else null;
        if (statement.public_data.initial_rw_root) |root| {
            if (initial_root == null or root != initial_root.?) return ProverError.InvalidStatement;
        }
        if (statement.public_data.final_rw_root) |root| {
            if (final_root == null or root != final_root.?) return ProverError.InvalidStatement;
        }
        statement.public_data.initial_rw_root = initial_root;
        statement.public_data.final_rw_root = final_root;
    } else if (statement.public_data.initial_rw_root != null or
        statement.public_data.final_rw_root != null)
    {
        return ProverError.InvalidStatement;
    }

    const total_hashes = poseidon_calls.len;

    // Merkle and Poseidon2 follow the pinned component registry order.
    const total_merkle_nodes = merkle_rows.len;
    const merkle_log_size: u32 = if (total_merkle_nodes > 0)
        @max(4, computeLogSize(total_merkle_nodes))
    else
        4;
    const merkle_infra_index = statement.n_infra;
    statement.infra_descs[merkle_infra_index] = .{
        .kind = .merkle,
        .log_size = merkle_log_size,
        .n_rows = @intCast(total_merkle_nodes),
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;

    const poseidon_log_size: u32 = if (total_hashes > 0)
        @max(4, computeLogSize(total_hashes))
    else
        4;
    const poseidon_infra_index = statement.n_infra;
    statement.infra_descs[poseidon_infra_index] = .{
        .kind = .poseidon2,
        .log_size = poseidon_log_size,
        .n_rows = @intCast(total_hashes),
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;

    // Unified clock update follows Poseidon2 in the pinned registry.
    var clock_update_log: u32 = 4;
    if (opt_chain) |chain| {
        const n_updates = chain.clock_updates_mem.items.len + chain.clock_updates_reg.items.len;
        if (n_updates > 0) clock_update_log = @max(computeLogSize(n_updates), 4);
    }
    const clock_infra_index = statement.n_infra;
    statement.infra_descs[clock_infra_index] = .{
        .kind = .clock_update,
        .log_size = clock_update_log,
        .n_rows = if (opt_chain) |chain| @intCast(
            chain.clock_updates_mem.items.len + chain.clock_updates_reg.items.len,
        ) else 0,
        .n_columns = infra.CLOCK_UPDATE_COLS,
    };
    statement.n_infra += 1;

    for (component_order.lookupTables()) |kind| {
        if (statement.n_infra == MAX_INFRA_COMPONENTS)
            return ProverError.TooManyInfrastructureComponents;
        statement.infra_descs[statement.n_infra] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        statement.n_infra += 1;
    }
    try statement_validation.validate(statement, switch (mode) {
        .prove => .proof,
        .relation_diagnostic => .relation_diagnostic,
    });

    // Security geometry is part of the RISC-V Fiat–Shamir statement. This
    // prevents a proof under one profile from sharing a transcript prefix with
    // another profile even when every execution field is identical.
    pcs_config.mixInto(channel);
    statement.public_data.mixInto(channel);

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);

    var retained_tree0: relation_diagnostic.RetainedTree = undefined;
    var retained_tree0_initialized = false;
    defer if (retained_tree0_initialized) retained_tree0.deinit(allocator);
    var retained_tree1: relation_diagnostic.RetainedTree = undefined;
    var retained_tree1_initialized = false;
    defer if (retained_tree1_initialized) retained_tree1.deinit(allocator);

    // Empty state chain for fallback when opt_chain is null.
    var empty_chain = state_chain.StateChainTracker.init(allocator);
    defer empty_chain.deinit();

    // -- Step 3: Tree 0 -- selectors and exact lookup-table tuples. --
    {
        var stage = try stage_profile.StageScope.begin(recorder, "riscv_preprocessed_commit", "RISC-V preprocessed trace commit");
        defer stage.end();
        const preprocessed = try preprocessed_trace.generate(allocator, statement);
        var moved = false;
        errdefer if (!moved) {
            for (preprocessed) |column| allocator.free(@constCast(column.values));
            allocator.free(preprocessed);
        };
        if (comptime mode == .relation_diagnostic) {
            retained_tree0 = try relation_diagnostic.RetainedTree.capture(allocator, preprocessed);
            retained_tree0_initialized = true;
        }
        if (test_mutation) |mutation|
            try test_witness_hook.applyPreprocessed(allocator, statement, preprocessed, mutation);
        moved = true;
        try Engine.commit(&scheme, allocator, preprocessed, recorder, channel);
    }

    // -- Step 4: Tree 1 -- Main trace (opcode + infrastructure columns). --
    const n_opcode_main = statement.nOpcodeMainColumns();
    const n_infra_main = statement.nInfraColumns();
    const n_main = n_opcode_main + n_infra_main;
    const main_columns = try allocator.alloc(prover_pcs.ColumnEvaluation, n_main);
    const main_initialized = allocator.alloc(bool, n_main) catch |err| {
        allocator.free(main_columns);
        return err;
    };
    defer allocator.free(main_initialized);
    @memset(main_initialized, false);
    var main_columns_moved = false;
    errdefer if (!main_columns_moved) {
        for (main_columns, main_initialized) |column, initialized| {
            if (initialized) allocator.free(@constCast(column.values));
        }
        allocator.free(main_columns);
    };
    const OpcodeGenerationWork = struct {
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        statement: RiscVStatement,
        result: opcode_trace.Columns = undefined,
        err: ?anyerror = null,

        fn run(work: *@This()) void {
            work.result = opcode_trace.generate(
                work.allocator,
                work.exec_trace,
                work.statement,
            ) catch |err| {
                work.err = err;
                return;
            };
        }
    };
    const opcode_work = try allocator.create(OpcodeGenerationWork);
    defer allocator.destroy(opcode_work);
    opcode_work.* = OpcodeGenerationWork{
        .allocator = allocator,
        .exec_trace = exec_trace,
        .statement = statement,
    };
    var opcode_stage = try stage_profile.StageScope.begin(recorder, "riscv_opcode_trace_generation", "RISC-V opcode trace generation (overlapped)");
    const opcode_thread = std.Thread.spawn(.{}, OpcodeGenerationWork.run, .{opcode_work}) catch null;
    var opcode_joined = false;
    var opcode_cleanup_on_error = true;
    defer if (opcode_thread) |thread| {
        if (!opcode_joined) thread.join();
    };
    errdefer {
        if (opcode_thread) |thread| {
            if (!opcode_joined) {
                thread.join();
                opcode_joined = true;
            }
        }
        if (opcode_cleanup_on_error and opcode_work.err == null) {
            opcode_work.result.deinit(allocator, statement);
        }
    }
    if (opcode_thread == null) OpcodeGenerationWork.run(opcode_work);

    var col_offset: usize = n_opcode_main;

    var infrastructure_stage = try stage_profile.StageScope.begin(recorder, "riscv_infrastructure_trace_generation", "RISC-V infrastructure trace generation");
    // Infrastructure columns.
    // Exact sparse decoded-program commitment.
    {
        const prog_cols = try program_commitment.generateMain(allocator, program.rows, program_log_size);
        for (0..program_commitment.N_MAIN_COLUMNS) |c| {
            main_columns[col_offset + c] = .{
                .log_size = program_log_size,
                .values = prog_cols.values[c],
            };
            main_initialized[col_offset + c] = true;
        }
        col_offset += program_commitment.N_MAIN_COLUMNS;
    }

    // Exact ordinary RW-memory boundary table.
    if (boundary_claims) |claims| {
        var row_start: usize = 0;
        for (memory_shard_lengths[0..memory_shard_count]) |shard_len| {
            const log_size = @max(computeLogSize(shard_len), 4);
            const generated = try memory_trace.generate(
                allocator,
                claims.rows[row_start..][0..shard_len],
                log_size,
            );
            for (generated.values) |values| {
                main_columns[col_offset] = .{ .log_size = log_size, .values = values };
                main_initialized[col_offset] = true;
                col_offset += 1;
            }
            row_start += shard_len;
        }
    }

    // Exact sparse Merkle rows: initial RW, final RW, then program.
    {
        const mkl_cols = try merkle_node.generateMain(allocator, merkle_rows, merkle_log_size);
        for (0..merkle_node.N_MAIN_COLUMNS) |c| {
            main_columns[col_offset + c] = .{
                .log_size = merkle_log_size,
                .values = mkl_cols.values[c],
            };
            main_initialized[col_offset + c] = true;
        }
        col_offset += merkle_node.N_MAIN_COLUMNS;
    }

    // Exact narrow Poseidon2 permutation calls, one per sparse Merkle node.
    {
        const p2_cols = try poseidon2_air.generateMain(allocator, poseidon_calls, poseidon_log_size);
        for (0..poseidon2_air.N_MAIN_COLUMNS) |c| {
            main_columns[col_offset + c] = .{
                .log_size = poseidon_log_size,
                .values = p2_cols.values[c],
            };
            main_initialized[col_offset + c] = true;
        }
        col_offset += poseidon2_air.N_MAIN_COLUMNS;
    }

    var clock_main: [clock_update_interaction.N_MAIN_COLUMNS][]M31 =
        .{&.{}} ** clock_update_interaction.N_MAIN_COLUMNS;
    var clock_main_initialized = false;
    defer if (clock_main_initialized) {
        for (clock_main) |column| allocator.free(column);
    };

    // Unified register + memory clock update (8 cols).
    {
        const chain_ptr = opt_chain orelse &empty_chain;
        const cu_cols = try infra.genClockUpdateColumns(allocator, chain_ptr, clock_update_log);
        clock_main = cu_cols.columns;
        clock_main_initialized = true;
        for (0..infra.CLOCK_UPDATE_COLS) |c| {
            main_columns[col_offset + c] = .{
                .log_size = clock_update_log,
                .values = try allocator.dupe(M31, clock_main[c]),
            };
            main_initialized[col_offset + c] = true;
        }
        col_offset += infra.CLOCK_UPDATE_COLS;
    }
    infrastructure_stage.end();

    if (opcode_thread) |thread| {
        thread.join();
        opcode_joined = true;
    }
    opcode_stage.end();
    if (opcode_work.err) |err| return err;
    opcode_cleanup_on_error = false;
    defer opcode_work.result.deinit(allocator, statement);

    // Derive table multiplicities from the exact family buffers that will be
    // committed below. This keeps both the lookup source and its commitment on
    // one witness path, including any future pre-commit mutation hook.
    var lookup_source = try lookup_sources.ingest(allocator, statement, &opcode_work.result);
    defer lookup_source.deinit(allocator);
    try lookup_sources.registerProgram(&lookup_source.counters, program.rows);
    if (boundary_claims) |claims| {
        try lookup_sources.registerMemoryBoundary(&lookup_source.counters, claims.rows);
    }
    try clock_update_interaction.registerRangeCheck20Counter(
        lookup_source.counters.get(.range_check_20),
    );
    for (component_order.lookupTables()) |kind| {
        const counter = &lookup_source.counters.counters[@intFromEnum(kind)];
        main_columns[col_offset] = .{
            .log_size = lookup_table_schema.logSize(kind),
            .values = try counter.committedColumn(allocator),
        };
        main_initialized[col_offset] = true;
        col_offset += 1;
    }

    var opcode_col_offset: usize = 0;
    for (0..statement.n_components) |comp_idx| {
        const desc = statement.component_descs[comp_idx];
        const generated = &opcode_work.result.components[comp_idx];
        if (generated.n_columns != desc.n_columns) return ProverError.InvalidStatement;
        for (generated.columns[0..generated.n_columns], 0..) |values, column| {
            main_columns[opcode_col_offset + column] = .{
                .log_size = desc.log_size,
                .values = try allocator.dupe(M31, values),
            };
            main_initialized[opcode_col_offset + column] = true;
        }
        opcode_col_offset += desc.n_columns;
    }
    std.debug.assert(opcode_col_offset == n_opcode_main);
    std.debug.assert(col_offset == n_main);

    if (test_mutation) |mutation|
        try test_witness_hook.applyMain(allocator, statement, main_columns, mutation);

    if (comptime mode == .relation_diagnostic) {
        retained_tree1 = try relation_diagnostic.RetainedTree.capture(allocator, main_columns);
        retained_tree1_initialized = true;
    }

    {
        var stage = try stage_profile.StageScope.begin(recorder, "riscv_main_trace_commit", "RISC-V main trace commit");
        defer stage.end();
        main_columns_moved = true;
        try Engine.commit(&scheme, allocator, main_columns, recorder, channel);
    }

    // Tree 2 carries exact declaration-order opcode and infrastructure
    // interactions generated from byte-identical base buffers retained across
    // the Tree1 commitment.
    const n_interaction = statement.nInteractionColumns();

    if (comptime mode == .prove) {
        std.log.info("Columns: opcode={d} infra={d} total tree1={d} interaction={d}", .{
            n_opcode_main,
            n_infra_main,
            n_main,
            n_interaction,
        });
        std.log.info("Poseidon2 Merkle: {d} exact sparse-node calls, poseidon_log_size={d}, merkle_log_size={d}", .{
            total_hashes,
            poseidon_log_size,
            merkle_log_size,
        });
    }

    // -- Step 5: LogUp interaction tree (tree 2). --
    const transcript_prefix: proof_transcript.ProverRelations = if (comptime mode == .prove)
        try proof_transcript.proveToRelations(allocator, channel, &statement)
    else blk: {
        var diagnostic_channel = Engine.Channel{};
        break :blk .{
            .interaction_pow = 0,
            .relations = try @import("../air/relation_challenges.zig").Relations.draw(
                allocator,
                &diagnostic_channel,
            ),
        };
    };
    const relations = transcript_prefix.relations;

    const interaction_claim = try allocator.create(RiscVInteractionClaim);
    var interaction_claim_owned = true;
    defer if (interaction_claim_owned) allocator.destroy(interaction_claim);
    interaction_claim.initZeroInto();
    interaction_claim.n_components = statement.n_components;
    interaction_claim.n_infra = statement.n_infra;
    interaction_claim.interaction_pow = transcript_prefix.interaction_pow;

    // Shifted cumulative columns remain alive through composition evaluation.
    // Opcode interactions consume the exact values retained by Tree 1.
    const opcode_results = try allocator.alloc(
        opcode_interaction.Result,
        statement.n_components,
    );
    defer allocator.free(opcode_results);
    var n_opcode_results: usize = 0;
    defer for (opcode_results[0..n_opcode_results]) |*result| result.deinit(allocator);
    var table_results: [component_order.LOOKUP_TABLE_COUNT]lookup_table_interaction.Result = undefined;
    var n_table_results: usize = 0;
    defer for (table_results[0..n_table_results]) |*result| result.deinit(allocator);
    var clock_result: ?clock_update_interaction.InteractionTrace = null;
    defer if (clock_result) |*result| result.deinit(allocator);
    var program_prev: program_interaction.Previous =
        .{.{ &.{}, &.{}, &.{}, &.{} }} ** program_interaction.N_SUMS;
    var merkle_prev: merkle_node.Previous =
        .{.{ &.{}, &.{}, &.{}, &.{} }} ** merkle_node.N_SUMS;
    var poseidon_prev: poseidon2_air.Previous =
        .{.{ &.{}, &.{}, &.{}, &.{} }} ** poseidon2_air.N_SUMS;
    const memory_prev = try allocator.alloc(memory_interaction.Previous, statement.n_infra);
    for (memory_prev) |*prev| prev.* = .{.{ &.{}, &.{}, &.{}, &.{} }} ** memory_interaction.N_SUMS;
    defer {
        for (&program_prev) |*set| interaction_gen.freeColumns(allocator, set);
        for (&merkle_prev) |*set| interaction_gen.freeColumns(allocator, set);
        for (&poseidon_prev) |*set| interaction_gen.freeColumns(allocator, set);
        for (0..statement.n_infra) |i| {
            if (statement.infra_descs[i].kind != .memory) continue;
            for (&memory_prev[i]) |*set| interaction_gen.freeColumns(allocator, set);
        }
        allocator.free(memory_prev);
    }

    {
        var stage = try stage_profile.StageScope.begin(recorder, "riscv_interaction_commit", "RISC-V interaction trace generation and commit");
        defer stage.end();

        const interaction_columns = try allocator.alloc(prover_pcs.ColumnEvaluation, n_interaction);
        var inter_col_idx: usize = 0;
        var interaction_columns_moved = false;
        errdefer {
            if (!interaction_columns_moved) {
                for (interaction_columns[0..inter_col_idx]) |column| {
                    allocator.free(@constCast(column.values));
                }
                allocator.free(interaction_columns);
            }
        }

        var opcode_main_offset: usize = 0;
        for (0..statement.n_components) |i| {
            const desc = statement.component_descs[i];
            const n_family_columns: usize = @intCast(desc.n_columns);
            var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
            for (
                opcode_work.result.components[i].columns[0..n_family_columns],
                family_columns[0..n_family_columns],
            ) |column, *values| values.* = column;
            opcode_results[n_opcode_results] = try opcode_interaction.generate(
                allocator,
                desc.family,
                family_columns[0..n_family_columns],
                desc.log_size,
                &relations,
            );
            const generated = &opcode_results[n_opcode_results];
            n_opcode_results += 1;
            @memcpy(
                interaction_claim.opcode_claims[i][0..generated.n_batches],
                generated.claims[0..generated.n_batches],
            );
            const columns = generated.takeColumns();
            for (columns[0..generated.nColumns()]) |values| {
                interaction_columns[inter_col_idx] = .{ .log_size = desc.log_size, .values = values };
                inter_col_idx += 1;
            }
            opcode_main_offset += n_family_columns;
        }
        std.debug.assert(opcode_main_offset == n_opcode_main);

        const rom = try program_interaction.generate(
            allocator,
            program.rows,
            program_log_size,
            &relations,
        );
        interaction_claim.program_claims[0] = rom.claims.sums;
        program_prev = rom.previous;
        for (rom.columns) |values| {
            interaction_columns[inter_col_idx] = .{ .log_size = program_log_size, .values = values };
            inter_col_idx += 1;
        }

        if (boundary_claims) |claims| {
            var row_start: usize = 0;
            for (0..statement.n_infra) |infra_index| {
                const desc = statement.infra_descs[infra_index];
                if (desc.kind != .memory) continue;
                const row_end = row_start + desc.n_rows;
                const generated = try memory_interaction.generate(
                    allocator,
                    claims.rows[row_start..row_end],
                    desc.log_size,
                    &relations,
                );
                interaction_claim.memory_claims[infra_index] = generated.claims.sums;
                memory_prev[infra_index] = generated.previous;
                for (generated.columns) |values| {
                    interaction_columns[inter_col_idx] = .{ .log_size = desc.log_size, .values = values };
                    inter_col_idx += 1;
                }
                row_start = row_end;
            }
            std.debug.assert(row_start == claims.rows.len);
        }

        const merkle_interaction = try merkle_node.generateInteraction(
            allocator,
            merkle_rows,
            merkle_log_size,
            &relations,
        );
        interaction_claim.merkle_claims[merkle_infra_index] = merkle_interaction.claims.sums;
        merkle_prev = merkle_interaction.previous;
        for (merkle_interaction.columns) |values| {
            interaction_columns[inter_col_idx] = .{ .log_size = merkle_log_size, .values = values };
            inter_col_idx += 1;
        }

        const poseidon_interaction = try poseidon2_air.generateInteraction(
            allocator,
            poseidon_calls,
            poseidon_log_size,
            &relations,
        );
        interaction_claim.poseidon_claims[poseidon_infra_index] = poseidon_interaction.claims.sums;
        poseidon_prev = poseidon_interaction.previous;
        for (poseidon_interaction.columns) |values| {
            interaction_columns[inter_col_idx] = .{ .log_size = poseidon_log_size, .values = values };
            inter_col_idx += 1;
        }

        var clock_views: [clock_update_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
        for (&clock_views, clock_main) |*view, column| view.* = column;
        clock_result = try clock_update_interaction.generate(
            allocator,
            &clock_views,
            clock_update_log,
            &relations,
        );
        interaction_claim.clock_claims[clock_infra_index] = clock_result.?.claim;
        const clock_columns = clock_result.?.takeColumns();
        for (clock_columns) |values| {
            interaction_columns[inter_col_idx] = .{
                .log_size = clock_update_log,
                .values = values,
            };
            inter_col_idx += 1;
        }

        const table_infra_start = statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
        for (component_order.lookupTables(), 0..) |kind, table_index| {
            const infra_index = table_infra_start + table_index;
            table_results[n_table_results] = try lookup_table_interaction.generate(
                allocator,
                &lookup_source.counters.counters[@intFromEnum(kind)],
                &relations,
            );
            const generated = &table_results[n_table_results];
            n_table_results += 1;
            interaction_claim.lookup_claims[infra_index] = generated.claim;
            const columns = generated.takeColumns();
            for (columns) |values| {
                interaction_columns[inter_col_idx] = .{
                    .log_size = lookup_table_schema.logSize(kind),
                    .values = values,
                };
                inter_col_idx += 1;
            }
        }
        std.debug.assert(inter_col_idx == n_interaction);

        try proof_transcript.mixInteractionClaim(channel, &statement, interaction_claim);
        interaction_columns_moved = true;
        try Engine.commit(&scheme, allocator, interaction_columns, recorder, channel);
    }

    if (comptime mode == .relation_diagnostic) {
        if (scheme.trees.items.len != 3) return error.InvalidTreeShape;
        return relation_diagnostic.build(
            allocator,
            &statement,
            &retained_tree0,
            &retained_tree1,
            .{
                scheme.trees.items[0].root(),
                scheme.trees.items[1].root(),
                scheme.trees.items[2].root(),
            },
            relations,
            interaction_claim,
        );
    }

    scheme_owned = false;
    const proof = try proof_finalize.prove(
        Engine,
        allocator,
        recorder,
        scheme,
        channel,
        statement,
        &relations,
        interaction_claim,
        opcode_results[0..n_opcode_results],
        table_results[0..n_table_results],
        &clock_result.?,
        program_prev,
        merkle_prev,
        poseidon_prev,
        memory_prev,
        n_main,
        n_interaction,
    );
    interaction_claim_owned = false;
    return .{ .statement = statement, .proof = proof, .interaction_claim = interaction_claim };
}

fn validateCompletionWitness(
    data: *const PublicData,
    opt_memory: ?*const memory_state.Snapshot,
) !void {
    const completion = data.completion orelse return ProverError.InvalidStatement;
    if (completion.kind != .halt_flag) return;
    const snapshot = opt_memory orelse return ProverError.InvalidStatement;
    for (snapshot.words) |word| {
        if (word.addr != completion.address) continue;
        if (!word.role.is_public_completion or
            word.final_word != completion.value or
            word.final_clock != completion.clock)
            return ProverError.InvalidStatement;
        return;
    }
    return ProverError.InvalidStatement;
}
