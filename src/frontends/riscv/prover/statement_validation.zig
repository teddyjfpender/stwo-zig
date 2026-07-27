//! Canonical RISC-V statement geometry and preprocessed-root validation.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const component_order = @import("../air/component_order.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const program_commitment = @import("../air/program/commitment.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const access_clock = @import("../access_clock.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const types = @import("types.zig");

const MAX_OPCODE_SHARD_LOG_SIZE: u32 = 16;
const MAX_OPCODE_SHARD_ROWS: usize = @as(usize, 1) << MAX_OPCODE_SHARD_LOG_SIZE;
pub const MAX_EXECUTION_STEPS: usize = types.MAX_COMPONENTS * MAX_OPCODE_SHARD_ROWS;
const MAX_MEMORY_SHARD_LOG_SIZE: u32 = 16;
const MAX_MEMORY_SHARD_ROWS: usize = @as(usize, 1) << MAX_MEMORY_SHARD_LOG_SIZE;
const MAX_MERKLE_ROWS_WITHOUT_COEFFICIENT_WRAP: u32 = (m31.Modulus - 1) / 2;
const MAX_PUBLIC_MERKLE_TUPLE_MULTIPLICITY: u64 = 3;
const MAX_PUBLIC_MEMORY_TUPLE_MULTIPLICITY: u64 = 2;

comptime {
    if (MAX_EXECUTION_STEPS >= m31.Modulus) {
        @compileError("RISC-V execution geometry must fit in one M31 field cycle");
    }
    if (MAX_EXECUTION_STEPS * access_clock.STRIDE != state_chain.CLOCK_PREV_BOUND) {
        @compileError("clock predecessor decomposition drifted from execution capacity");
    }
    if (access_clock.maximum(@intCast(MAX_EXECUTION_STEPS)) >= m31.Modulus) {
        @compileError("maximum RISC-V access clock must be canonical in M31");
    }
}

/// Compute log_size from a count, with minimum of 1.
pub fn computeLogSize(count: usize) u32 {
    if (count <= 1) return 1;
    return @intCast(std.math.log2_int_ceil(usize, count));
}

pub fn computeOpcodeLogSize(count: usize) u32 {
    return @max(@as(u32, 4), computeLogSize(count));
}

pub const AdmissionPolicy = enum {
    /// Proofs and verification admit only fully constrained opcode families.
    proof,
    /// Diagnostics use the same family admission policy as production proofs.
    relation_diagnostic,
};

pub fn validate(
    statement: types.RiscVStatement,
    policy: AdmissionPolicy,
) types.ProverError!void {
    if (statement.n_components == 0 or statement.n_components > types.MAX_COMPONENTS)
        return types.ProverError.InvalidStatement;
    if (statement.n_infra < 10 or statement.n_infra > types.MAX_INFRA_COMPONENTS)
        return types.ProverError.InvalidStatement;
    try validateTotalStepsFieldCycle(statement.total_steps);
    statement.public_data.validate() catch return types.ProverError.InvalidStatement;
    if (statement.public_data.initial_pc != statement.initial_pc or
        statement.public_data.final_pc != statement.final_pc or
        statement.public_data.clock != statement.total_steps or
        statement.public_data.io_entries.input_words.len !=
            std.math.divCeil(usize, statement.public_data.io_entries.input_len, 4) catch unreachable)
        return types.ProverError.InvalidStatement;

    var total_rows: u64 = 0;
    var previous_family_index: ?usize = null;
    var previous_rows: u32 = 0;
    for (0..statement.n_components) |i| {
        const desc = statement.component_descs[i];
        try validateFamily(desc.family, policy);
        if (desc.log_size == 0 or desc.log_size > MAX_OPCODE_SHARD_LOG_SIZE or
            desc.n_rows == 0 or desc.n_rows > MAX_OPCODE_SHARD_ROWS or
            desc.log_size != computeOpcodeLogSize(desc.n_rows) or
            desc.n_columns != trace_mod.nColumnsForFamily(desc.family))
            return types.ProverError.InvalidStatement;
        const family_index = component_order.opcodeFamilyIndex(desc.family);
        if (previous_family_index) |previous| {
            if (family_index < previous) return types.ProverError.InvalidStatement;
            if (family_index == previous and previous_rows != MAX_OPCODE_SHARD_ROWS)
                return types.ProverError.InvalidStatement;
        }
        previous_family_index = family_index;
        previous_rows = desc.n_rows;
        total_rows += desc.n_rows;
    }
    if (total_rows != statement.total_steps) return types.ProverError.InvalidStatement;

    const program = statement.infra_descs[0];
    if (program.kind != .program or program.n_rows == 0 or
        program.n_columns != program_commitment.N_MAIN_COLUMNS)
        return types.ProverError.InvalidStatement;

    const memory_start: usize = 1;
    var index = memory_start;
    while (index < statement.n_infra and statement.infra_descs[index].kind == .memory) : (index += 1) {}
    const memory_shards = statement.infra_descs[memory_start..index];
    try validateMemoryShards(memory_shards);
    if (index + 3 + component_order.LOOKUP_TABLE_COUNT != statement.n_infra)
        return types.ProverError.InvalidStatement;
    const merkle_desc = statement.infra_descs[index];
    const poseidon_desc = statement.infra_descs[index + 1];
    const clock_update = statement.infra_descs[index + 2];
    if (merkle_desc.kind != .merkle or
        merkle_desc.n_columns != merkle_node.N_MAIN_COLUMNS or
        merkle_desc.log_size != @max(@as(u32, 4), computeLogSize(merkle_desc.n_rows)))
        return types.ProverError.InvalidStatement;
    if (poseidon_desc.kind != .poseidon2 or
        poseidon_desc.n_columns != poseidon2_air.N_MAIN_COLUMNS or
        poseidon_desc.log_size != @max(@as(u32, 4), computeLogSize(poseidon_desc.n_rows)))
        return types.ProverError.InvalidStatement;
    if (clock_update.kind != .clock_update or
        clock_update.n_columns != infra.CLOCK_UPDATE_COLS or
        clock_update.log_size != @max(@as(u32, 4), computeLogSize(clock_update.n_rows)))
        return types.ProverError.InvalidStatement;
    if (poseidon_desc.n_rows != merkle_desc.n_rows) return types.ProverError.InvalidStatement;
    try validateMerkleCoefficientLift(program.n_rows, memory_shards, merkle_desc.n_rows);
    try validateMemoryRelationCoefficientLift(
        statement.total_steps,
        memory_shards,
        clock_update.n_rows,
    );
    index += 3;
    for (component_order.lookupTables()) |kind| {
        const desc = statement.infra_descs[index];
        if (desc.kind != statement_mod.infraKindForTable(kind) or
            desc.log_size != lookup_table_schema.logSize(kind) or
            desc.n_rows != lookup_table_schema.size(kind) or
            desc.n_columns != 1)
            return types.ProverError.InvalidStatement;
        index += 1;
    }
    std.debug.assert(index == statement.n_infra);
    if (program.n_rows > (@as(usize, 1) << @intCast(program.log_size)) or
        program.log_size != computeLogSize(program.n_rows))
        return types.ProverError.InvalidStatement;
}

fn validateTotalStepsFieldCycle(total_steps: u32) types.ProverError!void {
    // The state bus exposes clocks 1 through total_steps + 1. Keep that final
    // endpoint canonical, and keep all derived access subclocks inside the
    // predecessor decomposition window.
    if (total_steps > MAX_EXECUTION_STEPS or
        total_steps >= m31.Modulus - 1 or
        access_clock.maximum(total_steps) >= state_chain.CLOCK_PREV_BOUND)
        return types.ProverError.InvalidStatement;
}

fn validateMerkleCoefficientLift(
    program_rows: u32,
    memory_shards: []const statement_mod.InfraComponentDesc,
    merkle_rows: u32,
) types.ProverError!void {
    // A malicious tuple need not occupy an honest depth: its negative side can
    // combine a coefficient-two node parent with one term from every program
    // or RW-boundary row, while its positive side can combine a
    // coefficient-two child with all three public roots. Bound the union of
    // every possible same-sign source below p. Then equality in M31 lifts to
    // ordinary-integer coefficient equality for every Merkle tuple. The node
    // bound also excludes the weaker p-row depth cycle.
    if (merkle_rows > MAX_MERKLE_ROWS_WITHOUT_COEFFICIENT_WRAP)
        return types.ProverError.InvalidStatement;

    var terms_per_side =
        @as(u64, merkle_rows) * 2 +
        @as(u64, program_rows) +
        MAX_PUBLIC_MERKLE_TUPLE_MULTIPLICITY;
    for (memory_shards) |desc| terms_per_side += @as(u64, desc.n_rows);
    if (terms_per_side >= m31.Modulus)
        return types.ProverError.InvalidStatement;
}

fn validateMemoryRelationCoefficientLift(
    total_steps: u32,
    memory_shards: []const statement_mod.InfraComponentDesc,
    clock_update_rows: u32,
) types.ProverError!void {
    // Every opcode contributes at most three access edges. Clock-update and
    // RW-boundary rows contribute one edge/term apiece; at most one output
    // word can coincide with the halt tuple, giving public multiplicity two.
    // A total below p prevents a nonzero integer coefficient from disappearing
    // in M31 and supplies the lift used by the strict-clock memory-path lemma.
    var terms_per_side =
        @as(u64, total_steps) * @as(u64, access_clock.MAX_ACCESSES_PER_INSTRUCTION) +
        @as(u64, clock_update_rows) + MAX_PUBLIC_MEMORY_TUPLE_MULTIPLICITY;
    for (memory_shards) |desc| terms_per_side += @as(u64, desc.n_rows);
    if (terms_per_side >= m31.Modulus)
        return types.ProverError.InvalidStatement;
}

fn validateFamily(
    family: trace_mod.OpcodeFamily,
    policy: AdmissionPolicy,
) types.ProverError!void {
    _ = policy;
    if (semantic_eval.isTraceCompatible(family)) return;
    // Every enum value is an admitted RV32IM proof family. A future family
    // cannot enter statement geometry before its semantic component lands.
    return types.ProverError.InvalidStatement;
}

fn validateMemoryShards(shards: []const statement_mod.InfraComponentDesc) types.ProverError!void {
    for (shards, 0..) |desc, shard_index| {
        if (desc.n_columns != memory_trace.N_COLUMNS or desc.n_rows == 0 or
            desc.n_rows > MAX_MEMORY_SHARD_ROWS or
            desc.log_size != @max(@as(u32, 4), computeLogSize(desc.n_rows)))
            return types.ProverError.InvalidStatement;
        if (shard_index + 1 < shards.len and desc.n_rows != MAX_MEMORY_SHARD_ROWS)
            return types.ProverError.InvalidStatement;
    }
}

pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    actual: types.Hasher.Hash,
) !void {
    const columns = try preprocessed_trace.generate(allocator, statement);
    var columns_moved = false;
    errdefer if (!columns_moved) {
        for (columns) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    };

    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    columns_moved = true;
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return types.ProverError.InvalidPreprocessedCommitment;
}

fn memoryShard(n_rows: u32) statement_mod.InfraComponentDesc {
    return .{
        .kind = .memory,
        .log_size = @max(@as(u32, 4), computeLogSize(n_rows)),
        .n_rows = n_rows,
        .n_columns = memory_trace.N_COLUMNS,
    };
}

test "statement validation: memory shard partition is canonical" {
    try validateMemoryShards(&.{});
    try validateMemoryShards(&.{memoryShard(17)});
    try validateMemoryShards(&.{
        memoryShard(MAX_MEMORY_SHARD_ROWS),
        memoryShard(17),
    });
    try validateMemoryShards(&.{
        memoryShard(MAX_MEMORY_SHARD_ROWS),
        memoryShard(MAX_MEMORY_SHARD_ROWS),
    });

    try std.testing.expectError(
        error.InvalidStatement,
        validateMemoryShards(&.{ memoryShard(16), memoryShard(17) }),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateMemoryShards(&.{
            memoryShard(17),
            memoryShard(MAX_MEMORY_SHARD_ROWS),
        }),
    );
}

test "statement validation: execution clock cannot wrap the base field" {
    try validateTotalStepsFieldCycle(@intCast(MAX_EXECUTION_STEPS));
    try std.testing.expectError(
        error.InvalidStatement,
        validateTotalStepsFieldCycle(@intCast(MAX_EXECUTION_STEPS + 1)),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateTotalStepsFieldCycle(m31.Modulus - 2),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateTotalStepsFieldCycle(m31.Modulus),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateTotalStepsFieldCycle(std.math.maxInt(u32)),
    );
}

test "statement validation: every Merkle coefficient side lifts to integers" {
    try validateMerkleCoefficientLift(1, &.{}, 0);
    try validateMerkleCoefficientLift(
        1,
        &.{},
        (m31.Modulus - 5) / 2,
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateMerkleCoefficientLift(
            1,
            &.{},
            (m31.Modulus - 3) / 2,
        ),
    );
    try validateMerkleCoefficientLift(m31.Modulus - 4, &.{}, 0);
    try std.testing.expectError(
        error.InvalidStatement,
        validateMerkleCoefficientLift(m31.Modulus - 3, &.{}, 0),
    );
    try validateMerkleCoefficientLift(
        m31.Modulus - 20,
        &.{memoryShard(16)},
        0,
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateMerkleCoefficientLift(
            m31.Modulus - 20,
            &.{memoryShard(17)},
            0,
        ),
    );
}

test "statement validation: memory relation coefficients cannot wrap the base field" {
    try validateMemoryRelationCoefficientLift(0, &.{}, m31.Modulus - 3);
    try std.testing.expectError(
        error.InvalidStatement,
        validateMemoryRelationCoefficientLift(0, &.{}, m31.Modulus - 2),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        validateMemoryRelationCoefficientLift(
            @intCast(MAX_EXECUTION_STEPS),
            &.{memoryShard(MAX_MEMORY_SHARD_ROWS)},
            m31.Modulus - 3,
        ),
    );
}

test "statement validation: only semantically constrained opcode families are admitted" {
    for (component_order.opcodeFamilies()) |family| {
        try validateFamily(family, .proof);
        try validateFamily(family, .relation_diagnostic);
        try std.testing.expect(semantic_eval.constraintCount(family) > 0);
    }
}
