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
const trace_mod = @import("../runner/trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const types = @import("types.zig");

const MAX_OPCODE_SHARD_LOG_SIZE: u32 = 16;
const MAX_OPCODE_SHARD_ROWS: usize = @as(usize, 1) << MAX_OPCODE_SHARD_LOG_SIZE;
const MAX_EXECUTION_STEPS: usize = types.MAX_COMPONENTS * MAX_OPCODE_SHARD_ROWS;
const MAX_MEMORY_SHARD_LOG_SIZE: u32 = 16;
const MAX_MEMORY_SHARD_ROWS: usize = @as(usize, 1) << MAX_MEMORY_SHARD_LOG_SIZE;

comptime {
    if (MAX_EXECUTION_STEPS >= m31.Modulus) {
        @compileError("RISC-V execution geometry must fit in one M31 field cycle");
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
    try validateMemoryShards(statement.infra_descs[memory_start..index]);
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
    // endpoint canonical so a long execution cannot close through M31 wraparound.
    if (total_steps >= m31.Modulus - 1) return types.ProverError.InvalidStatement;
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
    try validateTotalStepsFieldCycle(m31.Modulus - 2);
    try std.testing.expectError(
        error.InvalidStatement,
        validateTotalStepsFieldCycle(m31.Modulus - 1),
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

test "statement validation: only semantically constrained opcode families are admitted" {
    for (component_order.opcodeFamilies()) |family| {
        try validateFamily(family, .proof);
        try validateFamily(family, .relation_diagnostic);
        try std.testing.expect(semantic_eval.constraintCount(family) > 0);
    }
}
