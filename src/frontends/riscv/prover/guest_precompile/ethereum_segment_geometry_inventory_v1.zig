//! Count-only geometry inventory for retained Ethereum SegmentV2 leaves.
//!
//! This module computes exact sparse-frontier row counts and canonical base
//! statement descriptors without hashing sparse nodes or constructing provider
//! calls. It is geometry/custody substrate only: roots, ordered call identity,
//! provider planning, closure, and proof authority remain outside this API.

const std = @import("std");
const component_order = @import("../../air/component_order.zig");
const base_statement = @import("../../air/statement.zig");
const lookup_table_schema = @import("../../air/lookups/tables/schema.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const sparse_merkle = @import("../../air/memory_commitment/sparse_merkle.zig");
const program_commitment = @import("../../air/program/commitment.zig");
const execution_profile = @import("../../isa/profile.zig");
const infra = @import("../../infra_trace.zig");
const memory_state = @import("../../runner/memory_state.zig");
const runner_result = @import("../../runner/result.zig");
const trace_mod = @import("../../runner/trace.zig");
const segment_v2 = @import("../../recursion/segment_statement_v2.zig");
const statement_validation = @import("../statement_validation.zig");
const base_types = @import("../types.zig");

pub const format_version: u16 = 1;
const inventory_identity_domain =
    "stwo-zig/riscv/ethereum-segment-counted-inventory/v1\x00";
const program_inventory_identity_domain =
    "stwo-zig/riscv/ethereum-segment-program-inventory/v1\x00";
const maximum_opcode_shard_rows: usize = 1 << 16;

/// Reusable count-only authority for the immutable declared program image.
pub const ProgramInventoryV1 = struct {
    format: u16,
    declared_word_count: u32,
    program_row_count: u32,
    program_leaf_count: u32,
    merkle_node_count: u32,
    image_identity: [32]u8,
    identity: [32]u8,

    pub fn create(
        allocator: std.mem.Allocator,
        words: []const memory_state.WordState,
    ) !ProgramInventoryV1 {
        if (words.len == 0) return error.EmptyProgramCommitment;
        const declared_word_count = std.math.cast(u32, words.len) orelse
            return error.InvalidProgramInventory;
        var leaf_indices: std.ArrayList(u32) = .{};
        defer leaf_indices.deinit(allocator);
        const maximum_leaf_count = std.math.mul(usize, words.len, 4) catch
            return error.InvalidProgramInventory;
        try leaf_indices.ensureTotalCapacity(allocator, maximum_leaf_count);

        var previous_address: ?u32 = null;
        var row_count: u32 = 0;
        for (words) |word| {
            try execution_profile.requireProgramWordAddress(word.addr);
            if (previous_address) |previous| {
                if (word.addr <= previous) return error.InvalidProgramInventory;
            }
            previous_address = word.addr;
            if (word.initial_word == 0) continue;
            row_count = std.math.add(u32, row_count, 1) catch
                return error.InvalidProgramInventory;
            inline for (0..4) |limb| leaf_indices.appendAssumeCapacity(
                word.addr + @as(u32, @intCast(limb)),
            );
        }
        if (row_count == 0) return error.EmptyProgramCommitment;
        const leaf_count = std.math.cast(u32, leaf_indices.items.len) orelse
            return error.InvalidProgramInventory;
        const node_count = std.math.cast(
            u32,
            try sparse_merkle.countCanonicalNodeRowsFromSortedIndices(
                allocator,
                leaf_indices.items,
            ),
        ) orelse return error.InvalidProgramInventory;
        var result = ProgramInventoryV1{
            .format = format_version,
            .declared_word_count = declared_word_count,
            .program_row_count = row_count,
            .program_leaf_count = leaf_count,
            .merkle_node_count = node_count,
            .image_identity = programImageIdentity(words),
            .identity = undefined,
        };
        result.identity = programInventoryIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: ProgramInventoryV1) !void {
        const expected_leaves = std.math.mul(
            u32,
            self.program_row_count,
            4,
        ) catch return error.InvalidProgramInventory;
        if (self.format != format_version or self.declared_word_count == 0 or
            self.program_row_count == 0 or
            self.program_row_count > self.declared_word_count or
            self.program_leaf_count != expected_leaves or
            self.merkle_node_count == 0 or isZeroDigest(self.image_identity) or
            !std.meta.eql(self.identity, programInventoryIdentity(self)))
        {
            return error.InvalidProgramInventory;
        }
    }

    /// Rebind the complete immutable address/word image without rebuilding its
    /// sparse frontier. `create` remains the sole node-count constructor.
    pub fn validateImage(
        self: ProgramInventoryV1,
        words: []const memory_state.WordState,
    ) !void {
        try self.validate();
        const count = std.math.cast(u32, words.len) orelse
            return error.InvalidProgramInventory;
        if (count != self.declared_word_count or
            !std.meta.eql(self.image_identity, programImageIdentity(words)))
        {
            return error.ProgramInventoryMismatch;
        }
    }
};

pub const SparseBoundaryInventoryV1 = struct {
    nonzero_word_count: u32,
    nonzero_byte_count: u32,
    merkle_node_count: u32,

    pub fn validate(self: SparseBoundaryInventoryV1) !void {
        if (self.nonzero_word_count == 0) {
            if (self.nonzero_byte_count != 0 or self.merkle_node_count != 0)
                return error.InvalidExecutionInventory;
        } else if (self.nonzero_byte_count < self.nonzero_word_count or
            @as(u64, self.nonzero_byte_count) >
                4 * @as(u64, self.nonzero_word_count) or
            self.merkle_node_count == 0)
        {
            return error.InvalidExecutionInventory;
        }
    }
};

pub const ExecutionInventoryV1 = struct {
    format: u16,
    segment_index: u32,
    core_steps: u32,
    total_steps: u32,
    keccak_calls: u32,
    signer_calls: u32,
    opcode_family_counts: trace_mod.OpcodeFamilyCounts,
    program: ProgramInventoryV1,
    entry: SparseBoundaryInventoryV1,
    exit: SparseBoundaryInventoryV1,
    clock_update_rows: u32,
    provider_call_count: u32,
    identity: [32]u8,

    pub fn validate(self: ExecutionInventoryV1) !void {
        try self.program.validate();
        try self.entry.validate();
        try self.exit.validate();
        const external = std.math.add(
            u32,
            self.keccak_calls,
            self.signer_calls,
        ) catch return error.InvalidExecutionInventory;
        const total = std.math.add(u32, self.core_steps, external) catch
            return error.InvalidExecutionInventory;
        const provider = std.math.add(
            u32,
            self.program.merkle_node_count,
            self.entry.merkle_node_count,
        ) catch return error.InvalidExecutionInventory;
        const provider_total = std.math.add(
            u32,
            provider,
            self.exit.merkle_node_count,
        ) catch return error.InvalidExecutionInventory;
        if (self.format != format_version or self.core_steps == 0 or
            self.total_steps != total or
            self.opcode_family_counts.total() != self.core_steps or
            self.provider_call_count == 0 or
            self.provider_call_count != provider_total or
            !std.meta.eql(self.identity, executionInventoryIdentity(self)))
        {
            return error.InvalidExecutionInventory;
        }
    }
};

pub fn buildExecutionInventoryV1(
    allocator: std.mem.Allocator,
    result: *const runner_result.SegmentResult,
    program: ProgramInventoryV1,
    keccak_calls: u32,
    signer_calls: u32,
) !ExecutionInventoryV1 {
    try program.validateImage(result.rw_memory.program_words);
    const local_cycles = std.math.cast(u32, result.cycle_count) orelse
        return base_types.ProverError.InvalidStatement;
    try segment_v2.validateMemoryWords(
        result.rw_memory.words,
        result.segment_role,
        local_cycles,
    );
    const external = std.math.add(u32, keccak_calls, signer_calls) catch
        return error.InvalidExecutionInventory;
    const core_steps = std.math.cast(
        u32,
        result.execution_trace.step_count,
    ) orelse return error.InvalidExecutionInventory;
    const total_steps = std.math.add(u32, core_steps, external) catch
        return error.InvalidExecutionInventory;
    if (total_steps != local_cycles or
        result.execution_trace.recordedExternalSteps() != external)
    {
        return error.InvalidExecutionInventory;
    }
    result.execution_trace.validateClockRange(
        0,
        local_cycles,
        external,
    ) catch return error.InvalidExecutionInventory;

    const opcode_counts = try result.execution_trace.groupByOpcodeFamily(allocator);
    const entry = try sparseBoundaryInventory(
        allocator,
        result.rw_memory.words,
        .initial_word,
    );
    const exit = try sparseBoundaryInventory(
        allocator,
        result.rw_memory.words,
        .final_word,
    );
    const clock_update_count = std.math.add(
        usize,
        result.state_chain_tracker.clock_updates_mem.items.len,
        result.state_chain_tracker.clock_updates_reg.items.len,
    ) catch return error.InvalidExecutionInventory;
    const provider_count = std.math.add(
        u32,
        program.merkle_node_count,
        entry.merkle_node_count,
    ) catch return error.InvalidExecutionInventory;
    const provider_total = std.math.add(
        u32,
        provider_count,
        exit.merkle_node_count,
    ) catch return error.InvalidExecutionInventory;
    var inventory = ExecutionInventoryV1{
        .format = format_version,
        .segment_index = result.segment_index,
        .core_steps = core_steps,
        .total_steps = total_steps,
        .keccak_calls = keccak_calls,
        .signer_calls = signer_calls,
        .opcode_family_counts = opcode_counts,
        .program = program,
        .entry = entry,
        .exit = exit,
        .clock_update_rows = std.math.cast(u32, clock_update_count) orelse
            return error.InvalidExecutionInventory,
        .provider_call_count = provider_total,
        .identity = undefined,
    };
    inventory.identity = executionInventoryIdentity(inventory);
    try inventory.validate();
    return inventory;
}

pub fn countedCoreStatement(
    result: *const runner_result.SegmentResult,
    inventory: ExecutionInventoryV1,
) !base_statement.RiscVStatement {
    try inventory.validate();
    var statement = base_statement.RiscVStatement{
        .n_components = 0,
        .component_descs = undefined,
        .initial_pc = result.execution_trace.initial_pc,
        .final_pc = result.execution_trace.final_pc,
        .total_steps = inventory.total_steps,
        // Never transcript-mixed or admitted. Retained V3 custody owns roots;
        // this value supplies CPU/count fields to descriptor constructors only.
        .public_data = .{
            .initial_pc = result.execution_trace.initial_pc,
            .final_pc = result.execution_trace.final_pc,
            .clock = inventory.total_steps,
            .initial_regs = result.entry_cpu.regs,
            .final_regs = result.exit_cpu.regs,
            .reg_last_clock = result.exit_access_clocks.register_clocks,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = null,
            .io_entries = .{
                .input_start = 0,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0,
                .output_data_addr = 0,
                .output_words = &.{},
            },
        },
        .n_infra = 0,
        .infra_descs = undefined,
    };
    try describeOpcodeShards(&statement, inventory.opcode_family_counts);
    if (statement.n_components == 0) return base_types.ProverError.EmptyTrace;
    try appendInfraGeometry(&statement, inventory);
    return statement;
}

fn sparseBoundaryInventory(
    allocator: std.mem.Allocator,
    words: []const memory_state.WordState,
    comptime side: segment_v2.SnapshotSide,
) !SparseBoundaryInventoryV1 {
    var leaf_indices: std.ArrayList(u32) = .{};
    defer leaf_indices.deinit(allocator);
    const capacity = std.math.mul(usize, words.len, 4) catch
        return error.InvalidExecutionInventory;
    try leaf_indices.ensureTotalCapacity(allocator, capacity);
    var nonzero_words: u32 = 0;
    for (words) |word| {
        const value = @field(word, @tagName(side));
        if (value == 0) continue;
        nonzero_words = std.math.add(u32, nonzero_words, 1) catch
            return error.InvalidExecutionInventory;
        for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            if (@as(u8, @truncate(value >> shift)) == 0) continue;
            leaf_indices.appendAssumeCapacity(
                word.addr + @as(u32, @intCast(limb)),
            );
        }
    }
    const result = SparseBoundaryInventoryV1{
        .nonzero_word_count = nonzero_words,
        .nonzero_byte_count = std.math.cast(u32, leaf_indices.items.len) orelse
            return error.InvalidExecutionInventory,
        .merkle_node_count = std.math.cast(
            u32,
            try sparse_merkle.countCanonicalNodeRowsFromSortedIndices(
                allocator,
                leaf_indices.items,
            ),
        ) orelse return error.InvalidExecutionInventory,
    };
    try result.validate();
    return result;
}

fn describeOpcodeShards(
    statement: *base_statement.RiscVStatement,
    counts: trace_mod.OpcodeFamilyCounts,
) !void {
    for (component_order.opcodeFamilies()) |family| {
        var remaining = counts.get(family);
        while (remaining > 0) {
            if (statement.n_components >= base_statement.MAX_COMPONENTS)
                return base_types.ProverError.TooManyOpcodeComponents;
            const shard_rows = @min(remaining, maximum_opcode_shard_rows);
            statement.component_descs[statement.n_components] = .{
                .family = family,
                .log_size = statement_validation.computeOpcodeLogSize(shard_rows),
                .n_rows = @intCast(shard_rows),
                .n_columns = trace_mod.nColumnsForFamily(family),
            };
            statement.n_components += 1;
            remaining -= shard_rows;
        }
    }
}

fn appendInfraGeometry(
    statement: *base_statement.RiscVStatement,
    inventory: ExecutionInventoryV1,
) !void {
    try appendInfra(statement, .{
        .kind = .program,
        .log_size = statement_validation.computeLogSize(
            inventory.program.program_row_count,
        ),
        .n_rows = inventory.program.program_row_count,
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    });
    const provider_log_size = @max(
        @as(u32, 4),
        statement_validation.computeLogSize(inventory.provider_call_count),
    );
    try appendInfra(statement, .{
        .kind = .merkle,
        .log_size = provider_log_size,
        .n_rows = inventory.provider_call_count,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    });
    try appendInfra(statement, .{
        .kind = .poseidon2,
        .log_size = provider_log_size,
        .n_rows = inventory.provider_call_count,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    });
    try appendInfra(statement, .{
        .kind = .clock_update,
        .log_size = @max(
            @as(u32, 4),
            statement_validation.computeLogSize(inventory.clock_update_rows),
        ),
        .n_rows = inventory.clock_update_rows,
        .n_columns = infra.CLOCK_UPDATE_COLS,
    });
    for (component_order.lookupTables()) |kind| try appendInfra(statement, .{
        .kind = base_statement.infraKindForTable(kind),
        .log_size = lookup_table_schema.logSize(kind),
        .n_rows = @intCast(lookup_table_schema.size(kind)),
        .n_columns = 1,
    });
}

fn appendInfra(
    statement: *base_statement.RiscVStatement,
    descriptor: base_statement.InfraComponentDesc,
) !void {
    if (statement.n_infra >= base_statement.MAX_INFRA_COMPONENTS)
        return base_types.ProverError.TooManyInfrastructureComponents;
    statement.infra_descs[statement.n_infra] = descriptor;
    statement.n_infra += 1;
}

fn programImageIdentity(words: []const memory_state.WordState) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(program_inventory_identity_domain);
    hashInteger(&hash, u32, @intCast(words.len));
    for (words) |word| {
        hashInteger(&hash, u32, word.addr);
        hashInteger(&hash, u32, word.initial_word);
    }
    return hash.finalResult();
}

fn programInventoryIdentity(value: ProgramInventoryV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(program_inventory_identity_domain);
    hashInteger(&hash, u16, value.format);
    hashInteger(&hash, u32, value.declared_word_count);
    hashInteger(&hash, u32, value.program_row_count);
    hashInteger(&hash, u32, value.program_leaf_count);
    hashInteger(&hash, u32, value.merkle_node_count);
    hash.update(&value.image_identity);
    return hash.finalResult();
}

fn executionInventoryIdentity(value: ExecutionInventoryV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(inventory_identity_domain);
    hashInteger(&hash, u16, value.format);
    hashInteger(&hash, u32, value.segment_index);
    hashInteger(&hash, u32, value.core_steps);
    hashInteger(&hash, u32, value.total_steps);
    hashInteger(&hash, u32, value.keccak_calls);
    hashInteger(&hash, u32, value.signer_calls);
    for (value.opcode_family_counts.counts) |count|
        hashInteger(&hash, u64, @intCast(count));
    hash.update(&value.program.identity);
    inline for (.{ value.entry, value.exit }) |boundary| {
        hashInteger(&hash, u32, boundary.nonzero_word_count);
        hashInteger(&hash, u32, boundary.nonzero_byte_count);
        hashInteger(&hash, u32, boundary.merkle_node_count);
    }
    hashInteger(&hash, u32, value.clock_update_rows);
    hashInteger(&hash, u32, value.provider_call_count);
    return hash.finalResult();
}

fn isZeroDigest(value: [32]u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn hashInteger(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "program inventory node count matches canonical sparse tree" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x0010_0093, .final_word = 0x0010_0093, .final_clock = 0 },
        .{ .addr = 0x1004, .initial_word = 0, .final_word = 0, .final_clock = 0 },
        .{ .addr = 0x1008, .initial_word = 0x0020_8113, .final_word = 0x0020_8113, .final_clock = 0 },
    };
    const inventory = try ProgramInventoryV1.create(std.testing.allocator, &words);
    try inventory.validateImage(&words);
    const leaves = [_]sparse_merkle.Leaf{
        .{ .index = 0x1000, .value = 1 },
        .{ .index = 0x1001, .value = 1 },
        .{ .index = 0x1002, .value = 1 },
        .{ .index = 0x1003, .value = 1 },
        .{ .index = 0x1008, .value = 1 },
        .{ .index = 0x1009, .value = 1 },
        .{ .index = 0x100a, .value = 1 },
        .{ .index = 0x100b, .value = 1 },
    };
    var tree = try sparse_merkle.build(std.testing.allocator, &leaves);
    defer tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 2), inventory.program_row_count);
    try std.testing.expectEqual(tree.nodes.len, inventory.merkle_node_count);

    var mutated = words;
    mutated[2].initial_word ^= 1;
    try std.testing.expectError(
        error.ProgramInventoryMismatch,
        inventory.validateImage(&mutated),
    );
}

test "boundary inventory counts exact nonzero-byte sparse frontier" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x2000, .initial_word = 0, .final_word = 0x0000_0100, .final_clock = 1 },
        .{ .addr = 0x2004, .initial_word = 0x8000_0001, .final_word = 0, .final_clock = 2 },
    };
    const initial = try sparseBoundaryInventory(
        std.testing.allocator,
        &words,
        .initial_word,
    );
    try std.testing.expectEqual(@as(u32, 1), initial.nonzero_word_count);
    try std.testing.expectEqual(@as(u32, 2), initial.nonzero_byte_count);
    var initial_tree = try sparse_merkle.build(std.testing.allocator, &.{
        .{ .index = 0x2004, .value = 1 },
        .{ .index = 0x2007, .value = 0x80 },
    });
    defer initial_tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        initial_tree.nodes.len,
        initial.merkle_node_count,
    );

    const final = try sparseBoundaryInventory(
        std.testing.allocator,
        &words,
        .final_word,
    );
    try std.testing.expectEqual(@as(u32, 1), final.nonzero_word_count);
    try std.testing.expectEqual(@as(u32, 1), final.nonzero_byte_count);
    var final_tree = try sparse_merkle.build(std.testing.allocator, &.{.{
        .index = 0x2001,
        .value = 1,
    }});
    defer final_tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(final_tree.nodes.len, final.merkle_node_count);
}
