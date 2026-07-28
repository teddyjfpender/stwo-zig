//! Owned schema-v4 projection of a production RISC-V statement and claim.

const std = @import("std");
const stwo = @import("stwo");

const artifact = stwo.interop.riscv_artifact;
const statement_mod = stwo.frontends.riscv.air.statement;

pub const WireArena = struct {
    statement: artifact.StatementWire,
    claim: artifact.InteractionClaimWire,
    components: []artifact.ComponentWire,
    infrastructure: []artifact.InfraComponentWire,
    input_words: []u32,
    output_words: []artifact.OutputWordWire,
    opcode_claims: []artifact.OpcodeClaimWire,
    opcode_sums: []artifact.Qm31Wire,
    infrastructure_claims: []artifact.InfraClaimWire,
    infrastructure_sums: []artifact.Qm31Wire,

    pub fn init(allocator: std.mem.Allocator, output: anytype) !WireArena {
        const statement = output.statement;
        const claim = output.interaction_claim;
        if (claim.n_components != statement.n_components or claim.n_infra != statement.n_infra)
            return error.InvalidInteractionClaim;
        const n_components: usize = @intCast(statement.n_components);
        const n_infra: usize = @intCast(statement.n_infra);

        var self: WireArena = undefined;
        self.components = try allocator.alloc(artifact.ComponentWire, n_components);
        errdefer allocator.free(self.components);
        try projectComponents(self.components, statement);

        self.infrastructure = try allocator.alloc(artifact.InfraComponentWire, n_infra);
        errdefer allocator.free(self.infrastructure);
        for (self.infrastructure, 0..) |*wire, index| {
            const desc = statement.infra_descs[index];
            wire.* = .{
                .index = @intCast(index),
                .kind = @intFromEnum(desc.kind),
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = desc.n_columns,
                .claim_count = statement_mod.nClaimedSumsForInfra(desc.kind),
            };
        }

        const io = statement.public_data.io_entries;
        const completion = statement.public_data.completion orelse
            return error.InvalidCompletion;
        self.input_words = try allocator.dupe(u32, io.input_words);
        errdefer allocator.free(self.input_words);
        self.output_words = try allocator.alloc(artifact.OutputWordWire, io.output_words.len);
        errdefer allocator.free(self.output_words);
        for (self.output_words, io.output_words) |*wire, word| {
            wire.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
        }

        self.opcode_claims = try allocator.alloc(artifact.OpcodeClaimWire, n_components);
        errdefer allocator.free(self.opcode_claims);
        const opcode_sum_count = try countOpcodeSums(statement);
        self.opcode_sums = try allocator.alloc(artifact.Qm31Wire, opcode_sum_count);
        errdefer allocator.free(self.opcode_sums);
        var opcode_cursor: usize = 0;
        for (self.opcode_claims, 0..) |*wire, index| {
            const desc = statement.component_descs[index];
            const sums = try claim.opcodeClaims(desc.family, index);
            const projected = self.opcode_sums[opcode_cursor..][0..sums.len];
            for (projected, sums) |*destination, sum| destination.* = qm31Wire(sum);
            wire.* = .{ .component_index = @intCast(index), .claimed_sums = projected };
            opcode_cursor += sums.len;
        }
        std.debug.assert(opcode_cursor == self.opcode_sums.len);

        self.infrastructure_claims = try allocator.alloc(artifact.InfraClaimWire, n_infra);
        errdefer allocator.free(self.infrastructure_claims);
        const infrastructure_sum_count = try countInfrastructureSums(statement);
        self.infrastructure_sums = try allocator.alloc(artifact.Qm31Wire, infrastructure_sum_count);
        errdefer allocator.free(self.infrastructure_sums);
        var infrastructure_cursor: usize = 0;
        for (self.infrastructure_claims, 0..) |*wire, index| {
            const kind = statement.infra_descs[index].kind;
            const count: usize = @intCast(statement_mod.nClaimedSumsForInfra(kind));
            const projected = self.infrastructure_sums[infrastructure_cursor..][0..count];
            for (projected, 0..) |*destination, sum_index| {
                destination.* = qm31Wire(try claim.infraClaim(kind, index, sum_index));
            }
            wire.* = .{ .infrastructure_index = @intCast(index), .claimed_sums = projected };
            infrastructure_cursor += count;
        }
        std.debug.assert(infrastructure_cursor == self.infrastructure_sums.len);

        self.statement = .{
            .segment_ordinal = 0,
            .segment_count = 1,
            .initial_pc = statement.initial_pc,
            .final_pc = statement.final_pc,
            .total_steps = statement.total_steps,
            .components = self.components,
            .infrastructure = self.infrastructure,
            .public_data = .{
                .initial_pc = statement.public_data.initial_pc,
                .final_pc = statement.public_data.final_pc,
                .clock = statement.public_data.clock,
                .initial_regs = statement.public_data.initial_regs,
                .final_regs = statement.public_data.final_regs,
                .reg_last_clock = statement.public_data.reg_last_clock,
                .program_root = statement.public_data.program_root,
                .initial_rw_root = statement.public_data.initial_rw_root,
                .final_rw_root = statement.public_data.final_rw_root,
                .completion = .{
                    .kind = switch (completion.kind) {
                        .halt_flag => .halt_flag,
                        .unretired_self_loop => .unretired_self_loop,
                    },
                    .address = completion.address,
                    .value = completion.value,
                    .clock = completion.clock,
                },
                .input_start = io.input_start,
                .input_len = io.input_len,
                .input_words = self.input_words,
                .output_len = io.output_len,
                .output_len_addr = io.output_len_addr,
                .output_data_addr = io.output_data_addr,
                .output_words = self.output_words,
            },
        };
        self.claim = .{
            .interaction_pow = claim.interaction_pow,
            .opcode_claims = self.opcode_claims,
            .infrastructure_claims = self.infrastructure_claims,
        };
        return self;
    }

    pub fn deinit(self: *WireArena, allocator: std.mem.Allocator) void {
        allocator.free(self.components);
        allocator.free(self.infrastructure);
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        allocator.free(self.opcode_claims);
        allocator.free(self.opcode_sums);
        allocator.free(self.infrastructure_claims);
        allocator.free(self.infrastructure_sums);
        self.* = undefined;
    }
};

fn projectComponents(wires: []artifact.ComponentWire, statement: anytype) !void {
    var group_start: usize = 0;
    while (group_start < wires.len) {
        const family = statement.component_descs[group_start].family;
        var group_end = group_start + 1;
        while (group_end < wires.len and
            statement.component_descs[group_end].family == family) : (group_end += 1)
        {}
        var row_offset: u32 = 0;
        for (wires[group_start..group_end], 0..) |*wire, shard_index| {
            const index = group_start + shard_index;
            const desc = statement.component_descs[index];
            const batch_count = try statementClaimCount(statement, index);
            wire.* = .{
                .index = @intCast(index),
                .family = @intFromEnum(desc.family),
                .family_shard_index = @intCast(shard_index),
                .family_shard_count = @intCast(group_end - group_start),
                .row_offset = row_offset,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = desc.n_columns,
                .interaction_batch_count = batch_count,
            };
            row_offset = std.math.add(u32, row_offset, desc.n_rows) catch
                return error.InvalidStatementGeometry;
        }
        group_start = group_end;
    }
}

fn statementClaimCount(statement: anytype, index: usize) !u32 {
    const opcode_entries = stwo.frontends.riscv.air.lookups.opcode_entries;
    return std.math.cast(u32, opcode_entries.batchCount(statement.component_descs[index].family)) orelse
        error.InvalidStatementGeometry;
}

fn countOpcodeSums(statement: anytype) !usize {
    var total: usize = 0;
    for (0..statement.n_components) |index| {
        total = std.math.add(usize, total, try statementClaimCount(statement, index)) catch
            return error.InvalidStatementGeometry;
    }
    return total;
}

fn countInfrastructureSums(statement: anytype) !usize {
    var total: usize = 0;
    for (0..statement.n_infra) |index| {
        total = std.math.add(
            usize,
            total,
            statement_mod.nClaimedSumsForInfra(statement.infra_descs[index].kind),
        ) catch return error.InvalidStatementGeometry;
    }
    return total;
}

fn qm31Wire(value: anytype) artifact.Qm31Wire {
    const limbs = value.toM31Array();
    return .{ limbs[0].v, limbs[1].v, limbs[2].v, limbs[3].v };
}

test "artifact protocol snapshot matches production RISC-V registries" {
    const wire = artifact.wire_protocol;
    const order = stwo.frontends.riscv.air.component_order;
    const entries = stwo.frontends.riscv.air.lookups.opcode_entries;
    const tables = stwo.frontends.riscv.air.lookups.tables.schema;
    const transcript = stwo.frontends.riscv.air.transcript;
    const trace = stwo.frontends.riscv.runner.trace;

    try std.testing.expectEqual(artifact.SCHEMA_VERSION, wire.INTERACTION_POW_SCHEMA_VERSION);
    try std.testing.expectEqual(wire.INTERACTION_POW_BITS, transcript.INTERACTION_POW_BITS);
    try std.testing.expectEqual(wire.FAMILIES.len, order.opcodeFamilies().len);
    for (order.opcodeFamilies(), wire.FAMILIES) |family, metadata| {
        try std.testing.expectEqual(metadata.ordinal, @intFromEnum(family));
        try std.testing.expectEqual(metadata.n_main_columns, trace.nColumnsForFamily(family));
        try std.testing.expectEqual(metadata.n_interaction_batches, entries.batchCount(family));
    }
    for (order.lookupTables(), wire.TABLES) |table, metadata| {
        const infra_kind = statement_mod.infraKindForTable(table);
        try std.testing.expectEqual(@intFromEnum(metadata.kind), @intFromEnum(infra_kind));
        try std.testing.expectEqual(metadata.log_size, tables.logSize(table));
        try std.testing.expectEqual(metadata.n_rows, tables.size(table));
        try std.testing.expectEqual(
            metadata.preprocessed_columns,
            statement_mod.nPreprocessedColumnsForInfra(infra_kind),
        );
    }
    inline for (@typeInfo(statement_mod.InfraKind).@"enum".fields) |field| {
        const kind: statement_mod.InfraKind = @enumFromInt(field.value);
        const wire_kind: wire.InfraKind = @enumFromInt(field.value);
        try std.testing.expectEqual(wire.claimCount(wire_kind), statement_mod.nClaimedSumsForInfra(kind));
    }
}
