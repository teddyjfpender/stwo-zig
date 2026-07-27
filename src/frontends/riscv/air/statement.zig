//! Public RISC-V proof shape and transcript claims.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const component = @import("component.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");
const merkle_node = @import("memory_commitment/merkle_node.zig");
const lookup_entry = @import("lookups/entry.zig");
const opcode_entries = @import("lookups/opcode_entries.zig");
const opcode_interaction = @import("lookups/opcode_interaction.zig");
const table_schema = @import("lookups/tables/schema.zig");
const clock_update_interaction = @import("clock_update_interaction.zig");
const poseidon2_air = @import("memory_commitment/poseidon2_air.zig");
const program_interaction = @import("program/interaction.zig");
const public_data = @import("public_data.zig");
const trace_mod = @import("../runner/trace.zig");
const transcript_claims = @import("transcript/claims.zig");

const QM31 = qm31.QM31;
pub const FamilyComponentDesc = component.FamilyComponentDesc;
pub const PublicData = public_data.PublicData;

pub const MAX_COMPONENTS: usize = 256;
pub const MAX_INFRA_COMPONENTS: usize = 512;
pub const MAX_INTERACTION_COLUMNS: usize =
    MAX_COMPONENTS * opcode_interaction.MAX_COLUMNS + MAX_INFRA_COMPONENTS * 16;

pub const InfraKind = enum(u32) {
    program,
    memory,
    clock_update,
    poseidon2,
    merkle,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const InfraComponentDesc = struct {
    kind: InfraKind,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};

pub fn nInteractionColsForInfra(kind: InfraKind) u32 {
    return switch (kind) {
        .program => program_interaction.N_COLUMNS,
        .memory => memory_interaction.N_COLUMNS,
        .poseidon2 => poseidon2_air.N_INTERACTION_COLUMNS,
        .merkle => merkle_node.N_INTERACTION_COLUMNS,
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => 4,
        .clock_update => clock_update_interaction.N_INTERACTION_COLUMNS,
    };
}

pub fn nClaimedSumsForInfra(kind: InfraKind) u32 {
    return nInteractionColsForInfra(kind) / 4;
}

pub fn tableKind(kind: InfraKind) ?table_schema.Kind {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => null,
    };
}

pub fn infraKindForTable(kind: table_schema.Kind) InfraKind {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

pub fn nPreprocessedColumnsForInfra(kind: InfraKind) u32 {
    return if (tableKind(kind)) |table|
        @intCast(1 + table_schema.arity(table))
    else
        2;
}

pub const RiscVStatement = struct {
    n_components: u32,
    component_descs: [MAX_COMPONENTS]FamilyComponentDesc,
    initial_pc: u32,
    final_pc: u32,
    total_steps: u32,
    public_data: PublicData,
    n_infra: u32 = 0,
    infra_descs: [MAX_INFRA_COMPONENTS]InfraComponentDesc = undefined,

    pub fn nPreprocessedColumns(self: *const RiscVStatement) u32 {
        var total = 2 * self.n_components;
        for (0..self.n_infra) |index| {
            total += nPreprocessedColumnsForInfra(self.infra_descs[index].kind);
        }
        return total;
    }

    pub fn preprocessedOffsetForInfra(self: *const RiscVStatement, infra_index: usize) usize {
        std.debug.assert(infra_index <= self.n_infra);
        var offset: usize = 2 * self.n_components;
        for (0..infra_index) |index| {
            offset += nPreprocessedColumnsForInfra(self.infra_descs[index].kind);
        }
        return offset;
    }

    pub fn nOpcodeMainColumns(self: *const RiscVStatement) u32 {
        var total: u32 = 0;
        for (0..self.n_components) |i| total += self.component_descs[i].n_columns;
        return total;
    }

    pub fn nInfraColumns(self: *const RiscVStatement) u32 {
        var total: u32 = 0;
        for (0..self.n_infra) |i| total += self.infra_descs[i].n_columns;
        return total;
    }

    pub fn nMainColumns(self: *const RiscVStatement) u32 {
        return self.nOpcodeMainColumns() + self.nInfraColumns();
    }

    pub fn nInteractionColumns(self: *const RiscVStatement) u32 {
        var total: u32 = 0;
        for (0..self.n_components) |i| {
            total += @intCast(opcode_interaction.nColumns(self.component_descs[i].family));
        }
        for (0..self.n_infra) |i| total += nInteractionColsForInfra(self.infra_descs[i].kind);
        return total;
    }

    pub fn nPreprocessedCells(self: *const RiscVStatement) u64 {
        var total: u64 = 0;
        for (0..self.n_components) |i| {
            total += @as(u64, 2) << @intCast(self.component_descs[i].log_size);
        }
        for (0..self.n_infra) |i| {
            total += @as(u64, nPreprocessedColumnsForInfra(self.infra_descs[i].kind)) <<
                @intCast(self.infra_descs[i].log_size);
        }
        return total;
    }

    pub fn nMainCells(self: *const RiscVStatement) u64 {
        var total: u64 = 0;
        for (0..self.n_components) |i| {
            total += @as(u64, self.component_descs[i].n_columns) <<
                @intCast(self.component_descs[i].log_size);
        }
        for (0..self.n_infra) |i| {
            total += @as(u64, self.infra_descs[i].n_columns) <<
                @intCast(self.infra_descs[i].log_size);
        }
        return total;
    }

    pub fn nInteractionCells(self: *const RiscVStatement) u64 {
        var total: u64 = 0;
        for (0..self.n_components) |i| {
            total += @as(u64, @intCast(opcode_interaction.nColumns(self.component_descs[i].family))) <<
                @intCast(self.component_descs[i].log_size);
        }
        for (0..self.n_infra) |i| {
            total += @as(u64, nInteractionColsForInfra(self.infra_descs[i].kind)) <<
                @intCast(self.infra_descs[i].log_size);
        }
        return total;
    }

    pub fn canonicalMainClaim(self: *const RiscVStatement) transcript_claims.MainClaim {
        var log_sizes = [_]u32{0} ** transcript_claims.COMPONENT_COUNT;
        for (0..self.n_components) |i| {
            const desc = self.component_descs[i];
            const index = @intFromEnum(componentForFamily(desc.family));
            log_sizes[index] = @max(log_sizes[index], desc.log_size);
        }
        for (0..self.n_infra) |i| {
            const desc = self.infra_descs[i];
            const index = @intFromEnum(componentForInfra(desc.kind));
            log_sizes[index] = @max(log_sizes[index], desc.log_size);
        }
        return transcript_claims.MainClaim.init(log_sizes);
    }

    /// Domain-separated extension to Stark-V's canonical 27-component claim.
    /// Upstream has one table per family; Zig shards large tables and must bind
    /// the complete shard geometry before drawing relation challenges.
    pub fn mixShardManifest(self: RiscVStatement, channel: anytype) void {
        channel.mixU32s(&.{
            0x5348_5244, // "SHRD"
            self.n_components,
            self.n_infra,
        });
        for (0..self.n_components) |i| {
            const desc = self.component_descs[i];
            channel.mixU32s(&.{
                @intFromEnum(desc.family),
                desc.log_size,
                desc.n_rows,
                desc.n_columns,
            });
        }
        for (0..self.n_infra) |i| {
            const desc = self.infra_descs[i];
            channel.mixU32s(&.{
                @intFromEnum(desc.kind),
                desc.log_size,
                desc.n_rows,
                desc.n_columns,
            });
        }
    }
};

pub const CanonicalInteractionClaim = struct {
    claimed_sums: [transcript_claims.COMPONENT_COUNT]QM31,
    log_sizes: [MAX_INTERACTION_COLUMNS]u32,
    n_log_sizes: usize,

    pub fn view(self: *const CanonicalInteractionClaim) transcript_claims.InteractionClaim {
        return transcript_claims.InteractionClaim.init(
            self.claimed_sums,
            self.log_sizes[0..self.n_log_sizes],
        );
    }
};

pub const RiscVInteractionClaim = struct {
    opcode_claims: [MAX_COMPONENTS][lookup_entry.MAX_BATCHES]QM31,
    program_claims: [MAX_INFRA_COMPONENTS][program_interaction.N_SUMS]QM31,
    memory_claims: [MAX_INFRA_COMPONENTS][memory_interaction.N_SUMS]QM31,
    merkle_claims: [MAX_INFRA_COMPONENTS][merkle_node.N_SUMS]QM31,
    poseidon_claims: [MAX_INFRA_COMPONENTS][poseidon2_air.N_SUMS]QM31,
    clock_claims: [MAX_INFRA_COMPONENTS][clock_update_interaction.N_SUMS]QM31,
    lookup_claims: [MAX_INFRA_COMPONENTS]QM31,
    n_components: u32,
    n_infra: u32,
    interaction_pow: u64,

    pub fn initZero() RiscVInteractionClaim {
        var result: RiscVInteractionClaim = undefined;
        result.initZeroInto();
        return result;
    }

    /// Initializes caller-owned storage without materializing another
    /// two-megabyte fixed-capacity claim on the stack.
    pub fn initZeroInto(self: *RiscVInteractionClaim) void {
        for (&self.opcode_claims) |*claims| @memset(claims, QM31.zero());
        for (&self.program_claims) |*claims| @memset(claims, QM31.zero());
        for (&self.memory_claims) |*claims| @memset(claims, QM31.zero());
        for (&self.merkle_claims) |*claims| @memset(claims, QM31.zero());
        for (&self.poseidon_claims) |*claims| @memset(claims, QM31.zero());
        for (&self.clock_claims) |*claims| @memset(claims, QM31.zero());
        @memset(&self.lookup_claims, QM31.zero());
        self.n_components = 0;
        self.n_infra = 0;
        self.interaction_pow = 0;
    }

    pub fn opcodeClaims(
        self: *const RiscVInteractionClaim,
        family: trace_mod.OpcodeFamily,
        index: usize,
    ) ![]const QM31 {
        if (index >= self.n_components) return error.InvalidInteractionClaim;
        return self.opcode_claims[index][0..opcode_entries.batchCount(family)];
    }

    pub fn opcodeClaimTotal(
        self: *const RiscVInteractionClaim,
        family: trace_mod.OpcodeFamily,
        index: usize,
    ) !QM31 {
        var result = QM31.zero();
        for (try self.opcodeClaims(family, index)) |sum| result = result.add(sum);
        return result;
    }

    pub fn infraClaim(self: *const RiscVInteractionClaim, kind: InfraKind, index: usize, sum: usize) !QM31 {
        if (index >= self.n_infra or sum >= nClaimedSumsForInfra(kind))
            return error.InvalidInteractionClaim;
        return switch (kind) {
            .program => self.program_claims[index][sum],
            .memory => self.memory_claims[index][sum],
            .merkle => self.merkle_claims[index][sum],
            .poseidon2 => self.poseidon_claims[index][sum],
            .bitwise,
            .range_check_20,
            .range_check_8_11,
            .range_check_8_8_4,
            .range_check_8_8,
            .range_check_m31,
            => self.lookup_claims[index],
            .clock_update => self.clock_claims[index][sum],
        };
    }

    pub fn setInfraClaim(
        self: *RiscVInteractionClaim,
        kind: InfraKind,
        index: usize,
        sum: usize,
        value: QM31,
    ) !void {
        if (index >= self.n_infra or sum >= nClaimedSumsForInfra(kind))
            return error.InvalidInteractionClaim;
        switch (kind) {
            .program => self.program_claims[index][sum] = value,
            .memory => self.memory_claims[index][sum] = value,
            .merkle => self.merkle_claims[index][sum] = value,
            .poseidon2 => self.poseidon_claims[index][sum] = value,
            .bitwise,
            .range_check_20,
            .range_check_8_11,
            .range_check_8_8_4,
            .range_check_8_8,
            .range_check_m31,
            => self.lookup_claims[index] = value,
            .clock_update => self.clock_claims[index][sum] = value,
        }
    }

    pub fn infraClaimTotal(self: *const RiscVInteractionClaim, kind: InfraKind, index: usize) !QM31 {
        var result = QM31.zero();
        for (0..nClaimedSumsForInfra(kind)) |sum| {
            result = result.add(try self.infraClaim(kind, index, sum));
        }
        return result;
    }

    pub fn canonical(
        self: *const RiscVInteractionClaim,
        statement: *const RiscVStatement,
    ) !CanonicalInteractionClaim {
        if (self.n_components != statement.n_components or self.n_infra != statement.n_infra)
            return error.InvalidInteractionClaim;
        var result = CanonicalInteractionClaim{
            .claimed_sums = .{QM31.zero()} ** transcript_claims.COMPONENT_COUNT,
            .log_sizes = undefined,
            .n_log_sizes = 0,
        };
        for (0..statement.n_components) |i| {
            const desc = statement.component_descs[i];
            const claim_index = @intFromEnum(componentForFamily(desc.family));
            result.claimed_sums[claim_index] = result.claimed_sums[claim_index]
                .add(try self.opcodeClaimTotal(desc.family, i));
            for (0..opcode_interaction.nColumns(desc.family)) |_| {
                if (result.n_log_sizes == result.log_sizes.len) return error.TooManyInteractionColumns;
                result.log_sizes[result.n_log_sizes] = desc.log_size;
                result.n_log_sizes += 1;
            }
        }
        for (0..statement.n_infra) |i| {
            const desc = statement.infra_descs[i];
            const claim_index = @intFromEnum(componentForInfra(desc.kind));
            result.claimed_sums[claim_index] = result.claimed_sums[claim_index]
                .add(try self.infraClaimTotal(desc.kind, i));
            for (0..nInteractionColsForInfra(desc.kind)) |_| {
                if (result.n_log_sizes == result.log_sizes.len) return error.TooManyInteractionColumns;
                result.log_sizes[result.n_log_sizes] = desc.log_size;
                result.n_log_sizes += 1;
            }
        }
        return result;
    }
};

fn componentForFamily(family: trace_mod.OpcodeFamily) transcript_claims.Component {
    return switch (family) {
        .auipc => .auipc,
        .base_alu_imm => .base_alu_imm,
        .base_alu_reg => .base_alu_reg,
        .branch_eq => .branch_eq,
        .branch_lt => .branch_lt,
        .div => .div,
        .jal => .jal,
        .jalr => .jalr,
        .load_store => .load_store,
        .lt_imm => .lt_imm,
        .lt_reg => .lt_reg,
        .lui => .lui,
        .mul => .mul,
        .mulh => .mulh,
        .shifts_imm => .shifts_imm,
        .shifts_reg => .shifts_reg,
        .fence => .fence,
    };
}

fn componentForInfra(kind: InfraKind) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}
