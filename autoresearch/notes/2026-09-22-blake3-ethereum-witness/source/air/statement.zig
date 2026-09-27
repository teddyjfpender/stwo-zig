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
const composition_manifest = @import("lang/opcode_composition_manifest.zig");
const trace_mod = @import("../runner/trace.zig");
const transcript_claims = @import("transcript/claims.zig");

const QM31 = qm31.QM31;
pub const FamilyComponentDesc = component.FamilyComponentDesc;
pub const PublicData = public_data.PublicData;

pub const MAX_COMPONENTS = @import("statement_geometry.zig").MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = @import("statement_geometry.zig").MAX_INFRA_COMPONENTS;
pub const MAX_INTERACTION_COLUMNS: usize =
    MAX_COMPONENTS * opcode_interaction.MAX_COLUMNS + MAX_INFRA_COMPONENTS * 16;

pub const InfraKind = @import("statement_geometry.zig").InfraKind;
pub const InfraComponentDesc = @import("statement_geometry.zig").InfraComponentDesc;

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

pub const RiscVStatement = ExecutionStatement(false);
/// Execution/clock/lookup shape for the full-width BLAKE3 public contract.
/// Program and memory providers are admitted by the BLAKE3 commitment roster.
pub const Blake3ExecutionStatement = ExecutionStatement(true);
fn ExecutionStatement(comptime blake3: bool) type {
    return struct {
        const Self = @This();
        n_components: u32,
        component_descs: [MAX_COMPONENTS]FamilyComponentDesc,
        initial_pc: u32,
        final_pc: u32,
        total_steps: u32,
        public_data: if (blake3) public_data.Blake3PublicData else PublicData,
        n_infra: u32 = 0,
        infra_descs: [MAX_INFRA_COMPONENTS]InfraComponentDesc = undefined,

        /// Admits only execution geometry; commitment-plan/key admission must
        /// separately bind provider components and full-width public roots.
        pub fn validateBlake3Execution(self: *const Self) !void {
            return self.validateBlake3ExecutionWithExternal(0);
        }

        /// Native geometry only. An extension verifier must independently bind
        /// and prove every external retirement; base-only admission passes zero.
        pub fn validateBlake3ExecutionWithExternal(self: *const Self, external_retirements: u32) !void {
            if (!blake3) @compileError("BLAKE3 execution requires full-width public roots");
            if (self.n_components > MAX_COMPONENTS or self.n_infra > MAX_INFRA_COMPONENTS) return error.InvalidStatement;
            try self.public_data.validate();
            if (self.initial_pc >= (1 << 30) or self.final_pc >= (1 << 30)) return error.InvalidStatement;
            if (self.initial_pc != self.public_data.initial_pc or self.final_pc != self.public_data.final_pc or self.total_steps != self.public_data.clock) return error.InvalidStatement;
            const order = @import("component_order.zig");
            const max_shard_rows: u32 = 1 << 16;
            if (self.total_steps > MAX_COMPONENTS * max_shard_rows or @import("../access_clock.zig").maximum(self.total_steps) >= @import("../runner/state_chain.zig").CLOCK_PREV_BOUND) return error.InvalidStatement;
            var rows: u64 = 0;
            var previous_family: ?usize = null;
            var previous_rows: u32 = 0;
            for (self.component_descs[0..self.n_components]) |desc| {
                if (desc.n_rows == 0 or desc.n_rows > max_shard_rows or desc.log_size != @max(1, std.math.log2_int_ceil(u32, desc.n_rows)) or desc.n_columns != trace_mod.nColumnsForFamily(desc.family)) return error.InvalidStatement;
                if (!@import("semantic_eval.zig").isTraceCompatible(desc.family)) return error.InvalidStatement;
                const family = order.opcodeFamilyIndex(desc.family);
                if (previous_family) |previous| {
                    if (family < previous or (family == previous and previous_rows != max_shard_rows)) return error.InvalidStatement;
                }
                previous_family = family;
                previous_rows = desc.n_rows;
                rows += desc.n_rows;
            }
            if (rows + @as(u64, external_retirements) != self.total_steps) return error.InvalidStatement;
            var previous_infra: ?usize = null;
            for (self.infra_descs[0..self.n_infra]) |desc| {
                switch (desc.kind) {
                    .program, .memory, .merkle, .poseidon2 => return error.LegacyCommitmentInBlake3Execution,
                    else => {},
                }
                if (desc.log_size == 0 or desc.log_size > 24 or desc.n_rows == 0 or desc.n_rows > @as(u32, 1) << @intCast(desc.log_size)) return error.InvalidStatement;
                const rank: usize = if (tableKind(desc.kind)) |kind| blk: {
                    if (desc.log_size != table_schema.logSize(kind) or desc.n_rows != table_schema.size(kind) or desc.n_columns != 1) return error.InvalidStatement;
                    break :blk 1 + order.lookupTableIndex(kind);
                } else blk: {
                    if (desc.kind != .clock_update or desc.n_columns != @import("../infra_trace.zig").CLOCK_UPDATE_COLS or desc.log_size != @max(1, std.math.log2_int_ceil(u32, desc.n_rows))) return error.InvalidStatement;
                    break :blk 0;
                };
                if (previous_infra) |previous| if (rank <= previous) return error.InvalidStatement;
                previous_infra = rank;
            }
        }

        /// Initializes every fixed-capacity descriptor slot to a valid canonical
        /// zero value. Encoders consume only active prefixes, but owned/cold
        /// reconstructions must never retain undefined enum values in the inactive
        /// capacity: whole-value custody checks and diagnostic formatters may walk
        /// those slots after the producing workspace has gone away.
        pub fn initializeDescriptorStorage(self: *Self) void {
            const empty_component: FamilyComponentDesc = .{
                .family = .base_alu_reg,
                .log_size = 0,
                .n_rows = 0,
                .n_columns = 0,
            };
            const empty_infrastructure: InfraComponentDesc = .{
                .kind = .program,
                .log_size = 0,
                .n_rows = 0,
                .n_columns = 0,
            };
            self.component_descs = .{empty_component} ** MAX_COMPONENTS;
            self.infra_descs = .{empty_infrastructure} ** MAX_INFRA_COMPONENTS;
        }

        pub fn nPreprocessedColumns(self: *const Self) u32 {
            var total = 2 * self.n_components;
            for (0..self.n_infra) |index| {
                total += nPreprocessedColumnsForInfra(self.infra_descs[index].kind);
            }
            return total;
        }

        pub fn preprocessedOffsetForInfra(self: *const Self, infra_index: usize) usize {
            std.debug.assert(infra_index <= self.n_infra);
            var offset: usize = 2 * self.n_components;
            for (0..infra_index) |index| {
                offset += nPreprocessedColumnsForInfra(self.infra_descs[index].kind);
            }
            return offset;
        }

        pub fn nOpcodeMainColumns(self: *const Self) u32 {
            var total: u32 = 0;
            for (0..self.n_components) |i| total += self.component_descs[i].n_columns;
            return total;
        }

        pub fn nInfraColumns(self: *const Self) u32 {
            var total: u32 = 0;
            for (0..self.n_infra) |i| total += self.infra_descs[i].n_columns;
            return total;
        }

        pub fn nMainColumns(self: *const Self) u32 {
            return self.nOpcodeMainColumns() + self.nInfraColumns();
        }

        pub fn nInteractionColumns(self: *const Self) u32 {
            var total: u32 = 0;
            for (0..self.n_components) |i| {
                total += @intCast(opcode_interaction.nColumns(self.component_descs[i].family));
            }
            for (0..self.n_infra) |i| total += nInteractionColsForInfra(self.infra_descs[i].kind);
            return total;
        }

        pub fn nPreprocessedCells(self: *const Self) u64 {
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

        pub fn nMainCells(self: *const Self) u64 {
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

        pub fn nInteractionCells(self: *const Self) u64 {
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

        pub fn canonicalMainClaim(self: *const Self) transcript_claims.MainClaim {
            var log_sizes = [_]u32{0} ** transcript_claims.COMPONENT_COUNT;
            for (0..self.n_components) |i| {
                const desc = self.component_descs[i];
                const index = @intFromEnum(
                    composition_manifest.transcriptComponent(desc.family),
                );
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
        pub fn mixShardManifest(self: Self, channel: anytype) void {
            channel.mixU32s(&.{
                if (blake3) 0x4253_4852 else 0x5348_5244, // "BSHR" / legacy "SHRD"
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
}

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

    /// Borrow one infrastructure component's active detailed claims as a
    /// contiguous segment. Fixed-capacity slack is never exposed. Besides
    /// avoiding copies, this lets profile transcripts hash one canonical
    /// component frame instead of one hash-chain round per physical claim.
    pub fn infraClaims(
        self: *const RiscVInteractionClaim,
        kind: InfraKind,
        index: usize,
    ) ![]const QM31 {
        if (index >= self.n_infra) return error.InvalidInteractionClaim;
        const count = nClaimedSumsForInfra(kind);
        return switch (kind) {
            .program => self.program_claims[index][0..count],
            .memory => self.memory_claims[index][0..count],
            .merkle => self.merkle_claims[index][0..count],
            .poseidon2 => self.poseidon_claims[index][0..count],
            .clock_update => self.clock_claims[index][0..count],
            .bitwise,
            .range_check_20,
            .range_check_8_11,
            .range_check_8_8_4,
            .range_check_8_8,
            .range_check_m31,
            => self.lookup_claims[index .. index + 1],
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
            const claim_index = @intFromEnum(
                composition_manifest.transcriptComponent(desc.family),
            );
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
