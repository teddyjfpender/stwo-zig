//! Native execution columns for the full-width commitment join. Uses the same
//! typed opcode, clock and table generators as the ordinary prover, with no
//! legacy program/memory/Poseidon witness construction.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const trace = @import("../runner/trace.zig");
const chain_mod = @import("../runner/state_chain.zig");
const statement_mod = @import("../air/statement.zig");
const public = @import("../air/public_data.zig");
const opcode = @import("opcode_trace.zig");
const order = @import("../air/component_order.zig");
const infra = @import("../infra_trace.zig");
const clock = @import("../air/clock_update_interaction.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const tables = @import("../air/lookups/tables/schema.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    statement: statement_mod.Blake3ExecutionStatement,
    opcode_columns: opcode.Columns,
    clock_main: [infra.CLOCK_UPDATE_COLS][]M = @splat(&.{}),
    preprocessed: std.ArrayList(Column) = .empty,
    main: std.ArrayList(Column) = .empty,
    interaction: std.ArrayList(Column) = .empty,
    claims: statement_mod.RiscVInteractionClaim = undefined,
    external_retirements: u32 = 0,
    tables_ready: bool = false,
    compact_ranges: ?*@import("compact_range_set.zig").Owner = null,
    failed: bool = false,
    interaction_ready: bool = false,
    native_only_v5: bool = false,
    pub fn init(a: std.mem.Allocator, execution: *const trace.Trace, data: public.Blake3PublicData, chain: *const chain_mod.StateChainTracker) !*Owner {
        return initWithExternal(a, execution, data, chain, 0);
    }
    /// Explicit versioned local-zero witness recipe. Canonical activation is
    /// coordinated with the caller AIR and register-window protocol, rather
    /// than inferred from a projection or a host register address.
    pub fn initLocalZeroWithExternal(a: std.mem.Allocator, execution: *const trace.Trace, data: public.Blake3PublicData, chain: *const chain_mod.StateChainTracker, external_retirements: u32) !*Owner {
        if (data.initial_regs[0] != 0 or data.final_regs[0] != 0) return error.NonzeroX0SemanticWitness;
        var local_data = data;
        local_data.reg_last_clock[0] = 0;
        var filtered: std.ArrayList(chain_mod.ClockUpdate) = .empty;
        defer filtered.deinit(a);
        for (chain.clock_updates_reg.items) |row| if (row.addr != 0) {
            try filtered.append(a, row);
        };
        // The old kernel reads these borrowed buffers only during init.
        // Neither the shallow view nor its maps gain ownership.
        var view = chain.*;
        view.clock_updates_reg = filtered;
        view.reg_last_clk[0] = 0;
        return initWithExternalRecipe(a, execution, local_data, &view, external_retirements, true);
    }
    /// Native columns only: the caller must supply authenticated external AIR
    /// and register its shared-table demand before includeCommitments.
    pub fn initWithExternal(a: std.mem.Allocator, execution: *const trace.Trace, data: public.Blake3PublicData, chain: *const chain_mod.StateChainTracker, external_retirements: u32) !*Owner {
        return initWithExternalRecipe(a, execution, data, chain, external_retirements, false);
    }
    fn initWithExternalRecipe(a: std.mem.Allocator, execution: *const trace.Trace, data: public.Blake3PublicData, chain: *const chain_mod.StateChainTracker, external_retirements: u32, local_zero: bool) !*Owner {
        try execution.validateClockAuthority();
        if (execution.recordedExternalSteps() != external_retirements or
            try std.math.add(usize, execution.rows.items.len, external_retirements) != data.clock) return error.InvalidExecutionTrace;
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .arena = std.heap.ArenaAllocator.init(a), .statement = undefined, .opcode_columns = undefined, .external_retirements = external_retirements };
        errdefer self.deinit();
        const arena = self.arena.allocator();
        self.claims.initZeroInto();
        self.statement.initializeDescriptorStorage();
        self.statement.n_components = 0;
        self.statement.n_infra = 0;
        self.statement.x0_local_custody_version = if (local_zero) @import("../air/x0_local_custody_v1.zig").VERSION else 0;
        self.statement.initial_pc = data.initial_pc;
        self.statement.final_pc = data.final_pc;
        self.statement.total_steps = data.clock;
        self.statement.public_data = data;
        const counts = try execution.groupByOpcodeFamily(arena);
        for (order.opcodeFamilies()) |family| {
            var remaining = counts.get(family);
            while (remaining != 0) {
                if (self.statement.n_components == statement_mod.MAX_COMPONENTS) return error.TooManyOpcodeShards;
                const n = @min(remaining, opcode.MAX_OPCODE_SHARD_ROWS);
                self.statement.component_descs[self.statement.n_components] = .{ .family = family, .log_size = logSize(n), .n_rows = @intCast(n), .n_columns = if (local_zero) @intCast(try @import("../air/x0_native_envelope_v1.zig").mainColumnCount(family)) else opcode.nCommittedColumnsForFamily(family) };
                self.statement.n_components += 1;
                remaining -= n;
            }
        }
        const clock_rows = try std.math.add(usize, chain.clock_updates_mem.items.len, chain.clock_updates_reg.items.len);
        if (clock_rows != 0) {
            try self.appendInfra(.clock_update, logSize(clock_rows), clock_rows, infra.CLOCK_UPDATE_COLS);
        }
        try self.statement.validateBlake3ExecutionWithExternal(self.external_retirements);
        self.opcode_columns = try opcode.generate(arena, execution, self.statement);
        for (self.statement.component_descs[0..self.statement.n_components], 0..) |desc, i| {
            if (self.opcode_columns.components[i].n_real_rows != desc.n_rows) return error.OpcodeRowCountMismatch;
            for (self.opcode_columns.components[i].columns[0..desc.n_columns]) |values| try self.main.append(arena, .{ .log_size = desc.log_size, .values = values });
        }
        if (clock_rows != 0) {
            const log = self.statement.infra_descs[0].log_size;
            const generated = try infra.genClockUpdateColumns(arena, chain, log);
            if (generated.n_real_rows != clock_rows) return error.ClockRowCountMismatch;
            self.clock_main = generated.columns;
            for (self.clock_main) |values| try self.main.append(arena, .{ .log_size = log, .values = values });
            try clock.registerRangeCheckCounters(&self.opcode_columns.lookup_counters.?, &self.clock_main);
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        if (self.compact_ranges) |compact| compact.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
    /// Commitments register into the same table census as native execution.
    /// Call before committing any tree; table geometry is finalized here.
    pub fn includeCommitments(self: *Owner, commitments: *const @import("blake3_commitment_columns.zig").Owner) !void {
        return self.includeCommitmentsMode(commitments, false);
    }
    /// Block-v5 native-only first round. Opcode/clock rows are proved here;
    /// program, memory and lookup-table requests must close against separate
    /// fresh proofs using the same sealed universal challenges. This method
    /// never attaches per-leaf BLAKE3 custody or local table providers.
    pub fn sealNativeOnly(self: *Owner) !void {
        if (self.tables_ready or self.failed or self.compact_ranges != null)
            return error.InvalidExecutionPhase;
        errdefer self.failed = true;
        try protocol.nativePreprocessedWithExternal(
            self.arena.allocator(),
            &self.statement,
            self.external_retirements,
            &self.preprocessed,
        );
        if (self.main.items.len != self.statement.nMainColumns() or
            self.preprocessed.items.len != self.statement.nPreprocessedColumns())
            return error.ExecutionGeometryMismatch;
        self.native_only_v5 = true;
        self.tables_ready = true;
    }
    /// Experimental preparation only: caller must separately admit and commit
    /// compact columns/claims. The current product proof entry point rejects it.
    pub fn includeCompactCommitments(self: *Owner, commitments: *const @import("blake3_commitment_columns.zig").Owner) !void {
        return self.includeCommitmentsMode(commitments, true);
    }
    fn includeCommitmentsMode(self: *Owner, commitments: *const @import("blake3_commitment_columns.zig").Owner, compact: bool) !void {
        if (self.tables_ready) return error.LookupTablesAlreadyPrepared;
        if (self.failed) return error.InvalidExecutionPhase;
        errdefer self.failed = true;
        const a = self.arena.allocator();
        try commitments.registerLookups(&self.opcode_columns.lookup_counters.?);
        if (compact) {
            const ranges = @import("compact_range_set.zig");
            const counters = &self.opcode_columns.lookup_counters.?;
            const plan = try ranges.derivePlan(counters);
            self.compact_ranges = try ranges.Owner.init(self.allocator, counters, plan, try plan.identity());
            try self.compact_ranges.?.mergeByteCounts(counters.get(.range_check_8_8));
        }
        for (order.lookupTables()) |kind| {
            const counter = self.opcode_columns.lookup_counters.?.get(kind);
            if (std.process.hasEnvVarConstant("STWO_RISCV_LOOKUP_DEMAND_PROFILE")) {
                var distinct: usize = 0;
                for (counter.values) |value| {
                    if (!value.isZero()) distinct += 1;
                }
                std.debug.print("BLAKE3_LOOKUP_DEMAND {{\"kind\":\"{s}\",\"domain_rows\":{d},\"distinct_nonzero\":{d}}}\n", .{
                    @tagName(kind), counter.values.len, distinct,
                });
            }
            if (compact and (kind == .range_check_20 or kind == .range_check_8_11 or kind == .range_check_8_8_4)) continue;
            const active = for (counter.values) |value| {
                if (!value.isZero()) break true;
            } else false;
            if (!active) continue;
            try self.appendInfra(statement_mod.infraKindForTable(kind), tables.logSize(kind), tables.size(kind), 1);
            try self.main.append(a, .{ .log_size = tables.logSize(kind), .values = try counter.committedColumn(a) });
        }
        try self.statement.validateBlake3ExecutionWithExternal(self.external_retirements);
        try protocol.nativePreprocessedWithExternal(a, &self.statement, self.external_retirements, &self.preprocessed);
        if (self.main.items.len != self.statement.nMainColumns() or self.preprocessed.items.len != self.statement.nPreprocessedColumns()) return error.ExecutionGeometryMismatch;
        self.tables_ready = true;
    }
    pub fn generateInteractions(self: *Owner, relations: *const @import("../air/relation_challenges.zig").Relations) !void {
        if (self.compact_ranges != null) return error.CompactRangeProtocolNotAdmitted;
        return self.generateNativeInteractions(relations);
    }
    pub fn generateCompactNativeInteractions(self: *Owner, relations: *const @import("../air/relation_challenges.zig").Relations) !void {
        if (self.compact_ranges == null) return error.CompactRangeProtocolNotAdmitted;
        return self.generateNativeInteractions(relations);
    }
    fn generateNativeInteractions(self: *Owner, relations: *const @import("../air/relation_challenges.zig").Relations) !void {
        if (self.failed or !self.tables_ready or self.interaction_ready or self.interaction.items.len != 0) return error.InvalidExecutionPhase;
        errdefer self.failed = true;
        const a = self.arena.allocator();
        self.claims.n_components = self.statement.n_components;
        self.claims.n_infra = self.statement.n_infra;
        for (self.statement.component_descs[0..self.statement.n_components], 0..) |desc, i| {
            const source = &self.opcode_columns.components[i];
            const generated = try opcode_interaction.generate(a, desc.family, source.columns[0..source.n_columns], desc.log_size, relations);
            @memcpy(self.claims.opcode_claims[i][0..generated.n_batches], generated.claims[0..generated.n_batches]);
            for (generated.columns[0..generated.nColumns()]) |values| try self.interaction.append(a, .{ .log_size = desc.log_size, .values = values });
        }
        for (self.statement.infra_descs[0..self.statement.n_infra], 0..) |desc, i| {
            if (desc.kind == .clock_update) {
                const generated = try clock.generate(a, &self.clock_main, desc.log_size, relations);
                self.claims.clock_claims[i] = generated.claims;
                for (generated.columns) |values| try self.interaction.append(a, .{ .log_size = desc.log_size, .values = values });
            } else {
                const kind = statement_mod.tableKind(desc.kind) orelse return error.LegacyCommitmentInBlake3Execution;
                const generated = try table_interaction.generate(a, self.opcode_columns.lookup_counters.?.get(kind), relations);
                self.claims.lookup_claims[i] = generated.claim;
                for (generated.columns) |values| try self.interaction.append(a, .{ .log_size = desc.log_size, .values = values });
            }
        }
        if (self.interaction.items.len != self.statement.nInteractionColumns()) return error.ExecutionGeometryMismatch;
        self.interaction_ready = true;
    }
    fn appendInfra(self: *Owner, kind: statement_mod.InfraKind, log: u32, rows: usize, width: usize) !void {
        if (self.statement.n_infra == statement_mod.MAX_INFRA_COMPONENTS or log > 24) return error.ExecutionGeometryOverflow;
        self.statement.infra_descs[self.statement.n_infra] = .{ .kind = kind, .log_size = log, .n_rows = @intCast(rows), .n_columns = @intCast(width) };
        self.statement.n_infra += 1;
    }
};
fn logSize(rows: usize) u32 {
    return @max(1, std.math.log2_int_ceil(usize, @max(1, rows)));
}
