//! Immutable detached-parent preparation shared by CPU and device producers.
const std = @import("std");
const core = @import("stwo_core");
const component_types = @import("detached_parent_components_v1.zig");
pub const manifest_mod = component_types.manifest_mod;
pub const Relations = component_types.Relations;
pub const LOGICAL_ROWS = component_types.LOGICAL_ROWS;
pub const Component = component_types.Component;
pub const ParametersV1 = component_types.ParametersV1;
pub const ClaimsV1 = component_types.ClaimsV1;
pub const OwnedComponentsV1 = component_types.OwnedComponentsV1;
pub const LogicalRowsV1 = component_types.LogicalRowsV1;
pub const logicalIndex = component_types.logicalIndex;
const canonicalBase = component_types.canonicalBase;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const device_interaction = @import("air/framework_device_interaction.zig");
const CompactLedger = @import("compact_tuple_ledger_v1.zig").Owner;
const range = @import("air/range_check_8_8_bridge.zig");
const provider = @import("air/universal_shared_provider.zig");
const PoseidonAdapter = provider.Poseidon2Degree3AdapterForManifest(manifest_mod);
const air = struct {
    const direct_constraint_program = @import("air/direct_constraint_program.zig");
    const framework_interaction = @import("air/framework_interaction.zig");
    const relation_interaction = @import("air/relation_interaction.zig");
    const universal_relation_binding = @import("air/universal_relation_binding.zig");
};
const native_relations = @import("../air/relation_challenges.zig");
const native_poseidon = @import("../air/memory_commitment/poseidon2_air.zig");
const table_counter = @import("../air/lookups/tables/counter.zig");
const poseidon_air = @import("../air/memory_commitment/poseidon2_universal_degree3_v1.zig");
pub const ProviderCall = poseidon_air.Call;

// Match the leaf's existing worker policy and reuse the exact native writer.
// The compact AIR shares these IO entries and claims with the legacy layout.
fn generatePoseidonInteraction(allocator: std.mem.Allocator, calls: []const ProviderCall, outputs: []const [16]u32, log_size: u32, relations: *const native_relations.Relations, pool: ?*work_pool.WorkPool) !native_poseidon.Interaction {
    if (log_size >= 12) if (pool) |active_pool| {
        return native_poseidon.generateIoInteractionFromOutputsParallel(allocator, calls, outputs, log_size, relations, active_pool) catch |err| switch (err) {
            error.DivisionByZero => error.ZeroDenominator,
            else => err,
        };
    };
    return poseidon_air.generateIoInteractionFromOutputs(allocator, calls, outputs, log_size, relations);
}

fn profileTimer() !?std.time.Timer {
    return if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) try std.time.Timer.start() else null;
}
fn profileLap(timer: *?std.time.Timer) u64 {
    return if (timer.*) |*value| value.lap() else 0;
}

/// A private snapshot, admitted once at construction. The caller may destroy
/// every source row and child owner immediately after init returns.
pub const PreparedV1 = opaque {
    const Self = @This();
    const Storage = struct {
        allocator: std.mem.Allocator,
        rows: LogicalRowsV1,
        copied: usize = 0,
        calls: []ProviderCall,
        outputs: [][16]u32,
        manifest: manifest_mod.Manifest,
        parameters: ParametersV1,
        components: ?*OwnedComponentsV1 = null,
        range_batch: ?range.PreparedBatch = null,
        main_generated: bool = false,
    };
    fn storage(self: *const Self) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn init(allocator: std.mem.Allocator, rows: LogicalRowsV1, calls: []const ProviderCall) !*Self {
        return initForManifest(allocator, rows, calls, null);
    }

    /// An independently admitted retained key may select the reviewed compact
    /// identity. Derive all geometry from the witness and require the complete
    /// resulting seal to match; the candidate cannot supply arbitrary geometry.
    pub fn initForManifest(allocator: std.mem.Allocator, rows: LogicalRowsV1, calls: []const ProviderCall, admitted_manifest: ?*const manifest_mod.Manifest) !*Self {
        if (admitted_manifest) |manifest_value| try manifest_value.validate();
        const active_calls = std.math.cast(u32, calls.len) orelse return error.ArithmeticOverflow;
        const data = try allocator.create(Storage);
        data.* = .{ .allocator = allocator, .rows = undefined, .calls = &.{}, .outputs = &.{}, .manifest = undefined, .parameters = .{ .words = @splat(&.{}), .poseidon_active_rows = active_calls } };
        const self: *Self = @ptrCast(data);
        errdefer self.deinit();
        var builder = manifest_mod.Builder{};
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            data.rows[index] = try allocator.dupe([entry.Air.LOGICAL_INPUT_COUNT]M31, rows[index]);
            data.copied += 1;
            for (data.rows[index]) |row| for (row) |word| try canonicalBase(word);
            const count = Component(entry).PARAMETER_COLUMN_COUNT;
            if (count != 0) {
                if (data.rows[index].len == 0) return error.DetachedParentParameterMismatch;
                const start = entry.Air.LOGICAL_INPUT_COUNT - count;
                const words = data.rows[index][0][start..];
                for (data.rows[index][1..]) |row| if (!std.meta.eql(words[0..count].*, row[start..][0..count].*))
                    return error.DetachedParentParameterMismatch;
                data.parameters.words[@intFromEnum(entry.row)] = words;
            }
            _ = try builder.append(Component(entry).manifestGeometry(entry.row, try traceLogSize(rows[index].len)));
        }
        for (calls) |call| {
            if (!call.io or call.wide or call.narrow_output != null) return error.DetachedParentProviderMode;
            for (call.input) |word| if (word >= core.fields.m31.Modulus) return error.DetachedParentNonCanonicalField;
        }
        data.calls = try allocator.dupe(ProviderCall, calls);
        data.outputs = try allocator.alloc([16]u32, calls.len);
        const poseidon_geometry = PoseidonAdapter.manifestGeometry(try traceLogSize(calls.len));
        if (admitted_manifest) |manifest_value| {
            const admitted = try manifest_value.placement(.poseidon2);
            if (!PoseidonAdapter.acceptsGeometry(admitted.geometry) or admitted.geometry.log_size != poseidon_geometry.log_size)
                return error.DetachedParentManifestMismatch;
        }
        _ = try builder.append(poseidon_geometry);
        _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
        data.manifest = try builder.seal();
        if (admitted_manifest) |manifest_value| {
            if (!std.mem.eql(u8, &data.manifest.seal, &manifest_value.seal)) return error.DetachedParentManifestMismatch;
        }
        const dummy_relations = Relations.dummy();
        const zero_claims = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
        data.components = try OwnedComponentsV1.init(allocator, &data.manifest, data.parameters, &dummy_relations, zero_claims);
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            var scratch: [air.direct_constraint_program.MAX_NODES]M31 = undefined;
            var roots: [entry.Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            for (data.rows[index]) |row| {
                try data.components.?.directPlan(index).evaluateBaseInto(&row, &scratch, &roots);
                for (roots) |root| if (!root.isZero()) return error.DetachedParentConstraintViolation;
            }
        }
        return self;
    }
    pub fn deinit(self: *Self) void {
        const data: *Storage = @ptrCast(@alignCast(self));
        if (data.range_batch) |*batch| batch.deinit();
        if (data.components) |components| components.deinit();
        data.allocator.free(data.outputs);
        data.allocator.free(data.calls);
        inline for (0..LOGICAL_ROWS.len) |index| if (index < data.copied) data.allocator.free(data.rows[index]);
        data.allocator.destroy(data);
    }
    pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
        return &self.storage().manifest;
    }
    pub fn parameters(self: *const Self) ParametersV1 {
        return self.storage().parameters;
    }

    /// Destinations belong to the proof transaction. Reject aliases before any
    /// mutation so a caller cannot rewrite this immutable admission snapshot.
    fn preflight(self: *const Self, tree: usize, destination: [][]M31) !void {
        const data = self.storage();
        if (tree > 2) return error.InvalidTreeIndex;
        const expected = switch (tree) {
            0 => data.manifest.total_preprocessed_columns,
            1 => data.manifest.total_main_columns,
            2 => data.manifest.total_interaction_columns,
            else => unreachable,
        };
        if (destination.len != expected) return error.DetachedParentDestinationMismatch;
        for (data.manifest.roster_rows[0..data.manifest.roster_count]) |row| {
            const placement = data.manifest.placements[row].?;
            const offset = switch (tree) {
                0 => placement.preprocessed_offset,
                1 => placement.main_offset,
                2 => placement.interaction_offset,
                else => unreachable,
            };
            const count = switch (tree) {
                0 => placement.geometry.preprocessed_columns,
                1 => placement.geometry.main_columns,
                2 => placement.geometry.interaction_columns,
                else => unreachable,
            };
            for (destination[offset..][0..count]) |column| if (column.len != @as(usize, 1) << @intCast(placement.geometry.log_size)) return error.DetachedParentDestinationMismatch;
        }
        for (destination, 0..) |column, index| {
            for (destination[0..index]) |other| if (overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(other))) return error.DestinationAlias;
            inline for (0..LOGICAL_ROWS.len) |slot| if (overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(data.rows[slot]))) return error.DestinationAlias;
            if (overlapBytes(std.mem.sliceAsBytes(column), std.mem.asBytes(data)) or
                overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(data.calls)) or
                overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(data.outputs))) return error.DestinationAlias;
            if (data.range_batch) |batch| if (overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(batch.counter.values))) return error.DestinationAlias;
        }
    }
    fn fillLogical(self: *const Self, tree: usize, destination: [][]M31) void {
        const data = self.storage();
        for (destination) |column| @memset(column, M31.zero());
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            const placement = data.manifest.placements[@intFromEnum(entry.row)].?;
            const count = if (tree == 0) entry.Air.PREPROCESSED_COLUMN_COUNT else entry.Air.PHYSICAL_MAIN_COLUMN_COUNT;
            const offset = if (tree == 0) placement.preprocessed_offset else placement.main_offset;
            device_interaction.writeColumns(entry.Air, data.rows[index], placement.geometry.log_size, tree, destination[offset..][0..count]);
        }
    }
    pub fn fillPreprocessedInto(self: *const Self, destination: [][]M31) !void {
        try self.preflight(0, destination);
        self.fillLogical(0, destination);
        const data = self.storage();
        const poseidon = data.manifest.placements[34].?;
        destination[poseidon.preprocessed_offset][air.framework_interaction.committedRow(0, poseidon.geometry.log_size)] = M31.one();
        const placement = data.manifest.placements[35].?;
        destination[placement.preprocessed_offset][range.committedRow(0)] = M31.one();
        for (0..range.TABLE_SIZE) |logical| {
            const row = range.committedRow(logical);
            destination[placement.preprocessed_offset + 1][row] = M31.fromCanonical(@intCast(logical & 255));
            destination[placement.preprocessed_offset + 2][row] = M31.fromCanonical(@intCast(logical >> 8));
        }
    }
    fn fillMainBody(self: *Self, destination: [][]M31) !void {
        const data: *Storage = @ptrCast(@alignCast(self));
        self.fillLogical(1, destination);
        const placement = data.manifest.placements[34].?;
        var columns = destination[placement.main_offset..][0..poseidon_air.N_MAIN_COLUMNS].*;
        try poseidon_air.generateMainInto(data.allocator, &columns, data.calls, placement.geometry.log_size);
        for (data.outputs, 0..) |*output, logical| {
            const row = air.framework_interaction.committedRow(logical, placement.geometry.log_size);
            for (output, poseidon_air.outputFromColumns(M31, columns, row)) |*word, field| word.* = field.toU32();
        }
    }
    fn fillRangeInto(self: *const Self, batch: *const range.PreparedBatch, destination: [][]M31) !void {
        const data = self.storage();
        const placement = data.manifest.placements[35].?;
        var columns = destination[placement.main_offset..][0..range.PHYSICAL_MAIN_COLUMN_COUNT].*;
        try data.components.?.rangeExecutor().generateMainInto(batch, &columns);
    }
    fn appendSourceTuples(self: *const Self, ledger: *air.relation_interaction.TupleLedger) !void {
        const data = self.storage();
        inline for (LOGICAL_ROWS, 0..) |entry, index| try data.components.?.relationPlan(index).appendPreparedTupleContributions(ledger, @intFromEnum(entry.row), data.rows[index], air.relation_interaction.allDomainMask());
    }
    /// Cold generation for independent audits/tests. Production finalizes once
    /// below, sharing the source projection with exact closure.
    pub fn fillMainInto(self: *Self, destination: [][]M31) !void {
        try self.preflight(1, destination);
        const data: *Storage = @ptrCast(@alignCast(self));
        data.main_generated = false;
        errdefer for (destination) |column| @memset(column, M31.zero());
        if (data.range_batch == null) {
            var counter = try table_counter.Counter.init(data.allocator, .range_check_8_8);
            defer counter.deinit(data.allocator);
            inline for (LOGICAL_ROWS, 0..) |_, index| for (data.rows[index]) |row| {
                for (data.components.?.relationPlan(index).preparedEntries(row)) |event| if (event.domain == .range_check_8_8)
                    try counter.registerRaw(event.numerator, event.values[0..event.arity]);
            };
            data.range_batch = try range.PreparedBatch.init(data.allocator, &counter);
        }
        try self.fillMainBody(destination);
        try self.fillRangeInto(&data.range_batch.?, destination);
        data.main_generated = true;
    }
    /// Source tuples are projected once into the existing exact ledger. Its
    /// range counter supplies row35; actual provider/public tuples close before
    /// any mutable state is published to interaction generation or commitment.
    pub fn finalizeMainInto(self: *Self, expected: *const @import("detached_parent_protocol_v1.zig").ExpectedV1, destination: [][]M31) !air.relation_interaction.TupleClosureReport {
        var timer = try profileTimer();
        try @import("detached_parent_protocol_v1.zig").validateExpected(expected);
        try self.preflight(1, destination);
        for (destination) |column| if (overlapBytes(std.mem.asBytes(expected), std.mem.sliceAsBytes(column))) return error.DestinationAlias;
        const data: *Storage = @ptrCast(@alignCast(self));
        data.main_generated = false;
        errdefer for (destination) |column| @memset(column, M31.zero());
        const preflight_ns = profileLap(&timer);
        try self.fillMainBody(destination);
        const main_fill_ns = profileLap(&timer);
        var compact = try CompactLedger.init(data.allocator, false);
        defer compact.deinit();
        var ledger = compact.ledger();
        defer ledger.deinit();
        try self.appendSourceTuples(&ledger);
        const source_projection_ns = profileLap(&timer);
        var batch = try range.PreparedBatch.init(data.allocator, &compact.source_counter);
        errdefer batch.deinit();
        try self.fillRangeInto(&batch, destination);
        const range_fill_ns = profileLap(&timer);
        const report = try self.closeProviderTuples(expected, destination, &batch, &compact, &ledger);
        if (data.range_batch) |*previous| previous.deinit();
        data.range_batch = batch;
        data.main_generated = true;
        const closure_ns = profileLap(&timer);
        if (timer != null) std.debug.print("PARENT_MAIN_FINALIZE preflight_ns={d} main_fill_ns={d} source_projection_ns={d} range_fill_ns={d} closure_ns={d}\n", .{ preflight_ns, main_fill_ns, source_projection_ns, range_fill_ns, closure_ns });
        return report;
    }
    /// Challenge-independent diagnostic over exact typed/native relation entries.
    /// This never supplies a residual to the proof; a nonzero tuple aborts before
    /// PCS/FRI. Native provider entries are read from the generated main columns.
    pub fn auditExactTupleClosure(self: *const Self, expected: *const @import("detached_parent_protocol_v1.zig").ExpectedV1, main_columns: [][]M31) !air.relation_interaction.TupleClosureReport {
        const protocol = @import("detached_parent_protocol_v1.zig");
        try protocol.validateExpected(expected);
        try self.preflight(1, main_columns);
        const data = self.storage();
        if (!data.main_generated) return error.DetachedParentMainNotGenerated;
        var compact = try CompactLedger.init(data.allocator, false);
        defer compact.deinit();
        var ledger = compact.ledger();
        defer ledger.deinit();
        try self.appendSourceTuples(&ledger);
        return self.closeProviderTuples(expected, main_columns, &data.range_batch.?, &compact, &ledger);
    }
    fn closeProviderTuples(self: *const Self, expected: *const @import("detached_parent_protocol_v1.zig").ExpectedV1, main_columns: [][]M31, batch: *const range.PreparedBatch, compact: *CompactLedger, ledger: *air.relation_interaction.TupleLedger) !air.relation_interaction.TupleClosureReport {
        const protocol = @import("detached_parent_protocol_v1.zig");
        const data = self.storage();
        try batch.validate();
        const range_placement = data.manifest.placements[35].?;
        for (batch.counter.values, 0..) |expected_multiplicity, logical| {
            const actual = main_columns[range_placement.main_offset][range.committedRow(logical)];
            if (!actual.eql(expected_multiplicity)) return error.DetachedParentRangeMainChanged;
        }
        const placement = data.manifest.placements[34].?;
        for (data.calls, data.outputs, 0..) |call, output, logical| {
            const physical = air.framework_interaction.committedRow(logical, placement.geometry.log_size);
            const columns = main_columns[placement.main_offset..][0..poseidon_air.N_MAIN_COLUMNS];
            for (call.input, 0..) |word, column| if (columns[1 + column][physical].toU32() != word) return error.DetachedParentProviderMainChanged;
            for (output, poseidon_air.outputFromColumns(M31, columns, physical)) |word, field| if (field.toU32() != word) return error.DetachedParentProviderMainChanged;
            const entries = poseidon_air.entriesFromColumns(QM31, columns, physical);
            for (entries.entries[0..entries.len], 0..) |event, ordinal| {
                const domain: @FieldType(air.relation_interaction.TupleContribution, "domain") = switch (event.domain) {
                    .poseidon2 => .poseidon2,
                    .poseidon2_io => .poseidon2_io,
                    else => return error.DetachedParentProviderMode,
                };
                try ledger.append(domain, 34, @intCast(ordinal), switch (event.role) {
                    .request => .request,
                    .consume => .consume,
                    .emit => .emit,
                }, event.numerator, event.values[0..event.arity]);
            }
        }
        try compact.sealSourceHistogram(null, 0);
        const range_plan = try range.authenticateRelation(data.components.?.rangeDefinition());
        for (0..range.TABLE_SIZE) |row| for (range_plan.preparedEntries(batch.preparedRelationRow(row))) |event|
            try ledger.append(event.domain, 35, event.ordinal, event.role, event.numerator, event.values[0..event.arity]);
        for (expected, 0..) |word, index| {
            const base = protocol.publicTuple(index, word);
            var tuple: [3]QM31 = undefined;
            for (base, &tuple) |value, *secure| secure.* = QM31.fromBase(value);
            try ledger.append(.recursion_statement_word, 255, 0, .emit, QM31.one(), &tuple);
        }
        const report = try compact.classify();
        if (!report.isClosed()) {
            ledger.printUnmatched(8);
            return error.DetachedParentExactTupleClosureMismatch;
        }
        return report;
    }
    pub fn fillInteractionInto(self: *const Self, relations: *const Relations, destination: [][]M31, pool: ?*work_pool.WorkPool) !ClaimsV1 {
        return self.fillInteractionForBackend(void, relations, destination, pool);
    }
    pub fn fillInteractionForBackend(self: *const Self, comptime Backend: type, relations: *const Relations, destination: [][]M31, pool: ?*work_pool.WorkPool) !ClaimsV1 {
        var timer = try profileTimer();
        try self.preflight(2, destination);
        const data = self.storage();
        if (!data.main_generated) return error.DetachedParentMainNotGenerated;
        try relations.validate();
        for (destination) |column| @memset(column, M31.zero());
        errdefer for (destination) |column| @memset(column, M31.zero());
        var result = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = undefined };
        const capable = comptime Backend != void and @hasDecl(Backend, "supportsFrameworkInteractions");
        const device = if (capable) try Backend.supportsFrameworkInteractions() else false;
        const preflight_ns = profileLap(&timer);
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            const row = @intFromEnum(entry.row);
            const placement = data.manifest.placements[row].?;
            const Framework = air.framework_interaction.Runtime(air.universal_relation_binding.Binding(entry.Air).Runtime);
            result.values[row] = generated: {
                if (comptime capable) {
                    if (device) break :generated try device_interaction.generateInto(Backend, entry.Air, data.allocator, data.components.?.directPlan(index), data.components.?.relationPlan(index), data.rows[index], &data.parameters.forRow(entry), placement.geometry.log_size, relations, destination[placement.interaction_offset..][0..entry.Air.INTERACTION_COLUMN_COUNT]);
                }
                var interaction = try Framework.generatePrepared(data.allocator, data.components.?.relationPlan(index), data.rows[index], placement.geometry.log_size, relations);
                defer interaction.deinit(data.allocator);
                for (interaction.columns, 0..) |column, local| @memcpy(destination[placement.interaction_offset + local], column);
                break :generated interaction.claimed_sum;
            };
        }
        const typed_ns = profileLap(&timer);
        const providers = try provider.SharedProviderRelations.init(relations);
        const poseidon = data.manifest.placements[34].?;
        var interaction = try generatePoseidonInteraction(data.allocator, data.calls, data.outputs, poseidon.geometry.log_size, &providers.native, pool);
        defer interaction.deinit(data.allocator);
        for (interaction.columns, 0..) |column, local| @memcpy(destination[poseidon.interaction_offset + local], column);
        result.poseidon_partials = interaction.claims.sums;
        result.values[34] = interaction.claims.total();
        const poseidon_ns = profileLap(&timer);
        var range_interaction = try data.range_batch.?.generateNativeInteraction(data.allocator, &providers.native);
        defer range_interaction.deinit(data.allocator);
        const range_placement = data.manifest.placements[35].?;
        for (range_interaction.columns, 0..) |column, local| @memcpy(destination[range_placement.interaction_offset + local], column);
        result.values[35] = range_interaction.claim;
        _ = try result.vector(&data.manifest);
        const range_ns = profileLap(&timer);
        if (timer != null) std.debug.print("PARENT_INTERACTION_FILL preflight_ns={d} typed_ns={d} poseidon_ns={d} range_ns={d}\n", .{ preflight_ns, typed_ns, poseidon_ns, range_ns });
        return result;
    }
};

// Compare distances instead of adding byte lengths to addresses, so the check
// cannot wrap at the end of the address space. Empty slices never overlap.
fn overlapBytes(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const lhs = @intFromPtr(left.ptr);
    const rhs = @intFromPtr(right.ptr);
    return if (lhs <= rhs) rhs - lhs < left.len else lhs - rhs < right.len;
}

fn traceLogSize(count: usize) !u32 {
    if (count > @as(usize, 1) << 28) return error.DetachedParentTraceTooLarge;
    return @max(4, std.math.log2_int_ceil(usize, @max(count, 1)));
}

pub fn testSnapshotAdmission() !*PreparedV1 {
    if (!@import("builtin").is_test) @compileError("test-only fixture");
    const allocator = std.testing.allocator;
    const SourceRows = comptime blk: {
        var types: [LOGICAL_ROWS.len]type = undefined;
        for (LOGICAL_ROWS, 0..) |entry, index| types[index] = [1][entry.Air.LOGICAL_INPUT_COUNT]M31;
        break :blk std.meta.Tuple(&types);
    };
    var source_rows: SourceRows = undefined;
    var rows: LogicalRowsV1 = undefined;
    inline for (0..LOGICAL_ROWS.len) |index| {
        source_rows[index][0] = @splat(M31.zero());
        rows[index] = &source_rows[index];
    }
    const prepared = try PreparedV1.init(allocator, rows, &.{});
    errdefer prepared.deinit();
    try prepared.parameters().validate(prepared.manifest());
    // Canonical admission roundtrips exactly; independently resealed retired identity fails.
    const compact_identity = @import("../air/memory_commitment/poseidon2_universal_identity_v2.zig");
    try std.testing.expectEqualSlices(u8, &compact_identity.CANONICAL_DIGEST, &prepared.manifest().placements[34].?.geometry.semantic_digest);
    var legacy_builder = manifest_mod.Builder{};
    for (prepared.manifest().roster_rows[0..prepared.manifest().roster_count]) |row| {
        var geometry = prepared.manifest().placements[row].?.geometry;
        if (row == 34) geometry.semantic_digest = compact_identity.LEGACY_SOURCE_DIGEST;
        _ = try legacy_builder.append(geometry);
    }
    const retained_manifest = try legacy_builder.seal();
    try std.testing.expectError(error.DetachedParentManifestMismatch, PreparedV1.initForManifest(allocator, rows, &.{}, &retained_manifest));
    const retained = try PreparedV1.initForManifest(allocator, rows, &.{}, prepared.manifest());
    defer retained.deinit();
    try std.testing.expectEqualSlices(u8, &prepared.manifest().seal, &retained.manifest().seal);
    var changed_builder = manifest_mod.Builder{};
    for (prepared.manifest().roster_rows[0..prepared.manifest().roster_count]) |row| {
        var geometry = prepared.manifest().placements[row].?.geometry;
        if (row == 11) geometry.log_size += 1;
        _ = try changed_builder.append(geometry);
    }
    const wrong_geometry = try changed_builder.seal();
    try std.testing.expectError(error.DetachedParentManifestMismatch, PreparedV1.initForManifest(allocator, rows, &.{}, &wrong_geometry));
    source_rows[logicalIndex(11)][0][0] = M31.one();
    try std.testing.expect(prepared.storage().rows[logicalIndex(11)][0][0].isZero());
    try std.testing.expectError(error.DetachedParentConstraintViolation, PreparedV1.init(allocator, rows, &.{}));
    var claims = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    _ = try claims.vector(prepared.manifest());
    claims.values[15] = QM31.one();
    try std.testing.expectError(error.DetachedParentInactiveClaim, claims.vector(prepared.manifest()));
    claims.values[15] = QM31.zero();
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.DetachedParentProviderClaimMismatch, claims.vector(prepared.manifest()));
    var changed_manifest = prepared.manifest().*;
    changed_manifest.placements[11].?.geometry.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.ManifestSealMismatch, prepared.parameters().validate(&changed_manifest));
    return prepared;
}

pub fn testPoseidonInteractionPolicy() !void {
    if (!@import("builtin").is_test) @compileError("test-only oracle");
    const allocator = std.testing.allocator;
    const native = native_poseidon;
    var relations = native_relations.Relations.dummy();
    const calls = try allocator.alloc(ProviderCall, 4101);
    defer allocator.free(calls);
    const outputs = try allocator.alloc([16]u32, calls.len);
    defer allocator.free(outputs);
    for (calls, outputs, 0..) |*call, *output, row| {
        call.* = .{ .input = undefined, .io = true };
        for (&call.input, 0..) |*word, lane| word.* = @intCast(row * 31 + lane * 7);
        for (native.output(native.fill(call.*)), output) |value, *word| word.* = value.toU32();
    }
    // An absent pool keeps the serial fallback available even above threshold.
    {
        var serial = try native.generateIoInteractionFromOutputs(allocator, calls[0..7], outputs[0..7], 12, &relations);
        defer serial.deinit(allocator);
        var actual = try generatePoseidonInteraction(allocator, calls[0..7], outputs[0..7], 12, &relations, null);
        defer actual.deinit(allocator);
        try std.testing.expectEqualDeep(serial.claims, actual.claims);
        for (serial.columns, actual.columns) |expected, column| try std.testing.expectEqualSlices(M31, expected, column);
    }
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    // Below threshold, at threshold with padding, and across the 4096-row
    // inversion chunk boundary. Every call has a distinct input/output tuple.
    for ([_]struct { log: u32, active: usize }{
        .{ .log = 11, .active = 7 },
        .{ .log = 12, .active = 4093 },
        .{ .log = 13, .active = 4101 },
    }) |case| {
        var serial = try native.generateIoInteractionFromOutputs(allocator, calls[0..case.active], outputs[0..case.active], case.log, &relations);
        defer serial.deinit(allocator);
        var actual = try generatePoseidonInteraction(allocator, calls[0..case.active], outputs[0..case.active], case.log, &relations, &pool);
        defer actual.deinit(allocator);
        try std.testing.expectEqualDeep(serial.claims, actual.claims);
        for (serial.columns, actual.columns) |expected, column| try std.testing.expectEqualSlices(M31, expected, column);
    }
    // alpha=0 retains alpha^0=1; row0 input0=0 makes this a genuine pole.
    relations.poseidon2_io = @TypeOf(relations.poseidon2_io).init(QM31.zero(), QM31.zero());
    try std.testing.expectError(error.ZeroDenominator, native.generateIoInteractionFromOutputs(allocator, calls[0..1], outputs[0..1], 12, &relations));
    try std.testing.expectError(error.ZeroDenominator, generatePoseidonInteraction(allocator, calls[0..1], outputs[0..1], 12, &relations, &pool));
}
