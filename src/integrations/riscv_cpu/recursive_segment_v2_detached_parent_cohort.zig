//! One active typed catalog for the detached two-child development parent.
//! Producer and fresh verifier instantiate these same adapters. No native
//! capture, generated-claim receipt, or mutable source participates in admission.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
pub const manifest_mod = air.universal_adapter_manifest;
const provider = air.universal_shared_provider;
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Relations = air.universal_challenges.UniversalRelations;

pub const LOGICAL_ROWS = rows: {
    var result: [28]air.universal_catalog.Entry = undefined;
    var count: usize = 0;
    for (air.universal_catalog.LOGICAL_ROWS, 0..) |entry, index| {
        if (index >= 14 and index < 20) continue;
        result[count] = .{
            .Air = switch (index) {
                10 => air.field_statement_word_v3,
                11 => air.detached_graph_input_v1,
                12 => air.detached_poseidon_graph_v1,
                13 => air.fixed_wire_v3,
                else => entry.Air,
            },
            .row = entry.row,
            .requires_location = entry.requires_location,
        };
        count += 1;
    }
    if (count != result.len) @compileError("detached parent active catalog drift");
    break :rows result;
};

pub fn Component(comptime entry: air.universal_catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    return air.universal_typed_component.Component(entry.Air, air.universal_relation_binding.Binding(entry.Air));
}

pub const ParametersV1 = struct {
    words: [manifest_mod.COMPONENT_COUNT][]const M31,
    poseidon_active_rows: u32,

    pub fn validate(self: ParametersV1, manifest: *const manifest_mod.Manifest) !void {
        try manifest.validate();
        if (manifest.roster_count != LOGICAL_ROWS.len + 2) return error.DetachedParentManifestMismatch;
        inline for (LOGICAL_ROWS) |entry| {
            const row = @intFromEnum(entry.row);
            const placement = manifest.placements[row] orelse return error.DetachedParentManifestMismatch;
            if (!std.meta.eql(placement.geometry, Component(entry).manifestGeometry(entry.row, placement.geometry.log_size)) or
                self.words[row].len != Component(entry).PARAMETER_COLUMN_COUNT)
                return error.DetachedParentManifestMismatch;
            for (self.words[row]) |word| try canonicalBase(word);
        }
        for (14..20) |row| if (manifest.placements[row] != null or self.words[row].len != 0)
            return error.DetachedParentManifestMismatch;
        const poseidon = manifest.placements[34] orelse return error.DetachedParentManifestMismatch;
        const range_placement = manifest.placements[35] orelse return error.DetachedParentManifestMismatch;
        if (!std.meta.eql(poseidon.geometry, provider.Poseidon2Adapter.manifestGeometry(poseidon.geometry.log_size)) or
            !std.meta.eql(range_placement.geometry, provider.RangeCheck8x8Adapter.manifestGeometry()) or
            self.words[34].len != 0 or self.words[35].len != 0 or
            self.poseidon_active_rows > (@as(u64, 1) << @intCast(poseidon.geometry.log_size)))
            return error.DetachedParentManifestMismatch;
    }

    pub fn forRow(self: ParametersV1, comptime entry: air.universal_catalog.Entry) [Component(entry).PARAMETER_COLUMN_COUNT]M31 {
        return self.words[@intFromEnum(entry.row)][0..Component(entry).PARAMETER_COLUMN_COUNT].*;
    }
};

pub const ClaimsV1 = struct {
    values: [manifest_mod.COMPONENT_COUNT]QM31,
    poseidon_partials: [2]QM31,

    pub fn vector(self: ClaimsV1, manifest: *const manifest_mod.Manifest) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        for (self.values, 0..) |value, row| {
            for (value.toM31Array()) |word| try canonicalBase(word);
            if (manifest.placements[row] != null) try result.bind(@enumFromInt(row), value) else if (!value.isZero())
                return error.DetachedParentInactiveClaim;
        }
        for (self.poseidon_partials) |partial| for (partial.toM31Array()) |word| try canonicalBase(word);
        if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[34]))
            return error.DetachedParentProviderClaimMismatch;
        try result.sealClaims(manifest);
        return result;
    }
};

fn Tuple(comptime definitions: bool) type {
    var types: [LOGICAL_ROWS.len]type = undefined;
    for (LOGICAL_ROWS, 0..) |entry, index| types[index] = if (definitions) entry.Air.Definition else Component(entry);
    return std.meta.Tuple(&types);
}

/// All adapter pointers target this immutable heap owner. Parameters are copied
/// into adapters at admission; this owner never borrows key slice storage.
pub const OwnedComponentsV1 = opaque {
    const Self = @This();
    const Storage = struct {
        allocator: std.mem.Allocator,
        manifest: manifest_mod.Manifest,
        relations: Relations,
        providers: provider.SharedProviderRelations,
        definitions: Tuple(true),
        initialized: usize = 0,
        logical: Tuple(false),
        range_definition: range.Definition,
        range_initialized: bool = false,
        range_executor: range.Executor,
        poseidon: provider.Poseidon2Adapter,
        range_component: provider.RangeCheck8x8Adapter,
        gate: manifest_mod.ProofGate,
    };

    pub fn init(allocator: std.mem.Allocator, manifest: *const manifest_mod.Manifest, parameters: ParametersV1, relations: *const Relations, claims: ClaimsV1) !*Self {
        try parameters.validate(manifest);
        _ = try claims.vector(manifest);
        try relations.validate();
        const gate = try manifest_mod.ProofGate.init(manifest);
        const storage = try allocator.create(Storage);
        storage.* = .{
            .allocator = allocator,
            .manifest = manifest.*,
            .relations = relations.*,
            .providers = undefined,
            .definitions = undefined,
            .logical = undefined,
            .range_definition = undefined,
            .range_executor = undefined,
            .poseidon = undefined,
            .range_component = undefined,
            .gate = gate,
        };
        const self: *Self = @ptrCast(storage);
        errdefer self.deinit();
        storage.providers = try provider.SharedProviderRelations.init(&storage.relations);
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            const row = @intFromEnum(entry.row);
            storage.definitions[index] = if (entry.requires_location) try entry.Air.build(allocator, .generated) else try entry.Air.build(allocator);
            storage.initialized += 1;
            const relation = try air.universal_relation_binding.Binding(entry.Air).authenticate(&storage.definitions[index]);
            storage.logical[index] = try Component(entry).init(&storage.definitions[index], relation, &storage.manifest, entry.row, storage.manifest.placements[row].?.geometry.log_size, parameters.forRow(entry), &storage.relations, claims.values[row]);
            try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
        }
        storage.poseidon = try provider.Poseidon2Adapter.init(&storage.manifest, storage.manifest.placements[34].?.geometry.log_size, parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
        try storage.gate.append(&storage.manifest, try storage.poseidon.binding(&storage.manifest));
        storage.range_definition = try range.build(allocator);
        storage.range_initialized = true;
        storage.range_executor = try range.Executor.init(&storage.range_definition, &try range.Binding.canonical(&storage.range_definition));
        storage.range_component = try provider.RangeCheck8x8Adapter.init(&storage.range_definition, &storage.range_executor, &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
        try storage.gate.append(&storage.manifest, try storage.range_component.binding(&storage.manifest));
        try storage.gate.sealGate(&storage.manifest);
        return self;
    }

    pub fn deinit(self: *Self) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        inline for (0..LOGICAL_ROWS.len) |index| if (index < storage.initialized) storage.definitions[index].deinit();
        if (storage.range_initialized) storage.range_definition.deinit();
        storage.allocator.destroy(storage);
    }

    pub fn verifierComponents(self: *const Self) ![]const core.air.components.Component {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return storage.gate.verifierSlice();
    }

    pub fn recordCompositionV3(self: *const Self, program: anytype) !frontend.recursion.recursion_air_composition_circuit_v3.segment_recorder_v3.ProgramResultV3 {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        inline for (LOGICAL_ROWS, 0..) |entry, index|
            _ = try program.recordTypedComponent(entry.row, &storage.logical[index]);
        _ = try program.recordPoseidonProvider(&storage.poseidon);
        _ = try program.recordRangeCheck8x8Provider(&storage.range_component);
        return program.finishProgram();
    }

    pub fn appendToGate(self: *const Self, manifest: *const manifest_mod.Manifest, gate: *manifest_mod.ProofGate) !void {
        if (gate.count != 0 or gate.sealed) return error.DetachedParentManifestMismatch;
        const storage: *const Storage = @ptrCast(@alignCast(self));
        try storage.gate.validate(manifest);
        gate.* = storage.gate;
    }
};

fn canonicalBase(value: M31) !void {
    if (value.toU32() >= core.fields.m31.Modulus) return error.DetachedParentNonCanonicalField;
}

pub fn logicalIndex(comptime row: usize) comptime_int {
    inline for (LOGICAL_ROWS, 0..) |entry, index| if (@intFromEnum(entry.row) == row) return index;
    @compileError("row is not active in the detached parent");
}
pub const LogicalRowsV1 = blk: {
    var types: [LOGICAL_ROWS.len]type = undefined;
    for (LOGICAL_ROWS, 0..) |entry, index| types[index] = []const [entry.Air.LOGICAL_INPUT_COUNT]M31;
    break :blk std.meta.Tuple(&types);
};
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
pub const ProviderCall = poseidon_air.Call;

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
        _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(try traceLogSize(calls.len)));
        _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
        data.manifest = try builder.seal();
        const dummy_relations = Relations.dummy();
        const zero_claims = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
        data.components = try OwnedComponentsV1.init(allocator, &data.manifest, data.parameters, &dummy_relations, zero_claims);
        const admitted: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(data.components.?));
        var counter = try frontend.air.lookups.tables.counter.Counter.init(allocator, .range_check_8_8);
        defer counter.deinit(allocator);
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            var scratch: [air.direct_constraint_program.MAX_NODES]M31 = undefined;
            var roots: [entry.Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
            for (data.rows[index]) |row| {
                try admitted.logical[index].direct.evaluateBaseInto(&row, &scratch, &roots);
                for (roots) |root| if (!root.isZero()) return error.DetachedParentConstraintViolation;
                for (admitted.logical[index].relation_plan.preparedEntries(row)) |event| if (event.domain == .range_check_8_8)
                    try counter.registerRaw(event.numerator, event.values[0..event.arity]);
            }
        }
        data.range_batch = try range.PreparedBatch.init(allocator, &counter);
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
                overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(data.outputs)) or
                overlapBytes(std.mem.sliceAsBytes(column), std.mem.sliceAsBytes(data.range_batch.?.counter.values))) return error.DestinationAlias;
        }
    }
    fn fillLogical(self: *const Self, tree: usize, destination: [][]M31) void {
        const data = self.storage();
        for (destination) |column| @memset(column, M31.zero());
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            const placement = data.manifest.placements[@intFromEnum(entry.row)].?;
            const count = if (tree == 0) entry.Air.PREPROCESSED_COLUMN_COUNT else entry.Air.PHYSICAL_MAIN_COLUMN_COUNT;
            const source_start = if (tree == 0) entry.Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
            const offset = if (tree == 0) placement.preprocessed_offset else placement.main_offset;
            for (data.rows[index], 0..) |row, logical| {
                const physical = air.framework_interaction.committedRow(logical, placement.geometry.log_size);
                for (0..count) |column| destination[offset + column][physical] = row[source_start + column];
            }
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
    pub fn fillMainInto(self: *Self, destination: [][]M31) !void {
        try self.preflight(1, destination);
        const data: *Storage = @ptrCast(@alignCast(self));
        data.main_generated = false;
        self.fillLogical(1, destination);
        errdefer for (destination) |column| @memset(column, M31.zero());
        const placement = data.manifest.placements[34].?;
        var columns = destination[placement.main_offset..][0..poseidon_air.N_MAIN_COLUMNS].*;
        try poseidon_air.generateMainInto(data.allocator, &columns, data.calls, placement.geometry.log_size);
        for (data.outputs, 0..) |*output, logical| {
            const row = air.framework_interaction.committedRow(logical, placement.geometry.log_size);
            for (output, 0..) |*word, column| word.* = columns[provider.POSEIDON_OUTPUT_COLUMN_START + column][row].toU32();
        }
        const range_placement = data.manifest.placements[35].?;
        var range_columns = destination[range_placement.main_offset..][0..range.PHYSICAL_MAIN_COLUMN_COUNT].*;
        const admitted: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(data.components.?));
        try admitted.range_executor.generateMainInto(&data.range_batch.?, &range_columns);
        data.main_generated = true;
    }
    /// Challenge-independent diagnostic over exact typed/native relation entries.
    /// This never supplies a residual to the proof; a nonzero tuple aborts before
    /// PCS/FRI. Native provider entries are read from the generated main columns.
    pub fn auditExactTupleClosure(self: *const Self, expected: *const @import("recursive_segment_v2_detached_parent_protocol.zig").ExpectedV1, main_columns: [][]M31) !air.relation_interaction.TupleClosureReport {
        const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
        try protocol.validateExpected(expected);
        try self.preflight(1, main_columns);
        const data = self.storage();
        if (!data.main_generated) return error.DetachedParentMainNotGenerated;
        try data.range_batch.?.validate();
        const range_placement = data.manifest.placements[35].?;
        for (data.range_batch.?.counter.values, 0..) |expected_multiplicity, logical| {
            const actual = main_columns[range_placement.main_offset][range.committedRow(logical)];
            if (!actual.eql(expected_multiplicity)) return error.DetachedParentRangeMainChanged;
        }
        const admitted: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(data.components.?));
        var compact = try @import("recursive_compact_tuple_ledger_v1.zig").Owner.init(data.allocator, false);
        defer compact.deinit();
        var ledger = compact.ledger();
        defer ledger.deinit();
        inline for (LOGICAL_ROWS, 0..) |entry, index| try admitted.logical[index].relation_plan.appendPreparedTupleContributions(&ledger, @intFromEnum(entry.row), data.rows[index], air.relation_interaction.allDomainMask());
        const placement = data.manifest.placements[34].?;
        for (data.calls, data.outputs, 0..) |call, output, logical| {
            const physical = air.framework_interaction.committedRow(logical, placement.geometry.log_size);
            var main: [poseidon_air.N_MAIN_COLUMNS]QM31 = undefined;
            for (&main, 0..) |*word, column| word.* = QM31.fromBase(main_columns[placement.main_offset + column][physical]);
            for (call.input, 0..) |word, column| if (!main[1 + column].eql(QM31.fromU32Unchecked(word, 0, 0, 0))) return error.DetachedParentProviderMainChanged;
            for (output, 0..) |word, column| if (!main[provider.POSEIDON_OUTPUT_COLUMN_START + column].eql(QM31.fromU32Unchecked(word, 0, 0, 0))) return error.DetachedParentProviderMainChanged;
            const entries = poseidon_air.entries(main);
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
        const range_plan = try range.authenticateRelation(&admitted.range_definition);
        for (0..range.TABLE_SIZE) |row| for (range_plan.preparedEntries(data.range_batch.?.preparedRelationRow(row))) |event|
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
    pub fn fillInteractionInto(self: *const Self, relations: *const Relations, destination: [][]M31) !ClaimsV1 {
        try self.preflight(2, destination);
        const data = self.storage();
        if (!data.main_generated) return error.DetachedParentMainNotGenerated;
        try relations.validate();
        for (destination) |column| @memset(column, M31.zero());
        errdefer for (destination) |column| @memset(column, M31.zero());
        const admitted: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(data.components.?));
        var result = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = undefined };
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            const row = @intFromEnum(entry.row);
            const placement = data.manifest.placements[row].?;
            const Framework = air.framework_interaction.Runtime(air.universal_relation_binding.Binding(entry.Air).Runtime);
            var interaction = try Framework.generatePrepared(data.allocator, &admitted.logical[index].relation_plan, data.rows[index], placement.geometry.log_size, relations);
            defer interaction.deinit(data.allocator);
            for (interaction.columns, 0..) |column, local| @memcpy(destination[placement.interaction_offset + local], column);
            result.values[row] = interaction.claimed_sum;
        }
        const providers = try provider.SharedProviderRelations.init(relations);
        const poseidon = data.manifest.placements[34].?;
        var interaction = try poseidon_air.generateIoInteractionFromOutputs(data.allocator, data.calls, data.outputs, poseidon.geometry.log_size, &providers.native);
        defer interaction.deinit(data.allocator);
        for (interaction.columns, 0..) |column, local| @memcpy(destination[poseidon.interaction_offset + local], column);
        result.poseidon_partials = interaction.claims.sums;
        result.values[34] = interaction.claims.total();
        var range_interaction = try data.range_batch.?.generateNativeInteraction(data.allocator, &providers.native);
        defer range_interaction.deinit(data.allocator);
        const range_placement = data.manifest.placements[35].?;
        for (range_interaction.columns, 0..) |column, local| @memcpy(destination[range_placement.interaction_offset + local], column);
        result.values[35] = range_interaction.claim;
        _ = try result.vector(&data.manifest);
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

test "detached parent snapshots typed rows and rejects mutable ingress and inactive claims" {
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
    defer prepared.deinit();
    try prepared.parameters().validate(prepared.manifest());
    source_rows[logicalIndex(11)][0][0] = M31.one();
    try std.testing.expect(prepared.storage().rows[logicalIndex(11)][0][0].isZero());
    try std.testing.expectError(error.DetachedParentConstraintViolation, PreparedV1.init(allocator, rows, &.{}));
    var claims = ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    _ = try claims.vector(prepared.manifest());
    claims.values[14] = QM31.one();
    try std.testing.expectError(error.DetachedParentInactiveClaim, claims.vector(prepared.manifest()));
    claims.values[14] = QM31.zero();
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.DetachedParentProviderClaimMismatch, claims.vector(prepared.manifest()));
    var changed_manifest = prepared.manifest().*;
    changed_manifest.placements[11].?.geometry.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.ManifestSealMismatch, prepared.parameters().validate(&changed_manifest));
    const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
    const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
    // Structural fixture only: these nonzero placeholders are not independent
    // key admission. Derive wire-decoder bounds without any witness or proof.
    var key = protocol.KeyV1{ .manifest = prepared.manifest().*, .parameters = prepared.parameters(), .preprocessed_root = @splat(1), .child_key_sha256 = @splat(@splat(1)) };
    const shape = try verifier.proofPreflightShape(allocator, &key);
    try std.testing.expectEqual(prepared.manifest().total_preprocessed_columns, shape.tree_columns[0]);
    try std.testing.expectEqual(prepared.manifest().total_main_columns, shape.tree_columns[1]);
    try std.testing.expectEqual(prepared.manifest().total_interaction_columns, shape.tree_columns[2]);
    key.version += 1;
    try std.testing.expectError(error.DetachedParentProfileMismatch, verifier.proofPreflightShape(allocator, &key));
    key.version = protocol.VERSION;
    key.pcs_config.fri_config.n_queries += 1;
    try std.testing.expectError(error.DetachedParentProfileMismatch, verifier.proofPreflightShape(allocator, &key));
}
