//! One active typed catalog for the detached two-child development parent.
//! Producer and fresh verifier instantiate these same adapters. No native
//! capture, generated-claim receipt, or mutable source participates in admission.
const std = @import("std");
const core = @import("stwo_core");
const air = struct {
    const detached_parent_catalog_v1 = @import("air/detached_parent_catalog_v1.zig");
    const qm31_mul_full = @import("air/qm31_mul_full.zig");
    const range_check_8_8_bridge = @import("air/range_check_8_8_bridge.zig");
    const universal_adapter_manifest = @import("air/universal_adapter_manifest.zig");
    const universal_catalog = @import("air/universal_catalog_entry.zig");
    const universal_challenges = @import("air/universal_challenges.zig");
    const universal_relation_binding = @import("air/universal_relation_binding.zig");
    const universal_shared_provider = @import("air/universal_shared_provider.zig");
    const universal_typed_component = @import("air/universal_typed_component.zig");
};
pub const manifest_mod = air.universal_adapter_manifest;
const provider = air.universal_shared_provider;
const PoseidonAdapter = provider.Poseidon2Degree3AdapterWithCompatibility(manifest_mod, .allow_reviewed_legacy);
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Relations = air.universal_challenges.UniversalRelations;

pub const LOGICAL_ROWS = air.detached_parent_catalog_v1.LOGICAL_ROWS;

pub fn Component(comptime entry: air.universal_catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    return air.universal_typed_component.Component(entry.Air, air.universal_relation_binding.Binding(entry.Air));
}

const contract = @import("detached_parent_contract_v1.zig");
const legacy_mul_entry = contract.legacy_mul_entry;
const usesLegacyMul = contract.usesLegacyMul;
const usesLegacyPoseidon = contract.usesLegacyPoseidon;
pub const ParametersV1 = contract.ParametersV1;
pub const ClaimsV1 = contract.ClaimsV1;

const definitions_mod = @import("detached_parent_definitions_v1.zig");

fn ComponentTuple() type {
    var types: [LOGICAL_ROWS.len]type = undefined;
    for (LOGICAL_ROWS, 0..) |entry, index| types[index] = Component(entry);
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
        definitions: definitions_mod.Definitions,
        logical: ComponentTuple(),
        legacy_mul: Component(legacy_mul_entry),
        range_executor: range.Executor,
        poseidon: PoseidonAdapter,
        legacy_poseidon: provider.Poseidon2Adapter,
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
            .definitions = definitions_mod.Definitions.init(allocator),
            .logical = undefined,
            .legacy_mul = undefined,
            .range_executor = undefined,
            .poseidon = undefined,
            .legacy_poseidon = undefined,
            .range_component = undefined,
            .gate = gate,
        };
        const self: *Self = @ptrCast(storage);
        errdefer self.deinit();
        storage.providers = try provider.SharedProviderRelations.init(&storage.relations);
        inline for (LOGICAL_ROWS, 0..) |entry, index| try initLogical(storage, entry, index, parameters, claims);
        if (usesLegacyPoseidon(manifest)) {
            storage.legacy_poseidon = try provider.Poseidon2Adapter.init(&storage.manifest, storage.manifest.placements[34].?.geometry.log_size, parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
            try storage.gate.append(&storage.manifest, try storage.legacy_poseidon.binding(&storage.manifest));
        } else {
            storage.poseidon = try PoseidonAdapter.initWithAllocator(allocator, &storage.manifest, storage.manifest.placements[34].?.geometry.log_size, parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
            try storage.gate.append(&storage.manifest, try storage.poseidon.binding(&storage.manifest));
        }
        try storage.definitions.initRange();
        storage.range_executor = try range.Executor.init(&storage.definitions.range_definition, &try range.Binding.canonical(&storage.definitions.range_definition));
        storage.range_component = try provider.RangeCheck8x8Adapter.init(&storage.definitions.range_definition, &storage.range_executor, &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
        try storage.gate.append(&storage.manifest, try storage.range_component.binding(&storage.manifest));
        try storage.gate.sealGate(&storage.manifest);
        return self;
    }

    fn initLogical(storage: *Storage, comptime entry: air.universal_catalog.Entry, comptime index: usize, parameters: ParametersV1, claims: ClaimsV1) !void {
        const manifest = &storage.manifest;
        const row = @intFromEnum(entry.row);
        if (comptime row == 14) {
            if (manifest.placements[row] == null) {
                return;
            }
        }
        if (comptime row == 30) {
            if (usesLegacyMul(manifest)) {
                try storage.definitions.initLegacyMul();
                const relation = try air.universal_relation_binding.Binding(air.qm31_mul_full).authenticate(&storage.definitions.legacy_mul_definition);
                storage.legacy_mul = try Component(legacy_mul_entry).init(&storage.definitions.legacy_mul_definition, relation, &storage.manifest, .qm31_mul, storage.manifest.placements[30].?.geometry.log_size, parameters.forRow(legacy_mul_entry), &storage.relations, claims.values[30]);
                try storage.gate.append(&storage.manifest, try storage.legacy_mul.binding(&storage.manifest));
                return;
            }
        }
        try storage.definitions.initLogical(index);
        const relation = try air.universal_relation_binding.Binding(entry.Air).authenticate(&storage.definitions.logical[index]);
        storage.logical[index] = try Component(entry).init(&storage.definitions.logical[index], relation, &storage.manifest, entry.row, storage.manifest.placements[row].?.geometry.log_size, parameters.forRow(entry), &storage.relations, claims.values[row]);
        try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
    }

    pub fn deinit(self: *Self) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        storage.definitions.deinit();
        storage.allocator.destroy(storage);
    }

    // Internal consumers borrow admitted plans without repeating construction
    // or validation. Storage and its ownership flags remain private.
    pub fn directPlan(self: *const Self, comptime index: usize) *const @FieldType(Component(LOGICAL_ROWS[index]), "direct") {
        const data: *const Storage = @ptrCast(@alignCast(self));
        return &data.logical[index].direct;
    }

    pub fn relationPlan(self: *const Self, comptime index: usize) *const @FieldType(Component(LOGICAL_ROWS[index]), "relation_plan") {
        const data: *const Storage = @ptrCast(@alignCast(self));
        return &data.logical[index].relation_plan;
    }

    pub fn rangeExecutor(self: *const Self) *const range.Executor {
        const data: *const Storage = @ptrCast(@alignCast(self));
        return &data.range_executor;
    }

    pub fn rangeDefinition(self: *const Self) *const range.Definition {
        const data: *const Storage = @ptrCast(@alignCast(self));
        return &data.definitions.range_definition;
    }

    pub fn verifierComponents(self: *const Self) ![]const core.air.components.Component {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return storage.gate.verifierSlice();
    }

    pub fn recordCompositionV3(self: *const Self, program: anytype) anyerror!@typeInfo(@TypeOf(program.finishProgram())).error_union.payload {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        inline for (LOGICAL_ROWS, 0..) |entry, index| {
            if (storage.manifest.placements[@intFromEnum(entry.row)] != null) {
                if (@intFromEnum(entry.row) == 30 and storage.definitions.legacy_mul_initialized) {
                    _ = try program.recordTypedComponent(entry.row, &storage.legacy_mul);
                } else {
                    _ = try program.recordTypedComponent(entry.row, &storage.logical[index]);
                }
            }
        }
        if (usesLegacyPoseidon(&storage.manifest)) {
            _ = try program.recordPoseidonProvider(&storage.legacy_poseidon);
        } else {
            _ = try program.recordPoseidonProvider(&storage.poseidon);
        }
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

pub const canonicalBase = contract.canonicalBase;

pub fn logicalIndex(comptime row: usize) comptime_int {
    inline for (LOGICAL_ROWS, 0..) |entry, index| if (@intFromEnum(entry.row) == row) return index;
    @compileError("row is not active in the detached parent");
}
pub const LogicalRowsV1 = blk: {
    var types: [LOGICAL_ROWS.len]type = undefined;
    for (LOGICAL_ROWS, 0..) |entry, index| types[index] = []const [entry.Air.LOGICAL_INPUT_COUNT]M31;
    break :blk std.meta.Tuple(&types);
};
