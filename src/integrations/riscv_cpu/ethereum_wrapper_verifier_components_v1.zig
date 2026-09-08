//! Witness-free components for the admitted Ethereum universal-36 circuit.
//! This checks circuit shape; the caller must independently admit the exact
//! preprocessing root, manifest and parameters. Claims are untrusted until
//! the native STARK verifier checks the returned components.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const prefix = @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const suffix = @import("recursive_common_ethereum_incremental_leaf_suffix_components_v4.zig");
const native_parameters = @import("recursive_fri_component_parameters.zig");
const catalog = manifest_mod.StatementRootProfile.StatementRoutingOuterCatalog;
const provider = air.universal_shared_provider;
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Relations = air.universal_challenges.UniversalRelations;
pub const VERSION: u16 = 1;

pub const Ordinary = Types(manifest_mod);
pub const Initial38 = Types(air.ethereum_initial_input_manifest_v1);
pub const AdmissionParametersV1 = Ordinary.AdmissionParametersV1;
pub const ClaimsV1 = Ordinary.ClaimsV1;
pub const OwnedComponentsV1 = Ordinary.OwnedComponentsV1;

pub fn Types(comptime ManifestMod: type) type {
    if (ManifestMod != manifest_mod and ManifestMod != air.ethereum_initial_input_manifest_v1)
        @compileError("Ethereum verifier requires an explicitly selected manifest contract");
    return struct {
        const Selected = @This();
        const Entry = struct { Air: type, row: ManifestMod.ComponentKey, requires_location: bool = false };
        const logical_rows = rows: {
            var result: [ManifestMod.COMPONENT_COUNT - 2]Entry = undefined;
            for (catalog.LOGICAL_ROWS, 0..) |entry, index| result[index] = .{
                .Air = entry.Air,
                .row = @enumFromInt(@intFromEnum(entry.row)),
                .requires_location = entry.requires_location,
            };
            if (ManifestMod == air.ethereum_initial_input_manifest_v1) {
                result[catalog.LOGICAL_COUNT] = .{ .Air = ManifestMod.LaneAir, .row = .ethereum_initial_input_lane };
                result[catalog.LOGICAL_COUNT + 1] = .{ .Air = ManifestMod.PacketAir, .row = .ethereum_initial_input_packet };
            }
            break :rows result;
        };
        pub const AdmissionParametersV1 = struct {
            query_reference: air.query_bits_witness.Reference,
            poseidon_active_rows: u32,

            pub fn validate(self: Selected.AdmissionParametersV1, manifest: *const ManifestMod.Manifest) !ManifestMod.LogSizesV4 {
                var logs: ManifestMod.LogSizesV4 = undefined;
                for (manifest.placements, &logs) |placement, *log| log.* = (placement orelse return error.InvalidEthereumVerifierAdmission).geometry.log_size;
                try ManifestMod.validateExact(manifest, logs);
                try self.query_reference.validate();
                const query_rows = try std.math.add(u64, self.query_reference.vm.query_count, try std.math.mul(u64, 2, self.query_reference.recursion.query_count));
                if (query_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(ManifestMod.ComponentKey.query_bits)])) or
                    self.poseidon_active_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(ManifestMod.ComponentKey.poseidon2)])))
                    return error.InvalidEthereumVerifierAdmission;
                return logs;
            }
        };

        pub const ClaimsV1 = struct {
            values: [ManifestMod.COMPONENT_COUNT]QM31,
            poseidon_partials: [2]QM31,

            pub fn vector(self: Selected.ClaimsV1, manifest: *const ManifestMod.Manifest) !ManifestMod.ClaimVector {
                var result = try ManifestMod.ClaimVector.init(manifest);
                for (self.values, 0..) |value, index| {
                    try canonical(value);
                    try result.bind(@enumFromInt(index), value);
                }
                for (self.poseidon_partials) |partial| try canonical(partial);
                if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[@intFromEnum(ManifestMod.ComponentKey.poseidon2)]))
                    return error.InvalidEthereumVerifierClaims;
                try result.sealClaims(manifest);
                return result;
            }
        };

        fn Component(comptime entry: anytype) type {
            @setEvalBranchQuota(500_000);
            return air.universal_typed_component.ComponentForManifest(entry.Air, air.universal_relation_binding.Binding(entry.Air), ManifestMod);
        }
        fn Tuple(comptime definitions: bool) type {
            var types: [logical_rows.len]type = undefined;
            for (logical_rows, 0..) |entry, index| types[index] = if (definitions) entry.Air.Definition else Component(entry);
            return std.meta.Tuple(&types);
        }

        pub const OwnedComponentsV1 = opaque {
            const Self = @This();
            const Storage = struct {
                allocator: std.mem.Allocator,
                manifest: ManifestMod.Manifest,
                parameters: Selected.AdmissionParametersV1,
                relations: Relations,
                providers: provider.SharedProviderRelations,
                definitions: Tuple(true),
                initialized: usize = 0,
                logical: Tuple(false),
                range_definition: range.Definition,
                range_initialized: bool = false,
                range_executor: range.Executor,
                poseidon: provider.Poseidon2AdapterForManifest(ManifestMod),
                range_component: provider.RangeCheck8x8AdapterForManifest(ManifestMod),
                gate: ManifestMod.ProofGate,
            };

            pub fn init(allocator: std.mem.Allocator, manifest: *const ManifestMod.Manifest, parameters: Selected.AdmissionParametersV1, relations: *const Relations, claims: Selected.ClaimsV1) !*Self {
                const logs = try parameters.validate(manifest);
                _ = try claims.vector(manifest);
                try relations.validate();
                const gate = try ManifestMod.ProofGate.init(manifest);
                const storage = try allocator.create(Storage);
                storage.* = .{
                    .allocator = allocator,
                    .manifest = manifest.*,
                    .parameters = parameters,
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
                inline for (logical_rows, 0..) |entry, index| {
                    storage.definitions[index] = if (entry.requires_location) try entry.Air.build(allocator, .generated) else try entry.Air.build(allocator);
                    storage.initialized += 1;
                    const relation = try air.universal_relation_binding.Binding(entry.Air).authenticate(&storage.definitions[index]);
                    storage.logical[index] = try Component(entry).init(&storage.definitions[index], relation, &storage.manifest, @enumFromInt(@intFromEnum(entry.row)), logs[@intFromEnum(entry.row)], try parametersFor(entry, parameters), &storage.relations, claims.values[@intFromEnum(entry.row)]);
                    if (comptime index < catalog.LOGICAL_COUNT) try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
                }
                storage.poseidon = try provider.Poseidon2AdapterForManifest(ManifestMod).init(&storage.manifest, logs[34], parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
                try storage.gate.append(&storage.manifest, try storage.poseidon.binding(&storage.manifest));
                storage.range_definition = try range.build(allocator);
                storage.range_initialized = true;
                storage.range_executor = try range.Executor.init(&storage.range_definition, &try range.Binding.canonical(&storage.range_definition));
                storage.range_component = try provider.RangeCheck8x8AdapterForManifest(ManifestMod).init(&storage.range_definition, &storage.range_executor, &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
                try storage.gate.append(&storage.manifest, try storage.range_component.binding(&storage.manifest));
                inline for (catalog.LOGICAL_COUNT..logical_rows.len) |index|
                    try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
                try @import("ethereum_wrapper_composition_v1.zig").admitGate(&storage.manifest, &storage.gate);
                try storage.gate.sealGate(&storage.manifest);
                return self;
            }

            pub fn deinit(self: *Self) void {
                const storage: *Storage = @ptrCast(@alignCast(self));
                inline for (0..logical_rows.len) |index| if (index < storage.initialized) storage.definitions[index].deinit();
                if (storage.range_initialized) storage.range_definition.deinit();
                storage.allocator.destroy(storage);
            }

            /// Every pointer in these adapters targets this immutable heap owner.
            pub fn verifierComponents(self: *const Self) ![]const core.air.components.Component {
                const storage: *const Storage = @ptrCast(@alignCast(self));
                return storage.gate.verifierSlice();
            }

            /// Populate an empty proof gate from this owner's admitted AIRs.
            /// The copied adapters borrow this immutable owner, which must
            /// outlive the gate. The selected manifest remains an explicit input.
            pub fn appendToGate(self: *const Self, manifest: *const ManifestMod.Manifest, gate: *ManifestMod.ProofGate) !void {
                if (gate.count != 0 or gate.sealed) return error.InvalidEthereumVerifierAdmission;
                const storage: *const Storage = @ptrCast(@alignCast(self));
                try storage.gate.validate(manifest);
                gate.* = storage.gate;
            }

            /// Record the same admitted AIR definitions with symbolic samples and
            /// challenges. No witness columns or observed claim becomes a constant.
            pub fn recordComponents(self: *const Self, program: anytype) @TypeOf(program.finishProgram()) {
                const storage: *const Storage = @ptrCast(@alignCast(self));
                inline for (logical_rows[0..catalog.LOGICAL_COUNT], 0..) |entry, index|
                    _ = try program.recordTypedComponent(@as(ManifestMod.ComponentKey, @enumFromInt(@intFromEnum(entry.row))), &storage.logical[index]);
                _ = try program.recordPoseidonProvider(&storage.poseidon);
                _ = try program.recordRangeCheck8x8Provider(&storage.range_component);
                inline for (logical_rows[catalog.LOGICAL_COUNT..], catalog.LOGICAL_COUNT..) |entry, index|
                    _ = try program.recordTypedComponent(entry.row, &storage.logical[index]);
                return program.finishProgram();
            }
        };

        fn parametersFor(comptime entry: anytype, admitted: Selected.AdmissionParametersV1) ![Component(entry).PARAMETER_COLUMN_COUNT]M31 {
            const row = @intFromEnum(entry.row);
            if (comptime row >= manifest_mod.COMPONENT_COUNT) return .{};
            if (comptime row < 10) return @field(prefix.ParametersV4.role0(), @tagName(entry.row));
            if (comptime row < 18) {
                const fields = .{ "statement_input", "statement_semantics", "claim_input", "claim_hash", "io_hash", "claim_semantics", "public_logup", "public_logup_control" };
                return @field(suffix.ParametersV4.role0(), fields[row - 10]);
            }
            return switch (entry.row) {
                .vm_air_composition_input => native_parameters.vmInputParameters(.segment_leaf),
                .vm_air_composition_control => air.control_slice_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                .query_bits => try native_parameters.queryBitsParameters(admitted.query_reference, .segment_leaf),
                .query_mapping => native_parameters.queryMappingParameters(.segment_leaf),
                .merkle_root => native_parameters.merkleRootParameters(.segment_leaf),
                .trace_merkle => native_parameters.traceMerkleParameters(.segment_leaf),
                .pcs_deep_input => native_parameters.pcsParameters(.segment_leaf),
                .fri_merkle_leaf => native_parameters.friLeafParameters(.segment_leaf),
                .fri_merkle_node => air.fri_merkle_leaf_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                .fri_merkle_anchor => native_parameters.friAnchorParameters(.segment_leaf),
                .fri_verifier_control => native_parameters.controlParameters(.segment_leaf),
                .fri_verifier_input => native_parameters.inputParameters(.segment_leaf),
                .qm31_mul, .qm31_inv, .linear_ops => air.fri_verifier_input_witness.ProofKind.segment_leaf.selectors(),
                .merkle_path => .{},
                else => unreachable,
            };
        }
        fn canonical(value: QM31) !void {
            for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus) return error.InvalidEthereumVerifierClaims;
        }
    };
}

fn testAdmission() !struct { manifest: manifest_mod.Manifest, parameters: AdmissionParametersV1 } {
    var logs: manifest_mod.LogSizesV4 = @splat(4);
    logs[34] = manifest_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest_mod.RANGE_LOG_SIZE;
    const lane: air.query_bits_witness.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
    return .{ .manifest = try manifest_mod.buildForDerivedLogSizes(logs), .parameters = .{ .query_reference = try air.query_bits_witness.Reference.seal(lane, lane), .poseidon_active_rows = 1 } };
}

test "Ethereum witness-free verifier owns all36 components and survives external mutation" {
    const allocator = std.testing.allocator;
    var admitted = try testAdmission();
    var relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const owner = try OwnedComponentsV1.init(allocator, &admitted.manifest, admitted.parameters, &relations, claims);
    defer owner.deinit();
    const before = try owner.verifierComponents();
    try std.testing.expectEqual(@as(usize, 36), before.len);
    var constraints: usize = 0;
    for (before) |component| {
        constraints += component.nConstraints();
        try std.testing.expectEqual(@as(u8, 2), component.composition_geometry_override_v1.?.composition_log_split);
    }
    try std.testing.expectEqual(@as(usize, manifest_mod.CONSTRAINT_COUNT), constraints);
    admitted.manifest = undefined;
    admitted.parameters = undefined;
    relations = undefined;
    claims = undefined;
    // Rebinding exercises actual adapters against the owner's copied metadata
    // and challenge storage after every external input has been destroyed.
    const storage: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(owner));
    inline for (catalog.LOGICAL_ROWS, 0..) |_, index| _ = try storage.logical[index].binding(&storage.manifest);
    _ = try storage.poseidon.binding(&storage.manifest);
    _ = try storage.range_component.binding(&storage.manifest);
    try std.testing.expectEqual(before.ptr, (try owner.verifierComponents()).ptr);
}

test "Ethereum witness-free verifier rejects malformed admission and provider claims" {
    var admitted = try testAdmission();
    const relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.InvalidEthereumVerifierClaims, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.poseidon_partials[0] = QM31.zero();
    claims.values[0] = QM31.fromM31Array(.{ .{ .v = core.fields.m31.Modulus }, M31.zero(), M31.zero(), M31.zero() });
    try std.testing.expectError(error.InvalidEthereumVerifierClaims, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.values[0] = QM31.zero();
    const saved = admitted.parameters;
    admitted.parameters.poseidon_active_rows = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidEthereumVerifierAdmission, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    admitted.parameters = saved;
    var lane = saved.query_reference.vm;
    lane.query_count = 17;
    admitted.parameters.query_reference = try air.query_bits_witness.Reference.seal(lane, saved.query_reference.recursion);
    try std.testing.expectError(error.InvalidEthereumVerifierAdmission, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
}

test "Ethereum witness-free verifier releases partial AIR construction on allocation failure" {
    const admitted = try testAdmission();
    const relations = Relations.dummy();
    const claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    for ([_]usize{ 0, 1, 5, 20 }) |failure| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = failure });
        try std.testing.expectError(error.OutOfMemory, OwnedComponentsV1.init(failing.allocator(), &admitted.manifest, admitted.parameters, &relations, claims));
    }
}

test "Ethereum initial verifier owns38 typed components in exact claim order" {
    const allocator = std.testing.allocator;
    const ordinary = try testAdmission();
    const selected_manifest = air.ethereum_initial_input_manifest_v1;
    var selected = try selected_manifest.build(&ordinary.manifest, 40);
    const parameters: Initial38.AdmissionParametersV1 = .{ .query_reference = ordinary.parameters.query_reference, .poseidon_active_rows = ordinary.parameters.poseidon_active_rows };
    const relations = Relations.dummy();
    const claims: Initial38.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const owner = try Initial38.OwnedComponentsV1.init(allocator, &selected, parameters, &relations, claims);
    defer owner.deinit();
    const components = try owner.verifierComponents();
    try std.testing.expectEqual(@as(usize, 38), components.len);
    var constraints: usize = 0;
    for (components, selected.roster_rows) |component, row| {
        const geometry = selected.placements[row].?.geometry;
        try std.testing.expectEqual(@as(usize, geometry.direct_constraints) + geometry.interaction_batches, component.nConstraints());
        constraints += component.nConstraints();
        try std.testing.expectEqual(@as(u8, 2), component.composition_geometry_override_v1.?.composition_log_split);
    }
    try std.testing.expectEqual(@as(usize, selected.total_constraints), constraints);
    var gate = try selected_manifest.ProofGate.init(&selected);
    try owner.appendToGate(&selected, &gate);
    try gate.sealGate(&selected);
    try std.testing.expectEqual(@as(usize, 38), (try gate.proverSlice()).len);
    try std.testing.expectEqualDeep(components, try gate.verifierSlice());
    try std.testing.expectError(error.InvalidEthereumVerifierAdmission, owner.appendToGate(&selected, &gate));
    const other = try selected_manifest.build(&ordinary.manifest, 41);
    var other_gate = try selected_manifest.ProofGate.init(&other);
    try std.testing.expectError(error.AdapterCountMismatch, owner.appendToGate(&other, &other_gate));
    const layout = frontend.recursion.recursion_air_composition_circuit_v3.capture_layout_v3;
    const geometry = try layout.ethereumInitialWrapperFixedGeometryV1(&selected, 1);
    try std.testing.expectEqual(@as(u32, 2), geometry.composition_log_split);
    try std.testing.expectError(error.InvalidCompositionGeometry, layout.ethereumWrapperFixedGeometry(&selected, 1));
    try std.testing.expectError(error.InvalidCompositionGeometry, layout.ethereumInitialWrapperFixedGeometryV1(&ordinary.manifest, 1));
    selected.input_capacity += 1;
    try std.testing.expectError(error.ManifestSealMismatch, Initial38.OwnedComponentsV1.init(allocator, &selected, parameters, &relations, claims));
}
