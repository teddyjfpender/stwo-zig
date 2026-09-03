//! Shared placement and component storage for the combined Ethereum proof.

const std = @import("std");
const core_component = @import("stwo_core").air.components.Component;
const prover_component = @import("stwo_prover_engine").air.component_prover.ComponentProver;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const keccak_table_component = @import("../../air/guest_precompile/keccakf_table_component.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component = @import("../../air/guest_precompile/secp256k1_component.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const secp_trace = @import("../../air/guest_precompile/secp256k1_component_trace.zig");
const component_order = @import("../../air/component_order.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const program_commitment = @import("../../air/program/commitment.zig");
const base_statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const infra = @import("../../infra_trace.zig");
const trace_mod = @import("../../runner/trace.zig");
const proof_workspace = @import("../proof_workspace.zig");
const relations_mod = @import("ethereum_transcript.zig");
const types = @import("ethereum_types.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");

pub const Direction = enum { prover, verifier };
pub const extension_component_count: usize = statement_mod.component_count;
pub const max_handles = proof_workspace.MAX_COMPONENT_HANDLES +
    extension_component_count;

pub const PlacementDescriptor = struct {
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
};

pub fn Assembly(comptime direction: Direction) type {
    const Handle = if (direction == .prover) prover_component else core_component;
    return struct {
        const Self = @This();

        keccak: keccak_component.KeccakShardComponent,
        chi: keccak_table_component.KeccakTableComponent,
        xor5: keccak_table_component.KeccakTableComponent,
        product_base: secp_component.Component(secp_bundle.ProductBase),
        product_scalar: secp_component.Component(secp_bundle.ProductScalar),
        linear_base: secp_component.Component(secp_bundle.LinearBase),
        linear_scalar: secp_component.Component(secp_bundle.LinearScalar),
        point: secp_component.Component(secp_config.Point),
        split: secp_component.Component(secp_config.Split),
        scalar: secp_component.Component(secp_config.ScalarProgram),
        table: secp_component.Component(secp_config.Table),
        recovery: secp_component.Component(secp_config.Recovery),
        byte: secp_component.Component(secp_config.ByteTable),
        recovery_caller: secp_component.Component(secp_config.RecoveryCaller),
        handles: [max_handles]Handle,
        len: usize,

        pub fn create(
            allocator: std.mem.Allocator,
            core: *const base_statement.RiscVStatement,
            extension: *const statement_mod.Statement,
            relations: *const relations_mod.Relations,
            base: []const Handle,
            claim: *const types.ExtensionClaim,
        ) !*Self {
            return createAtBaseInteractionColumns(
                allocator,
                core,
                extension,
                relations,
                base,
                claim,
                core.nInteractionColumns(),
            );
        }

        /// SegmentV2 selects authenticated physical opcode lookup widths.
        /// Derive the Tree-2 base boundary from that typed authority inside the
        /// assembly API so callers cannot inject a stale compatibility offset.
        pub fn createAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const statement_mod.Statement,
            relations: *const relations_mod.Relations,
            base: []const Handle,
            claim: *const types.ExtensionClaim,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        ) !*Self {
            try extension.validateV2(native);
            const core = &native.core;
            const base_interaction_columns = try authenticated.totalInteractionColumns(
                core,
                manifest,
            );
            return createAtBaseInteractionColumns(
                allocator,
                core,
                extension,
                relations,
                base,
                claim,
                base_interaction_columns,
            );
        }

        pub fn createWithoutNativePoseidonAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            projection: *const native_provider_omit.ProjectionV1,
            full_native: *const statement_v2.RiscVStatementV2,
            extension: *const statement_mod.Statement,
            relations: *const relations_mod.Relations,
            base: []const Handle,
            claim: *const types.ExtensionClaim,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        ) !*Self {
            try projection.validateSealAndFull(full_native, extension);
            const projected_core = &projection.projected_native.core;
            try authenticated.validateAgainst(projected_core, manifest);
            const base_interaction_columns = try authenticated.totalInteractionColumns(
                projected_core,
                manifest,
            );
            return createAtBaseInteractionColumns(
                allocator,
                projected_core,
                extension,
                relations,
                base,
                claim,
                base_interaction_columns,
            );
        }

        fn createAtBaseInteractionColumns(
            allocator: std.mem.Allocator,
            core: *const base_statement.RiscVStatement,
            extension: *const statement_mod.Statement,
            relations: *const relations_mod.Relations,
            base: []const Handle,
            claim: *const types.ExtensionClaim,
            base_interaction_columns: usize,
        ) !*Self {
            try extension.validateStructure(core);
            try claim.validate(extension);
            if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
                return error.TooManyComponentHandles;
            const placements = try Placements.init(
                core,
                extension,
                base_interaction_columns,
            );
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.keccak = if (direction == .prover)
                try keccak_component.KeccakShardComponent.initProver(
                    claim.keccak_shard,
                    placements.keccak,
                    &relations.keccak,
                )
            else
                try keccak_component.KeccakShardComponent.initVerifier(
                    claim.keccak_shard,
                    placements.keccak,
                    &relations.keccak,
                );
            self.chi = if (direction == .prover)
                try keccak_table_component.KeccakTableComponent.initProver(
                    .chi,
                    placements.chi,
                    &relations.keccak,
                    claim.keccak_chi_table,
                )
            else
                try keccak_table_component.KeccakTableComponent.initVerifier(
                    .chi,
                    placements.chi,
                    &relations.keccak,
                    claim.keccak_chi_table,
                );
            self.xor5 = if (direction == .prover)
                try keccak_table_component.KeccakTableComponent.initProver(
                    .xor5,
                    placements.xor5,
                    &relations.keccak,
                    claim.keccak_xor5_table,
                )
            else
                try keccak_table_component.KeccakTableComponent.initVerifier(
                    .xor5,
                    placements.xor5,
                    &relations.keccak,
                    claim.keccak_xor5_table,
                );
            self.product_base = try secp_component.Component(secp_bundle.ProductBase).init(claim.product_base, placements.secp[0], &relations.secp);
            self.product_scalar = try secp_component.Component(secp_bundle.ProductScalar).init(claim.product_scalar, placements.secp[1], &relations.secp);
            self.linear_base = try secp_component.Component(secp_bundle.LinearBase).init(claim.linear_base, placements.secp[2], &relations.secp);
            self.linear_scalar = try secp_component.Component(secp_bundle.LinearScalar).init(claim.linear_scalar, placements.secp[3], &relations.secp);
            self.point = try secp_component.Component(secp_config.Point).init(claim.point, placements.secp[4], &relations.secp);
            self.split = try secp_component.Component(secp_config.Split).init(claim.split, placements.secp[5], &relations.secp);
            self.scalar = try secp_component.Component(secp_config.ScalarProgram).init(claim.scalar, placements.secp[6], &relations.secp);
            self.table = try secp_component.Component(secp_config.Table).init(claim.table, placements.secp[7], &relations.secp);
            self.recovery = try secp_component.Component(secp_config.Recovery).init(claim.recovery, placements.secp[8], &relations.secp);
            self.byte = try secp_component.Component(secp_config.ByteTable).init(claim.byte, placements.secp[9], &relations.secp);
            self.recovery_caller = try secp_component.Component(secp_config.RecoveryCaller).init(claim.recovery_caller, placements.secp[10], &relations.secp);

            @memcpy(self.handles[0..base.len], base);
            var cursor = base.len;
            inline for (.{
                &self.keccak,
                &self.chi,
                &self.xor5,
                &self.product_base,
                &self.product_scalar,
                &self.linear_base,
                &self.linear_scalar,
                &self.point,
                &self.split,
                &self.scalar,
                &self.table,
                &self.recovery,
                &self.byte,
                &self.recovery_caller,
            }) |component| {
                self.handles[cursor] = if (direction == .prover)
                    component.asProverComponent()
                else
                    component.asVerifierComponent();
                cursor += 1;
            }
            self.len = cursor;
            return self;
        }

        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.len];
        }

        /// Exact declaration-order placements used by the native verifier.
        /// The recursive capture copies these only after all 53 components
        /// have passed the core verifier; it never infers them from widths.
        pub fn extensionPlacements(
            self: *const Self,
        ) [extension_component_count]PlacementDescriptor {
            return .{
                normalPlacement(self.keccak.placement),
                tableDescriptor(self.chi.placement),
                tableDescriptor(self.xor5.placement),
                normalPlacement(self.product_base.placement),
                normalPlacement(self.product_scalar.placement),
                normalPlacement(self.linear_base.placement),
                normalPlacement(self.linear_scalar.placement),
                normalPlacement(self.point.placement),
                normalPlacement(self.split.placement),
                normalPlacement(self.scalar.placement),
                normalPlacement(self.table.placement),
                normalPlacement(self.recovery.placement),
                normalPlacement(self.byte.placement),
                normalPlacement(self.recovery_caller.placement),
            };
        }

        pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self);
        }
    };
}

fn normalPlacement(value: anytype) PlacementDescriptor {
    return .{
        .preprocessed_offset = value.preprocessed_offset,
        .main_offset = value.main_offset,
        .interaction_offset = value.interaction_offset,
    };
}

fn tableDescriptor(
    value: keccak_table_component.Placement,
) PlacementDescriptor {
    return .{
        .preprocessed_offset = value.is_first_col_idx,
        .main_offset = value.main_col_offset,
        .interaction_offset = value.interaction_col_offset,
    };
}

const Placements = struct {
    keccak: keccak_component.Placement,
    chi: keccak_table_component.Placement,
    xor5: keccak_table_component.Placement,
    secp: [11]secp_component.Placement,

    fn init(
        core: *const base_statement.RiscVStatement,
        extension: *const statement_mod.Statement,
        base_interaction_columns: usize,
    ) !Placements {
        var pp: usize = core.nPreprocessedColumns();
        var main: usize = core.nMainColumns();
        var interaction = base_interaction_columns;
        const keccak = keccak_component.Placement{
            .preprocessed_offset = pp,
            .main_offset = main,
            .interaction_offset = interaction,
        };
        pp = try add(pp, extension.components[0].preprocessed_columns);
        main = try add(main, extension.components[0].main_columns);
        interaction = try add(interaction, extension.components[0].interaction_columns);
        const chi = tablePlacement(pp, main, interaction);
        pp = try add(pp, extension.components[1].preprocessed_columns);
        main = try add(main, extension.components[1].main_columns);
        interaction = try add(interaction, extension.components[1].interaction_columns);
        const xor5 = tablePlacement(pp, main, interaction);
        pp = try add(pp, extension.components[2].preprocessed_columns);
        main = try add(main, extension.components[2].main_columns);
        interaction = try add(interaction, extension.components[2].interaction_columns);
        var secp: [11]secp_component.Placement = undefined;
        for (&secp, extension.components[3..]) |*placement, descriptor| {
            placement.* = .{
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
            };
            pp = try add(pp, descriptor.preprocessed_columns);
            main = try add(main, descriptor.main_columns);
            interaction = try add(interaction, descriptor.interaction_columns);
        }
        var expected_pp: usize = core.nPreprocessedColumns();
        var expected_main: usize = core.nMainColumns();
        var expected_interaction = base_interaction_columns;
        for (extension.components) |descriptor| {
            expected_pp = try add(expected_pp, descriptor.preprocessed_columns);
            expected_main = try add(expected_main, descriptor.main_columns);
            expected_interaction = try add(
                expected_interaction,
                descriptor.interaction_columns,
            );
        }
        if (pp != expected_pp or main != expected_main or
            interaction != expected_interaction)
        {
            return error.ColumnPlacementMismatch;
        }
        return .{ .keccak = keccak, .chi = chi, .xor5 = xor5, .secp = secp };
    }
};

fn tablePlacement(
    pp: usize,
    main: usize,
    interaction: usize,
) keccak_table_component.Placement {
    var tuples: [6]usize = undefined;
    for (&tuples, 0..) |*value, index| value.* = pp + 1 + index;
    return .{
        .is_first_col_idx = pp,
        .tuple_col_indices = tuples,
        .main_col_offset = main,
        .interaction_col_offset = interaction,
    };
}

fn add(left: usize, right: anytype) !usize {
    return std.math.add(usize, left, @intCast(right)) catch
        error.ColumnOffsetOverflow;
}

comptime {
    if (secp_trace.preprocessed_column_count != 3 or
        extension_component_count != 14)
    {
        @compileError("Ethereum component assembly geometry drifted");
    }
}

test "ethereum assembly keeps legacy placement and derives SegmentV2 placement" {
    const core = retainedSegmentZeroCoreForPlacementTest();
    var extension: statement_mod.Statement = undefined;
    for (&extension.components, 0..) |*descriptor, index| {
        descriptor.* = .{
            .kind = @enumFromInt(index + 1),
            .log_size = 1,
            .n_rows = 0,
            .preprocessed_columns = 0,
            .main_columns = 0,
            .interaction_columns = 0,
        };
    }

    try std.testing.expectEqual(@as(u32, 48), core.nPreprocessedColumns());
    try std.testing.expectEqual(@as(u32, 815), core.nMainColumns());
    try std.testing.expectEqual(@as(u32, 372), core.nInteractionColumns());
    const legacy = try Placements.init(
        &core,
        &extension,
        core.nInteractionColumns(),
    );
    try std.testing.expectEqual(@as(usize, 48), legacy.keccak.preprocessed_offset);
    try std.testing.expectEqual(@as(usize, 815), legacy.keccak.main_offset);
    try std.testing.expectEqual(@as(usize, 372), legacy.keccak.interaction_offset);

    const manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &core,
        &manifest,
    );
    const selected = try authenticated.totalInteractionColumns(&core, &manifest);
    try std.testing.expectEqual(@as(usize, 352), selected);
    const v2 = try Placements.init(&core, &extension, selected);
    try std.testing.expectEqual(@as(usize, 352), v2.keccak.interaction_offset);

    // The public SegmentV2 constructor accepts only this authenticated value;
    // a caller cannot supply `selected` directly. A stale authority therefore
    // fails before the private placement constructor becomes reachable.
    authenticated.opcode_interaction_columns += 4;
    try std.testing.expectError(
        error.InvalidStatementGeometry,
        authenticated.totalInteractionColumns(&core, &manifest),
    );
}

fn retainedSegmentZeroCoreForPlacementTest() base_statement.RiscVStatement {
    var core: base_statement.RiscVStatement = undefined;
    core.n_components = 0;
    core.component_descs = undefined;
    core.initial_pc = 1024;
    core.final_pc = 1480;
    core.total_steps = 628;
    core.public_data = undefined;
    for (component_order.opcodeFamilies()) |family| {
        const rows = retainedSegmentZeroRows(family);
        if (rows == 0) continue;
        core.component_descs[core.n_components] = .{
            .family = family,
            .log_size = @max(@as(u32, 4), std.math.log2_int_ceil(u32, rows)),
            .n_rows = rows,
            .n_columns = trace_mod.nColumnsForFamily(family),
        };
        core.n_components += 1;
    }
    core.n_infra = 10;
    core.infra_descs = undefined;
    const descriptors = [_]base_statement.InfraComponentDesc{
        infraDescriptor(.program, program_commitment.N_MAIN_COLUMNS),
        infraDescriptor(.merkle, merkle_node.N_MAIN_COLUMNS),
        infraDescriptor(.poseidon2, poseidon2_air.N_MAIN_COLUMNS),
        infraDescriptor(.clock_update, infra.CLOCK_UPDATE_COLS),
        infraDescriptor(.bitwise, 1),
        infraDescriptor(.range_check_20, 1),
        infraDescriptor(.range_check_8_11, 1),
        infraDescriptor(.range_check_8_8_4, 1),
        infraDescriptor(.range_check_8_8, 1),
        infraDescriptor(.range_check_m31, 1),
    };
    @memcpy(core.infra_descs[0..descriptors.len], &descriptors);
    return core;
}

fn infraDescriptor(
    kind: base_statement.InfraKind,
    n_columns: usize,
) base_statement.InfraComponentDesc {
    return .{
        .kind = kind,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = @intCast(n_columns),
    };
}

fn retainedSegmentZeroRows(family: trace_mod.OpcodeFamily) u32 {
    return switch (family) {
        .auipc => 9,
        .base_alu_imm => 205,
        .base_alu_reg => 55,
        .branch_eq => 29,
        .branch_lt => 100,
        .jal => 4,
        .jalr => 11,
        .load_store => 204,
        .lui => 8,
        .mul => 2,
        else => 0,
    };
}
