//! One allocation-free assembly authority for the base RISC-V AIR registry.
//!
//! Proving and verification deliberately share the same concrete component
//! storage and declaration walk. `Direction` selects only the erased handle
//! constructor; placement, fixed geometry, claims, and physical component
//! values have no side-specific branch. This keeps protocol-visible order from
//! drifting while preserving monomorphized prover/verifier handle types.

const std = @import("std");
const component_order = @import("../air/component_order.zig");
const clock_update_component = @import("../air/clock_update_component.zig");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const composition_manifest = @import("../air/lang/opcode_composition_manifest.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_component = @import("../air/lookups/opcode_component.zig");
const lookup_table_component = @import("../air/lookups/tables/component.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const riscv_component = @import("../air/component.zig");
const semantic_component = @import("../air/semantic_component.zig");
const statement_mod = @import("../air/statement.zig");
const proof_workspace = @import("proof_workspace.zig");
const types = @import("types.zig");

pub const Direction = enum { prover, verifier };

pub const INFRASTRUCTURE_KIND_COUNT: usize =
    @typeInfo(statement_mod.InfraKind).@"enum".fields.len;
pub const CANONICAL_INFRASTRUCTURE_ORDER = [INFRASTRUCTURE_KIND_COUNT]statement_mod.InfraKind{
    .program,
    .memory,
    .merkle,
    .poseidon2,
    .clock_update,
    .bitwise,
    .range_check_20,
    .range_check_8_11,
    .range_check_8_8_4,
    .range_check_8_8,
    .range_check_m31,
};

pub const InfrastructureAdapterKind = enum(u8) {
    trace,
    hash,
    clock_update,
    lookup_table,
};

/// Fixed geometry and physical adapter identity for one infrastructure kind.
/// Runtime row counts and log sizes remain statement data; column geometry is
/// compiled from the component owners that consume it.
pub const InfrastructureDescriptor = struct {
    kind: statement_mod.InfraKind,
    adapter_kind: InfrastructureAdapterKind,
    order_rank: u8,
    repeatable: bool,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    table_kind: ?lookup_table_schema.Kind = null,
};

pub fn infrastructureDescriptor(
    kind: statement_mod.InfraKind,
) InfrastructureDescriptor {
    if (tableForInfrastructure(kind)) |table_kind| {
        const metadata = lookup_table_component.ConstructionMetadata.forKind(
            table_kind,
        );
        return .{
            .kind = kind,
            .adapter_kind = .lookup_table,
            .order_rank = @intCast(5 + component_order.lookupTableIndex(table_kind)),
            .repeatable = false,
            .preprocessed_columns = metadata.preprocessed_columns,
            .main_columns = metadata.main_columns,
            .interaction_columns = metadata.interaction_columns,
            .table_kind = table_kind,
        };
    }
    return switch (kind) {
        .program => .{
            .kind = kind,
            .adapter_kind = .trace,
            .order_rank = 0,
            .repeatable = false,
            .preprocessed_columns = 2,
            .main_columns = program_commitment.N_MAIN_COLUMNS,
            .interaction_columns = program_interaction.N_COLUMNS,
        },
        .memory => .{
            .kind = kind,
            .adapter_kind = .trace,
            .order_rank = 1,
            .repeatable = true,
            .preprocessed_columns = 2,
            .main_columns = memory_trace.N_COLUMNS,
            .interaction_columns = memory_interaction.N_COLUMNS,
        },
        .merkle => .{
            .kind = kind,
            .adapter_kind = .hash,
            .order_rank = 2,
            .repeatable = false,
            .preprocessed_columns = 2,
            .main_columns = merkle_node.N_MAIN_COLUMNS,
            .interaction_columns = merkle_node.N_INTERACTION_COLUMNS,
        },
        .poseidon2 => .{
            .kind = kind,
            .adapter_kind = .hash,
            .order_rank = 3,
            .repeatable = false,
            .preprocessed_columns = 2,
            .main_columns = poseidon2_air.N_MAIN_COLUMNS,
            .interaction_columns = poseidon2_air.N_INTERACTION_COLUMNS,
        },
        .clock_update => .{
            .kind = kind,
            .adapter_kind = .clock_update,
            .order_rank = 4,
            .repeatable = false,
            .preprocessed_columns = 2,
            .main_columns = clock_update_interaction.N_MAIN_COLUMNS,
            .interaction_columns = clock_update_interaction.N_INTERACTION_COLUMNS,
        },
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => unreachable,
    };
}

/// O(1), fail-atomic infrastructure placement after the opcode prefix. The
/// monotonically increasing rank admits omitted test-fixture components and
/// repeated memory shards, while rejecting reordering or singleton aliasing.
pub const InfrastructureCursor = struct {
    infrastructure_count: usize = 0,
    adapter_count: usize,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    hash_count: usize = 0,
    seen_singletons: u16 = 0,
    last_order_rank: ?u8 = null,

    pub const Error = error{
        AdapterIndexOverflow,
        ColumnIndexOverflow,
        HashIndexOverflow,
        InfrastructureIndexOverflow,
        InfrastructureOrderMismatch,
        MainColumnCountMismatch,
    };

    pub const Placement = struct {
        kind: statement_mod.InfraKind,
        adapter_kind: InfrastructureAdapterKind,
        infrastructure_index: usize,
        adapter_index: usize,
        preprocessed_column_offset: usize,
        preprocessed_columns: usize,
        main_column_offset: usize,
        main_columns: usize,
        interaction_column_offset: usize,
        interaction_columns: usize,
        hash_index: ?usize,
        table_kind: ?lookup_table_schema.Kind,
    };

    pub fn init(opcode: composition_manifest.PlacementCursor) InfrastructureCursor {
        return .{
            .adapter_count = opcode.adapter_count,
            .preprocessed_columns = opcode.preprocessed_columns,
            .main_columns = opcode.main_columns,
            .interaction_columns = opcode.interaction_columns,
        };
    }

    pub fn append(
        self: *InfrastructureCursor,
        kind: statement_mod.InfraKind,
        declared_main_columns: usize,
    ) Error!Placement {
        const item = infrastructureDescriptor(kind);
        if (declared_main_columns != item.main_columns)
            return error.MainColumnCountMismatch;
        if (self.last_order_rank) |last| {
            if (item.order_rank < last or
                (item.order_rank == last and !item.repeatable))
            {
                return error.InfrastructureOrderMismatch;
            }
        }
        const singleton_bit = @as(u16, 1) << @intCast(item.order_rank);
        if (!item.repeatable and self.seen_singletons & singleton_bit != 0)
            return error.InfrastructureOrderMismatch;

        const infrastructure_index = self.infrastructure_count;
        const adapter_index = self.adapter_count;
        const next_infrastructure_count = std.math.add(
            usize,
            infrastructure_index,
            1,
        ) catch return error.InfrastructureIndexOverflow;
        const next_adapter_count = std.math.add(
            usize,
            adapter_index,
            1,
        ) catch return error.AdapterIndexOverflow;
        const next_preprocessed = std.math.add(
            usize,
            self.preprocessed_columns,
            item.preprocessed_columns,
        ) catch return error.ColumnIndexOverflow;
        const next_main = std.math.add(
            usize,
            self.main_columns,
            item.main_columns,
        ) catch return error.ColumnIndexOverflow;
        const next_interaction = std.math.add(
            usize,
            self.interaction_columns,
            item.interaction_columns,
        ) catch return error.ColumnIndexOverflow;
        const hash_index: ?usize = if (item.adapter_kind == .hash)
            self.hash_count
        else
            null;
        const next_hash_count = if (hash_index != null)
            std.math.add(usize, self.hash_count, 1) catch
                return error.HashIndexOverflow
        else
            self.hash_count;
        if (next_hash_count > proof_workspace.MAX_HASH_COMPONENTS)
            return error.HashIndexOverflow;

        const placement = Placement{
            .kind = kind,
            .adapter_kind = item.adapter_kind,
            .infrastructure_index = infrastructure_index,
            .adapter_index = adapter_index,
            .preprocessed_column_offset = self.preprocessed_columns,
            .preprocessed_columns = item.preprocessed_columns,
            .main_column_offset = self.main_columns,
            .main_columns = item.main_columns,
            .interaction_column_offset = self.interaction_columns,
            .interaction_columns = item.interaction_columns,
            .hash_index = hash_index,
            .table_kind = item.table_kind,
        };
        self.* = .{
            .infrastructure_count = next_infrastructure_count,
            .adapter_count = next_adapter_count,
            .preprocessed_columns = next_preprocessed,
            .main_columns = next_main,
            .interaction_columns = next_interaction,
            .hash_count = next_hash_count,
            .seen_singletons = self.seen_singletons |
                (if (item.repeatable) 0 else singleton_bit),
            .last_order_rank = item.order_rank,
        };
        return placement;
    }
};

/// Materializes the complete base component registry into caller-owned stable
/// storage. No allocation, runtime function-pointer selection, or prefix scan
/// occurs here; `direction` is erased at compile time.
pub fn assembleInto(
    comptime direction: Direction,
    workspace: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
) !void {
    return assembleIntoInternal(
        direction,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
        null,
        .legacy_role_filtered_v1,
    );
}

/// Append-only construction boundary for the authenticated variable-partition
/// lookup statement. Existing callers remain on `assembleInto` and therefore
/// cannot activate V2 accidentally.
pub fn assembleIntoAuthenticatedLookupV2(
    comptime direction: Direction,
    workspace: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) !void {
    try authenticated_statement.validateAgainst(statement, manifest);
    return assembleIntoInternal(
        direction,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
        .{
            .manifest = manifest,
            .statement = authenticated_statement,
        },
        .legacy_role_filtered_v1,
    );
}

/// Version-separated selected-lookup assembly for the full-state incremental
/// boundary. The core geometry and column placement remain byte-identical;
/// only memory infrastructure components select the split V3 evaluator.
pub fn assembleIntoAuthenticatedLookupV2WithIncrementalBoundaryV3(
    comptime direction: Direction,
    workspace: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) !void {
    try authenticated_statement.validateAgainst(statement, manifest);
    return assembleIntoInternal(
        direction,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
        .{
            .manifest = manifest,
            .statement = authenticated_statement,
        },
        .full_state_split_multiplicity_v3,
    );
}

const LookupV2Admission = struct {
    manifest: *const lookup_physical_v2.Manifest,
    statement: *const lookup_physical_v2.AuthenticatedStatement,
};

fn assembleIntoInternal(
    comptime direction: Direction,
    workspace: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
    lookup_v2: ?LookupV2Admission,
    memory_boundary_policy: riscv_component.MemoryBoundaryPolicy,
) !void {
    const components = &workspace.components;
    const component_count: usize = @intCast(statement.n_components);
    const infrastructure_count: usize = @intCast(statement.n_infra);
    const opcode_handles = std.math.mul(usize, component_count, 2) catch
        return types.ProverError.InvalidStatement;
    const expected_handles = std.math.add(
        usize,
        opcode_handles,
        infrastructure_count,
    ) catch return types.ProverError.InvalidStatement;
    if (component_count > statement_mod.MAX_COMPONENTS or
        infrastructure_count > statement_mod.MAX_INFRA_COMPONENTS or
        expected_handles > proof_workspace.MAX_COMPONENT_HANDLES or
        components.active().len != 0 or
        components.n_hash != 0)
    {
        return types.ProverError.InvalidStatement;
    }
    if (claim.n_components != statement.n_components or
        claim.n_infra != statement.n_infra)
    {
        return types.ProverError.InvalidInteractionClaim;
    }
    errdefer {
        components.n_handles = 0;
        components.n_hash = 0;
    }

    var opcode_cursor = composition_manifest.PlacementCursor{};
    var selected_interaction_columns: usize = 0;
    var previous_opcode_rank: ?usize = null;
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        const opcode_rank = composition_manifest.compositionIndex(desc.family);
        if (previous_opcode_rank) |previous| {
            if (opcode_rank < previous) return types.ProverError.InvalidStatement;
        }
        previous_opcode_rank = opcode_rank;
        const placement = opcode_cursor.append(
            desc.family,
            @intCast(desc.n_columns),
        ) catch return types.ProverError.InvalidStatement;
        if (placement.component_index != index or
            components.active().len != placement.semantic_adapter_index)
        {
            return types.ProverError.InvalidStatement;
        }
        components.semantic[index] = try semantic_component.SemanticComponent.init(
            desc.family,
            desc.log_size,
            placement.is_active_column,
            placement.main_column_offset,
        );
        push(direction, components, &components.semantic[index]);
        if (components.active().len != placement.lookup_adapter_index)
            return types.ProverError.InvalidStatement;
        if (lookup_v2) |authenticated| {
            const physical = authenticated.manifest.entryForFamily(desc.family);
            const batch_count: usize = @intCast(physical.detailed_claim_count);
            if (batch_count > claim.opcode_claims[index].len) {
                return types.ProverError.InvalidStatement;
            }
            components.opcode_lookup[index] =
                try opcode_component.OpcodeLookupComponent.initAuthenticatedPhysicalV2(
                    physical,
                    desc.log_size,
                    placement.is_first_column,
                    placement.main_column_offset,
                    selected_interaction_columns,
                    relations,
                    claim.opcode_claims[index][0..batch_count],
                );
            selected_interaction_columns = std.math.add(
                usize,
                selected_interaction_columns,
                @intCast(physical.interaction_column_count),
            ) catch return types.ProverError.InvalidStatement;
        } else if (comptime direction == .prover) {
            components.opcode_lookup[index] =
                try opcode_component.OpcodeLookupComponent.initProver(
                    desc.family,
                    desc.log_size,
                    placement.is_first_column,
                    placement.main_column_offset,
                    placement.interaction_column_offset,
                    relations,
                    try claim.opcodeClaims(desc.family, index),
                );
        } else {
            components.opcode_lookup[index] =
                try opcode_component.OpcodeLookupComponent.initVerifier(
                    desc.family,
                    desc.log_size,
                    placement.is_first_column,
                    placement.main_column_offset,
                    placement.interaction_column_offset,
                    relations,
                    try claim.opcodeClaims(desc.family, index),
                );
        }
        push(direction, components, &components.opcode_lookup[index]);
    }

    if (lookup_v2) |authenticated| {
        if (selected_interaction_columns !=
            @as(usize, authenticated.statement.opcode_interaction_columns))
        {
            return types.ProverError.InvalidStatement;
        }
        opcode_cursor.interaction_columns = selected_interaction_columns;
    }

    var infrastructure_cursor = InfrastructureCursor.init(opcode_cursor);
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        const placement = infrastructure_cursor.append(
            desc.kind,
            @intCast(desc.n_columns),
        ) catch return types.ProverError.InvalidStatement;
        if (placement.infrastructure_index != index or
            components.active().len != placement.adapter_index)
        {
            return types.ProverError.InvalidStatement;
        }

        switch (placement.adapter_kind) {
            .hash => {
                const expected_hash_index = placement.hash_index orelse
                    return types.ProverError.InvalidStatement;
                const hash = components.nextHash();
                if (hash != &components.hash[expected_hash_index])
                    return types.ProverError.InvalidStatement;
                hash.* = .{
                    .kind = if (desc.kind == .poseidon2) .poseidon2 else .merkle,
                    .log_size = desc.log_size,
                    .n_rows = desc.n_rows,
                    .is_first_col_idx = placement.preprocessed_column_offset,
                    .is_active_col_idx = placement.preprocessed_column_offset + 1,
                    .main_col_offset = placement.main_column_offset,
                    .interaction_col_offset = placement.interaction_column_offset,
                    .relations = relations,
                    .merkle_claims = claim.merkle_claims[index],
                    .poseidon_claims = claim.poseidon_claims[index],
                };
                push(direction, components, hash);
            },
            .lookup_table => {
                const table_kind = placement.table_kind orelse
                    return types.ProverError.InvalidStatement;
                const table_index = component_order.lookupTableIndex(table_kind);
                var tuple_indices: [lookup_table_schema.MAX_ARITY]usize = undefined;
                for (tuple_indices[0..lookup_table_schema.arity(table_kind)], 0..) |*column, tuple_offset| {
                    column.* = placement.preprocessed_column_offset + 1 + tuple_offset;
                }
                components.table[table_index] = if (comptime direction == .prover)
                    try lookup_table_component.LookupTableComponent.initProver(
                        table_kind,
                        placement.preprocessed_column_offset,
                        tuple_indices[0..lookup_table_schema.arity(table_kind)],
                        placement.main_column_offset,
                        placement.interaction_column_offset,
                        relations,
                        claim.lookup_claims[index],
                    )
                else
                    try lookup_table_component.LookupTableComponent.initVerifier(
                        table_kind,
                        placement.preprocessed_column_offset,
                        tuple_indices[0..lookup_table_schema.arity(table_kind)],
                        placement.main_column_offset,
                        placement.interaction_column_offset,
                        relations,
                        claim.lookup_claims[index],
                    );
                push(direction, components, &components.table[table_index]);
            },
            .clock_update => {
                if (comptime direction == .prover) {
                    components.clock = try clock_update_component.ClockUpdateComponent.initProver(
                        desc.log_size,
                        placement.preprocessed_column_offset,
                        placement.preprocessed_column_offset + 1,
                        placement.main_column_offset,
                        placement.interaction_column_offset,
                        relations,
                        claim.clock_claims[index],
                    );
                } else {
                    components.clock = clock_update_component.ClockUpdateComponent.initVerifier(
                        desc.log_size,
                        placement.preprocessed_column_offset,
                        placement.preprocessed_column_offset + 1,
                        placement.main_column_offset,
                        placement.interaction_column_offset,
                        relations,
                        claim.clock_claims[index],
                    );
                }
                push(direction, components, &components.clock);
            },
            .trace => {
                const kind: riscv_component.Kind = switch (desc.kind) {
                    .program => .program,
                    .memory => .memory,
                    else => return types.ProverError.InvalidStatement,
                };
                components.infra[index] = .{
                    .desc = .{
                        .family = .base_alu_reg,
                        .log_size = desc.log_size,
                        .n_rows = desc.n_rows,
                        .n_columns = desc.n_columns,
                    },
                    .initial_pc = statement.initial_pc,
                    .total_steps = statement.total_steps,
                    .is_first_col_idx = placement.preprocessed_column_offset,
                    .is_active_col_idx = placement.preprocessed_column_offset + 1,
                    .main_col_offset = placement.main_column_offset,
                    .kind = kind,
                    .memory_boundary_policy = if (kind == .memory)
                        memory_boundary_policy
                    else
                        .legacy_role_filtered_v1,
                    .relations = relations,
                    .interaction_col_offset = placement.interaction_column_offset,
                    .program_claims = claim.program_claims[index],
                    .memory_claims = claim.memory_claims[index],
                };
                push(direction, components, &components.infra[index]);
            },
        }
    }

    if (infrastructure_cursor.infrastructure_count != infrastructure_count or
        components.n_hash != infrastructure_cursor.hash_count or
        components.active().len != infrastructure_cursor.adapter_count or
        infrastructure_cursor.main_columns != n_main or
        infrastructure_cursor.interaction_columns != n_interaction)
    {
        return types.ProverError.InvalidStatement;
    }
}

fn push(
    comptime direction: Direction,
    components: anytype,
    component: anytype,
) void {
    if (comptime direction == .prover) {
        components.push(component.asProverComponent());
    } else {
        components.push(component.asVerifierComponent());
    }
}

fn tableForInfrastructure(
    kind: statement_mod.InfraKind,
) ?lookup_table_schema.Kind {
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

comptime {
    var seen = [_]bool{false} ** INFRASTRUCTURE_KIND_COUNT;
    for (CANONICAL_INFRASTRUCTURE_ORDER, 0..) |kind, index| {
        const ordinal = @intFromEnum(kind);
        if (ordinal >= seen.len or seen[ordinal])
            @compileError("base infrastructure order is not a permutation");
        seen[ordinal] = true;
        const item = infrastructureDescriptor(kind);
        if (@as(usize, item.order_rank) != index or
            item.preprocessed_columns == 0 or
            item.main_columns == 0 or
            item.interaction_columns == 0 or
            item.preprocessed_columns != @as(
                usize,
                statement_mod.nPreprocessedColumnsForInfra(kind),
            ) or
            item.interaction_columns != @as(
                usize,
                statement_mod.nInteractionColsForInfra(kind),
            ) or
            item.table_kind != statement_mod.tableKind(kind))
        {
            @compileError("invalid base infrastructure composition descriptor");
        }
    }
    for (seen) |present| {
        if (!present) @compileError("base infrastructure order omits a kind");
    }
}
