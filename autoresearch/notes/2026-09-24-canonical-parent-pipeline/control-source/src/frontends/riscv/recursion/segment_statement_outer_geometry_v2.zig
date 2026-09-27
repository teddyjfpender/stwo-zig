//! Statement routing geometry projected solely from the owning typed AIRs.
const roster = @import("air/universal_roster.zig");
const row10_air = @import("air/statement_input.zig");
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const Air = air_v2.StatementSemanticsV2;
const Sha256Digest = [32]u8;
pub const FROZEN_ROW_10: u8 = @intFromEnum(roster.Component.statement_input);
pub const ROUTING_ROW_11: u8 =
    @intFromEnum(roster.Component.statement_semantics_input);
pub const STATEMENT_SOURCE_COMPONENT_36: u8 = roster.COMPONENT_COUNT;

pub const OverrideActivationV2 = enum(u8) {
    explicitly_inactive = 0,
    active_v2_override = 1,
    appended_boundary_source = 2,
};

/// Exact manifest handoff for the central 38-component V2 roster. Geometry is
/// exported from each authoritative AIR and is never transcribed by callers.
pub const ComponentOverrideV2 = struct {
    component_index: u8,
    activation: OverrideActivationV2,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    relation_events: u16,
    protocol_constraint_degree: u8,
    profiled_constraint_degree: u8,
    semantic_digest: Sha256Digest,
};

pub const COMPONENT_OVERRIDE_TABLE_V2 = [_]ComponentOverrideV2{
    overrideFor(
        row10_air,
        FROZEN_ROW_10,
        .explicitly_inactive,
    ),
    overrideFor(
        Air,
        ROUTING_ROW_11,
        .active_v2_override,
    ),
    overrideFor(
        air_v2.Statement,
        STATEMENT_SOURCE_COMPONENT_36,
        .appended_boundary_source,
    ),
};

pub fn overrideFor(
    comptime ComponentAir: type,
    comptime component_index: u8,
    comptime activation: OverrideActivationV2,
) ComponentOverrideV2 {
    return .{
        .component_index = component_index,
        .activation = activation,
        .preprocessed_columns = ComponentAir.PREPROCESSED_COLUMN_COUNT,
        .main_columns = ComponentAir.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = ComponentAir.INTERACTION_COLUMN_COUNT,
        .direct_constraints = ComponentAir.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = ComponentAir.INTERACTION_BATCH_COUNT,
        .relation_events = ComponentAir.RELATION_EVENT_COUNT,
        .protocol_constraint_degree = ComponentAir.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = ComponentAir.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = ComponentAir.SEMANTIC_DIGEST,
    };
}
