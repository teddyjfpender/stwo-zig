//! Pure geometry projection from authenticated typed AIR declarations.
//! Components and key admission share this owner without importing a prover.

/// Equation-free manifest projection shared by every versioned outer
/// protocol.  Geometry is derived only from the authenticated typed AIR; a
/// manifest may select a different AIR for a versioned row, but it cannot
/// transcribe that AIR's widths, degrees, or semantic identity by hand.
pub fn manifestGeometryForAir(
    comptime Air: type,
    comptime manifest_mod: type,
    comptime roster_row: manifest_mod.ComponentKey,
    log_size: u32,
) manifest_mod.Geometry {
    return .{
        .roster_row = manifest_mod.keyIndex(roster_row),
        .log_size = log_size,
        .preprocessed_columns = Air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = Air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = Air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = Air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(
            protocolMaximumConstraintDegree(Air),
        ),
        .profiled_constraint_degree = Air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = Air.SEMANTIC_DIGEST,
    };
}

pub fn protocolMaximumConstraintDegree(comptime Air: type) u32 {
    const compatibility: u32 = if (@hasDecl(
        Air,
        "REFERENCE_MAXIMUM_CONSTRAINT_DEGREE",
    )) Air.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE else @max(
        Air.MAXIMUM_CONSTRAINT_DEGREE,
        if (Air.INTERACTION_BATCH_COUNT == 0) @as(u32, 0) else 3,
    );
    return if (@hasDecl(
        Air,
        "LOWERED_MAXIMUM_CONSTRAINT_DEGREE",
    )) @max(
        compatibility,
        Air.LOWERED_MAXIMUM_CONSTRAINT_DEGREE,
    ) else compatibility;
}

pub fn parameterColumnCount(comptime Air: type) usize {
    return Air.LOGICAL_INPUT_COUNT - Air.PREPROCESSED_COLUMN_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT;
}
