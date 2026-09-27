//! Internal segment leaf outer air v2 authority shard; use segment_leaf_outer_air_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_air_v2_contract.zig");
const dependency_1 = @import("segment_leaf_outer_air_v2_public_log_up.zig");

const PublicLogUp = dependency_1.PublicLogUp;
const Statement = dependency_0.Statement;
const source_v2 = dependency_0.source_v2;

comptime {
    if (Statement.Runtime.BATCH_COUNT != Statement.INTERACTION_BATCH_COUNT or
        Statement.Runtime.INTERACTION_COLUMN_COUNT !=
            Statement.INTERACTION_COLUMN_COUNT or
        PublicLogUp.Runtime.BATCH_COUNT != PublicLogUp.INTERACTION_BATCH_COUNT or
        PublicLogUp.Runtime.INTERACTION_COLUMN_COUNT !=
            PublicLogUp.INTERACTION_COLUMN_COUNT or
        Statement.PREPROCESSED_COLUMN_COUNT !=
            source_v2.PREPROCESSED_COLUMN_COUNT or
        Statement.PHYSICAL_MAIN_COLUMN_COUNT != source_v2.MAIN_COLUMN_COUNT or
        Statement.INTERACTION_COLUMN_COUNT !=
            source_v2.INTERACTION_COLUMN_COUNT or
        Statement.DIRECT_CONSTRAINT_COUNT !=
            source_v2.DIRECT_CONSTRAINT_COUNT)
    {
        @compileError("segment-leaf V2 typed authority geometry drifted");
    }
}
