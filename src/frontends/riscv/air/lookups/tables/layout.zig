//! Physical lookup-table component geometry, shared by proving and admission.
const schema = @import("schema_definition.zig");
pub const N_INTERACTION_COLUMNS: usize = 4;
pub const N_CONSTRAINTS: usize = 1;

pub const ConstructionMetadata = struct {
    kind: schema.Kind,
    log_size: u32,
    tuple_columns: usize,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    previous_masks: usize,
    constraints: usize,

    pub fn forKind(kind: schema.Kind) ConstructionMetadata {
        return .{
            .kind = kind,
            .log_size = schema.logSize(kind),
            .tuple_columns = schema.arity(kind),
            .preprocessed_columns = 1 + schema.arity(kind),
            .main_columns = 1,
            .interaction_columns = N_INTERACTION_COLUMNS,
            .previous_masks = N_INTERACTION_COLUMNS,
            .constraints = N_CONSTRAINTS,
        };
    }
};
