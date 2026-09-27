//! Recursive-parent lookup layout for the canonical G arithmetic and wire AIR.
//! The parent roster admits a degree-five, split-two composition domain. The
//! execution-leaf profile retains its separately admitted cubic layout.
const base = @import("blake3_g_call.zig");
pub const PHYSICAL_MAIN_COLUMN_COUNT = base.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = base.PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = base.LOGICAL_INPUT_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = base.MAXIMUM_CONSTRAINT_DEGREE;
pub const DIRECT_CONSTRAINT_COUNT = base.DIRECT_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = base.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE: u8 = 4;
pub const LOWERED_MAXIMUM_CONSTRAINT_DEGREE: u32 = 5;
pub const INTERACTION_BATCH_COUNT = (RELATION_EVENT_COUNT + LOOKUP_BATCH_SIZE - 1) / LOOKUP_BATCH_SIZE;
pub const INTERACTION_COLUMN_COUNT = INTERACTION_BATCH_COUNT * 4;
pub const SEMANTIC_DIGEST = base.SEMANTIC_DIGEST;
pub const Row = base.Row;
pub const Schedule = base.Schedule;
pub const Definition = base.Definition;
pub const computeSemanticDigest = base.computeSemanticDigest;
pub const build = base.build;
pub const logicalRow = base.logicalRow;
pub const fixedRow = base.fixedRow;
