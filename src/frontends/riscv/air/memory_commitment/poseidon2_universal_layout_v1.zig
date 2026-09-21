//! Canonical compact Poseidon physical geometry; no evaluator or witness owner.
const M31 = @import("stwo_core").fields.m31.M31;
const constants = @import("poseidon2_constants.zig");
pub const SCHEMA_VERSION: u16 = 1;
pub const STABLE_NAME = "stwo.recursion.poseidon2-universal-degree3.v1";
pub const WIDTH = @import("poseidon2_matrix.zig").WIDTH;
pub const N_SBOXES = WIDTH * constants.EXTERNAL_ROUND.len + constants.INTERNAL_ROUND.len;
pub const N_MAIN_COLUMNS = 19 + 2 * N_SBOXES;
pub const WIDE_COLUMN = N_MAIN_COLUMNS - 2;
pub const IO_COLUMN = N_MAIN_COLUMNS - 1;
pub const BINDS_ACTIVE_SELECTOR = false;
pub const N_CONSTRAINTS = 4 + 2 * N_SBOXES;
pub const N_SUMS: usize = 2;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;
pub const Row = [N_MAIN_COLUMNS]M31;
