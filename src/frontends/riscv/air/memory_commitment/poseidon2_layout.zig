//! Shared physical geometry of the pinned wide Poseidon2 AIR.
pub const WIDTH: usize = 16;
pub const N_TEMPORARIES: usize = 426;
pub const N_MAIN_COLUMNS: usize = 1 + WIDTH + N_TEMPORARIES + 2;
pub const N_MATERIALIZATION_CONSTRAINTS: usize = N_TEMPORARIES;
pub const N_PERMUTATION_CONSTRAINTS: usize = 1 + N_MATERIALIZATION_CONSTRAINTS;
pub const N_FLAG_CONSTRAINTS: usize = 3;
pub const N_CONSTRAINTS: usize = N_PERMUTATION_CONSTRAINTS + N_FLAG_CONSTRAINTS;
pub const N_SUMS: usize = 2;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u8 = 3;

pub const INPUT_START: usize = 1;
pub const TEMP_START: usize = INPUT_START + WIDTH;
pub const WIDE_COLUMN: usize = TEMP_START + N_TEMPORARIES;
pub const IO_COLUMN: usize = WIDE_COLUMN + 1;
pub const FIRST_FULL_ROUND_WIDTH: usize = 2 * WIDTH;
pub const MATERIALIZED_FULL_ROUND_WIDTH: usize = 3 * WIDTH;
pub const PARTIAL_ROUND_WIDTH: usize = 3;
pub const OUTPUT_START: usize = TEMP_START + N_TEMPORARIES - WIDTH;
