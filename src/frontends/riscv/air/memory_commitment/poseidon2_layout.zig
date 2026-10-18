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

/// The 32-lane `poseidon2_io` tuple shared by a narrow Poseidon2 row and its
/// sparse-Merkle caller: the full 16-lane input followed by the first output
/// lane and fifteen zeros.  Binding input and output in one tuple is what
/// makes the Merkle node <-> hash row pairing one-to-one; two separate
/// `poseidon2` terms let a prover pair one row's input with another row's
/// output.  A genuine atomic-IO tuple `[input16 || output16]` only collides
/// with this shape when output lanes 1..15 are all zero.
pub fn narrowIoTuple(comptime S: type, input: [WIDTH]S, output_lane0: S) [2 * WIDTH]S {
    var tuple = [_]S{S.zero()} ** (2 * WIDTH);
    @memcpy(tuple[0..WIDTH], &input);
    tuple[WIDTH] = output_lane0;
    return tuple;
}
