//! Width declarations for infrastructure layouts pending schema extraction.

fn OpaqueColumns(comptime n: usize) type {
    return struct {
        pub const N_COLUMNS: usize = n;
    };
}

pub const ProgramColumns = OpaqueColumns(10);
pub const MemoryCheckColumns = OpaqueColumns(9);
pub const MemClockUpdateColumns = OpaqueColumns(7);
pub const RegClockUpdateColumns = OpaqueColumns(7);
pub const MerkleColumns = OpaqueColumns(10);
pub const BitwiseMultiplicity = OpaqueColumns(1);
pub const RangeCheck20Multiplicity = OpaqueColumns(1);
pub const RangeCheck8_8Multiplicity = OpaqueColumns(1);
pub const RangeCheck8_11Multiplicity = OpaqueColumns(1);
pub const RangeCheck8_8_4Multiplicity = OpaqueColumns(1);
pub const RangeCheckM31Multiplicity = OpaqueColumns(1);
pub const Poseidon2Columns = OpaqueColumns(443);
