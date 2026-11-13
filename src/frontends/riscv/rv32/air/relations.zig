//! LogUp relation definitions for the RISC-V AIR.
//!
//! Each relation defines a virtual bus used by LogUp to connect components.
//! Relation IDs are hashed constants (M31) that uniquely identify each bus.
//! N_FIELDS specifies the number of field elements in each bus entry.
//!
//! Ported from stark-v's relation system for RV32IM.

const M31 = @import("stwo_core").fields.m31.M31;

/// CPU state transition bus: (pc, clk, regs...).
/// Connects opcode components to the CPU scheduling logic.
pub const OpcodeRelation = struct {
    /// Hashed relation identifier.
    pub const ID: M31 = M31.fromCanonical(428564188);
    /// Fields: pc, clk.
    pub const N_FIELDS: usize = 2;
};

/// Memory read/write bus: (addr_space, addr, clk, limb_0, limb_1, limb_2, limb_3).
/// addr_space distinguishes register file (0) from data memory (1).
pub const MemoryAccessRelation = struct {
    pub const ID: M31 = M31.fromCanonical(1444891767);
    /// Fields: addr_space, addr, clk, limb_0, limb_1, limb_2, limb_3.
    pub const N_FIELDS: usize = 7;
};

/// Register read/write bus: (addr_space=0, reg_id, clk, value).
/// Specialization of memory access for the 32 general-purpose registers.
pub const RegisterAccessRelation = struct {
    pub const ID: M31 = M31.fromCanonical(1662111297);
    /// Fields: reg_id, clk, value.
    pub const N_FIELDS: usize = 3;
};

/// Program ROM lookup: (pc, instruction_word).
/// Proves that the instruction at a given PC matches the loaded program.
pub const ProgramLookupRelation = struct {
    pub const ID: M31 = M31.fromCanonical(517791011);
    /// Fields: pc, instruction_word.
    pub const N_FIELDS: usize = 2;
};

/// Bitwise lookup table: supports AND, OR, XOR on 8-bit limbs.
/// The table contains all (a, b, a&b, a|b, a^b) tuples for 0 <= a,b < 256.
pub const BitwiseRelation = struct {
    pub const ID: M31 = M31.fromCanonical(892401537);
    /// Fields: a, b, and_result, or_result, xor_result.
    pub const N_FIELDS: usize = 5;
};

/// 20-bit range check: proves 0 <= x < 2^20.
/// Used for clock difference checks in memory consistency arguments.
pub const RangeCheck20Relation = struct {
    pub const ID: M31 = M31.fromCanonical(301925081);
    /// Fields: value.
    pub const N_FIELDS: usize = 1;
};

/// Two 8-bit limb range check: proves 0 <= a < 256 and 0 <= b < 256.
/// Used for byte decomposition in ALU operations.
pub const RangeCheck8_8Relation = struct {
    pub const ID: M31 = M31.fromCanonical(574329614);
    /// Fields: a, b.
    pub const N_FIELDS: usize = 2;
};

/// 8-bit + 11-bit range check: proves 0 <= a < 256 and 0 <= b < 2048.
/// Used for shift amount decomposition (5-bit shift in 32-bit word).
pub const RangeCheck8_11Relation = struct {
    pub const ID: M31 = M31.fromCanonical(739201455);
    /// Fields: a, b.
    pub const N_FIELDS: usize = 2;
};

/// Byte decomposition range check: proves three limbs in range.
/// 0 <= a < 256, 0 <= b < 256, 0 <= c < 16.
/// Used for load/store byte extraction.
pub const RangeCheck8_8_4Relation = struct {
    pub const ID: M31 = M31.fromCanonical(1023847291);
    /// Fields: a, b, c.
    pub const N_FIELDS: usize = 3;
};

/// M31 range check: proves 0 <= x < P (the Mersenne-31 prime).
/// Used for multiplication and division overflow handling.
pub const RangeCheckM31Relation = struct {
    pub const ID: M31 = M31.fromCanonical(1198234567);
    /// Fields: value.
    pub const N_FIELDS: usize = 1;
};

test "relation IDs are distinct" {
    const ids = [_]u32{
        OpcodeRelation.ID.v,
        MemoryAccessRelation.ID.v,
        RegisterAccessRelation.ID.v,
        ProgramLookupRelation.ID.v,
        BitwiseRelation.ID.v,
        RangeCheck20Relation.ID.v,
        RangeCheck8_8Relation.ID.v,
        RangeCheck8_11Relation.ID.v,
        RangeCheck8_8_4Relation.ID.v,
        RangeCheckM31Relation.ID.v,
    };
    // Check all pairs are distinct.
    for (ids, 0..) |a, i| {
        for (ids[i + 1 ..]) |b| {
            try @import("std").testing.expect(a != b);
        }
    }
}
