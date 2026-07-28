//! Stark-V-derived committed trace layouts with reviewed soundness extensions.
//!
//! The family layouts are the macro-expanded `define_trace_tables!` order at
//! `d478f783055aa0d73a93768a433a3c6c31c91d1c` supplies the legacy lineage.
//! Access fields expand in place to ten columns. Families without opcode flags
//! receive a leading enabler; intentional layout divergences are recorded in
//! `conformance/divergence-log.md`.

const base = @import("trace_columns/base.zig");
const compare = @import("trace_columns/compare.zig");
const control = @import("trace_columns/control.zig");
const memory = @import("trace_columns/memory.zig");
const m_extension = @import("trace_columns/m_extension.zig");
const infrastructure = @import("trace_columns/infrastructure.zig");

pub const BaseAluRegColumns = base.BaseAluRegColumns;
pub const BaseAluImmColumns = base.BaseAluImmColumns;
pub const ShiftsRegColumns = base.ShiftsRegColumns;
pub const ShiftsImmColumns = base.ShiftsImmColumns;
pub const LtRegColumns = compare.LtRegColumns;
pub const LtImmColumns = compare.LtImmColumns;
pub const BranchEqColumns = compare.BranchEqColumns;
pub const BranchLtColumns = compare.BranchLtColumns;
pub const LuiColumns = control.LuiColumns;
pub const AuipcColumns = control.AuipcColumns;
pub const JalrColumns = control.JalrColumns;
pub const JalColumns = control.JalColumns;
pub const FenceColumns = control.FenceColumns;
pub const LoadStoreColumns = memory.LoadStoreColumns;

pub const MulColumns = m_extension.MulColumns;
pub const MulhColumns = m_extension.MulhColumns;
pub const DivColumns = m_extension.DivColumns;
pub const ProgramColumns = infrastructure.ProgramColumns;
pub const MemoryCheckColumns = infrastructure.MemoryCheckColumns;
pub const MemClockUpdateColumns = infrastructure.MemClockUpdateColumns;
pub const RegClockUpdateColumns = infrastructure.RegClockUpdateColumns;
pub const MerkleColumns = infrastructure.MerkleColumns;
pub const BitwiseMultiplicity = infrastructure.BitwiseMultiplicity;
pub const RangeCheck20Multiplicity = infrastructure.RangeCheck20Multiplicity;
pub const RangeCheck8_8Multiplicity = infrastructure.RangeCheck8_8Multiplicity;
pub const RangeCheck8_11Multiplicity = infrastructure.RangeCheck8_11Multiplicity;
pub const RangeCheck8_8_4Multiplicity = infrastructure.RangeCheck8_8_4Multiplicity;
pub const RangeCheckM31Multiplicity = infrastructure.RangeCheckM31Multiplicity;
pub const Poseidon2Columns = infrastructure.Poseidon2Columns;

test "opcode-family widths preserve legacy prefixes and sound x0 extensions" {
    const std = @import("std");
    const expected = [_]usize{ 43, 35, 60, 51, 44, 37, 30, 37, 18, 29, 41, 20, 56, 39, 47, 67, 6 };
    const actual = [_]usize{
        BaseAluRegColumns.N_COLUMNS, BaseAluImmColumns.N_COLUMNS,
        ShiftsRegColumns.N_COLUMNS,  ShiftsImmColumns.N_COLUMNS,
        LtRegColumns.N_COLUMNS,      LtImmColumns.N_COLUMNS,
        BranchEqColumns.N_COLUMNS,   BranchLtColumns.N_COLUMNS,
        LuiColumns.N_COLUMNS,        AuipcColumns.N_COLUMNS,
        JalrColumns.N_COLUMNS,       JalColumns.N_COLUMNS,
        LoadStoreColumns.N_COLUMNS,  MulColumns.N_COLUMNS,
        MulhColumns.N_COLUMNS,       DivColumns.N_COLUMNS,
        FenceColumns.N_COLUMNS,
    };
    try std.testing.expectEqualSlices(usize, &expected, &actual);
}

test "total opcode family columns is 660" {
    const std = @import("std");
    const total = BaseAluRegColumns.N_COLUMNS + BaseAluImmColumns.N_COLUMNS +
        ShiftsRegColumns.N_COLUMNS + ShiftsImmColumns.N_COLUMNS +
        LtRegColumns.N_COLUMNS + LtImmColumns.N_COLUMNS +
        BranchEqColumns.N_COLUMNS + BranchLtColumns.N_COLUMNS +
        LuiColumns.N_COLUMNS + AuipcColumns.N_COLUMNS + JalrColumns.N_COLUMNS +
        JalColumns.N_COLUMNS + LoadStoreColumns.N_COLUMNS + MulColumns.N_COLUMNS +
        MulhColumns.N_COLUMNS + DivColumns.N_COLUMNS + FenceColumns.N_COLUMNS;
    try std.testing.expectEqual(@as(usize, 660), total);
}
