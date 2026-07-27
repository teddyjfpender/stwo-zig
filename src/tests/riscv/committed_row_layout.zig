//! Where each protocol object lives inside a committed opcode-family row.
//!
//! The AIR reads a family row through hand-written column indices spread across
//! `semantics/*.zig` and `opcode_memory.zig`. An adversarial test that wants to
//! perturb "the opcode selector" or "this access's emitted value" needs the same
//! map, and a test carrying its own magic numbers silently rots against a layout
//! change. So this module derives the map from the committed layout structs and
//! the AIR's own public accessors, and the derivation is checked rather than
//! asserted:
//!
//! - the selector block is located by scanning `opcode_*_flag` fields of the
//!   layout struct, and `selectorOpcodes` is verified against the corpus by
//!   `witness_rigidity_test.zig` (on each honest row exactly the selector named
//!   for the executed opcode must be one);
//! - the access block offsets mirror the private `opcode_memory.accessOffset`
//!   and are bound to `opcode_memory.accessFromMain` — the verifier's own layout
//!   map — by the sentinel test in `witness_rigidity_test.zig`.

const std = @import("std");
const layouts = @import("../../frontends/riscv/air/trace_columns.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");
const isa_decode = @import("../../frontends/riscv/isa/decode.zig");

const OpcodeFamily = trace_mod.OpcodeFamily;
const Opcode = isa_decode.Opcode;

/// `load_store` has the widest selector block: five loads and three stores.
pub const MAX_SELECTORS: usize = 8;

/// The `opcode_*_flag` block of one family, bound to architectural opcodes.
pub const SelectorLayout = struct {
    base: usize,
    opcodes: [MAX_SELECTORS]Opcode = .{.ADD} ** MAX_SELECTORS,
    len: usize,

    pub fn column(self: SelectorLayout, index: usize) usize {
        return self.base + index;
    }

    pub fn indexOf(self: SelectorLayout, opcode: Opcode) ?usize {
        for (self.opcodes[0..self.len], 0..) |candidate, index| {
            if (candidate == opcode) return index;
        }
        return null;
    }
};

/// Selector block of every family, indexed by `@intFromEnum(family)`.
pub const SELECTORS: [trace_mod.N_FAMILIES]SelectorLayout = blk: {
    var table: [trace_mod.N_FAMILIES]SelectorLayout = undefined;
    for (0..trace_mod.N_FAMILIES) |index| table[index] = selectorLayout(@enumFromInt(index));
    break :blk table;
};

/// Committed access blocks are ten contiguous columns — `addr`, four `previous`
/// limbs, `previous_clock`, four `next` limbs — packed immediately after the
/// clock and pc columns. Mirrors the private `opcode_memory.accessOffset`.
pub fn accessOffset(family: OpcodeFamily, slot: usize) usize {
    return semantic_eval.pcColumn(family) + 1 + slot * 10;
}

pub fn previousLimbColumn(family: OpcodeFamily, slot: usize, limb: usize) usize {
    return accessOffset(family, slot) + 1 + limb;
}

pub fn nextLimbColumn(family: OpcodeFamily, slot: usize, limb: usize) usize {
    return accessOffset(family, slot) + 6 + limb;
}

/// Column index of the named field of `family`'s committed layout struct.
///
/// The accessors above cover the objects every family shares. A family's own
/// witness columns — `div`'s `q_*`, `r_abs_*`, `lt_diff` and inverses — have no
/// such accessor, and their only map is the layout struct's field order, which
/// `selectorLayout` already relies on and which the test below binds to the
/// AIR's own `clockColumn` and `pcColumn` for every family. Addressing them by
/// name rather than by a literal means a renamed or reordered column is a
/// compile error instead of a probe silently landing on its neighbour.
pub fn columnOf(comptime family: OpcodeFamily, comptime name: []const u8) usize {
    return comptime found: {
        for (@typeInfo(LayoutFor(family)).@"struct".fields, 0..) |field, index| {
            if (std.mem.eql(u8, field.name, name)) break :found index;
        }
        @compileError("no committed column named '" ++ name ++ "' in " ++
            @typeName(LayoutFor(family)));
    };
}

/// The slot whose `next` is pinned to the row's computed result rather than to
/// its own `previous`, or null when the family writes nothing. Mirrors
/// `opcode_memory.accessKind`: slot 0 is `rd` for every writing family and
/// `dst` for `load_store`; branches and `fence` write no register or memory.
pub fn writtenSlot(family: OpcodeFamily) ?usize {
    return switch (family) {
        .branch_eq, .branch_lt, .fence => null,
        else => 0,
    };
}

/// Architectural opcode behind each `opcode_*_flag` column, in layout order.
///
/// The layout field names are not usable keys: `base_alu_imm` calls its `ADDI`
/// selector `opcode_add_flag`, and `branch_lt` orders its flags differently from
/// the protocol-ID order in `opcode_manifest`. So the binding is written out
/// here and verified against real traces by the caller.
fn selectorOpcodes(comptime family: OpcodeFamily) []const Opcode {
    return switch (family) {
        .base_alu_reg => &.{ .ADD, .SUB, .XOR, .OR, .AND },
        .base_alu_imm => &.{ .ADDI, .XORI, .ORI, .ANDI },
        .shifts_reg => &.{ .SLL, .SRL, .SRA },
        .shifts_imm => &.{ .SLLI, .SRLI, .SRAI },
        .lt_reg => &.{ .SLT, .SLTU },
        .lt_imm => &.{ .SLTI, .SLTIU },
        .branch_eq => &.{ .BEQ, .BNE },
        .branch_lt => &.{ .BLT, .BLTU, .BGE, .BGEU },
        .load_store => &.{ .LB, .LH, .LBU, .LHU, .LW, .SB, .SH, .SW },
        .mulh => &.{ .MULH, .MULHSU, .MULHU },
        .div => &.{ .DIV, .DIVU, .REM, .REMU },
        // Single-opcode families have no selector to relabel.
        .lui, .auipc, .jalr, .jal, .mul, .fence => &.{},
    };
}

fn LayoutFor(comptime family: OpcodeFamily) type {
    return switch (family) {
        .base_alu_reg => layouts.BaseAluRegColumns,
        .base_alu_imm => layouts.BaseAluImmColumns,
        .shifts_reg => layouts.ShiftsRegColumns,
        .shifts_imm => layouts.ShiftsImmColumns,
        .lt_reg => layouts.LtRegColumns,
        .lt_imm => layouts.LtImmColumns,
        .branch_eq => layouts.BranchEqColumns,
        .branch_lt => layouts.BranchLtColumns,
        .lui => layouts.LuiColumns,
        .auipc => layouts.AuipcColumns,
        .jalr => layouts.JalrColumns,
        .jal => layouts.JalColumns,
        .load_store => layouts.LoadStoreColumns,
        .mul => layouts.MulColumns,
        .mulh => layouts.MulhColumns,
        .div => layouts.DivColumns,
        .fence => layouts.FenceColumns,
    };
}

fn selectorLayout(comptime family: OpcodeFamily) SelectorLayout {
    @setEvalBranchQuota(20_000);
    const opcodes = selectorOpcodes(family);
    var base: usize = 0;
    var len: usize = 0;
    for (@typeInfo(LayoutFor(family)).@"struct".fields, 0..) |field, index| {
        if (!std.mem.startsWith(u8, field.name, "opcode_")) continue;
        if (!std.mem.endsWith(u8, field.name, "_flag")) continue;
        if (len == 0) base = index;
        // Callers address selectors as `base + i`; a gap in the flag block would
        // silently point a probe at an unrelated column.
        if (index != base + len) @compileError("non-contiguous selector block");
        len += 1;
    }
    if (len != opcodes.len) @compileError("selector opcode table does not match the layout");
    var result = SelectorLayout{ .base = base, .len = len };
    for (opcodes, 0..) |opcode, index| result.opcodes[index] = opcode;
    return result;
}

test "committed row layout: named columns agree with the AIR's own accessors" {
    // `columnOf` is only sound if the layout struct's field order is the
    // committed column order. The AIR states that order independently for the
    // two columns every family has, so agreeing with both on all seventeen
    // families is the derivation check, not an assumption.
    inline for (0..trace_mod.N_FAMILIES) |index| {
        const family: OpcodeFamily = @enumFromInt(index);
        try std.testing.expectEqual(
            semantic_eval.clockColumn(family),
            columnOf(family, "clock"),
        );
        try std.testing.expectEqual(semantic_eval.pcColumn(family), columnOf(family, "pc"));
    }
    // The access-block arithmetic and the selector scan must land on the same
    // columns the field names do.
    try std.testing.expectEqual(
        previousLimbColumn(.div, 2, 0),
        columnOf(.div, "rs2_prev_0"),
    );
    try std.testing.expectEqual(nextLimbColumn(.div, 2, 3), columnOf(.div, "rs2_next_3"));
    const div_selectors = SELECTORS[@intFromEnum(OpcodeFamily.div)];
    try std.testing.expectEqual(
        div_selectors.column(div_selectors.indexOf(.DIVU).?),
        columnOf(.div, "opcode_divu_flag"),
    );
}

test "committed row layout: every selector column lies inside its family" {
    for (0..trace_mod.N_FAMILIES) |index| {
        const family: OpcodeFamily = @enumFromInt(index);
        const selectors = SELECTORS[index];
        for (0..selectors.len) |slot| {
            try std.testing.expect(
                selectors.column(slot) < trace_mod.nColumnsForFamily(family),
            );
        }
    }
}
