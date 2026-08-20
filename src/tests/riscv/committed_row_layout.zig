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
//! - access positions come directly from `opcode_memory.accessLayout` — the
//!   verifier's production API — including the six-column source blocks whose
//!   emitted limbs alias their consumed limbs by construction.

const std = @import("std");
const layouts = @import("stwo_riscv_frontend").air.trace_columns;
const opcode_memory = @import("stwo_riscv_frontend").air.opcode_memory;
const semantic_eval = @import("stwo_riscv_frontend").air.semantic_eval;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const isa_decode = @import("stwo_riscv_frontend").isa.decode;

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

pub const AccessMode = opcode_memory.AccessMode;
pub const AccessLayout = opcode_memory.AccessLayout;
pub const accessLayout = opcode_memory.accessLayout;

/// First physical column of an access. This compatibility accessor delegates
/// to the production descriptor; invalid slots terminate the test rather than
/// manufacturing a column index.
pub fn accessOffset(family: OpcodeFamily, slot: usize) usize {
    return requireAccessLayout(family, slot).addressColumn();
}

pub fn previousLimbColumn(family: OpcodeFamily, slot: usize, limb: usize) usize {
    return requireAccessLayout(family, slot).previousLimbColumn(limb) orelse
        @panic("invalid opcode access limb");
}

pub fn nextLimbColumn(family: OpcodeFamily, slot: usize, limb: usize) usize {
    return requireAccessLayout(family, slot).nextLimbColumn(limb) orelse
        @panic("invalid opcode access limb");
}

fn requireAccessLayout(family: OpcodeFamily, slot: usize) AccessLayout {
    return accessLayout(family, slot) orelse @panic("invalid opcode access slot");
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

/// The slot whose emitted value is pinned to the row's computed result rather
/// than to its consumed value, or null when the family writes nothing.
pub fn writtenSlot(family: OpcodeFamily) ?usize {
    return opcode_memory.writtenSlot(family);
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

/// Field-name stem for the production access slot. This deliberately lives in
/// the independent test map: comparing it with `opcode_memory.accessLayout`
/// catches either the production descriptor or a committed struct reorder
/// instead of deriving both sides from the same offset arithmetic.
fn accessPrefix(comptime family: OpcodeFamily, comptime slot: usize) []const u8 {
    return switch (family) {
        .base_alu_reg, .shifts_reg, .lt_reg, .mul, .mulh, .div => switch (slot) {
            0 => "rd",
            1 => "rs1",
            2 => "rs2",
            else => @compileError("invalid three-access slot"),
        },
        .base_alu_imm, .shifts_imm, .lt_imm => switch (slot) {
            0 => "rd",
            1 => "rs1",
            else => @compileError("invalid two-access slot"),
        },
        .branch_eq, .branch_lt => switch (slot) {
            0 => "rs1",
            1 => "rs2",
            else => @compileError("invalid branch access slot"),
        },
        .lui, .auipc, .jal => if (slot == 0)
            "rd"
        else
            @compileError("invalid one-access slot"),
        .jalr => switch (slot) {
            0 => "rd",
            1 => "rs1",
            else => @compileError("invalid jalr access slot"),
        },
        .load_store => switch (slot) {
            0 => "dst",
            1 => "rs1",
            2 => "src",
            else => @compileError("invalid load/store access slot"),
        },
        .fence => @compileError("fence has no access slots"),
    };
}

fn accessFieldColumn(
    comptime family: OpcodeFamily,
    comptime slot: usize,
    comptime suffix: []const u8,
) usize {
    return columnOf(
        family,
        std.fmt.comptimePrint("{s}{s}", .{ accessPrefix(family, slot), suffix }),
    );
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
    try std.testing.expectEqual(
        previousLimbColumn(.base_alu_reg, 1, 0),
        columnOf(.base_alu_reg, "rs1_prev_0"),
    );
    try std.testing.expectEqual(
        previousLimbColumn(.base_alu_reg, 1, 0),
        nextLimbColumn(.base_alu_reg, 1, 0),
    );
    try std.testing.expectEqual(
        accessOffset(.load_store, 2),
        columnOf(.load_store, "src_addr"),
    );
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

test "committed row layout: production access descriptors match every named field" {
    inline for (0..trace_mod.N_FAMILIES) |family_index| {
        const family: OpcodeFamily = comptime @enumFromInt(family_index);
        const access_count = comptime opcode_memory.accessCount(family);
        inline for (0..access_count) |slot| {
            const access = accessLayout(family, slot).?;
            try std.testing.expectEqual(
                accessFieldColumn(family, slot, "_addr"),
                access.addressColumn(),
            );
            try std.testing.expectEqual(
                accessFieldColumn(family, slot, "_prev_0"),
                access.previousLimbColumn(0).?,
            );
            try std.testing.expectEqual(
                accessFieldColumn(family, slot, "_clock_prev"),
                access.previousClockColumn(),
            );
            if (access.aliasesEmittedValue()) {
                try std.testing.expectEqual(access.previousColumns(), access.nextColumns());
            } else {
                try std.testing.expectEqual(
                    accessFieldColumn(family, slot, "_next_0"),
                    access.nextLimbColumn(0).?,
                );
                try std.testing.expectEqual(
                    accessFieldColumn(family, slot, "_next_3"),
                    access.nextLimbColumn(3).?,
                );
            }
        }
    }
}
