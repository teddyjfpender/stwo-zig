//! Query surface over the Sail-derived operand-class corpus.
//!
//! `operand_class_corpus/*.zig` holds, for every opcode, the operand
//! classes the ISA admits and the AIR's structure distinguishes -- sign
//! boundaries, carry chains, zero divisors, shift decomposition edges,
//! alignment lanes, x0 patterns, backward control flow -- each as a
//! self-contained instruction body plus the architectural result the
//! pinned Sail model produced for it. `scripts/riscv_operand_classes.py`
//! documents the derivation, generates the data, and `check`s committed
//! data against regeneration; nothing here re-derives semantics.
//!
//! A coverage test asks for cases instead of hand-picking words:
//!
//!   const srl8 = operand_classes.only(.SRL, .shift_eight);
//!   for (operand_classes.all) |case| ...
//!
//! Bodies obey the guest fixture's register discipline (never x1-x5, only
//! x6/x7/x10/x28-x31), define every register and memory byte they read,
//! and keep control flow inside the body, so `guest_elf_fixture.build`
//! can wrap any of them unchanged. pc-relative expectations are stored as
//! offsets from the retiring pc; `RowCheck.expectedRdValue` re-anchors
//! them at the body's actual placement.

const std = @import("std");
const isa_decode = @import("../../frontends/riscv/isa/decode.zig");

pub const Opcode = isa_decode.Opcode;
pub const Class = @import("operand_class_corpus/tags.zig").Class;

/// One retirement the corpus pins: Sail's destination write, control step,
/// and memory effect for the body instruction at `index`.
pub const RowCheck = struct {
    index: usize,
    rd: u5,
    rd_value: u32,
    /// When set, `rd_value` is Sail's write minus the retiring pc, so the
    /// expectation transfers to wherever the body is placed. Never set for
    /// a discarded link (rd = x0), whose write is absolute zero.
    rd_pc_relative: bool = false,
    /// Sail's next_pc minus pc, wrapping: 4 on straight line, the branch
    /// or jump displacement otherwise.
    next_pc_offset: u32 = 4,
    mem_addr: u32 = 0,
    /// RVFI masks are anchored at the effective (unaligned) address.
    mem_rmask: u4 = 0,
    mem_wmask: u4 = 0,
    mem_rdata: u32 = 0,
    mem_wdata: u32 = 0,

    pub fn expectedRdValue(self: RowCheck, pc: u32) u32 {
        return if (self.rd_pc_relative) pc +% self.rd_value else self.rd_value;
    }

    pub fn expectedNextPc(self: RowCheck, pc: u32) u32 {
        return pc +% self.next_pc_offset;
    }

    pub fn touchesMemory(self: RowCheck) bool {
        return self.mem_rmask != 0 or self.mem_wmask != 0;
    }
};

pub const Case = struct {
    /// "op/class" (plus a variant suffix when one class carries several
    /// witnesses), unique across the corpus.
    name: []const u8,
    op: Opcode,
    class: Class,
    /// Architectural source operand values of the instruction under test,
    /// recovered from Sail's own rd_value stream; zero when the opcode has
    /// no such operand or the operand is pc-derived.
    rs1_val: u32 = 0,
    rs2_val: u32 = 0,
    /// A pc-derived operand (an AUIPC-based JALR base) has no absolute
    /// value that transfers across body placements, so its `rs*_val` is
    /// not comparable; the pc-relative checks pin the behavior instead.
    rs1_pc_derived: bool = false,
    rs2_pc_derived: bool = false,
    /// The instruction words Sail executed, verbatim: embed them unchanged
    /// or the expectations are about a different program.
    body: []const u32,
    /// Index in `body` of the instruction the class is about.
    under_test: usize,
    /// Body indices in Sail's retirement order. A skipped index is the
    /// not-taken arm of a forward branch; order deviating from index order
    /// is backward control flow. Each index retires at most once.
    retired: []const u8,
    /// Always includes `under_test`; store cases add the word read back
    /// through Sail's own load semantics.
    checks: []const RowCheck,

    pub fn underTestCheck(self: *const Case) RowCheck {
        for (self.checks) |check| {
            if (check.index == self.under_test) return check;
        }
        // The generator always pins the under-test retirement; reaching
        // this is corpus corruption, not a test-input condition.
        unreachable;
    }
};

pub const all = @import("operand_class_corpus/alu.zig").cases ++
    @import("operand_class_corpus/shift.zig").cases ++
    @import("operand_class_corpus/cmp_branch.zig").cases ++
    @import("operand_class_corpus/mul_div.zig").cases ++
    @import("operand_class_corpus/mem.zig").cases ++
    @import("operand_class_corpus/flow.zig").cases;

/// The single case of (`op`, `class`), resolved at comptime so a consumer
/// binds its constants to the corpus instead of transcribing them. Refuses
/// ambiguity: a class with several witnesses for one opcode must be chosen
/// by name via `named`.
pub fn only(comptime op: Opcode, comptime class: Class) Case {
    comptime {
        var found: ?Case = null;
        for (all) |case| {
            if (case.op != op or case.class != class) continue;
            if (found != null) {
                @compileError("operand class " ++ @tagName(class) ++ " of " ++
                    @tagName(op) ++ " has several cases; select one with named()");
            }
            found = case;
        }
        return found orelse @compileError("no case of " ++ @tagName(op) ++
            "/" ++ @tagName(class) ++ " in the corpus");
    }
}

/// The case with exactly this name, at comptime.
pub fn named(comptime name: []const u8) Case {
    comptime {
        for (all) |case| {
            if (std.mem.eql(u8, case.name, name)) return case;
        }
        @compileError("no operand-class case named " ++ name);
    }
}

/// How many corpus cases exercise `op`.
pub fn countOf(op: Opcode) usize {
    var count: usize = 0;
    for (all) |case| {
        if (case.op == op) count += 1;
    }
    return count;
}

/// Honest cases the AIR rejects today: real completeness findings this
/// corpus made, kept as data so every consumer handles them the same way.
///
/// Both commit a regular-path unsigned division whose quotient has bit 31
/// set (0x8ABCDEF1 / 1). `div.zig`'s `quotient_sign_range` request exists,
/// per its own comment, to bind the signed `q == 0, sign_xor == 1`
/// ambiguity, but its numerator `valid_not_zero_divisor - b_sign * c_sign`
/// is not gated on `is_signed`: on a DIVU/REMU row the direct constraint
/// `(1 - zero_divisor) * (q_sign - sign_xor) * q_sign` forces `q_sign = 0`,
/// so the request demands `q[3] < 128` and every honest unsigned quotient
/// >= 2^31 asks `range_check_m31` for a tuple that does not exist. The
/// prover itself refuses such a guest while ingesting lookup sources --
/// `operand_class_sweep_test` demonstrates that end to end and fails the
/// moment either row becomes admissible, so an AIR fix must delete these
/// entries in the same change.
pub const KNOWN_COMPLETENESS_REJECTIONS = [_][]const u8{
    "divu/div_divisor_one",
    "remu/div_divisor_one",
};

pub fn isKnownCompletenessRejection(name: []const u8) bool {
    for (KNOWN_COMPLETENESS_REJECTIONS) |known| {
        if (std.mem.eql(u8, known, name)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Corpus self-checks: structure only. Architectural agreement with the
// runner and AIR admissibility live in operand_class_sweep_test.zig.
// ---------------------------------------------------------------------------

// Runtime: milliseconds. Pure data traversal.
test "operand classes: every case is structurally coherent" {
    try std.testing.expect(all.len >= 250);
    for (all) |case| {
        try std.testing.expect(case.body.len > 0);
        try std.testing.expect(case.under_test < case.body.len);
        try std.testing.expect(case.retired.len > 0);
        try std.testing.expect(case.checks.len >= 1);
        var under_test_retired = false;
        for (case.retired) |index| {
            try std.testing.expect(index < case.body.len);
            if (index == case.under_test) under_test_retired = true;
        }
        try std.testing.expect(under_test_retired);
        for (case.checks) |check| {
            try std.testing.expect(check.index < case.body.len);
        }
        _ = case.underTestCheck();
    }
}

// Runtime: milliseconds.
test "operand classes: names are unique so a finding names one case" {
    const allocator = std.testing.allocator;
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    for (all) |case| {
        const entry = try seen.getOrPut(case.name);
        try std.testing.expect(!entry.found_existing);
    }
}

// Runtime: milliseconds. 292 words through the production decoder.
test "operand classes: the production decoder agrees the under-test word is the named opcode" {
    // The corpus was assembled by the generator's encoder and executed by
    // Sail; this closes the triangle with the decoder proofs actually run
    // through, so a corpus case can never silently test a different
    // instruction than its name claims.
    for (all) |case| {
        const decoded = try isa_decode.DecodedInst.decode(case.body[case.under_test]);
        try std.testing.expectEqual(case.op, decoded.opcode);
    }
}

// Runtime: milliseconds.
test "operand classes: comptime selection binds a consumer to the corpus" {
    const srl_eight = comptime only(.SRL, .shift_eight);
    try std.testing.expectEqual(Opcode.SRL, srl_eight.op);
    try std.testing.expectEqual(@as(u32, 8), srl_eight.rs2_val);
    const named_case = comptime named("sra/shift_sign_operand/shift_thirty_one");
    try std.testing.expectEqual(Opcode.SRA, named_case.op);
    try std.testing.expect(named_case.rs1_val >> 31 == 1);
}
