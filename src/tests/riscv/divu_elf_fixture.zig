//! The `DIVU` guest: one `div`-family committed row, computing `100 / 2`.
//!
//! `guest_elf_fixture.zig` owns the release ABI wrapper; this module owns only
//! the three instructions that set up and retire the division, plus the
//! architectural facts a divisor-forgery test needs in order to address the
//! committed row without re-deriving them from the encoding.
//!
//! The stream keeps the divisor in a register the `DIVU` row reads as `rs2`, so
//! the committed row carries an honest byte-decomposed divisor
//! (`rs2_next_*` limbs `[2, 0, 0, 0]`). That is the row a divisor-forgery test
//! must start from: the forgery replaces those limbs with `[0, 0, 0, 256]`,
//! whose field value is still `2` because `2^32 == 2 (mod 2^31 - 1)`.

const std = @import("std");
const guest_elf = @import("guest_elf_fixture.zig");

/// `ADDI x8, x0, 100`, `ADDI x9, x0, 2`, `DIVU x10, x8, x9`.
const BODY = [_]u32{
    0x0640_0413,
    0x0020_0493,
    0x0294_5533,
};

/// Position of the `DIVU` in `BODY`, which is what `guest_elf.bodyPc` and
/// `guest_elf.bodyClock` are indexed by.
const DIVU_BODY_INDEX: usize = 2;

/// The instruction body and publish register of this guest, for the shared
/// harness. `divu.RD` is published so the quotient reaches public output.
pub const SPEC = guest_elf.Spec{ .body = &BODY, .publish = divu.RD };

/// The architectural facts of the retired `DIVU`.
pub const divu = struct {
    pub const DIVIDEND: u32 = 100;
    pub const DIVISOR: u32 = 2;
    pub const QUOTIENT: u32 = DIVIDEND / DIVISOR;
    pub const RS1: u5 = 8;
    pub const RS2: u5 = 9;
    pub const RD: u5 = 10;
    /// Program counter of the `DIVU`.
    pub const PC: u32 = guest_elf.bodyPc(DIVU_BODY_INDEX);
    /// One-based execution clock of the `DIVU` row.
    pub const CLOCK: u32 = guest_elf.bodyClock(DIVU_BODY_INDEX);
    /// Index of the `DIVU` in `RunResult.execution_trace.rows`.
    pub const ROW: usize = guest_elf.bodyRow(DIVU_BODY_INDEX);
};

/// Build the guest. The caller owns the returned bytes.
pub fn buildDivuQuotientElf(allocator: std.mem.Allocator) ![]u8 {
    return guest_elf.build(allocator, SPEC);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const runner = @import("../../frontends/riscv/runner/mod.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");

// Runtime: well under a second. The guest retires eleven instructions.
test "divu fixture: the guest retires one div row whose quotient reaches public output" {
    const allocator = std.testing.allocator;
    const elf = try buildDivuQuotientElf(allocator);
    defer allocator.free(elf);

    var run = try runner.runWithInput(
        allocator,
        elf,
        &guest_elf.INPUT,
        guest_elf.maxSteps(SPEC),
    );
    defer run.deinit();

    try std.testing.expectEqual(runner.CompletionReason.halt_flag, run.completion_reason);
    try std.testing.expectEqual(guest_elf.instructionCount(SPEC), run.step_count);
    try std.testing.expectEqual(divu.QUOTIENT, run.final_regs[divu.RD]);

    // Exactly one `div` row, so a div-family probe addresses row 0 unambiguously.
    var counts = try run.execution_trace.groupByOpcodeFamily(allocator);
    try std.testing.expectEqual(@as(usize, 1), counts.get(.div));

    const div_row = run.execution_trace.rows.items[divu.ROW];
    try std.testing.expectEqual(trace_mod.OpcodeFamily.div, try trace_mod.proofOpcodeFamily(div_row.opcode));
    try std.testing.expectEqual(divu.PC, div_row.pc);
    try std.testing.expectEqual(divu.CLOCK, div_row.clk);
    try std.testing.expectEqual(divu.DIVIDEND, div_row.rs1_val);
    try std.testing.expectEqual(divu.DIVISOR, div_row.rs2_val);
    try std.testing.expectEqual(divu.QUOTIENT, div_row.rd_val);

    // The quotient is publicly bound, so a reader of the statement can see the
    // value the forgery tests contradict.
    try std.testing.expectEqual(@as(u32, 4), run.output_len);
    try std.testing.expect(run.output != null);
    try std.testing.expectEqual(
        divu.QUOTIENT,
        std.mem.readInt(u32, run.output.?[0..4], .little),
    );
}
