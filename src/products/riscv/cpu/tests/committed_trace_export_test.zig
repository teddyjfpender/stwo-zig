//! Exports real proving runs for the independent Python row checker
//! (`scripts/air_satisfaction.py`), and pins what each exported run is.
//!
//! The checker's value is that it shares no code with the Zig evaluator, so its
//! input has to be a trace Zig actually committed rather than one assembled for
//! it. Every file below therefore comes out of `Guest.proveCapturing`, i.e. out
//! of the production proving transaction, with the export taken between Tree 2
//! and proof assembly. See `prover/test_trace_dump.zig` for exactly which
//! buffers that reads and what "committed" does and does not mean there.
//!
//! Three runs, because a checker that has only ever seen a satisfying trace is
//! not evidence:
//!
//!  - `honest.json` — the guest proves and verifies. The checker must report
//!    every row satisfied, every activated table request in its table, and a
//!    zero global LogUp sum.
//!  - `forged_bitwise_result.json` — `bitwise_result_soundness_test.zig`'s
//!    forgery, whose whole guard is one preprocessed table request. Every direct
//!    constraint still vanishes, so the checker must report a LOOKUP violation
//!    and a non-zero global sum, and must not report a constraint violation.
//!  - `forged_addi_limb.json` — one destination limb of the body `ADDI` raised
//!    by one. That breaks the byte-carry chain directly, so the checker must
//!    report a CONSTRAINT violation. Proving refuses this row before a proof
//!    exists, which is why the export is taken before proof assembly: the file
//!    still has to describe the witness the prover committed.
//!
//! The assertions here are only about the export and the pipeline's verdict.
//! What the checker makes of the files is asserted in Python, by
//! `scripts/tests/test_air_satisfaction.py`.
//!
//! Runtime: about a minute and a half — three proofs of a ten-instruction guest
//! at three FRI queries, two of which also verify. Bounded by construction: the
//! guest is fixed and retires ten instructions.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const component_order = @import("stwo_riscv_frontend").air.component_order;
const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");

/// Where `air_satisfaction.py` expects to find the exports. Alongside
/// `zig-out/uniqueness-ir/`, which the checker reads in the same run.
const DIR = "zig-out/committed-trace";

/// `ADDI x6, x0, 15`, `XOR x0, x5, x6` — `bitwise_result_soundness_test.zig`'s
/// body, reused so the forged export below is a forgery whose attribution that
/// module already establishes row-locally.
const BODY = [_]u32{ 0x00F0_0313, 0x0062_C033 };
const SPEC = harness.Spec{ .body = &BODY, .publish = 6 };

const OPERAND: u32 = std.mem.readInt(u32, &guest_elf.INPUT, .little);
const MASK: u32 = 15;
const FORGED_XOR_LIMB: u32 = ((OPERAND ^ MASK) & 0xff) ^ 1;

const RESULT_0 = layout.columnOf(.base_alu_reg, "result_0");
const RD_NEXT_0 = layout.nextLimbColumn(.base_alu_imm, 0, 0);

/// One straight-line retirement from every one of the 17 proof families.
/// `JAL x0, +4` deliberately targets its successor. The final AUIPC/ADDI/JALR
/// trio computes the instruction after JALR without relying on host addresses.
const ALL_FAMILY_BODY = [_]u32{
    0x0070_0313, // ADDI x6, x0, 7
    0x0030_0393, // ADDI x7, x0, 3
    0x0073_0433, // ADD x8, x6, x7
    0x0003_0263, // BEQ x6, x0, +4 (not taken)
    0x0003_4263, // BLT x6, x0, +4 (not taken)
    0x0273_44B3, // DIV x9, x6, x7
    0x0040_006F, // JAL x0, +4
    0x0083_2513, // SLTI x10, x6, 8
    0x0063_A5B3, // SLT x11, x7, x6
    0x0273_0633, // MUL x12, x6, x7
    0x0273_16B3, // MULH x13, x6, x7
    0x0023_1713, // SLLI x14, x6, 2
    0x0073_17B3, // SLL x15, x6, x7
    0x0FF0_000F, // FENCE
    0x0000_0817, // AUIPC x16, 0
    0x00C8_0813, // ADDI x16, x16, 12
    0x0008_0067, // JALR x0, x16, 0
};

fn exportRun(
    guest: *const harness.Guest,
    mutation: ?harness.Mutation,
    name: []const u8,
) !harness.Outcome {
    var dump = harness.TraceDump.init(std.testing.allocator);
    defer dump.deinit();
    const outcome = try guest.proveCapturing(mutation, &dump);
    // Written on every outcome. A run the prover refused still committed the
    // witness the checker has to be able to read.
    try dump.writeTo(DIR, name);
    return outcome;
}

// Runtime: about 30 s. One proof and one verification of a ten-instruction guest.
test "committed trace export: an honest run exports and verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    try std.testing.expectEqual(
        harness.Outcome.verified,
        try exportRun(&guest, null, "honest.json"),
    );
}

// Runtime: about 30 s. One proof covers exactly the 17 opcode component kinds
// plus the 11 infrastructure kinds in the canonical transcript registry.
test "committed trace export: all 28 transcript component kinds export and verify" {
    const spec = harness.Spec{ .body = &ALL_FAMILY_BODY, .publish = 10 };
    var guest = try harness.Guest.init(std.testing.allocator, spec);
    defer guest.deinit();

    for (component_order.opcodeFamilies()) |family| {
        try std.testing.expect(try guest.familyRowCount(family) > 0);
    }
    var dump = harness.TraceDump.init(std.testing.allocator);
    defer dump.deinit();
    try std.testing.expectEqual(harness.Outcome.verified, try guest.proveCapturing(null, &dump));
    try std.testing.expectEqual(component_order.OPCODE_FAMILY_COUNT, dump.nOpcodeComponents());
    try std.testing.expectEqual(@as(usize, 11), dump.nInfraComponents());
    try std.testing.expectEqual(component_order.TRANSCRIPT_COMPONENT_COUNT, dump.nMainComponents());
    try dump.writeTo(DIR, "all_families.json");
    try guest.requireSailAgreement("committed-trace all-family guest");
}

// Runtime: about 30 s. One proof and one failed verification.
test "committed trace export: the forged bitwise result exports and loses at verification" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    const values = [_]harness.ColumnValue{
        .{ .column = RESULT_0, .value = FORGED_XOR_LIMB },
    };
    const override = harness.RowOverride{
        .target = .{ .opcode = .{ .family = .base_alu_reg } },
        .logical_row = 0,
        .values = &values,
    };
    try std.testing.expectEqual(
        harness.Outcome.rejected_verification,
        try exportRun(&guest, .{ .main_row = override }, "forged_bitwise_result.json"),
    );
}

// Runtime: about 30 s. One refused proof; no verification runs.
test "committed trace export: a forged ADDI destination limb exports and is refused by proving" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // Read the honest limb rather than transcribing it, so the forgery stays
    // "one more than the truth" if witness generation moves.
    const honest = try guest.honestRow(.base_alu_imm, 0);
    const forged = honest.m31At(RD_NEXT_0).add(M31.one());
    const values = [_]harness.ColumnValue{
        .{ .column = @intCast(RD_NEXT_0), .value = forged.toU32() },
    };
    const override = harness.RowOverride{
        .target = .{ .opcode = .{ .family = .base_alu_imm } },
        .logical_row = 0,
        .values = &values,
    };
    try std.testing.expectEqual(
        harness.Outcome.rejected_proving,
        try exportRun(&guest, .{ .main_row = override }, "forged_addi_limb.json"),
    );
}
