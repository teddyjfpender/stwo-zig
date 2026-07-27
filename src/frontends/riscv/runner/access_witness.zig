//! Oracle-aligned register access ordering for RV32IM trace witnesses.

const decode = @import("decode.zig");
const state_chain = @import("state_chain.zig");
const access_clock = @import("../access_clock.zig");

const DecodedInst = decode.DecodedInst;

const Plan = decode.OperandUsage;

pub const Witness = struct {
    rs1_prev_clock: u32,
    rs2_prev_clock: u32,
    rd_prev_clock: u32,
    rs1_clock: u32,
    rs2_clock: u32,
    rd_clock: u32,
    plan: Plan,

    pub fn recordRegisters(
        self: Witness,
        tracker: *state_chain.StateChainTracker,
        inst: DecodedInst,
        rs1_value: u32,
        rs2_value: u32,
        rd_previous_value: u32,
        rd_value: u32,
    ) !void {
        if (self.plan.reads_rs1)
            try tracker.recordRegAccess(inst.rs1, self.rs1_clock, rs1_value);
        if (self.plan.reads_rs2)
            try tracker.recordRegAccess(inst.rs2, self.rs2_clock, rs2_value);
        if (self.plan.writes_rd) {
            try tracker.recordRegTransition(
                inst.rd,
                self.rd_clock,
                rd_previous_value,
                rd_value,
            );
        }
    }
};

/// Capture previous clocks in strict source-before-destination access order.
pub fn capture(
    tracker: *const state_chain.StateChainTracker,
    inst: DecodedInst,
    instruction_clock: u32,
) Witness {
    const plan = decode.operandUsage(inst.opcode);
    var next_ordinal: u2 = 0;
    const rs1_clock = if (plan.reads_rs1) blk: {
        defer next_ordinal += 1;
        break :blk access_clock.encode(instruction_clock, @enumFromInt(next_ordinal));
    } else 0;
    const rs2_clock = if (plan.reads_rs2) blk: {
        defer next_ordinal += 1;
        break :blk access_clock.encode(instruction_clock, @enumFromInt(next_ordinal));
    } else 0;
    const rd_clock = if (plan.writes_rd)
        access_clock.encode(instruction_clock, @enumFromInt(next_ordinal))
    else
        0;

    const rs1_prev = if (plan.reads_rs1)
        state_chain.StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[inst.rs1],
            rs1_clock,
        )
    else
        0;
    const rs2_prev = if (!plan.reads_rs2)
        0
    else if (plan.reads_rs1 and inst.rs2 == inst.rs1)
        rs1_clock
    else
        state_chain.StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[inst.rs2],
            rs2_clock,
        );
    const rd_prev = if (!plan.writes_rd)
        0
    else if (plan.reads_rs2 and inst.rd == inst.rs2)
        rs2_clock
    else if (plan.reads_rs1 and inst.rd == inst.rs1)
        rs1_clock
    else
        state_chain.StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[inst.rd],
            rd_clock,
        );
    return .{
        .rs1_prev_clock = rs1_prev,
        .rs2_prev_clock = rs2_prev,
        .rd_prev_clock = rd_prev,
        .rs1_clock = rs1_clock,
        .rs2_clock = rs2_clock,
        .rd_clock = rd_clock,
        .plan = plan,
    };
}

test "access witness: aliased ADDI chains source before destination" {
    const std = @import("std");
    var tracker = state_chain.StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    tracker.reg_last_clk[1] = 7;

    const inst = try DecodedInst.decode(0x0010_8093); // ADDI x1, x1, 1
    const witness = capture(&tracker, inst, 8);
    try std.testing.expectEqual(@as(u32, 7), witness.rs1_prev_clock);
    try std.testing.expectEqual(@as(u32, 29), witness.rd_prev_clock);
    try witness.recordRegisters(&tracker, inst, 5, 0, 5, 6);
    try std.testing.expectEqual(@as(usize, 2), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 29), tracker.accesses.items[1].clk_prev);
    try std.testing.expectEqual(@as(u32, 30), tracker.accesses.items[1].clk);
}

test "access witness: store reads two sources and does not write rd" {
    const std = @import("std");
    var tracker = state_chain.StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();

    const inst = try DecodedInst.decode(0x0011_2023); // SW x1, 0(x2)
    const witness = capture(&tracker, inst, 3);
    try witness.recordRegisters(&tracker, inst, 0x100, 0x55, 0, 0);
    try std.testing.expectEqual(@as(usize, 2), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 2), tracker.accesses.items[0].addr);
    try std.testing.expectEqual(@as(u32, 1), tracker.accesses.items[1].addr);
    try std.testing.expectEqual(@as(u32, 9), tracker.accesses.items[0].clk);
    try std.testing.expectEqual(@as(u32, 10), tracker.accesses.items[1].clk);
}

test "access witness: aliased ADD sources advance through distinct subclocks" {
    const std = @import("std");
    var tracker = state_chain.StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    tracker.reg_last_clk[1] = 3;

    const inst = try DecodedInst.decode(0x0010_81b3); // ADD x3, x1, x1
    const witness = capture(&tracker, inst, 2);
    try std.testing.expectEqual(@as(u32, 3), witness.rs1_prev_clock);
    try std.testing.expectEqual(@as(u32, 5), witness.rs2_prev_clock);
    try std.testing.expectEqual(@as(u32, 5), witness.rs1_clock);
    try std.testing.expectEqual(@as(u32, 6), witness.rs2_clock);
}
