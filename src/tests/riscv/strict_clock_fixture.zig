//! Canonical strict register clocks for hand-written test traces.
//!
//! Runner-produced traces already use `runner/access_witness.zig`. Synthetic
//! tests that construct `TraceRow` values directly use this small mirror so
//! their predecessor clocks follow the same source-before-destination order.

const access_clock = @import("stwo_riscv_frontend").access_clock;
const decode = @import("stwo_riscv_frontend").runner.decode;
const trace = @import("stwo_riscv_frontend").runner.trace;

pub fn assignRegisterClocks(rows: []trace.TraceRow) void {
    var last_clock = [_]u32{0} ** 32;
    for (rows) |*row| {
        const usage = decode.operandUsage(row.opcode);
        var ordinal: u2 = 0;
        if (usage.reads_rs1) {
            row.rs1_prev_clk = last_clock[row.rs1];
            last_clock[row.rs1] = access_clock.encode(
                row.clk,
                @enumFromInt(ordinal),
            );
            ordinal += 1;
        } else {
            row.rs1_prev_clk = 0;
        }
        if (usage.reads_rs2) {
            row.rs2_prev_clk = last_clock[row.rs2];
            last_clock[row.rs2] = access_clock.encode(
                row.clk,
                @enumFromInt(ordinal),
            );
            ordinal += 1;
        } else {
            row.rs2_prev_clk = 0;
        }
        if (usage.writes_rd) {
            row.rd_prev_clk = last_clock[row.rd];
            last_clock[row.rd] = access_clock.encode(
                row.clk,
                @enumFromInt(ordinal),
            );
        } else {
            row.rd_prev_clk = 0;
        }
    }
}
