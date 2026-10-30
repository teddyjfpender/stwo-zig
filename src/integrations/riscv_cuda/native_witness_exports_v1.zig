//! Device-code export boundary for the canonical typed RISC-V row writers.
//!
//! The C backend lowers these exact Zig writers; the CUDA build decorates the
//! generated, allocation-free functions as device code. No second handwritten
//! witness recipe or CPU-produced main columns cross this boundary. This is a
//! primitive export, not admission of a complete resident RISC-V prover.
const std = @import("std");
const core = @import("stwo_core");
const trace = @import("stwo_riscv_frontend").runner.trace;
const Opcode = @import("stwo_riscv_frontend").runner.Opcode;
const M31 = core.fields.m31.M31;

pub const VERSION: u32 = 1;
pub const WORDS_PER_ROW: usize = 24;
pub const FAMILY_COUNT = trace.N_FAMILIES;
pub const Family = trace.OpcodeFamily;
pub const TraceRow = trace.TraceRow;
pub const Status = enum(u32) { ok, invalid_encoding, invalid_row, invalid_geometry };

/// Little-endian u32 words, independent of Zig's native TraceRow struct layout.
/// Values are architectural retirement records, not field witness columns.
pub const EncodedRow = [WORDS_PER_ROW]u32;

pub fn encode(row: TraceRow) EncodedRow {
    return .{
        row.clk,           row.pc,                    @intFromEnum(row.opcode),   row.rd,                         row.rs1,           row.rs2,
        @bitCast(row.imm), row.rs1_val,               row.rs2_val,                row.rs1_prev_clk,               row.rs2_prev_clk,  row.rd_prev_val,
        row.rd_prev_clk,   row.rd_val,                row.mem_addr,               row.mem_val,                    row.mem_prev_word, row.mem_next_word,
        row.mem_prev_clk,  @intFromBool(row.is_load), @intFromBool(row.is_store), @intFromBool(row.branch_taken), row.next_pc,       row.inst_word,
    };
}

pub inline fn decode(words: *const EncodedRow) ?TraceRow {
    if (words[2] > @intFromEnum(Opcode.FENCE) or
        words[3] > 31 or words[4] > 31 or words[5] > 31 or
        words[19] > 1 or words[20] > 1 or words[21] > 1)
        return null;
    return .{
        .clk = words[0],
        .pc = words[1],
        .opcode = @enumFromInt(words[2]),
        .rd = @intCast(words[3]),
        .rs1 = @intCast(words[4]),
        .rs2 = @intCast(words[5]),
        .imm = @bitCast(words[6]),
        .rs1_val = words[7],
        .rs2_val = words[8],
        .rs1_prev_clk = words[9],
        .rs2_prev_clk = words[10],
        .rd_prev_val = words[11],
        .rd_prev_clk = words[12],
        .rd_val = words[13],
        .mem_addr = words[14],
        .mem_val = words[15],
        .mem_prev_word = words[16],
        .mem_next_word = words[17],
        .mem_prev_clk = words[18],
        .is_load = words[19] != 0,
        .is_store = words[20] != 0,
        .branch_taken = words[21] != 0,
        .next_pc = words[22],
        .inst_word = words[23],
    };
}

pub fn Writer(comptime family: Family) type {
    return struct {
        pub const column_count: usize = trace.nColumnsForFamily(family);

        pub fn width() callconv(.c) u32 {
            return @intCast(column_count);
        }

        /// Validates before stores. The launcher owns bounds, disjoint buffers,
        /// padding initialization, family ordering and the aggregate status.
        pub fn run(words: *const EncodedRow, output: [*]u32, stride: usize, index: usize) callconv(.c) u32 {
            if (stride == 0 or index >= stride or stride > std.math.maxInt(usize) / column_count)
                return @intFromEnum(Status.invalid_geometry);
            const row = decode(words) orelse return @intFromEnum(Status.invalid_encoding);
            trace.validateFamilyRow(row, family) catch return @intFromEnum(Status.invalid_row);
            var columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
            inline for (0..column_count) |column| {
                const start: [*]M31 = @ptrCast(output + column * stride);
                columns[column] = start[0..stride];
            }
            trace.fillFamilyColumns(&columns, index, row, family);
            return @intFromEnum(Status.ok);
        }
    };
}

pub fn exportDeviceWriters() void {
    comptime {
        @setEvalBranchQuota(2_000_000);
        for (std.enums.values(Family)) |family| {
            @export(&Writer(family).run, .{
                .name = "stwo_riscv_native_row_" ++ @tagName(family) ++ "_v1",
            });
            @export(&Writer(family).width, .{
                .name = "stwo_riscv_native_width_" ++ @tagName(family) ++ "_v1",
            });
        }
    }
}

test "native CUDA row encoding is explicit and rejects narrowed values" {
    var row: EncodedRow = @splat(0);
    row[2] = @intFromEnum(Opcode.ADDI);
    row[6] = @bitCast(@as(i32, -2048));
    try std.testing.expectEqual(@as(i32, -2048), decode(&row).?.imm);
    inline for (.{ 3, 4, 5 }) |index| {
        row[index] = 32;
        try std.testing.expectEqual(@as(?TraceRow, null), decode(&row));
        row[index] = 0;
    }
    inline for (.{ 19, 20, 21 }) |index| {
        row[index] = 2;
        try std.testing.expectEqual(@as(?TraceRow, null), decode(&row));
        row[index] = 0;
    }
    row[2] = 255;
    try std.testing.expectEqual(@as(?TraceRow, null), decode(&row));
}
