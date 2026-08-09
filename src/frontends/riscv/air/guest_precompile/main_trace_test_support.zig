//! Production-shaped fixtures for the C-007 main-trace evidence.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const trace = @import("../../runner/trace.zig");
const permutation = @import("../memory_commitment/poseidon2.zig");
const statement_mod = @import("../statement.zig");

pub const RiscVStatement = statement_mod.RiscVStatement;
pub const FrozenCalls = call_buffer.Frozen;
pub const FrozenExecutionRows = guest_runner.FrozenExecutionRows;

pub const OwnedLogs = struct {
    calls: FrozenCalls,
    rows: FrozenExecutionRows,

    pub fn deinit(self: *OwnedLogs) void {
        self.rows.deinit();
        self.calls.deinit();
        self.* = undefined;
    }
};

pub fn coreFixture(n_guest: u32) RiscVStatement {
    const total_steps = 3 + n_guest;
    var result: RiscVStatement = undefined;
    result.n_components = 1;
    result.component_descs[0] = .{
        .family = .fence,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = trace.nColumnsForFamily(.fence),
    };
    result.initial_pc = 0x1000;
    result.final_pc = 0x1000 + 4 * total_steps;
    result.total_steps = total_steps;
    result.public_data = .{
        .initial_pc = result.initial_pc,
        .final_pc = result.final_pc,
        .clock = total_steps,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = 7,
        .initial_rw_root = if (n_guest == 0) null else 11,
        .final_rw_root = if (n_guest == 0) null else 13,
        .completion = null,
        .io_entries = .{
            .input_start = 0,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_words = &.{},
        },
    };
    result.n_infra = 3;
    result.infra_descs[0] = .{
        .kind = .program,
        .log_size = 3,
        .n_rows = 7,
        .n_columns = 10,
    };
    result.infra_descs[1] = .{
        .kind = .memory,
        .log_size = 4,
        .n_rows = 11,
        .n_columns = 8,
    };
    result.infra_descs[2] = .{
        .kind = .clock_update,
        .log_size = 4,
        .n_rows = 2,
        .n_columns = 10,
    };
    return result;
}

pub fn logsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) !OwnedLogs {
    var call_storage: std.ArrayList(call_buffer.Record) = .empty;
    errdefer call_storage.deinit(allocator);
    var row_storage: std.ArrayList(guest_runner.ExecutionRow) = .empty;
    errdefer row_storage.deinit(allocator);
    try call_storage.ensureTotalCapacity(allocator, count);
    try row_storage.ensureTotalCapacity(allocator, count);

    for (0..count) |index| {
        const clock: u32 = @intCast(index + 1);
        var input: [call_buffer.lane_count]u32 = undefined;
        for (&input, 0..) |*word, lane| {
            // The first two records intentionally have an identical function
            // tuple; later records remain distinct markers for placement.
            const call_marker = if (index < 2) 0 else index;
            word.* = @intCast(call_marker * 257 + lane);
        }
        input[0] = 0;
        input[1] = 1;
        input[2] = M31.fromCanonical(0x7fff_fffe).toU32();

        var state: permutation.State = undefined;
        for (&state, input) |*felt, word| felt.* = M31.fromCanonical(word);
        permutation.permute(&state);
        var output: [call_buffer.lane_count]u32 = undefined;
        for (&output, state) |*word, felt| word.* = felt.toU32();

        const pointer_previous = if (index == 0)
            0
        else
            access_clock.encode(clock - 1, .first);
        const memory_previous = if (index == 0)
            0
        else
            access_clock.encode(clock - 1, .second);
        const record = call_buffer.Record{
            .execution_clock = clock,
            .pc = 0x1000 + 4 * clock,
            .state_ptr = 0x2000,
            .pointer_register = 5,
            .pointer_previous_clock = pointer_previous,
            .input = input,
            .output = output,
            .memory_previous_clocks = .{memory_previous} ** call_buffer.lane_count,
        };
        call_storage.appendAssumeCapacity(record);
        row_storage.appendAssumeCapacity(.{
            .execution_clock = record.execution_clock,
            .pc = record.pc,
            .inst_word = custom0.encodePoseidon2(record.pointer_register),
            .call_index = @intCast(index),
        });
    }

    return .{
        .calls = .{
            .storage = call_storage,
            .allocator = allocator,
            .allocation_growths = @intFromBool(count != 0),
        },
        .rows = .{
            .storage = row_storage,
            .allocator = allocator,
        },
    };
}

pub fn independentCanonicalMaterializations(word: u32) [4]M31 {
    const raw = [4]u32{
        word & 0xff,
        (word >> 8) & 0xff,
        (word >> 16) & 0xff,
        (word >> 24) & 0xff,
    };
    const d0 = M31.fromCanonical(raw[0]).sub(M31.fromCanonical(255));
    const d1 = M31.fromCanonical(raw[1]).sub(M31.fromCanonical(255));
    const d2 = M31.fromCanonical(raw[2]).sub(M31.fromCanonical(255));
    const d3 = M31.fromCanonical(raw[3]).sub(M31.fromCanonical(127));
    const s0 = d0.mul(d0).add(d1.mul(d1));
    const s1 = d2.mul(d2).add(d3.mul(d3));
    const nz = s0.mul(s0).add(s1.mul(s1));
    return .{ s0, s1, nz, nz.invUncheckedNonZero() };
}
