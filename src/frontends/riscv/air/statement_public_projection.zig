//! Canonical native public-data projection of an authenticated segment wire.
const public_data_v1 = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
pub const Error = public_data_v2.Error || error{NonScalarProgramRoot};

pub fn canonicalCorePublicData(
    data: *const public_data_v2.PublicDataV2,
) Error!public_data_v1.PublicData {
    const metadata = try data.metadata();
    const cycle_count = metadata.global_cycle_end - metadata.global_cycle_start;
    const completion: ?public_data_v1.Completion = if (metadata.completion) |value|
        .{
            .kind = @enumFromInt(@intFromEnum(value.kind)),
            .address = value.address,
            .value = value.value,
            .clock = value.clock,
        }
    else
        null;

    return .{
        .initial_pc = metadata.entry_cpu.pc,
        .final_pc = metadata.exit_cpu.pc,
        .clock = cycle_count,
        .initial_regs = metadata.entry_cpu.registers,
        .final_regs = metadata.exit_cpu.registers,
        .reg_last_clock = metadata.exit_cpu.predecessor_clocks,
        .program_root = try scalarProgramRoot(metadata.program),
        .initial_rw_root = metadata.entry_continuation_root,
        .final_rw_root = metadata.exit_continuation_root,
        .completion = completion,
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
}

fn scalarProgramRoot(program: public_data_v2.Digest) Error!u32 {
    for (program[1..]) |word| if (word != 0)
        return error.NonScalarProgramRoot;
    return program[0];
}
