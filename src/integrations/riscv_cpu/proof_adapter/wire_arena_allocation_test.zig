//! Allocation-failure coverage for the adapter's proof-wire arena.

const std = @import("std");
const stwo = @import("stwo");
const WireArena = @import("wire_arena.zig").WireArena;

test "wire arena rolls back every partial allocation" {
    const prover = stwo.frontends.riscv.prover_mod;
    const public_data = stwo.frontends.riscv.air.public_data;
    const input_words = [_]u32{7};
    const output_words = [_]public_data.OutputWord{.{ .addr = 8, .value = 9, .clock = 10 }};
    var statement: prover.RiscVStatement = .{
        .n_components = 1,
        .component_descs = undefined,
        .initial_pc = 4,
        .final_pc = 8,
        .total_steps = 1,
        .public_data = .{
            .initial_pc = 4,
            .final_pc = 8,
            .clock = 1,
            .initial_regs = .{0} ** 32,
            .final_regs = .{0} ** 32,
            .reg_last_clock = .{0} ** 32,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .io_entries = .{
                .input_start = 0,
                .input_len = 4,
                .input_words = &input_words,
                .output_len = 4,
                .output_len_addr = 8,
                .output_data_addr = 12,
                .output_words = &output_words,
            },
            // Without a valid completion, construction returns before the
            // induced allocation failure and the rollback remains untested.
            .completion = .{ .kind = .halt_flag, .address = 8, .value = 1, .clock = 1 },
        },
        .n_infra = 1,
        .infra_descs = undefined,
    };
    statement.component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 1,
        .n_rows = 1,
        .n_columns = 4,
    };
    statement.infra_descs[0] = .{
        .kind = .program,
        .log_size = 1,
        .n_rows = 1,
        .n_columns = 4,
    };
    var claim = prover.RiscVInteractionClaim.initZero();
    claim.n_components = 1;
    claim.n_infra = 1;
    const output = .{ .statement = statement, .interaction_claim = claim };

    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        try std.testing.expectError(
            error.OutOfMemory,
            WireArena.init(failing.allocator(), output),
        );
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
