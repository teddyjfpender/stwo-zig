//! The prover's fail-closed admission gate, and the trace-only entrypoint that
//! must refuse what it cannot represent (issue #152 items 1, 5 and 7).
//!
//! Three things are pinned here, each with a check that goes red if the
//! corresponding guard is deleted:
//!
//!   1. `proveRiscVTraceOnlyNoPublicIo` rejects a run whose committed memory
//!      carries public I/O its synthesized statement never publishes, at the
//!      entrypoint rather than ~1.2 s later inside the prover.
//!   2. `admitRunForProving` is the one definition of "this run may be proved",
//!      reached by all three callers that hand a real `RunResult` to the prover:
//!      the production ELF adapter, the benchmark runner, and the hosted
//!      block-proving pipeline (`host/prove_block.zig`). Its completion verdict
//!      is asserted over the *whole* `CompletionReason` enum, so a new variant
//!      cannot be added without classifying it.
//!   3. `SECURE_PCS_CONFIG` is the single secure profile, and it is the one the
//!      staged adapter's `.secure` protocol returns.
//!
//! The guard is also checked for over-reach: an I/O-free guest's real committed
//! memory must still pass, or the fix would have broken every trace-only caller
//! it was meant to leave alone.

const std = @import("std");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const prover = @import("stwo_riscv_frontend").prover_mod;
const runner = @import("stwo_riscv_frontend").runner;
const host = @import("stwo_riscv_frontend").host;
const memory_state = @import("stwo_riscv_frontend").runner.memory_state;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const pcs = @import("stwo_core").pcs;

const CpuProverEngine = riscv_cpu.CpuProverEngine;

const TEST_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 2,
    },
};

/// A committed RW-memory image holding exactly the given words. The layout is
/// zeroed because these tests read the words' own roles, which is what the gate
/// reads: a guest is free to leave a declared region untouched, so the declared
/// region is not evidence.
fn snapshotOf(words: []memory_state.WordState) memory_state.Snapshot {
    return .{
        .layout = std.mem.zeroes(memory_state.MemoryLayout),
        .segment_role = memory_state.SegmentRole.single(),
        .words = words,
    };
}

/// Four ADDIs terminated by the canonical `jal x0, 0` completion sentinel: the
/// I/O-free shape the trace-only entrypoint exists to serve.
fn ioFreeElf() [84 + 5 * 4]u8 {
    return runner.trace_dump.buildTestElf(5, .{
        0x0010_0093, // ADDI x1, x0, 1
        0x0010_0093,
        0x0010_0093,
        0x0010_0093,
        0x0000_006f, // JAL x0, 0
    });
}

test "trace-only proving refuses a committed public-input word" {
    const allocator = std.testing.allocator;
    const elf = ioFreeElf();
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    // One word the guest actually read (final_clock > 0) in its public-input
    // region. The trace-only statement publishes `input_len = 0`, so the
    // public-I/O bus could never cancel this word's consume.
    var words = [_]memory_state.WordState{.{
        .addr = 0x0018_0000,
        .initial_word = 0x0403_0201,
        .final_word = 0x0403_0201,
        .final_clock = 2,
        .role = .{ .is_public_input = true },
    }};
    const memory = snapshotOf(&words);

    try std.testing.expectError(
        error.UnpublishedPublicIo,
        prover.proveRiscVTraceOnlyNoPublicIo(
            CpuProverEngine,
            allocator,
            TEST_CONFIG,
            &run.execution_trace,
            null,
            &memory,
            null,
        ),
    );
}

test "trace-only proving refuses committed public-output and completion words" {
    const allocator = std.testing.allocator;
    const elf = ioFreeElf();
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    const roles = [_]memory_state.WordRole{
        .{ .is_public_output = true },
        .{ .is_public_completion = true },
    };
    for (roles) |role| {
        var words = [_]memory_state.WordState{.{
            .addr = 0x0010_0004,
            .initial_word = 0,
            .final_word = 4,
            .final_clock = 3,
            .role = role,
        }};
        const memory = snapshotOf(&words);
        try std.testing.expectError(
            error.UnpublishedPublicIo,
            prover.proveRiscVTraceOnlyNoPublicIo(
                CpuProverEngine,
                allocator,
                TEST_CONFIG,
                &run.execution_trace,
                null,
                &memory,
                null,
            ),
        );
    }
}

test "the public-I/O gate does not fire on an untouched region or a published one" {
    // A declared-but-untouched public-input word emits no consume, so nothing is
    // left dangling and the run stays admissible. Without this the gate would
    // reject every guest whose linker script declares an I/O region.
    var untouched = [_]memory_state.WordState{.{
        .addr = 0x0018_0000,
        .initial_word = 0,
        .final_word = 0,
        .final_clock = 0,
        .role = .{ .is_public_input = true },
    }};
    const untouched_memory = snapshotOf(&untouched);
    try std.testing.expect(
        prover.classifyPublicIo(&untouched_memory, prover.PublishedIo.none) == null,
    );

    // The same word, read, is admissible for a caller that publishes input.
    var touched = [_]memory_state.WordState{.{
        .addr = 0x0018_0000,
        .initial_word = 7,
        .final_word = 7,
        .final_clock = 5,
        .role = .{ .is_public_input = true },
    }};
    const touched_memory = snapshotOf(&touched);
    try std.testing.expect(prover.classifyPublicIo(
        &touched_memory,
        .{ .input_len = 4, .output = true },
    ) == null);
    try std.testing.expectEqual(
        @as(?u32, 0x0018_0000),
        switch (prover.classifyPublicIo(
            &touched_memory,
            .{ .input_len = 0, .output = true },
        ).?) {
            .unpublished_public_io => |addr| addr,
            else => null,
        },
    );
}

test "an I/O-free guest's real committed memory remains admissible" {
    const allocator = std.testing.allocator;
    const elf = ioFreeElf();
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    // The guard must not be broader than the defect: this is the guest shape
    // that worked through the trace-only path before the gate existed.
    try std.testing.expect(
        prover.classifyPublicIo(&run.rw_memory, prover.PublishedIo.none) == null,
    );
    try prover.admitRunForProving(&run);
    try std.testing.expect(prover.classifyRunAdmission(&run) == null);
}

test "run admission classifies every completion reason exactly once" {
    // Asserted over the whole enum rather than over a sample: a new
    // `CompletionReason` must be classified, not silently admitted.
    var provable: usize = 0;
    for (std.enums.values(runner.CompletionReason)) |reason| {
        const rejection = prover.classifyCompletion(reason);
        switch (reason) {
            .halt_flag, .self_loop => {
                provable += 1;
                try std.testing.expect(rejection == null);
            },
            else => {
                try std.testing.expectEqual(
                    prover.RunAdmissionError.UnprovableCompletion,
                    rejection.?.toError(),
                );
                try std.testing.expectEqual(
                    reason,
                    rejection.?.unprovable_completion,
                );
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 2), provable);
}

test "run admission refuses a real ECALL-terminated run" {
    const allocator = std.testing.allocator;
    const elf = runner.trace_dump.buildTestElf(2, .{
        0x0010_0093, // ADDI x1, x0, 1
        0x0000_0073, // ECALL: an environment event, never a proof-bearing completion
    });
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.ecall, run.completion_reason);
    try std.testing.expectError(
        error.UnprovableCompletion,
        prover.admitRunForProving(&run),
    );
}

/// The hosted ABI's own termination: `a7 = HALT(0)`, `a0 = 42`, `ECALL`. This is
/// how an SP1-style guest ends, and the runner completes such a run as
/// `.host_halt` -- a reason `air/public_data.completionFromRun` cannot bind.
fn hostHaltElf() [84 + 3 * 4]u8 {
    return runner.trace_dump.buildTestElf(3, .{
        0x0000_0893, // ADDI x17, x0, 0  (a7 = HALT)
        0x02a0_0513, // ADDI x10, x0, 42 (a0 = exit code)
        0x0000_0073, // ECALL
    });
}

test "hosted block proving fails closed through the shared run-admission gate" {
    // The third caller that runs a real guest and hands the result to the
    // prover. It had no equivalent of the adapter's completion check, so a
    // hosted guest that terminated the only way the hosted ABI offers reached
    // the prover and died there instead of at the entrypoint.
    const allocator = std.testing.allocator;
    const elf = hostHaltElf();

    // Establish that this really is the reason the gate must classify, so the
    // test cannot start passing for an unrelated reason.
    var runtime = host.HostRuntime.init(allocator, &.{});
    defer runtime.deinit();
    var run = try runner.runWithHost(allocator, &elf, 1000, runtime.interface());
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.host_halt, run.completion_reason);
    try std.testing.expectEqual(
        prover.RunAdmissionError.UnprovableCompletion,
        prover.classifyRunAdmission(&run).?.toError(),
    );

    const block_input = host.BlockInput{ .serialized = &.{}, .allocator = allocator };
    try std.testing.expectError(
        error.UnprovableCompletion,
        host.proveEthereumBlockWithEngine(
            CpuProverEngine,
            allocator,
            &elf,
            &block_input,
            TEST_CONFIG,
            1000,
        ),
    );
}

test "hosted block proving still serves the syscall-free guest it was correct for" {
    // Over-reach check: the gate must refuse only what no statement can bind. A
    // hosted run that ends on the canonical `jal x0, 0` sentinel completes as
    // `.self_loop` and must still prove.
    const allocator = std.testing.allocator;
    const elf = ioFreeElf();

    var runtime = host.HostRuntime.init(allocator, &.{});
    defer runtime.deinit();
    var run = try runner.runWithHost(allocator, &elf, 1000, runtime.interface());
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.self_loop, run.completion_reason);

    const block_input = host.BlockInput{ .serialized = &.{}, .allocator = allocator };
    var result = try host.proveEthereumBlockWithEngine(
        CpuProverEngine,
        allocator,
        &elf,
        &block_input,
        TEST_CONFIG,
        1000,
    );
    defer result.deinit(allocator);
    try std.testing.expect(result.prove_output.statement.n_components > 0);
    try std.testing.expectEqual(run.step_count, result.cycles);
    try std.testing.expectEqual(@as(?u32, null), result.exit_code);
}

test "the secure PCS profile has exactly one definition" {
    // The numbers upstream CSP publishes through `secure_pcs_config()`. The
    // Python mirror in `scripts/riscv_csp_benchmark_lib/contract.py` parses this
    // same constant and refuses to validate a manifest when it disagrees, so a
    // benchmark cannot be reported from a profile that merely sounds secure.
    try std.testing.expectEqual(@as(u32, 26), prover.SECURE_PCS_CONFIG.pow_bits);
    try std.testing.expectEqual(
        @as(usize, 70),
        prover.SECURE_PCS_CONFIG.fri_config.n_queries,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        prover.SECURE_PCS_CONFIG.fri_config.log_blowup_factor,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        prover.SECURE_PCS_CONFIG.fri_config.log_last_layer_degree_bound,
    );
    try std.testing.expectEqual(@as(?u32, null), prover.SECURE_PCS_CONFIG.lifting_log_size);
}

test "the trace-only entrypoint keeps proving an I/O-free hand-built trace" {
    // The rename must not have changed what this path does for the callers it is
    // still correct for.
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    trace.initial_pc = 0x1000;
    trace.final_pc = 0x1004;
    try trace.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x0010_0093,
    });
    var output = try prover.proveRiscVTraceOnlyNoPublicIo(
        CpuProverEngine,
        allocator,
        TEST_CONFIG,
        &trace,
        null,
        null,
        null,
    );
    defer output.deinit(allocator);
    try std.testing.expect(output.statement.n_components > 0);
}
