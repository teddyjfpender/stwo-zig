//! Integrated Ethereum block proving pipeline.
//!
//! Combines ELF loading, hosted execution, and STARK proving
//! into a single function call.

const std = @import("std");
const host_mod = @import("mod.zig");
const runner_mod = @import("../runner/mod.zig");
const prover_mod = @import("../prover.zig");
const pcs_core = @import("stwo_core").pcs;
const BlockInput = @import("block_input.zig").BlockInput;

pub const ProveBlockResult = struct {
    /// Prover output (statement + proof).
    prove_output: prover_mod.ProveOutput,
    /// Exit code from the guest.
    exit_code: ?u32,
    /// Journal data (public output committed by the guest).
    journal: []const u8,
    /// Number of VM cycles executed.
    cycles: usize,

    pub fn deinit(self: *ProveBlockResult, allocator: std.mem.Allocator) void {
        self.prove_output.deinit(allocator);
        self.* = undefined;
    }
};

/// Prove an Ethereum block execution end-to-end.
///
/// 1. Loads the guest ELF.
/// 2. Sets up the host runtime with block input as a hint.
/// 3. Executes the guest with syscall dispatch.
/// 4. STARK proves the execution trace.
/// 5. Returns the proof, journal, and metadata.
pub fn proveEthereumBlockWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    block_input: *const BlockInput,
    pcs_config: pcs_core.PcsConfig,
    max_steps: usize,
) !ProveBlockResult {
    // Set up hints from block input.
    var hints_buf: [1][]const u8 = undefined;
    const hints = block_input.asHints(&hints_buf);

    // Create host runtime.
    var host_runtime = host_mod.HostRuntime.init(allocator, hints);
    defer host_runtime.deinit();

    // Execute the guest.
    var run_result = try runner_mod.runWithHost(
        allocator,
        elf_bytes,
        max_steps,
        host_runtime.interface(),
    );
    defer run_result.deinit();

    // Prove the execution.
    const prove_output = try prover_mod.proveRiscVTraceOnlyNoPublicIo(
        Engine,
        allocator,
        pcs_config,
        &run_result.execution_trace,
        &run_result.state_chain_tracker,
        &run_result.rw_memory,
        null,
    );

    return .{
        .prove_output = prove_output,
        .exit_code = run_result.exit_code,
        .journal = host_runtime.journalData(),
        .cycles = run_result.step_count,
    };
}
