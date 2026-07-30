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
/// 4. Refuses any run the prover cannot bind, through the shared
///    `prover_mod.admitRunForProving` gate.
/// 5. STARK proves the execution trace.
/// 6. Returns the proof, journal, and metadata.
///
/// ## Provable hosted runs are narrower than hosted runs
///
/// This is the third caller that hands a real `RunResult` to the prover, and it
/// is admitted by the same gate as the other two (see the call site below). Two
/// consequences are worth stating at the entry point rather than leaving to be
/// discovered from a downstream error:
///
///   - a guest that ends through the SP1-style `HALT` syscall completes as
///     `.host_halt`, which `air/public_data.completionFromRun` cannot bind. Such
///     a run is refused here with `UnprovableCompletion`; a provable guest must
///     end on the canonical `jal x0, 0` sentinel or its declared halt flag.
///   - every `ECALL` is an execution-only opcode, so a guest that uses *any*
///     syscall is refused later by the entry point's own opcode filter with
///     `UnsupportedForProof`. The hosted syscall surface is therefore available
///     to execution, not to proving.
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

    // Fail closed through the *one* definition of "this run may be proved".
    // `prover_mod.admitRunForProving` is the same function the production ELF
    // adapter (`src/integrations/riscv_cpu/proof_adapter.zig`) and the benchmark
    // runner (`src/tools/riscv/bench/runner.zig`) call; this path ran a real
    // guest and handed the result straight on, so an unbindable run surfaced as
    // an unrelated-looking failure deep inside the prover instead of here
    // (issue #152 item 5).
    //
    // The completion verdict is the leg this call adds. Its public-I/O leg is
    // evaluated against the run's own I/O, which is *weaker* than what this path
    // publishes; `proveRiscVTraceOnlyNoPublicIo` below re-checks the same
    // committed memory at `PublishedIo.none` strictness, so the strictest of the
    // two still decides.
    try prover_mod.admitRunForProving(&run_result);

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
