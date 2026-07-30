//! The RISC-V prover routes commitment and proving through the injected engine,
//! so a backend substitution cannot be silently bypassed.
//!
//! `CountingEngine` wraps `CpuProverEngine` and counts the calls the frontend
//! makes; the assertions are one `init`, three `commit`s, and one `prove`. Three
//! commits is the tree count the RISC-V schema fixes (preprocessed, main,
//! interaction), so a stage that quietly proved against a different scheme would
//! move a counter.
//!
//! Coverage, stated exactly, because the file name reads wider than it is. Two
//! traces are proven: a runner-produced four-row `base_alu_imm` run and a
//! hand-built one-row `mulh` run. The other fifteen opcode families in
//! `air/component_order.zig` are not reached here, no proof is verified, and no
//! witness is mutated. The base-ALU sample is runner-produced and its proven
//! retirement sequence is replayed through pinned Sail after the engine
//! assertions. Per-family committed-trace coverage lives in the
//! `*_soundness_test.zig` modules, with the canonical seventeen-family
//! accounting in `opcode_family_committed_soundness_test.zig`. This file
//! remains only a proving-substitution check and does not claim family
//! enumeration, proof verification, or witness mutation.

const std = @import("std");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const prover = @import("stwo_riscv_frontend").prover_mod;
const runner = @import("stwo_riscv_frontend").runner;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const pcs = @import("stwo_core").pcs;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_engine = @import("stwo_prover_engine").engine;
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;

const CpuProverEngine = riscv_cpu.CpuProverEngine;
const ExtendedProof = prover.ExtendedProof;

const CountingEngine = struct {
    pub const Component = prover_component.ComponentProver;
    pub const Scheme = CpuProverEngine.Scheme;
    pub const Channel = CpuProverEngine.Channel;
    pub const ExtendedProof = CpuProverEngine.ExtendedProof;
    pub const MerkleChannel = CpuProverEngine.MerkleChannel;
    var init_calls: usize = 0;
    var commit_calls: usize = 0;
    var prove_calls: usize = 0;

    fn reset() void {
        init_calls = 0;
        commit_calls = 0;
        prove_calls = 0;
    }

    pub fn init(allocator: std.mem.Allocator, config: pcs.PcsConfig) !Scheme {
        init_calls += 1;
        return CpuProverEngine.init(allocator, config);
    }

    pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
        CpuProverEngine.deinit(scheme, allocator);
    }

    pub fn commit(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
        recorder: ?*stage_profile.Recorder,
        channel: *Channel,
    ) !void {
        commit_calls += 1;
        return CpuProverEngine.commit(scheme, allocator, columns, recorder, channel);
    }

    pub fn prove(
        allocator: std.mem.Allocator,
        components: []const prover_component.ComponentProver,
        channel: *Channel,
        scheme: Scheme,
        options: prover_engine.ProveOptions,
    ) !CpuProverEngine.ExtendedProof {
        prove_calls += 1;
        return CpuProverEngine.prove(allocator, components, channel, scheme, options);
    }
};

const TEST_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 2,
    },
};

test "transaction engine is the proving substitution point" {
    CountingEngine.reset();
    const allocator = std.testing.allocator;
    const elf = runner.trace_dump.buildTestElf(5, .{
        0x0010_0093, // ADDI x1, x0, 1
        0x0010_0093,
        0x0010_0093,
        0x0010_0093,
        0x0000_006f, // JAL x0, 0: completion sentinel, not a retirement
    });
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    var output = try prover.proveRiscVTraceOnlyNoPublicIo(
        CountingEngine,
        allocator,
        TEST_CONFIG,
        &run.execution_trace,
        null,
        null,
        null,
    );
    defer output.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), CountingEngine.init_calls);
    try std.testing.expectEqual(@as(usize, 3), CountingEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), CountingEngine.prove_calls);

    // Attribute the exact runner trace delivered to the selected engine.
    // Last so an absent oracle skips only this sampled semantic leg.
    try runner.sail_oracle.requireAgreement(
        allocator,
        "proving-substitution four-ADDI runner guest",
        &elf,
        &run.execution_trace,
        run.cpu_final,
        &.{},
    );
}

test "MULH family reaches the selected proving engine" {
    CountingEngine.reset();
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    trace.initial_pc = 0x1000;
    trace.final_pc = 0x1004;
    try trace.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .MULHU,
        .rd = 3,
        .rs1 = 1,
        .rs2 = 2,
        .imm = 0,
        .rs1_val = 0x7fff_ffff,
        .rs2_val = 0x4000_0000,
        .rd_val = 0x1fff_ffff,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x0220_b1b3,
    });

    var output = try prover.proveRiscVTraceOnlyNoPublicIo(
        CountingEngine,
        allocator,
        TEST_CONFIG,
        &trace,
        null,
        null,
        null,
    );
    defer output.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), CountingEngine.init_calls);
    try std.testing.expectEqual(@as(usize, 3), CountingEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), CountingEngine.prove_calls);
}
