//! Fixed authority shared by the two-process Ethereum leaf artifact gate.

const std = @import("std");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
pub const riscv_cpu = @import("stwo_riscv_cpu_integration");

const public_data = frontend.air.public_data;
const runner = frontend.runner;

pub const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
pub const proof_artifact = riscv_cpu.ethereum_proof_artifact;
pub const max_steps: usize = 16;

pub const pcs_config: core.pcs.PcsConfig = .{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
    .lifting_log_size = null,
};

pub const artifact_limits: proof_artifact.Limits = .{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = 16 * 1024 * 1024,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

pub const OwnedPublicData = struct {
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    pub fn init(
        allocator: std.mem.Allocator,
        run: *const runner.EthereumRunResult,
    ) !OwnedPublicData {
        const input_words = try public_data.packInputWords(allocator, run.base.input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data.OutputWord,
            run.base.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, run.base.output_words) |*destination, source| {
            destination.* = .{
                .addr = source.addr,
                .value = source.value,
                .clock = source.clock,
            };
        }
        return .{
            .input_words = input_words,
            .output_words = output_words,
            .value = .{
                .initial_pc = run.base.initial_pc,
                .final_pc = run.base.final_pc,
                .clock = std.math.cast(u32, run.base.step_count) orelse
                    return error.ExecutionClockOutOfRange,
                .initial_regs = run.base.initial_regs,
                .final_regs = run.base.final_regs,
                .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
                .program_root = null,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = try public_data.completionFromRun(run.base),
                .io_entries = .{
                    .input_start = run.base.input_start,
                    .input_len = std.math.cast(u32, run.base.input.len) orelse
                        return error.InputLengthOutOfRange,
                    .input_words = input_words,
                    .output_len = run.base.output_len,
                    .output_len_addr = run.base.output_len_addr,
                    .output_data_addr = run.base.output_data_addr,
                    .output_words = output_words,
                },
            },
        };
    }

    pub fn deinit(self: *OwnedPublicData, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};
