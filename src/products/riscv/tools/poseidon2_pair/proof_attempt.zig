//! One verified CPU proof attempt for each exact C-013 guest arm.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const proof_wire = @import("stwo_proof_wire");
const riscv_cpu = @import("stwo_riscv_cpu_integration");

const public_data_mod = frontend.air.public_data;
const runner = frontend.runner;

pub const Metrics = struct {
    execution_steps: usize,
    execution_ns: u64,
    proving_ns: u64,
    proof_encoding_ns: u64,
    verification_ns: u64,
    verified_request_ns: u64,
    proof_wire_bytes: usize,
    proof_sha256: [32]u8,
    preprocessed_cells: u64,
    main_cells: u64,
    interaction_cells: u64,
    output: []u8,

    pub fn deinit(self: *Metrics, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
        self.* = undefined;
    }
};

pub fn software(
    allocator: std.mem.Allocator,
    elf: []const u8,
    input: []const u8,
    max_steps: usize,
    pcs_config: core.pcs.PcsConfig,
) !Metrics {
    const execution_start = try std.time.Instant.now();
    var run = try runner.runWithInput(allocator, elf, input, max_steps);
    defer run.deinit();
    const execution_ns = (try std.time.Instant.now()).since(execution_start);
    try frontend.prover_mod.admitRunForProving(&run);

    var public_data = try OwnedPublicData.init(allocator, &run);
    defer public_data.deinit();
    const proving_start = try std.time.Instant.now();
    var proof = try riscv_cpu.proveRiscVWithPublicData(
        allocator,
        pcs_config,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        null,
        public_data.value,
    );
    const proving_ns = (try std.time.Instant.now()).since(proving_start);
    var proof_moved = false;
    defer if (proof_moved)
        proof.deinitAfterProofMoved(allocator)
    else
        proof.deinit(allocator);

    const encoding_start = try std.time.Instant.now();
    const encoded = try proof_wire.encodeProofBytesBinary(allocator, proof.proof);
    defer allocator.free(encoded);
    const proof_encoding_ns = (try std.time.Instant.now()).since(encoding_start);
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &proof_digest, .{});

    const verification_start = try std.time.Instant.now();
    proof_moved = true;
    try riscv_cpu.verifyRiscV(
        allocator,
        pcs_config,
        proof.statement,
        proof.proof,
        proof.interaction_claim,
    );
    const verification_ns = (try std.time.Instant.now()).since(verification_start);
    const output = try copyOutput(allocator, &run);
    errdefer allocator.free(output);
    return metrics(
        &proof.statement,
        run.step_count,
        execution_ns,
        proving_ns,
        proof_encoding_ns,
        verification_ns,
        encoded.len,
        proof_digest,
        output,
    );
}

pub fn precompile(
    allocator: std.mem.Allocator,
    elf: []const u8,
    input: []const u8,
    max_steps: usize,
    pcs_config: core.pcs.PcsConfig,
) !Metrics {
    const execution_start = try std.time.Instant.now();
    var run = try runner.runPoseidon2ExtensionWithInput(
        allocator,
        elf,
        input,
        max_steps,
    );
    defer run.deinit();
    const execution_ns = (try std.time.Instant.now()).since(execution_start);
    try frontend.prover_mod.admitRunForProving(&run.base);

    var public_data = try OwnedPublicData.init(allocator, &run.base);
    defer public_data.deinit();
    const proving_start = try std.time.Instant.now();
    var proof = try riscv_cpu.provePoseidon2WithPublicData(
        allocator,
        pcs_config,
        &run.base.execution_trace,
        &run.calls,
        &run.execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        null,
        public_data.value,
    );
    const proving_ns = (try std.time.Instant.now()).since(proving_start);
    var proof_moved = false;
    defer if (proof_moved)
        proof.deinitAfterProofMoved(allocator)
    else
        proof.deinit(allocator);

    const encoding_start = try std.time.Instant.now();
    const encoded = try proof_wire.encodeProofBytesBinary(allocator, proof.proof);
    defer allocator.free(encoded);
    const proof_encoding_ns = (try std.time.Instant.now()).since(encoding_start);
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &proof_digest, .{});

    const verification_start = try std.time.Instant.now();
    proof_moved = true;
    try riscv_cpu.verifyPoseidon2(
        allocator,
        pcs_config,
        proof.statement,
        proof.extension,
        proof.artifact,
        proof.proof,
        proof.interaction_claim,
    );
    const verification_ns = (try std.time.Instant.now()).since(verification_start);
    const output = try copyOutput(allocator, &run.base);
    errdefer allocator.free(output);
    return metrics(
        &proof.statement,
        run.base.step_count,
        execution_ns,
        proving_ns,
        proof_encoding_ns,
        verification_ns,
        encoded.len,
        proof_digest,
        output,
    );
}

fn metrics(
    statement: *const frontend.prover_mod.RiscVStatement,
    execution_steps: usize,
    execution_ns: u64,
    proving_ns: u64,
    proof_encoding_ns: u64,
    verification_ns: u64,
    proof_wire_bytes: usize,
    proof_sha256: [32]u8,
    output: []u8,
) !Metrics {
    const execution_and_proving_ns = try std.math.add(
        u64,
        execution_ns,
        proving_ns,
    );
    const verified_request_ns = try std.math.add(
        u64,
        execution_and_proving_ns,
        verification_ns,
    );
    return .{
        .execution_steps = execution_steps,
        .execution_ns = execution_ns,
        .proving_ns = proving_ns,
        .proof_encoding_ns = proof_encoding_ns,
        .verification_ns = verification_ns,
        .verified_request_ns = verified_request_ns,
        .proof_wire_bytes = proof_wire_bytes,
        .proof_sha256 = proof_sha256,
        .preprocessed_cells = statement.nPreprocessedCells(),
        .main_cells = statement.nMainCells(),
        .interaction_cells = statement.nInteractionCells(),
        .output = output,
    };
}

fn copyOutput(
    allocator: std.mem.Allocator,
    run: *const runner.RunResult,
) ![]u8 {
    if (run.output_len == 0) return allocator.alloc(u8, 0);
    const output = run.output orelse return error.MissingGuestOutput;
    if (output.len != run.output_len) return error.GuestOutputLengthMismatch;
    return allocator.dupe(u8, output);
}

const OwnedPublicData = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data_mod.OutputWord,
    value: public_data_mod.PublicData,

    fn init(allocator: std.mem.Allocator, run: *const runner.RunResult) !OwnedPublicData {
        const input_words = try public_data_mod.packInputWords(allocator, run.input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data_mod.OutputWord,
            run.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, run.output_words) |*destination, source| destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
        return .{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = .{
                .initial_pc = run.initial_pc,
                .final_pc = run.final_pc,
                .clock = std.math.cast(u32, run.step_count) orelse
                    return error.ExecutionClockOutOfRange,
                .initial_regs = run.initial_regs,
                .final_regs = run.final_regs,
                .reg_last_clock = run.state_chain_tracker.reg_last_clk,
                .program_root = null,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = try public_data_mod.completionFromRun(run.*),
                .io_entries = .{
                    .input_start = run.input_start,
                    .input_len = std.math.cast(u32, run.input.len) orelse
                        return error.InputLengthOutOfRange,
                    .input_words = input_words,
                    .output_len = run.output_len,
                    .output_len_addr = run.output_len_addr,
                    .output_data_addr = run.output_data_addr,
                    .output_words = output_words,
                },
            },
        };
    }

    fn deinit(self: *OwnedPublicData) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};
