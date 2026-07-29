//! RISC-V end-to-end proving benchmark — comparable to stark-v.
//!
//! Measures the FULL pipeline: ELF execution → trace → STARK prove → verify.
//! Reports throughput in kHz (VM cycles / total_time / 1000) for direct
//! comparison with stark-v's published ~567 kHz on M2 Max.
//!
//! Usage:
//!   ./riscv_bench --fib-n 500000

const std = @import("std");
const builtin = @import("builtin");
const stage_profile = @import("stwo_prover_api").stage_profile;
const pcs_core = @import("stwo_core").pcs;

const Timer = struct {
    start: i128,
    fn begin() Timer {
        return .{ .start = std.time.nanoTimestamp() };
    }
    fn elapsedMs(self: Timer) f64 {
        const ns = std.time.nanoTimestamp() - self.start;
        return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
    }
    fn elapsedSec(self: Timer) f64 {
        return self.elapsedMs() / 1000.0;
    }
};

fn makeFibElf(allocator: std.mem.Allocator, n: u32) ![]u8 {
    var n_lo: u32 = n & 0xFFF;
    var n_hi: u32 = n & 0xFFFFF000;
    if (n_lo >= 0x800) {
        n_hi +%= 0x1000;
        n_lo = n_lo;
    }

    const instructions = [_]u32{
        // ADDI x1, x0, 0    (a = 0)
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (1 << 7) | 0x13,
        // ADDI x2, x0, 1    (b = 1)
        @as(u32, 1) << 20 | (0 << 15) | (0b000 << 12) | (2 << 7) | 0x13,
        // ADDI x3, x0, 2    (i = 2)
        @as(u32, 2) << 20 | (0 << 15) | (0b000 << 12) | (3 << 7) | 0x13,
        // ADDI x4, x0, N_lo
        (n_lo << 20) | (0 << 15) | (0b000 << 12) | (4 << 7) | 0x13,
        // LUI x5, N_hi
        (n_hi & 0xFFFFF000) | (5 << 7) | 0x37,
        // ADD x4, x4, x5    (N = N_lo + N_hi)
        (5 << 20) | (4 << 15) | (0b000 << 12) | (4 << 7) | 0x33,
        // loop: ADD x6, x1, x2  (tmp = a + b)
        (2 << 20) | (1 << 15) | (0b000 << 12) | (6 << 7) | 0x33,
        // ADDI x1, x2, 0    (a = b)
        (0 << 20) | (2 << 15) | (0b000 << 12) | (1 << 7) | 0x13,
        // ADDI x2, x6, 0    (b = tmp)
        (0 << 20) | (6 << 15) | (0b000 << 12) | (2 << 7) | 0x13,
        // ADDI x3, x3, 1    (i++)
        (1 << 20) | (3 << 15) | (0b000 << 12) | (3 << 7) | 0x13,
        // BNE x3, x4, -16   (if i != N, loop back 4 instructions)
        encodeBne(3, 4, @as(i13, -16)),
        // jal x0, 0 — the canonical zkVM completion sentinel.
        //
        // This is deliberately NOT `ecall` (0x00000073). ECALL is
        // `UnsupportedForProof`, so an ECALL-terminated trace has no
        // proof-bearing completion and the benchmark could only ever measure
        // execution, never the prove/verify pipeline it exists to measure.
        // The sentinel is an environment event: the runner observes it and
        // stops *without* retiring it, so the only difference to the measured
        // workload is that the terminator itself is no longer one retired
        // cycle. Everything the benchmark reports on — the fib loop — is
        // unchanged.
        0x0000006F,
    };

    const code_size = instructions.len * 4;
    const elf_size = 84 + code_size;
    const buf = try allocator.alloc(u8, elf_size);
    @memset(buf, 0);

    // ELF header
    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 1;
    buf[5] = 1;
    buf[6] = 1;
    buf[16] = 2;
    buf[18] = 0xF3;
    buf[20] = 1;
    std.mem.writeInt(u32, buf[24..28], 0x10000, .little);
    buf[28] = 52;
    buf[40] = 52;
    buf[42] = 32;
    buf[44] = 1;
    buf[52] = 1;
    buf[56] = 84;
    std.mem.writeInt(u32, buf[60..64], 0x10000, .little);
    std.mem.writeInt(u32, buf[68..72], @intCast(code_size), .little);
    std.mem.writeInt(u32, buf[72..76], @intCast(code_size), .little);

    for (instructions, 0..) |inst, i| {
        const off = 84 + i * 4;
        std.mem.writeInt(u32, buf[off..][0..4], inst, .little);
    }
    return buf;
}

fn encodeBne(rs1: u5, rs2: u5, offset: i13) u32 {
    const off: u13 = @bitCast(offset);
    const imm12: u1 = @truncate(off >> 12);
    const imm10_5: u6 = @truncate(off >> 5);
    const imm4_1: u4 = @truncate(off >> 1);
    const imm11: u1 = @truncate(off >> 11);
    return (@as(u32, imm12) << 31) | (@as(u32, imm10_5) << 25) |
        (@as(u32, rs2) << 20) | (@as(u32, rs1) << 15) |
        (0b001 << 12) | (@as(u32, imm4_1) << 8) | (@as(u32, imm11) << 7) | 0x63;
}

pub fn mainWithEngine(comptime frontend: type, comptime Engine: type) !void {
    const runner = frontend.runner;
    const riscv_prover = frontend.prover_mod;
    const host_mod = frontend.host;
    comptime riscv_prover.assertProverEngine(Engine);
    const allocator = std.heap.smp_allocator;
    if (comptime @hasDecl(Engine, "warmup")) try Engine.warmup();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var fib_n: u32 = 10000;
    var pow_bits: u32 = 0;
    var n_queries: u64 = 3;
    var production: bool = false;
    var elf_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var input_u32: ?u32 = null;
    var max_steps: usize = 10_000_000;
    var hosted: bool = false;
    var hint_path: ?[]const u8 = null;
    var run_only: bool = false;
    var profile_enabled: bool = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, args[i], "--fib-n") and i + 1 < args.len) {
            i += 1;
            fib_n = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--pow-bits") and i + 1 < args.len) {
            i += 1;
            pow_bits = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--n-queries") and i + 1 < args.len) {
            i += 1;
            n_queries = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--production")) {
            production = true;
        } else if (std.mem.eql(u8, args[i], "--elf") and i + 1 < args.len) {
            i += 1;
            elf_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--input") and i + 1 < args.len) {
            i += 1;
            input_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--input-u32") and i + 1 < args.len) {
            i += 1;
            input_u32 = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--max-steps") and i + 1 < args.len) {
            i += 1;
            max_steps = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--hosted")) {
            hosted = true;
        } else if (std.mem.eql(u8, args[i], "--hint") and i + 1 < args.len) {
            i += 1;
            hint_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--run-only")) {
            run_only = true;
        } else if (std.mem.eql(u8, args[i], "--profile")) {
            profile_enabled = true;
        } else {
            std.debug.print("unknown argument: {s}\n\n", .{args[i]});
            printUsage();
            return error.InvalidArgument;
        }
    }

    // --production matches stark-v's benchmark config: pow_bits=24, n_queries=70
    if (production) {
        pow_bits = 24;
        n_queries = 70;
    }

    std.debug.print("RISC-V End-to-End Proving Benchmark\n", .{});
    std.debug.print("====================================\n", .{});
    if (elf_path) |path| {
        std.debug.print("Workload: external ELF {s}\n", .{path});
    } else {
        std.debug.print("Workload: generated fib({d})\n", .{fib_n});
    }
    const cpu_count = std.Thread.getCpuCount() catch 1;
    std.debug.print("Security: pow_bits={d}, n_queries={d}", .{ pow_bits, n_queries });
    if (production) std.debug.print(" [PRODUCTION — matches stark-v]", .{});
    std.debug.print("\nOptimization: {s}\n", .{@tagName(builtin.mode)});
    if (builtin.mode == .Debug) {
        std.debug.print("WARNING: Debug throughput is not comparable to release benchmarks.\n", .{});
    }
    std.debug.print("CPU cores: {d} (used for parallel PoW grinding)\n\n", .{cpu_count});

    const config = pcs_core.PcsConfig{
        .pow_bits = pow_bits,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = n_queries,
        },
    };

    // Stage 1: Load or generate ELF
    const t_total = Timer.begin();
    const elf_bytes = if (elf_path) |path|
        try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024)
    else
        try makeFibElf(allocator, fib_n);
    defer allocator.free(elf_bytes);

    if (elf_path != null) {
        std.debug.print("ELF: {s} ({d} bytes)\n", .{ elf_path.?, elf_bytes.len });
    }

    // Stage 2: Execute
    const t_exec = Timer.begin();

    var input_buf: ?[]const u8 = null;
    defer if (input_buf) |buf| allocator.free(buf);
    if (input_path) |path| {
        input_buf = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
        std.debug.print("Input: {s} ({d} bytes)\n", .{ path, input_buf.?.len });
    } else if (input_u32) |value| {
        const encoded = try allocator.alloc(u8, @sizeOf(u32));
        std.mem.writeInt(u32, encoded[0..4], value, .little);
        input_buf = encoded;
        std.debug.print("Input u32: {d}\n", .{value});
    }

    // Load hint data if provided.
    var hint_data_buf: ?[]const u8 = null;
    defer if (hint_data_buf) |buf| allocator.free(buf);
    var hints_slice: []const []const u8 = &.{};
    var hints_storage: [1][]const u8 = undefined;
    if (hint_path) |hp| {
        hint_data_buf = try std.fs.cwd().readFileAlloc(allocator, hp, 64 * 1024 * 1024);
        hints_storage[0] = hint_data_buf.?;
        hints_slice = &hints_storage;
        std.debug.print("Hint: {s} ({d} bytes)\n", .{ hp, hint_data_buf.?.len });
    }

    // Set up host runtime if --hosted is specified.
    var host_runtime: ?host_mod.HostRuntime = null;
    defer if (host_runtime) |*rt| rt.deinit();
    var host_iface: ?runner.HostInterface = null;
    if (hosted) {
        host_runtime = host_mod.HostRuntime.init(allocator, hints_slice);
        host_iface = host_runtime.?.interface();
        std.debug.print("Mode: hosted (syscall dispatch enabled)\n", .{});
    }

    if (input_buf != null and hosted) return error.IncompatibleInputModes;
    const step_limit = if (elf_path != null) max_steps else fib_n * 6;
    var run_result = if (input_buf) |input|
        try runner.runWithInput(allocator, elf_bytes, input, step_limit)
    else
        try runner.runWithHost(allocator, elf_bytes, step_limit, host_iface);
    defer run_result.deinit();
    const exec_ms = t_exec.elapsedMs();

    if (run_result.exit_code) |code| {
        std.debug.print("Exit code: {d}\n", .{code});
    }
    if (host_runtime) |rt| {
        const journal = rt.journalData();
        if (journal.len > 0) {
            std.debug.print("Journal: {d} bytes", .{journal.len});
            if (journal.len <= 64) {
                std.debug.print(" [", .{});
                for (journal) |b| std.debug.print("{x:0>2}", .{b});
                std.debug.print("]", .{});
            }
            std.debug.print("\n", .{});
        }
    }

    const cycles = run_result.execution_trace.step_count;
    std.debug.print("Execute:  {d:.1}ms  ({d} cycles, {d:.0} kHz)\n", .{
        exec_ms, cycles, @as(f64, @floatFromInt(cycles)) / exec_ms,
    });

    if (run_only) {
        const total_ms = t_total.elapsedMs();
        std.debug.print("\nTotal (run-only): {d:.1}ms\n", .{total_ms});
        return;
    }

    // Fail closed on any run whose termination the statement cannot bind,
    // matching the production adapter's gate in
    // `src/integrations/riscv_cpu/proof_adapter.zig`. Only `.halt_flag` and
    // `.self_loop` carry a proof-bearing completion; anything else (ECALL,
    // EBREAK, a host halt, a step-limit cutoff, an undecodable word) would
    // otherwise be handed to the prover and fail far downstream with a
    // diagnostic that names neither the guest nor the reason.
    switch (run_result.completion_reason) {
        .halt_flag, .self_loop => {},
        else => |reason| {
            std.debug.print(
                \\
                \\ERROR: the guest ended with completion_reason={s}, which carries no
                \\       proof-bearing completion, so this run cannot be proved.
                \\       A provable guest must either write its linker-declared
                \\       __halt_flag or end on the canonical `jal x0, 0` sentinel.
                \\       Use --run-only to measure execution alone.
                \\
            , .{@tagName(reason)});
            return error.UnprovableCompletion;
        },
    }

    // Fail closed on the other statement the bench can otherwise build but not
    // prove: the guest read its linker-declared public-input region, yet no
    // `--input` was supplied. The committed memory image then carries
    // public-input words the statement's `input_len = 0` never publishes, so
    // the public-I/O bus cannot cancel. Detect it from the run's own committed
    // words rather than guessing from the declared region, which a guest is
    // free to leave untouched.
    if (run_result.input.len == 0) {
        for (run_result.rw_memory.words) |word| {
            if (!word.role.is_public_input or word.final_clock == 0) continue;
            std.debug.print(
                \\
                \\ERROR: the guest read its public-input region at 0x{x:0>8} but no
                \\       --input was supplied, so the statement would publish zero
                \\       input words for memory the proof commits as public input.
                \\       Pass --input PATH (or --input-u32 N) for this guest.
                \\
            , .{word.addr});
            return error.MissingGuestInput;
        }
    }

    // Stage 3: Prove
    //
    // The trace-only convenience entrypoint (`proveRiscVWithEngine`) synthesizes
    // a statement with an empty I/O region, so the public-I/O LogUp bus cannot
    // balance for any guest that actually reads input or writes output. Build the
    // same real public data the production adapter builds instead; the runner's
    // own initial/final register state is authoritative, which is why the derived
    // trace-only boundary is not used here either.
    const public_data_mod = frontend.air.public_data;
    const input_words = try public_data_mod.packInputWords(allocator, run_result.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        public_data_mod.OutputWord,
        run_result.output_words.len,
    );
    defer allocator.free(output_words);
    for (run_result.output_words, 0..) |word, word_index| output_words[word_index] = .{
        .addr = word.addr,
        .value = word.value,
        .clock = word.clock,
    };

    const t_prove = Timer.begin();
    var recorder = stage_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    const output = try riscv_prover.proveRiscVWithEngineAndPublicData(
        Engine,
        allocator,
        config,
        &run_result.execution_trace,
        &run_result.state_chain_tracker,
        &run_result.rw_memory,
        if (profile_enabled) &recorder else null,
        .{
            .initial_pc = run_result.initial_pc,
            .final_pc = run_result.final_pc,
            .clock = @intCast(run_result.step_count),
            .initial_regs = run_result.initial_regs,
            .final_regs = run_result.final_regs,
            .reg_last_clock = run_result.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = try public_data_mod.completionFromRun(run_result),
            .io_entries = .{
                .input_start = run_result.input_start,
                .input_len = @intCast(run_result.input.len),
                .input_words = input_words,
                .output_len = run_result.output_len,
                .output_len_addr = run_result.output_len_addr,
                .output_data_addr = run_result.output_data_addr,
                .output_words = output_words,
            },
        },
    );
    defer output.deinitAfterProofMoved(allocator);
    const prove_ms = t_prove.elapsedMs();

    std.debug.print("Prove:    {d:.1}ms\n", .{prove_ms});
    const preprocessed_cells = output.statement.nPreprocessedCells();
    const main_cells = output.statement.nMainCells();
    const interaction_cells = output.statement.nInteractionCells();
    const committed_cells = main_cells + interaction_cells;
    std.debug.print("Trace cells: preprocessed={d} main={d} interaction={d} committed={d}\n", .{
        preprocessed_cells,
        main_cells,
        interaction_cells,
        committed_cells,
    });
    std.debug.print("Committed cells/cycle: {d:.2}\n", .{
        @as(f64, @floatFromInt(committed_cells)) / @as(f64, @floatFromInt(cycles)),
    });
    if (profile_enabled) {
        std.debug.print("Trace layout:\n", .{});
        for (0..output.statement.n_components) |component_index| {
            const desc = output.statement.component_descs[component_index];
            const cells = @as(u64, desc.n_columns) << @intCast(desc.log_size);
            std.debug.print("  opcode {s}: log={d} columns={d} cells={d}\n", .{
                @tagName(desc.family), desc.log_size, desc.n_columns, cells,
            });
        }
        for (0..output.statement.n_infra) |infra_index| {
            const desc = output.statement.infra_descs[infra_index];
            const cells = @as(u64, desc.n_columns) << @intCast(desc.log_size);
            std.debug.print("  infra {s}: log={d} columns={d} cells={d}\n", .{
                @tagName(desc.kind), desc.log_size, desc.n_columns, cells,
            });
        }
        var profile = try recorder.snapshot(allocator);
        defer profile.deinit(allocator);
        std.debug.print("Profile:\n", .{});
        printProfileNodes(profile.stages, 1);
    }

    // Stage 4: Verify
    const t_verify = Timer.begin();
    // Verification is backend-neutral; the engine supplies the protocol types.
    try riscv_prover.verifyRiscVWithEngine(
        Engine,
        allocator,
        config,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
    const verify_ms = t_verify.elapsedMs();

    std.debug.print("Verify:   {d:.1}ms\n", .{verify_ms});

    const total_ms = t_total.elapsedMs();
    const prove_verify_ms = prove_ms + verify_ms;
    const run_prove_ms = exec_ms + prove_ms;

    std.debug.print("\n", .{});
    std.debug.print("Total:    {d:.1}ms\n", .{total_ms});
    std.debug.print("Run+Prove:{d:.1}ms  ({d:.1} kHz)\n", .{
        run_prove_ms,
        @as(f64, @floatFromInt(cycles)) / run_prove_ms,
    });
    std.debug.print("Prove+Verify: {d:.1}ms\n", .{prove_verify_ms});
    std.debug.print("\n", .{});

    const run_prove_khz = @as(f64, @floatFromInt(cycles)) / run_prove_ms;
    std.debug.print("Throughput (run+prove): {d:.1} kHz\n", .{run_prove_khz});
}

fn printUsage() void {
    std.debug.print(
        \\Usage: riscv-bench [options]
        \\
        \\  --fib-n N         Prove a generated fib(N) guest (default: 10000)
        \\  --elf PATH        Prove an RV32IM ELF instead of the generated guest
        \\  --input PATH      Load bytes into the ELF's linker-defined input region
        \\  --input-u32 N     Pass one little-endian u32 to the guest
        \\  --max-steps N     Execution limit for --elf (default: 10000000)
        \\  --hosted          Enable host-call support
        \\  --hint PATH       Host hint input
        \\  --pow-bits N      Proof-of-work bits (default: 0)
        \\  --n-queries N     FRI query count (default: 3)
        \\  --production      Use pow_bits=24 and n_queries=70
        \\  --run-only        Execute the guest without proving
        \\  --profile         Print nested prover stage timings
        \\  -h, --help        Show this help
        \\
    , .{});
}

fn printProfileNodes(nodes: []const stage_profile.StageNode, depth: usize) void {
    for (nodes) |node| {
        for (0..depth) |_| std.debug.print("  ", .{});
        std.debug.print("{s}: {d:.3}s\n", .{ node.id, node.seconds });
        if (node.children) |children| printProfileNodes(children, depth + 1);
    }
}
