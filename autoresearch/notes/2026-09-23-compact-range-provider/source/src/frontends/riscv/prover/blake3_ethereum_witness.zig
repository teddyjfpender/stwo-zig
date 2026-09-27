//! Full-width Ethereum witness preparation without legacy commitment witnesses.
//! This owns preparation only. It is not an extension proof or admission key.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const public = @import("../air/public_data.zig");
const memory_mod = @import("blake3_commitment_witness.zig");
const plan_mod = @import("blake3_commitment_plan.zig");
const Native = @import("blake3_execution_trace.zig").Owner;
const Hashes = @import("blake3_commitment_columns.zig").Owner;
const Extension = @import("guest_precompile/ethereum_witness.zig").Witness;
const registration = @import("../air/guest_precompile/ethereum_lookup_registration.zig");
pub const Owner = struct {
    owned_io: ?@import("blake3_segment_public.zig").Owned = null,
    memory: memory_mod.Witness,
    plan: plan_mod.Plan,
    native: *Native,
    hashes: *Hashes,
    extension: Extension,
    statement: @import("blake3_ethereum_statement.zig").Statement,

    /// Run tapes are borrowed during construction. Public I/O slices in `data`
    /// must outlive this owner, as for the base native-column API.
    pub fn init(a: std.mem.Allocator, run: *const runner.EthereumRunResult, data: public.Blake3PublicData) !Owner {
        return initInternal(false, false, a, run, data);
    }
    /// Own public I/O derived from the completed runner result. No caller-built
    /// statement or borrowed I/O storage is required by this entry point.
    pub fn initRun(a: std.mem.Allocator, run: *const runner.EthereumRunResult) !Owner {
        return initRunMode(a, run, false);
    }
    pub fn initCompactRun(a: std.mem.Allocator, run: *const runner.EthereumRunResult) !Owner {
        return initRunMode(a, run, true);
    }
    fn initRunMode(a: std.mem.Allocator, run: *const runner.EthereumRunResult, compact: bool) !Owner {
        var io = try @import("blake3_segment_public.zig").Owned.initRun(a, &run.base);
        errdefer io.deinit();
        var result = try initInternal(false, compact, a, run, io.data);
        result.owned_io = io;
        return result;
    }
    /// Own all public I/O copied from a validated leaf-local runner segment.
    pub fn initSegment(a: std.mem.Allocator, segment: *const runner.EthereumSegmentResult) !Owner {
        var io = try @import("blake3_segment_public.zig").Owned.init(a, &segment.base);
        errdefer io.deinit();
        var result = try initInternal(true, false, a, segment, io.data);
        result.owned_io = io;
        return result;
    }
    fn initInternal(comptime segmented: bool, compact: bool, a: std.mem.Allocator, run: anytype, data: public.Blake3PublicData) !Owner {
        const stage_profile = @import("stwo_prover_engine").stage_profile;
        var recorder = stage_profile.Recorder.initWithOptions(a, "host", "blake3-ethereum-witness", .{ .capture_tasks = false });
        defer recorder.deinit();
        const diagnostic: ?*stage_profile.Recorder = if (std.process.hasEnvVarConstant("STWO_RISCV_EXECUTION_PROFILE")) &recorder else null;
        var phase = try stage_profile.StageScope.begin(diagnostic, "witness.precompile", "Preflight and precompile witness");
        defer phase.end();
        const input_bytes = if (segmented) run.base.input orelse &.{} else run.base.input;
        const initial_pc = if (segmented) run.base.entry_cpu.pc else run.base.initial_pc;
        const final_pc = if (segmented) run.base.exit_cpu.pc else run.base.final_pc;
        const initial_regs = if (segmented) run.base.entry_cpu.regs else run.base.initial_regs;
        const final_regs = if (segmented) run.base.exit_cpu.regs else run.base.final_regs;
        const steps = if (segmented) run.base.cycle_count else run.base.step_count;
        const completion = if (segmented) try @import("blake3_segment_public.zig").completion(&run.base) else try public.completionFromRun(run.base);
        const keccak = run.keccakf_calls.records();
        const signer = run.signer_recovery_calls.records();
        const keccak_rows = run.keccakf_execution_rows.rows();
        const signer_rows = run.signer_recovery_execution_rows.rows();
        const count = try std.math.add(usize, keccak.len, signer.len);
        const external = std.math.cast(u32, count) orelse return error.InvalidExecutionTrace;
        if (keccak.len != keccak_rows.len or signer.len != signer_rows.len or
            steps != data.clock or
            initial_pc != data.initial_pc or final_pc != data.final_pc or
            !std.meta.eql(initial_regs, data.initial_regs) or
            !std.meta.eql(final_regs, data.final_regs) or
            !std.meta.eql(run.base.state_chain_tracker.reg_last_clk, data.reg_last_clock)) return error.InvalidExecutionTrace;
        const io = data.io_entries;
        if (io.input_start != run.base.input_start or io.input_len != input_bytes.len or
            io.input_words.len != try std.math.divCeil(usize, input_bytes.len, 4) or
            io.output_len != run.base.output_len or io.output_len_addr != run.base.output_len_addr or
            io.output_data_addr != run.base.output_data_addr or io.output_words.len != run.base.output_words.len or
            !std.meta.eql(data.completion, completion)) return error.InvalidExecutionPublicIo;
        for (io.input_words, 0..) |value, i| {
            var expected: u32 = 0;
            const begin = i * 4;
            for (input_bytes[begin..@min(begin + 4, input_bytes.len)], 0..) |byte, j| expected |= @as(u32, byte) << @as(u5, @intCast(j * 8));
            if (value != expected) return error.InvalidExecutionPublicIo;
        }
        for (io.output_words, run.base.output_words) |claimed, actual| {
            if (claimed.addr != actual.addr or claimed.value != actual.value or claimed.clock != actual.clock) return error.InvalidExecutionPublicIo;
        }
        try run.base.execution_trace.validateClockRange(0, data.clock, count);
        // Existing preflight cross-binds every call to its independently retained
        // retirement row, including the disjoint union of the two clock tapes.
        var extension = try Extension.init(a, keccak, keccak_rows, signer, signer_rows, data.clock);
        errdefer extension.deinit();
        phase.end();
        phase = try stage_profile.StageScope.begin(diagnostic, "witness.memory", "Memory commitment plan");
        var bound = data;
        var memory = try memory_mod.build(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_v1 }, .{ run.base.execution_trace.rows.items, keccak_rows, signer_rows }, &run.base.rw_memory, @import("commitment_program_witness.zig").completionFetch(bound.completion), 100);
        errdefer memory.deinit();
        try memory.bindPublic(&bound);
        var plan = try memory.plan(a);
        errdefer plan.deinit();
        const pin = try plan_mod.Admission.init(&plan, try plan.identity());
        phase.end();
        phase = try stage_profile.StageScope.begin(diagnostic, "witness.hashes", "Hash columns and witness");
        const hashes = try Hashes.init(a, pin);
        errdefer hashes.deinit();
        try hashes.prepareMain(&memory);
        phase.end();
        phase = try stage_profile.StageScope.begin(diagnostic, "witness.native", "Native execution columns");
        const native = try Native.initWithExternal(a, &run.base.execution_trace, bound, &run.base.state_chain_tracker, external);
        errdefer native.deinit();
        // One census covers native operations, clock updates, external callers
        // and BLAKE3 providers before any table multiplicity column is emitted.
        phase.end();
        phase = try stage_profile.StageScope.begin(diagnostic, "witness.lookup_counts", "Shared lookup counts and statement");
        const lookups = registration.Context{ .keccak = keccak, .recovery = signer };
        try lookups.register(&native.opcode_columns.lookup_counters.?);
        if (compact) try native.includeCompactCommitments(hashes) else try native.includeCommitments(hashes);
        const statement = try @import("blake3_ethereum_statement.zig").canonical(&native.statement, pin, hashes.logs, @intCast(keccak.len), @intCast(signer.len), extension.shapes());
        phase.end();
        if (diagnostic != null) {
            var snapshot = try recorder.snapshot(a);
            defer snapshot.deinit(a);
            const json = try std.json.Stringify.valueAlloc(a, snapshot, .{});
            defer a.free(json);
            std.debug.print("BLAKE3_WITNESS_STAGE_PROFILE {s}\n", .{json});
        }
        return .{ .memory = memory, .plan = plan, .native = native, .hashes = hashes, .extension = extension, .statement = statement };
    }
    pub fn admission(self: *const Owner) !plan_mod.Admission {
        return plan_mod.Admission.init(&self.plan, try self.plan.identity());
    }
    pub fn deinit(self: *Owner) void {
        self.native.deinit();
        self.hashes.deinit();
        self.plan.deinit();
        self.memory.deinit();
        self.extension.deinit();
        if (self.owned_io) |*io| io.deinit();
        self.* = undefined;
    }
};
