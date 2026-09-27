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
    memory: memory_mod.Witness,
    plan: plan_mod.Plan,
    native: *Native,
    hashes: *Hashes,
    extension: Extension,
    statement: @import("blake3_ethereum_statement.zig").Statement,

    /// Run tapes are borrowed during construction. Public I/O slices in `data`
    /// must outlive this owner, as for the base native-column API.
    pub fn init(a: std.mem.Allocator, run: *const runner.EthereumRunResult, data: public.Blake3PublicData) !Owner {
        const keccak = run.keccakf_calls.records();
        const signer = run.signer_recovery_calls.records();
        const keccak_rows = run.keccakf_execution_rows.rows();
        const signer_rows = run.signer_recovery_execution_rows.rows();
        const count = try std.math.add(usize, keccak.len, signer.len);
        const external = std.math.cast(u32, count) orelse return error.InvalidExecutionTrace;
        if (keccak.len != keccak_rows.len or signer.len != signer_rows.len or
            run.base.step_count != data.clock or
            run.base.initial_pc != data.initial_pc or run.base.final_pc != data.final_pc or
            !std.meta.eql(run.base.initial_regs, data.initial_regs) or
            !std.meta.eql(run.base.final_regs, data.final_regs) or
            !std.meta.eql(run.base.state_chain_tracker.reg_last_clk, data.reg_last_clock)) return error.InvalidExecutionTrace;
        const io = data.io_entries;
        if (io.input_start != run.base.input_start or io.input_len != run.base.input.len or
            io.input_words.len != try std.math.divCeil(usize, run.base.input.len, 4) or
            io.output_len != run.base.output_len or io.output_len_addr != run.base.output_len_addr or
            io.output_data_addr != run.base.output_data_addr or io.output_words.len != run.base.output_words.len or
            !std.meta.eql(data.completion, try public.completionFromRun(run.base))) return error.InvalidExecutionPublicIo;
        for (io.input_words, 0..) |value, i| {
            var expected: u32 = 0;
            const begin = i * 4;
            for (run.base.input[begin..@min(begin + 4, run.base.input.len)], 0..) |byte, j| expected |= @as(u32, byte) << @as(u5, @intCast(j * 8));
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
        var bound = data;
        var memory = try memory_mod.build(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_ethereum_v1 }, .{ run.base.execution_trace.rows.items, keccak_rows, signer_rows }, &run.base.rw_memory, @import("commitment_program_witness.zig").completionFetch(bound.completion), 100);
        errdefer memory.deinit();
        try memory.bindPublic(&bound);
        var plan = try memory.plan(a);
        errdefer plan.deinit();
        const pin = try plan_mod.Admission.init(&plan, try plan.identity());
        const hashes = try Hashes.init(a, pin);
        errdefer hashes.deinit();
        try hashes.prepareMain(&memory);
        const native = try Native.initWithExternal(a, &run.base.execution_trace, bound, &run.base.state_chain_tracker, external);
        errdefer native.deinit();
        // One census covers native operations, clock updates, external callers
        // and BLAKE3 providers before any table multiplicity column is emitted.
        const lookups = registration.Context{ .keccak = keccak, .recovery = signer };
        try lookups.register(&native.opcode_columns.lookup_counters.?);
        try native.includeCommitments(hashes);
        const statement = try @import("blake3_ethereum_statement.zig").canonical(&native.statement, pin, hashes.logs, @intCast(keccak.len), @intCast(signer.len), extension.shapes());
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
        self.* = undefined;
    }
};
