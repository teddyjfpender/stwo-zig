//! Guest Poseidon witness joined to full-width BLAKE3 program/memory providers.
//! Guest permutation rows are retained; no prover-owned Poseidon tree is built.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const memory_mod = @import("blake3_commitment_witness.zig");
const plan_mod = @import("blake3_commitment_plan.zig");
const Native = @import("blake3_execution_trace.zig").Owner;
const Hashes = @import("blake3_commitment_columns.zig").Owner;
const guest_main = @import("../air/guest_precompile/main_trace.zig");
const statement_mod = @import("blake3_poseidon_statement.zig");
const public_io = @import("blake3_segment_public.zig");
pub const Owner = struct {
    owned_io: public_io.Owned,
    memory: memory_mod.Witness,
    plan: plan_mod.Plan,
    native: *Native,
    hashes: *Hashes,
    extension: guest_main.Result,
    statement: statement_mod.Statement,

    pub fn initRun(a: std.mem.Allocator, run: *const runner.Poseidon2RunResult) !Owner {
        const external = std.math.cast(u32, run.calls.len()) orelse return error.InvalidExecutionTrace;
        if (run.execution_rows.rows().len != external) return error.InvalidExecutionTrace;
        try run.base.execution_trace.validateClockRange(0, @intCast(run.base.step_count), external);
        var io = try public_io.Owned.initRun(a, &run.base);
        errdefer io.deinit();
        var memory = try memory_mod.build(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = .rv32im_zkvm_poseidon2_v1 }, .{ run.base.execution_trace.rows.items, run.execution_rows.rows() }, &run.base.rw_memory, @import("commitment_program_witness.zig").completionFetch(io.data.completion), 100);
        errdefer memory.deinit();
        try memory.bindPublic(&io.data);
        var plan = try memory.plan(a);
        errdefer plan.deinit();
        const pin = try plan_mod.Admission.init(&plan, try plan.identity());
        const hashes = try Hashes.init(a, pin);
        errdefer hashes.deinit();
        try hashes.prepareMain(&memory);
        const native = try Native.initWithExternal(a, &run.base.execution_trace, io.data, &run.base.state_chain_tracker, external);
        errdefer native.deinit();
        var statement = try statement_mod.canonical(&native.statement, pin, hashes.logs, external);
        var extension = try guest_main.generateBlake3(a, &native.statement, pin, hashes.logs, &statement, &run.calls, &run.execution_rows);
        errdefer extension.deinit();
        _ = try @import("../air/guest_precompile/lookup_registration.zig").registerBlake3(&native.statement, pin, hashes.logs, &statement, &extension, &native.opcode_columns.lookup_counters.?);
        try native.includeCommitments(hashes);
        statement = try statement_mod.canonical(&native.statement, pin, hashes.logs, external);
        return .{ .owned_io = io, .memory = memory, .plan = plan, .native = native, .hashes = hashes, .extension = extension, .statement = statement };
    }
    pub fn admission(self: *const Owner) !plan_mod.Admission {
        return plan_mod.Admission.init(&self.plan, try self.plan.identity());
    }
    pub fn deinit(self: *Owner) void {
        self.extension.deinit();
        self.native.deinit();
        self.hashes.deinit();
        self.plan.deinit();
        self.memory.deinit();
        self.owned_io.deinit();
        self.* = undefined;
    }
};
