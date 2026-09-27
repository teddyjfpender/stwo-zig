//! Object/semantic only. Real original first-commit body, NEVER execute export.
const std = @import("std");
const Native = @import("prover/blake3_execution_trace.zig");
const Capacity = @import("prover/block_v5_native_capacity_proof_v1.zig");
const Memory = @import("prover/block_v5_native_capacity_fused_stage_v1.zig");
const Selection = @import("prover/block_v5_readonly_input_selection_v1.zig");
const Proposal = @import("prover/block_v5_readonly_input_proposal_v1.zig");
const Counters = @import("prover/block_v5_readonly_input_counter_collection_v2.zig");
const Collection = @import("prover/block_v5_native_capacity_readonly_collection_v2.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
pub export fn stwo_native_readonly_stream_collection_body_gate(a: *const std.mem.Allocator, owner: *Native.Owner, native: *const Capacity.Proposal, memory: *const Memory.Proposal, memory_limits: *const Memory.Limits, selection: *const Selection.Owned, limits: *const Proposal.Limits, groups: *Counters.Owned) void {
    _ = Collection.collect(a.*, owner, native, memory, memory_limits.*, selection, limits.*, groups) catch return;
}

const Cpu = @import("stwo_cpu_backend").CpuBackend;
const CallerFirst = @import("prover/block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).FirstRound;
const CallerCollection = @import("prover/block_v5_caller_readonly_collection_v2.zig").ForBackend(Cpu);
const CallerLimits = @import("prover/block_v5_caller_readonly_protocol_v1.zig").Limits;
const Frame = @import("air/block/memory_event.zig").Frame;
const ByteCounter = @import("air/lookups/tables/counter.zig").Counter;
pub export fn stwo_caller_readonly_stream_collection_body_gate(a: *const std.mem.Allocator, prefix: *CallerFirst, index: u32, frame: *const Frame, selection: *const Selection.Owned, limits: *const CallerLimits, target: *ByteCounter, groups: *Counters.Owned) void {
    var result = CallerCollection.collect(a.*, prefix, &prefix.witness.statement, prefix.total_steps, index, frame.*, selection, limits.*, target, groups) catch return;
    result.deinit(a.*);
}
