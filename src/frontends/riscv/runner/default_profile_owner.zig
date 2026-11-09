//! Native/Poseidon/Keccak default owners; no product selection or runtime registration.
const std = @import("std");
const ExecutionProfile = @import("../isa/execution_profile.zig").ExecutionProfile;
const result_mod = @import("base_result.zig");
const extension_state = @import("guest_precompile/generic_session_state.zig");
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const guest_precompile = struct {
    pub const poseidon2_v1 = @import("guest_precompile/poseidon2_v1.zig");
    pub const keccakf_v1 = @import("guest_precompile/keccakf_v1.zig");
};
pub fn For(comptime selected_profile: ExecutionProfile) type {
    const StateType = switch (selected_profile) {
        .rv32im_zkvm_v1 => extension_state.Empty,
        .rv32im_zkvm_poseidon2_v1 => extension_state.Poseidon2,
        .rv32im_zkvm_keccakf_v1 => extension_state.Keccakf,
        else => @compileError("product profiles require their explicit typed owner"),
    };
    const SegmentResultType = switch (selected_profile) {
        .rv32im_zkvm_v1 => result_mod.SegmentResult,
        .rv32im_zkvm_poseidon2_v1 => result_mod.Poseidon2SegmentResult,
        .rv32im_zkvm_keccakf_v1 => result_mod.KeccakfSegmentResult,
        else => unreachable,
    };
    const RunResultType = switch (selected_profile) {
        .rv32im_zkvm_v1 => result_mod.RunResult,
        .rv32im_zkvm_poseidon2_v1 => result_mod.Poseidon2RunResult,
        .rv32im_zkvm_keccakf_v1 => result_mod.KeccakfRunResult,
        else => unreachable,
    };
    return struct {
        pub const profile = selected_profile;
        pub const State = StateType;
        pub const CandidateAuthority = void;
        pub const SegmentResult = SegmentResultType;
        pub const RunResult = RunResultType;
        pub const is_candidate = false;
        pub const allows_local_custody = selected_profile == .rv32im_zkvm_v1;
        pub const unavailable_authority_error = error.EthereumCandidatePolicyUnavailable;
        pub fn runFromSegment(segment: *SegmentResult, comptime segmentToRunResult: anytype) !RunResult {
            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                errdefer segment.deinit();
                const base = segmentToRunResult(&segment.base);
                const result = result_mod.Poseidon2RunResult{
                    .base = base,
                    .calls = segment.calls,
                    .execution_rows = segment.execution_rows,
                };
                segment.* = undefined;
                return result;
            } else if (comptime profile == .rv32im_zkvm_keccakf_v1) {
                errdefer segment.deinit();
                const base = segmentToRunResult(&segment.base);
                const result = result_mod.KeccakfRunResult{
                    .base = base,
                    .calls = segment.calls,
                    .execution_rows = segment.execution_rows,
                };
                segment.* = undefined;
                return result;
            } else {
                errdefer segment.deinit();
                return segmentToRunResult(segment);
            }
        }
        pub fn freezeSegment(base_result: result_mod.SegmentResult, extension: *State) !SegmentResult {
            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                return .{
                    .base = base_result,
                    .calls = extension.calls.freeze(),
                    .execution_rows = extension.rows.freeze(),
                };
            } else if (comptime profile == .rv32im_zkvm_keccakf_v1) {
                return .{
                    .base = base_result,
                    .calls = extension.calls.freeze(),
                    .execution_rows = extension.rows.freeze(),
                };
            } else {
                return base_result;
            }
        }
        pub fn retireCustom0(self: anytype, inst_word: u32, execution_clock: u32, exec_trace: *trace.Trace, chain_tracker: *state_chain.StateChainTracker, extension: *State) !void {
            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                try guest_precompile.poseidon2_v1.executeWithRecordedClock(
                    profile,
                    inst_word,
                    execution_clock,
                    extension.external_step_origin,
                    &self.cpu,
                    &self.memory,
                    self.elf_info.memory_layout,
                    chain_tracker,
                    exec_trace,
                    &extension.calls,
                    &extension.rows,
                );
            } else if (comptime profile == .rv32im_zkvm_keccakf_v1) {
                try guest_precompile.keccakf_v1.executeWithRecordedClock(
                    profile,
                    inst_word,
                    execution_clock,
                    extension.external_step_origin,
                    &self.cpu,
                    &self.memory,
                    self.elf_info.memory_layout,
                    chain_tracker,
                    exec_trace,
                    &extension.calls,
                    &extension.rows,
                );
            } else {
                unreachable;
            }
        }
    };
}
