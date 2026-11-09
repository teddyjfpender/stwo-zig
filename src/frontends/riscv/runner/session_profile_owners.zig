//! Resumable RV32IM execution with owned, proof-oriented segment boundaries.
//!
//! The architectural state, sparse memory, and decoded-instruction cache live
//! for the whole session. Trace and state-chain logs are owned per segment.
//! Existing V2 sessions keep clocks global across resumes; the explicit
//! leaf-local frame resets proof-internal clocks at every boundary so a later
//! versioned recursive wrapper can own global position without widening M31
//! clock columns. This is intentionally a runner substrate: V1/V2 admission
//! continues to fail closed on non-first locally clocked segments.

const std = @import("std");
const ethereum_candidate_combined_authority =
    @import("../isa/ethereum_candidate_combined_authority_v1.zig");
const ethereum_bulk_memcpy_authority =
    @import("../isa/ethereum_bulk_memcpy_candidate_v1.zig");
const ethereum_stack_swap_authority =
    @import("../isa/ethereum_stack_swap_candidate_v1.zig");
const execution_profile = @import("../isa/execution_profile.zig");
const access_clock = @import("../access_clock.zig");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const decode_cache = @import("decode_cache.zig");
const elf_loader = @import("elf_loader.zig");
const ethereum_candidate_combined_state =
    @import("guest_precompile/ethereum_candidate_combined_v1.zig");
const ethereum_bulk_memcpy_state =
    @import("guest_precompile/ethereum_bulk_memcpy_candidate_v1.zig");
const ethereum_stack_swap_state =
    @import("guest_precompile/ethereum_stack_swap_candidate_v1.zig");
const extension_state = @import("guest_precompile/session_state.zig");
const host_mod = @import("../host/interface.zig");
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const segment_capacity = @import("segment_capacity.zig");
const memory_state = @import("memory_state.zig");
const result_mod = @import("result.zig");
const ethereum_candidate_combined_result =
    @import("ethereum_candidate_combined_result_v1.zig");
const ethereum_bulk_memcpy_result =
    @import("ethereum_bulk_memcpy_candidate_result_v1.zig");
const ethereum_stack_swap_result =
    @import("ethereum_stack_swap_candidate_result_v1.zig");
const session_support = @import("segment_session_support.zig");
const session_contract = @import("segment_session_contract.zig");
const session_retirement = @import("segment_session_retirement.zig");

const ExecutionProfile = execution_profile.ExecutionProfile;
const guest_precompile = @import("guest_precompile/mod.zig");

fn ConfiguredSegmentResultForPolicy(
    comptime profile: ExecutionProfile,
    comptime ethereum_stack_swap_candidate: bool,
    comptime ethereum_bulk_memcpy_candidate: bool,
) type {
    if (ethereum_stack_swap_candidate and ethereum_bulk_memcpy_candidate)
        return ethereum_candidate_combined_result.SegmentResult;
    if (ethereum_stack_swap_candidate) {
        if (profile != .rv32im_zkvm_ethereum_v1)
            @compileError("the SWAP candidate policy requires the Ethereum profile");
        return ethereum_stack_swap_result.SegmentResult;
    }
    if (ethereum_bulk_memcpy_candidate) {
        if (profile != .rv32im_zkvm_ethereum_v1)
            @compileError("the bulk-memcpy candidate requires the Ethereum profile");
        return ethereum_bulk_memcpy_result.SegmentResult;
    }
    return switch (profile) {
        .rv32im_zkvm_v1 => result_mod.SegmentResult,
        .rv32im_zkvm_poseidon2_v1 => result_mod.Poseidon2SegmentResult,
        .rv32im_zkvm_keccakf_v1 => result_mod.KeccakfSegmentResult,
        .rv32im_zkvm_ethereum_v1 => result_mod.EthereumSegmentResult,
        .rv32im_zkvm_ethereum_sha_v1 => result_mod.EthereumShaSegmentResult,
    };
}
fn ConfiguredRunResultForPolicy(
    comptime profile: ExecutionProfile,
    comptime ethereum_stack_swap_candidate: bool,
    comptime ethereum_bulk_memcpy_candidate: bool,
) type {
    if (ethereum_stack_swap_candidate and ethereum_bulk_memcpy_candidate)
        return ethereum_candidate_combined_result.RunResult;
    if (ethereum_stack_swap_candidate) return ethereum_stack_swap_result.RunResult;
    if (ethereum_bulk_memcpy_candidate) return ethereum_bulk_memcpy_result.RunResult;
    return switch (profile) {
        .rv32im_zkvm_v1 => result_mod.RunResult,
        .rv32im_zkvm_poseidon2_v1 => result_mod.Poseidon2RunResult,
        .rv32im_zkvm_keccakf_v1 => result_mod.KeccakfRunResult,
        .rv32im_zkvm_ethereum_v1 => result_mod.EthereumRunResult,
        .rv32im_zkvm_ethereum_sha_v1 => result_mod.EthereumShaRunResult,
    };
}

pub fn For(comptime selected_profile: execution_profile.ExecutionProfile, comptime ethereum_stack_swap_candidate: bool, comptime ethereum_bulk_memcpy_candidate: bool) type {
    if (!ethereum_stack_swap_candidate and !ethereum_bulk_memcpy_candidate and selected_profile != .rv32im_zkvm_ethereum_v1 and selected_profile != .rv32im_zkvm_ethereum_sha_v1) return @import("default_profile_owner.zig").For(selected_profile);
    const combined_candidate = ethereum_stack_swap_candidate and
        ethereum_bulk_memcpy_candidate;
    const AuthorityType = if (combined_candidate)
        ethereum_candidate_combined_authority.Authority
    else if (ethereum_stack_swap_candidate)
        ethereum_stack_swap_authority.Authority
    else if (ethereum_bulk_memcpy_candidate)
        ethereum_bulk_memcpy_authority.Authority
    else
        void;
    const StateType = if (combined_candidate)
        ethereum_candidate_combined_state.State
    else if (ethereum_stack_swap_candidate)
        ethereum_stack_swap_state.State
    else if (ethereum_bulk_memcpy_candidate)
        ethereum_bulk_memcpy_state.State
    else
        extension_state.State(selected_profile);
    const candidate = ethereum_stack_swap_candidate or ethereum_bulk_memcpy_candidate;
    const SegmentResultType = ConfiguredSegmentResultForPolicy(selected_profile, ethereum_stack_swap_candidate, ethereum_bulk_memcpy_candidate);
    const RunResultType = ConfiguredRunResultForPolicy(selected_profile, ethereum_stack_swap_candidate, ethereum_bulk_memcpy_candidate);
    return struct {
        pub const profile = selected_profile;
        pub const is_candidate = candidate;
        pub const allows_local_custody = selected_profile == .rv32im_zkvm_v1 or selected_profile == .rv32im_zkvm_ethereum_v1 or selected_profile == .rv32im_zkvm_ethereum_sha_v1;
        pub const CandidateAuthority = AuthorityType;
        pub const State = StateType;
        pub const SegmentResult = SegmentResultType;
        pub const RunResult = RunResultType;
        pub const required_authority_error = if (combined_candidate) error.EthereumCombinedCandidateAuthorityRequired else if (ethereum_stack_swap_candidate) error.EthereumStackSwapAuthorityRequired else error.EthereumBulkMemcpyAuthorityRequired;
        pub const unavailable_authority_error = error.EthereumCandidatePolicyUnavailable;
        pub fn runFromSegment(segment: *SegmentResult, comptime segmentToRunResult: anytype) !RunResult {
            if (comptime combined_candidate) {
                errdefer segment.deinit();
                const result = ethereum_candidate_combined_result.runFromSegment(
                    segmentToRunResult(&segment.ethereum.base),
                    segment,
                );
                segment.* = undefined;
                return result;
            } else if (comptime ethereum_stack_swap_candidate) {
                errdefer segment.deinit();
                const result = ethereum_stack_swap_result.runFromSegment(
                    segmentToRunResult(&segment.ethereum.base),
                    segment,
                );
                segment.* = undefined;
                return result;
            } else if (comptime ethereum_bulk_memcpy_candidate) {
                errdefer segment.deinit();
                const result = ethereum_bulk_memcpy_result.runFromSegment(
                    segmentToRunResult(&segment.ethereum.base),
                    segment,
                );
                segment.* = undefined;
                return result;
            } else if (comptime profile == .rv32im_zkvm_ethereum_sha_v1) {
                errdefer segment.deinit();
                const result = result_mod.EthereumShaRunResult{ .base = segmentToRunResult(&segment.base), .extension = segment.extension };
                segment.* = undefined;
                return result;
            } else {
                errdefer segment.deinit();
                const result = result_mod.ethereumRunFromSegment(
                    segmentToRunResult(&segment.base),
                    segment,
                );
                segment.* = undefined;
                return result;
            }
        }
        pub fn freezeSegment(base_result: result_mod.SegmentResult, extension: *State) !SegmentResult {
            if (comptime combined_candidate) {
                return ethereum_candidate_combined_result.freezeSegment(
                    base_result,
                    extension,
                );
            } else if (comptime ethereum_stack_swap_candidate) {
                return ethereum_stack_swap_result.freezeSegment(base_result, extension);
            } else if (comptime ethereum_bulk_memcpy_candidate) {
                return ethereum_bulk_memcpy_result.freezeSegment(base_result, extension);
            } else if (comptime profile == .rv32im_zkvm_ethereum_v1) {
                return result_mod.freezeEthereumSegment(base_result, extension);
            } else {
                return try result_mod.freezeEthereumShaSegment(base_result, extension);
            }
        }
        pub fn retireCustom0(self: anytype, inst_word: u32, execution_clock: u32, exec_trace: *trace.Trace, chain_tracker: *state_chain.StateChainTracker, extension: *State) !void {
            if (comptime ethereum_stack_swap_candidate or
                ethereum_bulk_memcpy_candidate)
            {
                try extension.executeWithRecordedClock(
                    inst_word,
                    execution_clock,
                    &self.cpu,
                    &self.memory,
                    self.elf_info.memory_layout,
                    chain_tracker,
                    exec_trace,
                );
            } else if (comptime profile == .rv32im_zkvm_ethereum_sha_v1) {
                try @import("guest_precompile/ethereum_sha.zig").executeWithRecordedClock(inst_word, execution_clock, &self.cpu, &self.memory, self.elf_info.memory_layout, chain_tracker, exec_trace, extension);
            } else {
                try guest_precompile.ethereum_v1.executeWithRecordedClock(
                    profile,
                    inst_word,
                    execution_clock,
                    &self.cpu,
                    &self.memory,
                    self.elf_info.memory_layout,
                    chain_tracker,
                    exec_trace,
                    extension,
                );
            }
        }
    };
}
