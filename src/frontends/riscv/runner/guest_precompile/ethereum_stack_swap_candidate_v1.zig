//! Candidate-only combined Ethereum and U256 SWAP execution state.
//!
//! Keccak, signer recovery, and SWAP retain independent local tapes but share
//! the one external-retirement clock. Default Ethereum dispatch never imports
//! this module.

const std = @import("std");

const custom0 = @import("../../isa/custom0.zig");
const authority_mod = @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const candidate_dispatch = @import("stack_swap_candidate_dispatch_v1.zig");
const keccakf_v1 = @import("keccakf_v1.zig");
const recovery_v1 = @import("secp256k1_recover_v1.zig");
const session_state = @import("session_state.zig");
const swap_runner = @import("stack_swap_v1.zig");
const swap_tape = @import("stack_swap_session_tape_v1.zig");

pub const production_active = false;

pub const State = struct {
    authority: authority_mod.Authority,
    ethereum: session_state.Ethereum,
    stack_swap: swap_tape.Builder,
    dispatcher: candidate_dispatch.Dispatcher,

    pub fn init(
        allocator: std.mem.Allocator,
        budget: usize,
        external_step_origin: usize,
        authority: authority_mod.Authority,
    ) !State {
        try authority.validate();
        var ethereum = try session_state.Ethereum.init(
            allocator,
            budget,
            external_step_origin,
        );
        errdefer ethereum.deinit();
        var stack_swap = try swap_tape.Builder.init(
            allocator,
            authority.stack_swap,
            @min(budget, swap_tape.max_calls),
            external_step_origin,
        );
        errdefer stack_swap.deinit();
        const dispatcher = try candidate_dispatch.Dispatcher.init(authority.stack_swap);
        return .{
            .authority = authority,
            .ethereum = ethereum,
            .stack_swap = stack_swap,
            .dispatcher = dispatcher,
        };
    }

    pub fn deinit(self: *State) void {
        self.ethereum.deinit();
        self.stack_swap.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const State) !session_state.ExternalCounts {
        const ethereum = try self.ethereum.externalCounts();
        const swap = self.stack_swap.externalCounts();
        return .{
            .calls = try std.math.add(usize, ethereum.calls, swap.calls),
            .rows = try std.math.add(usize, ethereum.rows, swap.rows),
        };
    }

    pub fn validateExternalCount(self: *const State, expected: usize) bool {
        self.authority.validate() catch return false;
        self.dispatcher.validate() catch return false;
        if (self.ethereum.external_step_origin != self.stack_swap.external_step_origin)
            return false;
        const ethereum_counts = self.ethereum.externalCounts() catch return false;
        if (!self.ethereum.validateExternalCount(ethereum_counts.calls)) return false;
        self.stack_swap.validate() catch return false;
        const counts = self.externalCounts() catch return false;
        return counts.calls == expected and counts.rows == expected;
    }

    pub fn executeWithRecordedClock(
        self: *State,
        inst_word: u32,
        execution_clock: u32,
        cpu: *Cpu,
        memory: *Memory,
        layout: MemoryLayout,
        tracker: *StateChainTracker,
        trace: *Trace,
    ) !void {
        try self.authority.validate();
        const counts = try self.externalCounts();
        if (self.dispatcher.claims(inst_word)) {
            return swap_runner.executeWithAggregateRecordedClock(
                inst_word,
                execution_clock,
                self.stack_swap.external_step_origin,
                counts.calls,
                counts.rows,
                cpu,
                memory,
                layout,
                tracker,
                trace,
                &self.stack_swap,
            );
        }

        const decoded = try custom0.decode(authority_mod.base_profile, inst_word);
        switch (decoded.opcode) {
            .keccakf_1600_permute_in_place_v1 => try keccakf_v1.executeWithAggregateRecordedClock(
                authority_mod.base_profile,
                inst_word,
                execution_clock,
                self.ethereum.external_step_origin,
                cpu,
                memory,
                layout,
                tracker,
                trace,
                counts.calls,
                counts.rows,
                &self.ethereum.keccakf_calls,
                &self.ethereum.keccakf_rows,
            ),
            .secp256k1_recover_signer_v1 => try recovery_v1.executeWithRecordedClock(
                authority_mod.base_profile,
                inst_word,
                execution_clock,
                self.ethereum.external_step_origin,
                cpu,
                memory,
                layout,
                tracker,
                trace,
                counts.calls,
                counts.rows,
                &self.ethereum.signer_recovery_calls,
                &self.ethereum.signer_recovery_rows,
            ),
            .poseidon2_m31_permute_in_place_v1 => return error.InvalidPrecompileEncoding,
        }
    }
};

comptime {
    if (production_active or authority_mod.production_active or
        candidate_dispatch.production_active)
    {
        @compileError("Ethereum+SWAP candidate dispatch became production-active");
    }
}
