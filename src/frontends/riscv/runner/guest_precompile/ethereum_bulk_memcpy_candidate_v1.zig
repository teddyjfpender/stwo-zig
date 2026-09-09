//! Candidate-only combined Ethereum and bulk-memcpy execution state.
//!
//! Keccak, signer recovery, and bulk memcpy retain independent local tapes
//! while sharing one external-retirement clock. Default Ethereum dispatch is
//! unchanged and never imports this module.

const std = @import("std");

const custom0 = @import("../../isa/custom0.zig");
const authority_mod = @import("../../isa/ethereum_bulk_memcpy_candidate_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const bulk_call_buffer = @import("bulk_memcpy_call_buffer_v1.zig");
const bulk_dispatch = @import("bulk_memcpy_candidate_dispatch_v1.zig");
const bulk_tape = @import("bulk_memcpy_session_tape_v1.zig");
const keccakf_v1 = @import("keccakf_v1.zig");
const recovery_v1 = @import("secp256k1_recover_v1.zig");
const session_state = @import("session_state.zig");

pub const production_active = false;

pub const State = struct {
    authority: authority_mod.Authority,
    ethereum: session_state.Ethereum,
    bulk_memcpy: bulk_tape.Builder,
    dispatcher: bulk_dispatch.Dispatcher,

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
        var bulk_memcpy = try bulk_tape.Builder.init(
            allocator,
            @min(budget, bulk_call_buffer.max_calls),
            bulk_call_buffer.max_word_rows,
            external_step_origin,
        );
        errdefer bulk_memcpy.deinit();
        return .{
            .authority = authority,
            .ethereum = ethereum,
            .bulk_memcpy = bulk_memcpy,
            .dispatcher = try .init(authority.bulk_memcpy),
        };
    }

    pub fn deinit(self: *State) void {
        self.ethereum.deinit();
        self.bulk_memcpy.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const State) !session_state.ExternalCounts {
        const ethereum = try self.ethereum.externalCounts();
        const bulk = self.bulk_memcpy.externalCounts();
        return .{
            .calls = try std.math.add(usize, ethereum.calls, bulk.calls),
            .rows = try std.math.add(usize, ethereum.rows, bulk.rows),
        };
    }

    pub fn validateExternalCount(self: *const State, expected: usize) bool {
        self.authority.validate() catch return false;
        self.dispatcher.validate() catch return false;
        if (self.ethereum.external_step_origin !=
            self.bulk_memcpy.external_step_origin)
        {
            return false;
        }
        const ethereum_counts = self.ethereum.externalCounts() catch return false;
        if (!self.ethereum.validateExternalCount(ethereum_counts.calls)) return false;
        self.bulk_memcpy.validate() catch return false;
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
            return self.dispatcher.retireCustom0(
                inst_word,
                execution_clock,
                self.bulk_memcpy.external_step_origin,
                counts.calls,
                counts.rows,
                cpu,
                memory,
                layout,
                tracker,
                trace,
                &self.bulk_memcpy,
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
        bulk_dispatch.production_active)
    {
        @compileError("Ethereum+bulk-memcpy candidate state became active");
    }
}
