//! Combined execution storage and retirement authority for Keccak, recovery and
//! SHA. Explicit ELF execution admission is separate from proof activation.
const std = @import("std");
const session = @import("session_state.zig");
const ethereum = @import("ethereum_v1.zig");
const sha = @import("sha256_compression_v1.zig");
const custom0 = @import("../../isa/custom0.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const Layout = @import("../memory_state.zig").MemoryLayout;
const Tracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;

pub const production_active = sha.production_active;

/// Proof-owned tapes. Freezing moves their backing allocations unchanged.
pub const Frozen = struct {
    keccakf_calls: @import("keccakf_call_buffer.zig").Frozen,
    keccakf_execution_rows: @import("keccakf_v1.zig").FrozenExecutionRows,
    signer_recovery_calls: @import("secp256k1_recover_call_buffer.zig").Frozen,
    signer_recovery_execution_rows: @import("secp256k1_recover_v1.zig").FrozenExecutionRows,
    sha_calls: sha.Frozen,

    pub fn deinit(self: *Frozen) void {
        self.sha_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.keccakf_calls.deinit();
        self.* = undefined;
    }
};

pub const State = struct {
    ethereum: session.Ethereum,
    sha: sha.Tape,
    budget: usize,

    pub fn init(a: std.mem.Allocator, budget: usize, origin: usize) !State {
        return .{
            .ethereum = try session.Ethereum.init(a, budget, origin),
            .sha = .{ .allocator = a, .limit = budget },
            .budget = budget,
        };
    }

    /// Validate all counts before transferring any allocation. `recorded_total`
    /// is the trace's cumulative count, including the segment's prior origin.
    pub fn freeze(self: *State, recorded_total: usize) !Frozen {
        const expected = std.math.sub(usize, recorded_total, self.ethereum.external_step_origin) catch return error.ProfileClockCountMismatch;
        return self.freezeSegment(expected);
    }

    /// Extracted segment traces already contain local external counts.
    pub fn freezeSegment(self: *State, expected: usize) !Frozen {
        if (!self.validateExternalCount(expected)) return error.ProfileClockCountMismatch;
        const result = Frozen{
            .keccakf_calls = self.ethereum.keccakf_calls.freeze(),
            .keccakf_execution_rows = self.ethereum.keccakf_rows.freeze(),
            .signer_recovery_calls = self.ethereum.signer_recovery_calls.freeze(),
            .signer_recovery_execution_rows = self.ethereum.signer_recovery_rows.freeze(),
            .sha_calls = self.sha.freeze(),
        };
        self.budget = 0;
        return result;
    }

    pub fn deinit(self: *State) void {
        self.sha.deinit();
        self.ethereum.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const State) !session.ExternalCounts {
        const base = try self.ethereum.externalCounts();
        if (!self.ethereum.validateExternalCount(base.calls)) return error.ProfileClockAuthorityMismatch;
        return .{
            .calls = try std.math.add(usize, base.calls, self.sha.len()),
            .rows = try std.math.add(usize, base.rows, self.sha.len()),
        };
    }

    pub fn validateExternalCount(self: *const State, expected: usize) bool {
        const counts = self.externalCounts() catch return false;
        return counts.calls == expected and counts.rows == expected and expected <= self.budget;
    }
};

pub fn executeWithRecordedClock(word: u32, clock: u32, cpu: *Cpu, memory: *Memory, layout: Layout, tracker: *Tracker, trace: *Trace, state: *State) !void {
    const counts = try state.externalCounts();
    if (counts.calls >= state.budget) return error.PrecompileCallLimitExceeded;
    const decoded = try custom0.decode(.rv32im_zkvm_ethereum_sha_v1, word);
    if (decoded.opcode == .sha256_compress_v1) {
        try sha.executeWithRecordedClock(word, clock, state.ethereum.external_step_origin, counts.calls, counts.rows, cpu, memory, layout, tracker, trace, &state.sha);
    } else {
        try ethereum.executeWithAggregateRecordedClock(.rv32im_zkvm_ethereum_v1, word, clock, cpu, memory, layout, tracker, trace, &state.ethereum, counts);
    }
}
