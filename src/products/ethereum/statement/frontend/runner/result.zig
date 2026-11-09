//! Owned output of one RISC-V execution.

const std = @import("std");
const execution_boundary = @import("../../../../../frontends/riscv/runner/execution_boundary.zig");
const base_result = @import("../../../../../frontends/riscv/runner/base_result.zig");
const Cpu = @import("../../../../../frontends/riscv/runner/cpu.zig").Cpu;
const trace = @import("../../../../../frontends/riscv/runner/trace.zig");
const state_chain = @import("../../../../../frontends/riscv/runner/state_chain.zig");
const memory_state = @import("../../../../../frontends/riscv/runner/memory_state.zig");
const guest_precompile = @import("../../../../../frontends/riscv/runner/guest_precompile/mod.zig");

pub const CompletionReason = execution_boundary.CompletionReason;

pub const CONTINUATION_SCHEMA_VERSION = execution_boundary.CONTINUATION_SCHEMA_VERSION;

/// Clock namespace used by one segmented trace.
///
/// The existing SegmentV2 path uses `global_continuous`. Large recursive jobs
/// use `leaf_local`: every independently proved leaf starts at instruction
/// clock one, while a versioned outer statement owns its global position.
/// Keeping this explicit prevents a locally rebased trace from being mistaken
/// for the existing globally clocked protocol.
pub const SegmentClockFrame = execution_boundary.SegmentClockFrame;

pub const MemoryAccessClock = execution_boundary.MemoryAccessClock;

/// Exact predecessor-clock custody at a segment edge. Global-continuous V2
/// segments authenticate this boundary explicitly. Leaf-local segments reset
/// it to zero and require a versioned outer state-adjacency statement.
pub const AccessClockBoundary = execution_boundary.AccessClockBoundary;

/// Copyable authority required to resume exactly one yielded execution.
/// Validation happens before the session mutates any architectural state.
pub const ContinuationToken = execution_boundary.ContinuationToken;

/// A final, word-aligned guest output value and its last access clock.
pub const OutputWord = execution_boundary.OutputWord;

/// Owned proof input for one bounded execution segment.
///
/// A yielded segment has `completion_reason == null`, no output, and a
/// continuation token.  A completed segment has the inverse shape.  Keeping
/// this distinct from `RunResult` prevents an intermediate boundary from ever
/// being admitted as a completed V1 execution by accident.
pub const SegmentResult = base_result.SegmentResult;

pub const Poseidon2SegmentResult = base_result.Poseidon2SegmentResult;

pub const KeccakfSegmentResult = base_result.KeccakfSegmentResult;

/// Segment-owned result for the combined Ethereum execution profile. Each
/// precompile retains an independent local call-index tape.
pub const EthereumSegmentResult = struct {
    base: SegmentResult,
    keccakf_calls: guest_precompile.keccakf_call_buffer.Frozen,
    keccakf_execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,
    signer_recovery_calls: guest_precompile.secp256k1_recover_call_buffer.Frozen,
    signer_recovery_execution_rows: guest_precompile.secp256k1_recover_v1.FrozenExecutionRows,

    pub fn deinit(self: *EthereumSegmentResult) void {
        self.keccakf_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Allocation-free ownership transfer from the mutable combined extension.
pub fn freezeEthereumSegment(
    base: SegmentResult,
    extension: *guest_precompile.session_state.Ethereum,
) EthereumSegmentResult {
    return .{
        .base = base,
        .keccakf_calls = extension.keccakf_calls.freeze(),
        .keccakf_execution_rows = extension.keccakf_rows.freeze(),
        .signer_recovery_calls = extension.signer_recovery_calls.freeze(),
        .signer_recovery_execution_rows = extension.signer_recovery_rows.freeze(),
    };
}

/// Combined SHA/Keccak/recovery input for a bounded production leaf. Profile
/// admission is separate; ownership alone never authorizes a proof statement.
pub const EthereumShaSegmentResult = struct {
    base: SegmentResult,
    extension: @import("guest_precompile/ethereum_sha.zig").Frozen,

    pub fn deinit(self: *EthereumShaSegmentResult) void {
        self.extension.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// On error, both `base` and every extension tape remain caller-owned.
pub fn freezeEthereumShaSegment(base: SegmentResult, extension: *@import("guest_precompile/ethereum_sha.zig").State) !EthereumShaSegmentResult {
    return .{ .base = base, .extension = try extension.freezeSegment(base.execution_trace.recordedExternalSteps()) };
}

pub const EthereumShaRunResult = struct {
    base: RunResult,
    extension: @import("guest_precompile/ethereum_sha.zig").Frozen,
    pub fn deinit(self: *EthereumShaRunResult) void {
        self.extension.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Owned result of running a RISC-V program to completion.
pub const RunResult = base_result.RunResult;

/// Owned result for the explicit Poseidon2 extension runner. Keeping extension
/// storage outside `RunResult` preserves the base runner's type and hot state.
pub const Poseidon2RunResult = base_result.Poseidon2RunResult;

/// Owned result for the explicit Keccak-f extension runner.
pub const KeccakfRunResult = base_result.KeccakfRunResult;

/// Owned one-shot result for the combined Ethereum execution profile.
pub const EthereumRunResult = struct {
    base: RunResult,
    keccakf_calls: guest_precompile.keccakf_call_buffer.Frozen,
    keccakf_execution_rows: guest_precompile.keccakf_v1.FrozenExecutionRows,
    signer_recovery_calls: guest_precompile.secp256k1_recover_call_buffer.Frozen,
    signer_recovery_execution_rows: guest_precompile.secp256k1_recover_v1.FrozenExecutionRows,

    pub fn deinit(self: *EthereumRunResult) void {
        self.keccakf_calls.deinit();
        self.keccakf_execution_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_execution_rows.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Transfer an already-frozen segment payload into its one-shot result.
pub fn ethereumRunFromSegment(
    base: RunResult,
    segment: *const EthereumSegmentResult,
) EthereumRunResult {
    return .{
        .base = base,
        .keccakf_calls = segment.keccakf_calls,
        .keccakf_execution_rows = segment.keccakf_execution_rows,
        .signer_recovery_calls = segment.signer_recovery_calls,
        .signer_recovery_execution_rows = segment.signer_recovery_execution_rows,
    };
}
