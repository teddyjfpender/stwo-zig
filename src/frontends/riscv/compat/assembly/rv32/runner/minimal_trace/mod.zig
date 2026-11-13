//! Two-phase base-RV32 execution substrate.
//!
//! Capture owns only canonical leaf custody. Replay reconstructs full typed
//! retirement rows and access chains from an authenticated program, memory
//! boundary, CPU checkpoint, and ordered old-word tape.

pub const types = @import("stwo_riscv_rv32").execution.minimal_trace.types;
pub const capture = @import("stwo_riscv_rv32").execution.minimal_trace.capture;
pub const parallel_replay = @import("stwo_riscv_rv32").execution.minimal_trace.parallel_replay;
pub const replay = @import("stwo_riscv_rv32").execution.minimal_trace.replay;

pub const FORMAT_VERSION = types.FORMAT_VERSION;
pub const SCHEMA_VERSION = types.SCHEMA_VERSION;
pub const MAX_LEAF_CYCLES = types.MAX_LEAF_CYCLES;
pub const Digest = types.Digest;
pub const SourceIdentityV1 = types.SourceIdentityV1;
pub const CompletionV1 = types.CompletionV1;
pub const CaptureV1 = types.CaptureV1;
pub const LeafV1 = types.LeafV1;

pub const CaptureRequestV1 = capture.RequestV1;
pub const CaptureResultV1 = capture.ResultV1;
pub const CaptureDispatcherV1 = capture.DispatcherV1;
pub const captureLeafFast = capture.captureLeaf;

pub const ProgramWord = replay.ProgramWord;
pub const ProgramSource = replay.ProgramSource;
pub const SliceProgram = replay.SliceProgram;
pub const DenseProgram = replay.DenseProgram;
pub const BoundaryWord = replay.BoundaryWord;
pub const BoundarySource = replay.BoundarySource;
pub const SliceBoundary = replay.SliceBoundary;
pub const MemoryReadCursor = replay.MemoryReadCursor;
pub const ReplayResult = replay.Result;
pub const replayLeaf = replay.replay;

pub const ParallelReplayRequestV1 = parallel_replay.RequestV1;
pub const ParallelReplayOptionsV1 = parallel_replay.OptionsV1;
pub const ParallelReplaySinkV1 = parallel_replay.SinkV1;
pub const ParallelReplayReceiptV1 = parallel_replay.ReceiptV1;
pub const replayLeavesParallel = parallel_replay.replayLeaves;

test {
    _ = @import("../../../../tests/rv32/runner/minimal_trace/test.zig");
}
