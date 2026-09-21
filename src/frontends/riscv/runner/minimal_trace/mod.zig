//! Two-phase base-RV32 execution substrate.
//!
//! Capture owns only canonical leaf custody. Replay reconstructs full typed
//! retirement rows and access chains from an authenticated program, memory
//! boundary, CPU checkpoint, and ordered old-word tape.

pub const types = @import("types.zig");
pub const capture = @import("capture.zig");
pub const ethereum_capture = @import("ethereum_capture.zig");
pub const ethereum_parallel_replay = @import("ethereum_parallel_replay.zig");
pub const ethereum_replay = @import("ethereum_replay.zig");
pub const ethereum_semantic_capture = @import("ethereum_semantic_capture.zig");
pub const ethereum_types = @import("ethereum_types.zig");
pub const ethereum_wire = @import("ethereum_wire.zig");
pub const parallel_replay = @import("parallel_replay.zig");
pub const replay = @import("replay.zig");

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

pub const EthereumMinimalLeafV1 = ethereum_types.LeafV1;
pub const ethereumCpuIdentity = ethereum_types.cpuIdentity;
pub const EthereumCaptureRequestV1 = ethereum_capture.RequestV1;
pub const EthereumCaptureResultV1 = ethereum_capture.ResultV1;
pub const captureEthereumLeafFromSegment = ethereum_capture.captureFromSegment;
pub const EthereumSemanticSegmentObservationV1 =
    ethereum_semantic_capture.SegmentObservationV1;
pub const EthereumReplayRequestV1 = ethereum_replay.RequestV1;
pub const EthereumReplayResultV1 = ethereum_replay.ResultV1;
pub const replayEthereumLeaf = ethereum_replay.replay;
pub const EthereumParallelReplayRequestV1 = ethereum_parallel_replay.RequestV1;
pub const EthereumParallelReplayOptionsV1 = ethereum_parallel_replay.OptionsV1;
pub const EthereumParallelReplaySinkV1 = ethereum_parallel_replay.SinkV1;
pub const EthereumParallelReplayReceiptV1 = ethereum_parallel_replay.ReceiptV1;
pub const replayEthereumLeavesParallel = ethereum_parallel_replay.replayLeaves;
pub const EthereumMinimalArtifactV1 = ethereum_wire.ArtifactV1;
pub const encodeEthereumMinimalArtifactAlloc = ethereum_wire.encodeAlloc;
pub const decodeEthereumMinimalArtifactAlloc = ethereum_wire.decodeAlloc;

test {
    _ = @import("test.zig");
}
