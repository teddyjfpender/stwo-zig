//! Canonical packed36 replay of the immutable sorted block stream. Execution
//! and memory sizes are independent; only one memory trace/PCS stays live.
pub const ForBackend = @import("block_v5_memory_compact_replay_v1.zig").ForPackedBackend;
pub const SortedSource = @import("block_v5_memory_replay_adapter_v1.zig").SortedSource;
pub const fromReplay = @import("block_v5_memory_replay_adapter_v1.zig").fromReplay;
