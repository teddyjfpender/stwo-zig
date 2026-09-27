//! Genuine capacity fused program identities with shared census bookkeeping.
pub const ForBackend = @import("block_v5_program_first_round_v1.zig").ForCapacity(true).ForBackend;
pub const ExtensionPin = @import("block_v5_program_first_round_v1.zig").ExtensionPin;
