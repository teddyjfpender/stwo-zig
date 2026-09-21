//! Host-side interface for RISC-V guest↔host syscall communication.
//!
//! Provides the `HostInterface` vtable that the runner calls on ECALL,
//! and the `HostRuntime` default implementation with standard syscalls.

const std = @import("std");

pub const hint_oracle = @import("hint_oracle.zig");
pub const runtime = @import("runtime.zig");
pub const block_input = @import("block_input.zig");
pub const prove_block = @import("prove_block.zig");

pub const HintOracle = hint_oracle.HintOracle;
pub const HostRuntime = runtime.HostRuntime;
pub const BlockInput = block_input.BlockInput;
pub const proveEthereumBlockWithEngine = prove_block.proveEthereumBlockWithEngine;

const interface = @import("interface.zig");
pub const SyscallNr = interface.SyscallNr;
pub const SyscallResult = interface.SyscallResult;
pub const MemoryWrite = interface.MemoryWrite;
pub const HostInterface = interface.HostInterface;

test "SyscallNr known values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(SyscallNr.HALT));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(SyscallNr.WRITE));
    try std.testing.expectEqual(@as(u32, 16), @intFromEnum(SyscallNr.COMMIT));
    try std.testing.expectEqual(@as(u32, 240), @intFromEnum(SyscallNr.HINT_LEN));
    try std.testing.expectEqual(@as(u32, 241), @intFromEnum(SyscallNr.HINT_READ));
}
