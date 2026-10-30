//! Public admission operands, never verification receipts. Receivers reconstruct
//! these from the pinned ELF/input/output statement before deriving any key.
const std = @import("std");
const core = @import("stwo_core");
pub const Initial = struct { policy_id: [32]u8, snapshot_id: [32]u8, cpu: @import("../runner/cpu.zig").Cpu };
pub const Terminal = struct { policy_id: [32]u8, policy: @import("block_v7_terminal_protocol_v1.zig").Policy };
pub const Options = struct {
    initial: ?Initial = null,
    terminal: ?Terminal = null,
    pub fn isEmpty(self: @This()) bool {
        return self.initial == null and self.terminal == null;
    }
    pub fn validate(self: @This()) !void {
        if (self.initial) |p| if (std.mem.allEqual(u8, &p.policy_id, 0) or std.mem.allEqual(u8, &p.snapshot_id, 0) or p.cpu.regs[0] != 0) return error.InvalidFullInitialPort;
        if (self.terminal) |p| {
            try p.policy.validate();
            if (std.mem.allEqual(u8, &p.policy_id, 0)) return error.InvalidFullTerminalPort;
        }
    }
    pub fn mix(self: @This(), ch: anytype) void {
        if (self.isEmpty()) return;
        ch.mixU32s(&.{ 0x42384250, 1, @intFromBool(self.initial != null), @intFromBool(self.terminal != null) });
        if (self.initial) |p| {
            ch.mixRoot(p.policy_id);
            ch.mixRoot(p.snapshot_id);
            ch.mixU32s(&.{p.cpu.pc});
            ch.mixU32s(&p.cpu.regs);
        }
        if (self.terminal) |p| {
            ch.mixRoot(p.policy_id);
            ch.mixU64(p.policy.final_cycle);
            ch.mixU32s(&.{ p.policy.halt_address, p.policy.length_address, p.policy.data_address, p.policy.output_end });
            for (p.policy.output) |byte| ch.mixU32s(&.{byte});
        }
    }
};
