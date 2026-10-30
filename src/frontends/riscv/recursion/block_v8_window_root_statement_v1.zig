//! Exact admitted window coverage. Snapshot IDs identify complete selected
//! memory states; initial/terminal validity requires separate boundary AIR.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("../runner/cpu.zig").Cpu;
pub const WindowSpan = struct {
    elf_sha256: [32]u8,
    config: core.pcs.PcsConfig,
    first_cycle: u64,
    cycles: u64,
    incoming_snapshot_id: [32]u8,
    outgoing_snapshot_id: [32]u8,
    initial_cpu: Cpu,
    final_cpu: Cpu,
    initial_policy_id: ?[32]u8 = null,
    terminal_policy_id: ?[32]u8 = null,
    pub fn validate(v: WindowSpan) !void {
        if (!std.meta.eql(v.config, @import("blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config()) or v.first_cycle == 0 or v.cycles == 0 or try std.math.add(u64, v.first_cycle, v.cycles) >= 1 << 30 or v.initial_cpu.regs[0] != 0 or v.final_cpu.regs[0] != 0 or (v.initial_cpu.pc | v.final_cpu.pc) & 3 != 0) return error.InvalidB8WindowSpan;
    }
    pub fn mix(v: WindowSpan, ch: anytype) void {
        ch.mixU32s(&.{ 0x42385753, 1 });
        ch.mixRoot(v.elf_sha256);
        v.config.mixInto(ch);
        ch.mixU64(v.first_cycle);
        ch.mixU64(v.cycles);
        ch.mixRoot(v.incoming_snapshot_id);
        ch.mixRoot(v.outgoing_snapshot_id);
        ch.mixU32s(&.{ v.initial_cpu.pc, v.final_cpu.pc });
        ch.mixU32s(&v.initial_cpu.regs);
        ch.mixU32s(&v.final_cpu.regs);
        ch.mixU32s(&.{ @intFromBool(v.initial_policy_id != null), @intFromBool(v.terminal_policy_id != null) });
        if (v.initial_policy_id) |id| ch.mixRoot(id);
        if (v.terminal_policy_id) |id| ch.mixRoot(id);
    }
    pub fn identity(v: WindowSpan) ![32]u8 {
        try v.validate();
        var ch = core.proof_suites.Blake3.Channel{};
        v.mix(&ch);
        return ch.digestBytes();
    }
};
pub fn merge(children: []const WindowSpan) !WindowSpan {
    if (children.len < 2 or children.len > 4) return error.InvalidB8WindowFanIn;
    var out = children[0];
    try out.validate();
    for (children[1..]) |right| {
        try right.validate();
        if (!std.meta.eql(out.elf_sha256, right.elf_sha256) or !std.meta.eql(out.config, right.config) or try std.math.add(u64, out.first_cycle, out.cycles) != right.first_cycle or !std.meta.eql(out.outgoing_snapshot_id, right.incoming_snapshot_id) or !std.meta.eql(out.final_cpu, right.initial_cpu) or out.terminal_policy_id != null or right.initial_policy_id != null) return error.NonAdjacentB8Windows;
        out.cycles = try std.math.add(u64, out.cycles, right.cycles);
        out.outgoing_snapshot_id = right.outgoing_snapshot_id;
        out.final_cpu = right.final_cpu;
        out.terminal_policy_id = right.terminal_policy_id;
    }
    try out.validate();
    return out;
}
