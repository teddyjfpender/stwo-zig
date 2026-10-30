//! Independently reconstructed fresh-execution boundary. RAM roots and public
//! input hashes are intentionally absent from this new statement authority.
const std = @import("std");
const core = @import("stwo_core");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Frame = @import("../air/block/memory_event.zig").Frame;
const Windows = @import("block_v5_register_windows_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
pub const Native = struct { shape: *const Shape, frame: Frame, external_retirements: u32 = 0 };
pub const Policy = struct {
    initialized: *const Initial.Owned,
    program_root: [32]u8,
    terminal: Terminal.Policy,
    config: core.pcs.PcsConfig,
    /// Independently admitted nonterminal execution. This changes the theorem
    /// and statement domain; it never attests successful whole-guest completion.
    window: ?*const Window.Owned = null,
    pub fn initialRegisters(self: Policy) [32]u32 {
        if (self.window) |window| return window.boundary.initial_cpu.regs;
        var r: [32]u32 = @splat(0);
        r[2] = self.initialized.info.stack_pointer;
        r[3] = self.initialized.info.global_pointer;
        return r;
    }
    pub fn validate(self: Policy) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.window) |window| {
            try window.validate();
            if (!std.meta.eql(self.initialized.elf_sha256, window.initial.elf_sha256) or
                !std.meta.eql(self.initialized.info, window.initial.info) or
                !std.meta.eql(self.program_root, window.program_root) or
                self.initialized.intervals.len != window.initial.intervals.len)
                return error.UntrustedV7WindowInitialization;
            for (self.initialized.intervals, window.initial.intervals) |actual, expected|
                if (!std.meta.eql(actual, expected)) return error.UntrustedV7WindowInitialization;
            return;
        }
        try self.terminal.validate();
        const halt = try self.initialized.find(self.terminal.halt_address);
        if (!halt.allowed or halt.private or halt.value != 0) return error.InvalidV7InitialHalt;
        const info = self.initialized.info;
        const t = self.terminal;
        if (t.halt_address != info.halt_flag or t.length_address != info.output_len or t.data_address != info.output_data or t.output_end != info.output_end or std.mem.allEqual(u8, &self.program_root, 0)) return error.InvalidV7ExecutionPolicy;
    }
    pub fn digest(self: Policy) ![32]u8 {
        try self.validate();
        var ch = core.proof_suites.Blake3.Channel{};
        if (self.window) |window| {
            ch.mixU32s(&.{ 0x42375753, 2, 2, @intFromEnum(self.initialized.info.execution_profile) });
            ch.mixRoot(self.initialized.elf_sha256);
            ch.mixRoot(self.program_root);
            self.config.mixInto(&ch);
            window.mix(&ch);
            ch.mixU64(self.initialized.intervals.len);
            for (self.initialized.intervals) |row| for (row.tuple()) |v| ch.mixU32s(&.{v.toU32()});
            return ch.digestBytes();
        }
        ch.mixU32s(&.{ 0x42374553, 2, 1, @intFromEnum(self.initialized.info.execution_profile), self.initialized.info.entry_point });
        ch.mixRoot(self.initialized.elf_sha256);
        ch.mixRoot(self.program_root);
        self.config.mixInto(&ch);
        ch.mixU32s(&self.initialRegisters());
        ch.mixU64(self.initialized.intervals.len);
        for (self.initialized.intervals) |row| for (row.tuple()) |v| ch.mixU32s(&.{v.toU32()});
        ch.mixU64(self.terminal.final_cycle);
        ch.mixU32s(&.{ self.terminal.halt_address, self.terminal.length_address, self.terminal.data_address, self.terminal.output_end });
        for (self.terminal.output) |byte| ch.mixU32s(&.{byte});
        return ch.digestBytes();
    }
    pub fn validateWindows(self: Policy, natives: []const Native) !void {
        try self.validate();
        if (natives.len == 0) return error.MissingV7Execution;
        var registers = self.initialRegisters();
        var pc = if (self.window) |window| window.boundary.initial_cpu.pc else self.initialized.info.entry_point;
        var cycle: u64 = 1;
        for (natives, 0..) |native, index| {
            const shape = native.shape;
            const data = &shape.public_data;
            try shape.validateBlake3ExecutionWithExternal(native.external_retirements);
            const root = data.program_root orelse return error.MissingV7ProgramRoot;
            const completion = data.completion orelse return error.MissingCompletion;
            if (index + 1 == natives.len and self.window == null) {
                if (completion.kind != .halt_flag or completion.address != self.terminal.halt_address or completion.value != 1) return error.UntrustedV7Completion;
            } else if (completion.kind != .unretired_program_fetch) return error.UntrustedV7Completion;
            if (shape.localZeroCustody()) return error.UnqualifiedV7LocalZero;
            if (native.frame.clock_frame != .leaf_local or native.frame.global_first_cycle != cycle or native.frame.cycle_count != data.clock or data.initial_pc != pc or !std.meta.eql(data.initial_regs, registers) or
                !std.meta.eql(root.bytes, self.program_root) or data.initial_rw_root != null or data.final_rw_root != null or
                data.io_entries.input_len != 0 or data.io_entries.input_words.len != 0 or data.io_entries.output_len != 0 or data.io_entries.output_words.len != 0) return error.UntrustedV7ExecutionBoundary;
            // Keep exact existing mode-1 window clock/unchanged-register checks.
            const window = Windows.Window.fromPublic(0, 1, data.*);
            try (Windows.Plan{ .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &.{window} }).validate();
            cycle = try std.math.add(u64, cycle, data.clock);
            pc = data.final_pc;
            registers = data.final_regs;
        }
        if (cycle - 1 != self.finalCycle()) return error.UntrustedV7FinalCycle;
        if (self.window) |window| {
            if (pc != window.boundary.final_cpu.pc or !std.meta.eql(registers, window.boundary.final_cpu.regs))
                return error.UntrustedV7WindowEndpoint;
        }
    }
    pub fn finalCycle(self: Policy) u64 {
        return if (self.window) |window| window.boundary.cycles else self.terminal.final_cycle;
    }
};
