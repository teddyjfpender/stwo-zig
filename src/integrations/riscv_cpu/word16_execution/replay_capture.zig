//! Compact capture retained across the global-challenge barrier. Only CPU/JALR
//! transport is copied; original Prepared owns all borrowed normalized facts
//! through stage two. Never call Prepared.deinit on this borrowed overlay.
const std = @import("std");
const Prepared = @import("prepared.zig").Prepared;
const CPU = @import("cpu_source.zig");
pub const CaptureSeal = CPU.CaptureSeal;
const J = @import("jalr_source.zig");
pub const Capture = struct {
    value: Prepared,
    pub fn init(a: std.mem.Allocator, original: *const Prepared) !Capture {
        const cpu = original.cpu orelse return error.PreparedExecutionConsumed;
        const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
        if (jalr.main.len != 0 or jalr.fixed.len != 0 or jalr.interaction.len != 0) return error.CpuReplayRequiresUnmaterializedCapture;
        var own_cpu = try cpu.cloneCapture(a);
        errdefer own_cpu.deinit();
        const own_jalr = try J.Source.capture(a, jalr.facts, jalr.log_size);
        var overlay = original.*;
        overlay.cpu = own_cpu;
        overlay.jalr = own_jalr;
        return .{ .value = overlay };
    }
    /// Original normalized facts remain immutable and live until this view
    /// joins and deinitializes. Metadata has independent reference ownership;
    /// mutable projection histograms and JALR headers are private small copies.
    pub fn borrowSealed(a: std.mem.Allocator, original: *const Prepared, seal: CaptureSeal) !Capture {
        const cpu = original.cpu orelse return error.PreparedExecutionConsumed;
        const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
        if (jalr.main.len != 0 or jalr.fixed.len != 0 or jalr.interaction.len != 0) return error.CpuReplayRequiresUnmaterializedCapture;
        if (!std.mem.eql(u8, &original.program_identity, &cpu.program.identity)) return error.CaptureSealMismatch;
        var own_cpu = try cpu.borrowSealed(a, seal);
        errdefer own_cpu.deinit();
        const own_jalr = try J.Source.capture(a, jalr.facts, jalr.log_size);
        var overlay = original.*;
        overlay.cpu = own_cpu;
        overlay.jalr = own_jalr;
        return .{ .value = overlay };
    }
    pub fn deinit(self: *Capture) void {
        if (self.value.cpu) |*cpu| cpu.deinit();
        if (self.value.jalr) |*jalr| jalr.deinit();
        self.* = undefined;
    }
    pub fn bytes(original: *const Prepared) !usize {
        const cpu = original.cpu orelse return error.PreparedExecutionConsumed;
        const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
        var n: usize = @sizeOf(Capture);
        inline for (.{ cpu.metadata, cpu.rom_counts, cpu.counts16, cpu.counts8, jalr.facts, original.alu.facts, original.alu.weights, original.binary.facts, original.binary.weights, original.shift, original.shift_weights, original.division, original.multiplication, original.zbb.facts, original.zbb.weights }) |slice| n = try std.math.add(usize, n, std.mem.sliceAsBytes(slice).len);
        return n;
    }
};

/// One semantic content seal at ordered publication, after capture workers join.
/// This private scheduling domain does not alter captured-value diagnostics,
/// native statements, MAIN roots, or verifier bytes. No pointer is hashed.
pub fn sealCaptured(original: *Prepared) !CaptureSeal {
    const cpu = if (original.cpu) |*value| value else return error.PreparedExecutionConsumed;
    if (cpu.capture_seal) |seal| return seal;
    const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
    var h = @import("capture_seal.zig").Hasher{};
    h.write("stwo/rv64/private-capture-seal/v1\x00");
    h.value(.{ original.program_identity, original.raw_counts, original.unique_memory_words, cpu.public, cpu.epoch, cpu.log_size, cpu.compact, cpu.fused_tail, cpu.u8_pairs });
    // Metadata is a pinned padding-free little-endian wire layout. One bulk
    // update replaces millions of repeated field-framing/hash calls.
    comptime {
        if (@import("builtin").target.cpu.arch.endian() != .little or @sizeOf(CPU.Metadata) != 56 or @offsetOf(CPU.Metadata, "clocks") != 40 or @offsetOf(CPU.Metadata, "rom_row") != 52) @compileError("capture metadata seal requires the declared little-endian layout");
    }
    h.value(cpu.metadata.len);
    h.write(std.mem.sliceAsBytes(cpu.metadata));
    h.value(.{ cpu.rom_counts, cpu.counts16, cpu.counts8, original.alu.facts, original.alu.weights, original.binary.facts, original.binary.weights, original.shift, original.shift_weights, original.division, original.multiplication, original.zbb.facts, original.zbb.weights, jalr.facts, jalr.log_size });
    return cpu.sealCapture(h.final());
}
