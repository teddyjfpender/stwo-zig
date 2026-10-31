//! Producer-only retained-packet import. Native packet hashes/roots are advice;
//! execution authority comes from the new AIR and global receiver.
const std = @import("std");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Packet = @import("../../word16_execution/packet.zig");
const C = @import("../../word16_execution/coordinator.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const Coverage = @import("../../word16_execution/coverage.zig");
const Memory = @import("../../word16_execution/memory/statement.zig");
const Collector = @import("../services/collector.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    native: std.ArrayList(*Native),
    advice: Collector.Advice,
    total_steps: u64,
    final_pc: u64,
    final_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, jobs: std.fs.Dir, prefix_packets: u32) !Owner {
        if (prefix_packets > 256) return error.TooManyEthereumPackets;
        var packets: std.ArrayList(Packet.Packet) = .{};
        defer {
            for (packets.items) |*p| p.deinit();
            packets.deinit(a);
        }
        var native: std.ArrayList(*Native) = .{};
        errdefer {
            for (native.items) |n| {
                n.deinit();
                a.destroy(n);
            }
            native.deinit(a);
        }
        var total: u64 = 0;
        var pc = image.initial_pc;
        var regs = image.initial_registers;
        var index: usize = 0;
        while (index < 256) : (index += 1) {
            var name: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&name, "job-{d:0>6}.work", .{index});
            var file = try jobs.openFile(path, .{});
            defer file.close();
            try packets.ensureUnusedCapacity(a, 1);
            const packet = try Packet.read(a, file, image, config);
            // From this point packets owns tape on both success and error.
            packets.appendAssumeCapacity(packet);
            const p = &packets.items[packets.items.len - 1];
            if (index == 0) try C.requireGenesis(image, p);
            if (p.metadata.index != index or p.metadata.first_step != total or p.public.statement.initial_pc != pc or !std.mem.eql(u64, &p.public.statement.initial_registers, &regs)) return error.NonAdjacentEthereumPacket;
            total = try std.math.add(u64, total, p.tape.len);
            if (total > config.max_steps) return error.EthereumStepBudgetExceeded;
            pc = p.public.statement.final_pc;
            regs = p.public.statement.final_registers;
            try native.ensureUnusedCapacity(a, 1);
            const n = capture: {
                const value = try a.create(Native);
                errdefer a.destroy(value);
                value.* = try Native.captureForCombinedServicesLEv2(a, program, C.boundary(p), @intCast(index + 1), try Coverage.minimalPrefixLog(@intCast(p.tape.len)), &p.tape, .{ .deduplicate_shift = true });
                break :capture value;
            };
            native.appendAssumeCapacity(n);
            if ((prefix_packets != 0 and index + 1 == prefix_packets) or (prefix_packets == 0 and pc == image.terminal_pc)) break;
            if (p.tape.len != config.batch_steps) return error.IncompleteEthereumPacketChain;
        }
        if (prefix_packets == 0 and pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
        const tapes = try a.alloc(*const @import("stwo_riscv_frontend").rv64.compact_tape.Tape, packets.items.len);
        defer a.free(tapes);
        for (packets.items, tapes) |*p, *t| t.* = &p.tape;
        var advice = try Collector.collect(a, native.items, tapes, Memory.fromOwner(image));
        errdefer advice.deinit();
        return .{ .allocator = a, .native = native, .advice = advice, .total_steps = total, .final_pc = pc, .final_registers = regs };
    }
    pub fn deinit(self: *Owner) void {
        for (self.native.items) |n| {
            n.deinit();
            self.allocator.destroy(n);
        }
        self.native.deinit(self.allocator);
        self.advice.deinit();
        self.* = undefined;
    }
};
