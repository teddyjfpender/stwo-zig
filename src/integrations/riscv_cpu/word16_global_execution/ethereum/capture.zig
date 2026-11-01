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
pub const Options = @import("capture_prefetch.zig").Options;
pub const ScheduleStats = struct {
    max_inflight_packets: u8 = 1,
    max_worker_shards: u8 = 1,
    decoded_packet_heap_limit_bytes: ?usize = null,
    max_reserved_decoded_packet_heap_bytes: usize = 0,
    max_single_packet_decoded_heap_bytes: usize = 0,
};
pub const Owner = struct {
    capture_schedule: ScheduleStats = .{},
    allocator: std.mem.Allocator,
    native: std.ArrayList(*Native),
    advice: Collector.Advice,
    total_steps: u64,
    final_pc: u64,
    final_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, jobs: std.fs.Dir, prefix_packets: u32) !Owner {
        if (prefix_packets > 256) return error.TooManyEthereumPackets;
        var collector = Collector.Builder.init(a, Memory.fromOwner(image));
        defer collector.deinit();
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
            var packet = try Packet.read(a, file, image, config);
            defer packet.deinit();
            const p = &packet;
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
            try collector.append(n, &p.tape);
            // The ledger and service advice own all predecessor/call data.
            // MAIN/INTER generation retains its separate CPU metadata.
            n.cpu.?.releaseCaptureRecords();
            if ((prefix_packets != 0 and index + 1 == prefix_packets) or (prefix_packets == 0 and pc == image.terminal_pc)) break;
            if (p.tape.len != config.batch_steps) return error.IncompleteEthereumPacketChain;
        }
        if (prefix_packets == 0 and pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
        var advice = try collector.finish();
        errdefer advice.deinit();
        return .{ .allocator = a, .native = native, .advice = advice, .total_steps = total, .final_pc = pc, .final_registers = regs };
    }
    /// Opt-in producer scheduling only. The caller allocator must support
    /// concurrent allocations; image/program and packet files remain immutable.
    pub fn initWithOptions(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, jobs: std.fs.Dir, prefix_packets: u32, options: Options) !Owner {
        if (options.max_inflight_packets == 1) return init(a, image, program, config, jobs, prefix_packets);
        return @import("capture_prefetch.zig").run(a, image, program, config, jobs, prefix_packets, options);
    }
    /// Quiescent measurement only: do not race source handoff or stage jobs.
    /// Counts owned requested payload, not allocator cache or immutable setup.
    pub fn ownership(self: *const Owner) struct { native_payload: usize, native_headers: usize, advice: @import("capture_ownership.zig").AdvicePayload } {
        const Owned = @import("capture_ownership.zig");
        var total: usize = 0;
        for (self.native.items) |value| total += Owned.native(value).total();
        return .{ .native_payload = total, .native_headers = self.native.items.len * @sizeOf(Native) + self.native.capacity * @sizeOf(*Native), .advice = Owned.advice(&self.advice) };
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
