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
        var ordered = Ordered.init(a, image, config, prefix_packets);
        defer ordered.deinit();
        var index: usize = 0;
        while (index < 256) : (index += 1) {
            var name: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&name, "job-{d:0>6}.work", .{index});
            var file = try jobs.openFile(path, .{});
            defer file.close();
            var packet = try Packet.read(a, file, image, config);
            defer packet.deinit();
            try ordered.admit(&packet);
            const n = try captureOne(a, program, &packet, index);
            if (try ordered.accept(&packet, n)) return ordered.finish(.{});
        }
        return error.MissingEthereumTerminalPacket;
    }
    /// One packet's narrow capture. Reads only this packet and the immutable
    /// program, so distinct packets may be captured concurrently.
    pub fn captureOne(a: std.mem.Allocator, program: *const Program, p: *const Packet.Packet, index: usize) !*Native {
        const value = try a.create(Native);
        errdefer a.destroy(value);
        value.* = try Native.captureForCombinedServices(a, program, C.boundary(p), @intCast(index + 1), try Coverage.minimalCpuLog(@intCast(p.tape.len)), &p.tape, .{ .deduplicate_shift = true });
        return value;
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
/// The single ordered authority over packet adjacency, step budget, completion
/// and the global ledger. Every capture schedule (serial, windowed, in-process)
/// feeds packets here strictly in index order; capture order never matters.
pub const Ordered = struct {
    allocator: std.mem.Allocator,
    image: *const Image.Owner,
    config: Request.Config,
    prefix_packets: u32,
    collector: Collector.Builder,
    native: std.ArrayList(*Native) = .{},
    total: u64 = 0,
    pc: u64,
    regs: [32]u64,
    next_index: usize = 0,
    admitted: usize = 0,
    done: bool = false,
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, config: Request.Config, prefix_packets: u32) Ordered {
        return .{ .allocator = a, .image = image, .config = config, .prefix_packets = prefix_packets, .collector = Collector.Builder.init(a, Memory.fromOwner(image)), .pc = image.initial_pc, .regs = image.initial_registers };
    }
    /// Ordered adjacency/budget admission of the next packet, before its
    /// capture is accepted. Advances the expected chain state.
    pub fn admit(self: *Ordered, p: *const Packet.Packet) !void {
        if (self.done or self.admitted != self.next_index or self.next_index >= 256) return error.TooManyEthereumPackets;
        const index = self.next_index;
        if (index == 0) try C.requireGenesis(self.image, p);
        if (p.metadata.index != index or p.metadata.first_step != self.total or p.public.statement.initial_pc != self.pc or !std.mem.eql(u64, &p.public.statement.initial_registers, &self.regs)) return error.NonAdjacentEthereumPacket;
        self.total = try std.math.add(u64, self.total, p.tape.len);
        if (self.total > self.config.max_steps) return error.EthereumStepBudgetExceeded;
        self.pc = p.public.statement.final_pc;
        self.regs = p.public.statement.final_registers;
        self.admitted += 1;
    }
    /// Accepts the capture of the packet just admitted. Takes ownership of
    /// `n` (also on error). Returns true once the requested prefix or the
    /// terminal packet has been consumed.
    pub fn accept(self: *Ordered, p: *const Packet.Packet, n: *Native) !bool {
        const a = self.allocator;
        if (self.admitted != self.next_index + 1) {
            n.deinit();
            a.destroy(n);
            return error.NonAdjacentEthereumPacket;
        }
        self.native.ensureUnusedCapacity(a, 1) catch |err| {
            n.deinit();
            a.destroy(n);
            return err;
        };
        self.native.appendAssumeCapacity(n);
        try self.collector.append(n, &p.tape);
        // The ledger and service advice own all predecessor/call data.
        // MAIN/INTER generation retains its separate CPU metadata.
        n.cpu.?.releaseCaptureRecords();
        self.next_index += 1;
        if ((self.prefix_packets != 0 and self.next_index == self.prefix_packets) or (self.prefix_packets == 0 and self.pc == self.image.terminal_pc)) {
            self.done = true;
            return true;
        }
        if (p.tape.len != self.config.batch_steps) return error.IncompleteEthereumPacketChain;
        return false;
    }
    pub fn finish(self: *Ordered, stats: ScheduleStats) !Owner {
        if (!self.done) return error.MissingEthereumTerminalPacket;
        var advice = try self.collector.finish();
        errdefer advice.deinit();
        const native = self.native;
        self.native = .{};
        return .{ .capture_schedule = stats, .allocator = self.allocator, .native = native, .advice = advice, .total_steps = self.total, .final_pc = self.pc, .final_registers = self.regs };
    }
    pub fn deinit(self: *Ordered) void {
        for (self.native.items) |n| {
            n.deinit();
            self.allocator.destroy(n);
        }
        self.native.deinit(self.allocator);
        self.collector.deinit();
        self.* = undefined;
    }
};
