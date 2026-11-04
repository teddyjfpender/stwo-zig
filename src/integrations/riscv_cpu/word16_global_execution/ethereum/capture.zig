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
const LS = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
pub const Options = @import("capture_prefetch.zig").Options;
pub const MAX_INFLIGHT = @import("capture_prefetch.zig").MAX_INFLIGHT;
pub const ScheduleStats = struct {
    max_inflight_packets: u8 = 1,
    max_worker_shards: u8 = 1,
    decoded_packet_heap_limit_bytes: ?usize = null,
    max_reserved_decoded_packet_heap_bytes: usize = 0,
    max_single_packet_decoded_heap_bytes: usize = 0,
};
/// Producer timing of the ordered owner, nanoseconds from `Ordered.init` (the
/// start of capture on every route). Report-only; never enters a proof.
pub const Timing = struct {
    /// Segment 0 inputs ready: its capture accepted and its ledger shard built.
    first_inputs_ns: u64 = 0,
    /// Last segment accepted (ledger shard built), before `finish`.
    last_inputs_ns: u64 = 0,
    /// Serial ordered ledger (`Collector.Builder.append`), summed.
    ledger_ns: u64 = 0,
    /// `finish` (global initial/terminal boundary cells).
    finish_ns: u64 = 0,
};
/// Per-segment readiness hook (M6 streaming stage 1). Called on the ordered
/// owner's thread, strictly in index order, once a segment's narrow capture is
/// accepted and its ledger shard (LS events with RAM predecessors) is final.
/// `native` and `events` stay owned by the capture and immutable until
/// `Owner.deinit`; a consumer may read them from other threads but must not
/// block here (the ledger of the next segment waits). Scheduling only: the
/// hook observes data and never changes it, so outputs are byte-identical
/// with or without it.
pub const Ready = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, index: usize, native: *const Native, events: []const LS.native.Event, at_ns: u64) void,
};
pub const Owner = struct {
    capture_schedule: ScheduleStats = .{},
    timing: Timing = .{},
    /// Monotonic instants of `timing.first_inputs_ns`/`last_inputs_ns`, so a
    /// caller can place them on its own clock (null if no clock).
    first_inputs_at: ?std.time.Instant = null,
    last_inputs_at: ?std.time.Instant = null,
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
    origin: ?std.time.Instant,
    timing: Timing = .{},
    first_inputs_at: ?std.time.Instant = null,
    last_inputs_at: ?std.time.Instant = null,
    /// Optional M6 hook, see `Ready`.
    on_ready: ?Ready = null,
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, config: Request.Config, prefix_packets: u32) Ordered {
        return .{ .origin = std.time.Instant.now() catch null, .allocator = a, .image = image, .config = config, .prefix_packets = prefix_packets, .collector = Collector.Builder.init(a, Memory.fromOwner(image)), .pc = image.initial_pc, .regs = image.initial_registers };
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
        return self.acceptWithEvents(p, n, null);
    }
    /// `accept` with an optional LS event array prepared off this thread
    /// (`Collector.prepareEvents`); ownership of both `n` and `events` is
    /// taken (also on error). Outputs are identical to `accept`.
    pub fn acceptWithEvents(self: *Ordered, p: *const Packet.Packet, n: *Native, events: ?[]LS.native.Event) !bool {
        const a = self.allocator;
        var prepared = events;
        defer if (prepared) |e| a.free(e);
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
        const ledger_start = self.elapsed();
        try self.collector.appendWithEvents(n, &p.tape, &prepared);
        const ledger_end = self.elapsed();
        self.timing.ledger_ns += ledger_end - ledger_start;
        const now = std.time.Instant.now() catch null;
        if (self.next_index == 0) {
            self.timing.first_inputs_ns = ledger_end;
            self.first_inputs_at = now;
        }
        self.timing.last_inputs_ns = ledger_end;
        self.last_inputs_at = now;
        // The ledger and service advice own all predecessor/call data.
        // MAIN/INTER generation retains its separate CPU metadata.
        n.cpu.?.releaseCaptureRecords();
        if (self.on_ready) |ready| ready.call(ready.context, self.next_index, n, self.collector.lastEvents(), ledger_end);
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
        const finish_start = self.elapsed();
        var advice = try self.collector.finish();
        errdefer advice.deinit();
        self.timing.finish_ns = self.elapsed() - finish_start;
        const native = self.native;
        self.native = .{};
        return .{ .capture_schedule = stats, .timing = self.timing, .first_inputs_at = self.first_inputs_at, .last_inputs_at = self.last_inputs_at, .allocator = self.allocator, .native = native, .advice = advice, .total_steps = self.total, .final_pc = self.pc, .final_registers = self.regs };
    }
    fn elapsed(self: *const Ordered) u64 {
        const origin = self.origin orelse return 0;
        const now = std.time.Instant.now() catch return 0;
        return now.since(origin);
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
