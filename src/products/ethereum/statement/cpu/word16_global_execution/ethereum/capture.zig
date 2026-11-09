//! Producer-only retained-packet import. Native packet hashes/roots are advice;
//! execution authority comes from the new AIR and global receiver.
const std = @import("std");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../../../../../integrations/riscv_cpu/word16_execution/expected_image.zig");
const Packet = @import("../../../../../../integrations/riscv_cpu/word16_execution/packet.zig");
const C = @import("../../../../../../integrations/riscv_cpu/word16_execution/coordinator.zig");
const Native = @import("../../../../../../integrations/riscv_cpu/word16_execution/prepared.zig").Prepared;
const Program = @import("../../../../../../integrations/riscv_cpu/word16_execution/program.zig").Program;
const Coverage = @import("../../../../../../integrations/riscv_cpu/word16_execution/coverage.zig");
const Memory = @import("../../../../../../integrations/riscv_cpu/word16_execution/memory/statement.zig");
const Collector = @import("../../../../../../integrations/riscv_cpu/word16_global_execution/services/collector.zig");
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
pub const GlobalRamInfo = struct { counters: @import("stwo_riscv_frontend").rv64.checkpoint.Counters, total_steps: u64, final_pc: u64 };
pub const Ready = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque, index: usize, native: *const Native, events: []const LS.native.Event, at_ns: u64) void,
    cancel: ?*const fn (*anyopaque) void = null,
    /// Runs before source.next waits for traced CPU0. Borrowed for this call
    /// only, not until Owner.deinit; asynchronous readers must own a copy.
    first_pass: ?*const fn (*anyopaque, *const @import("../../../../../../integrations/riscv_cpu/word16_execution/cpu_source.zig").FirstPass) void = null,
    /// Whole first-pass GLOBAL INITIAL, derived from the pinned initial image.
    /// Called on a bounded one-request helper; data borrowed for this call only.
    global_ram: ?*const fn (*anyopaque, []const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell, GlobalRamInfo) void = null,
    /// Transfers the helper allocation when true; receiver must free with the
    /// supplied allocator after all asynchronous readers join, including cancel.
    /// Keep cells alive until capture returns: the helper still borrows them
    /// for mandatory final Collector equivalence (also on receiver failure).
    take_global_ram: ?*const fn (*anyopaque, std.mem.Allocator, []@import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell, GlobalRamInfo) bool = null,
    /// Immutable until Owner.deinit; callback never waits for GPU completion.
    terminal_ready: ?*const fn (*anyopaque, []const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell) void = null,
    /// Seal once before publishing; default capture retains its old behavior.
    seal_native: bool = false,
    native_segment: ?*const fn (*anyopaque, usize, *const Native, Collector.Shard, u64) void = null,
    ram_stack_budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = null,
    require_ram_stack_budget: bool = false,
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
        var collector = Collector.Builder.init(a, Memory.fromOwner(image));
        // Same image, page-at-a-time first-touch reads (exact, see OwnerPages).
        collector.ledger.pages = .{ .owner = image };
        return .{ .origin = std.time.Instant.now() catch null, .allocator = a, .image = image, .config = config, .prefix_packets = prefix_packets, .collector = collector, .pc = image.initial_pc, .regs = image.initial_registers };
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
        return self.acceptPrepared(p, n, events, null);
    }
    /// `acceptWithEvents` with an optional phase-1 segment ledger built off
    /// this thread (`Collector.prepareLocal`, M8 two-phase ledger); ownership
    /// of `local` is taken (also on error). Outputs are identical.
    pub fn acceptPrepared(self: *Ordered, p: *const Packet.Packet, n: *Native, events: ?[]LS.native.Event, local: ?*Collector.Local) !bool {
        const a = self.allocator;
        var prepared = events;
        defer if (prepared) |e| a.free(e);
        var owned_local = local;
        defer if (owned_local) |l| l.deinit(a);
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
        if (owned_local) |l| {
            owned_local = null;
            try self.collector.appendLocal(l, n, &p.tape, &prepared);
        } else try self.collector.appendWithEvents(n, &p.tape, &prepared);
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
        if (self.on_ready) |ready| {
            if (ready.seal_native) _ = try @import("../../../../../../integrations/riscv_cpu/word16_execution/replay_capture.zig").sealCaptured(n);
            ready.call(ready.context, self.next_index, n, self.collector.lastEvents(), ledger_end);
            if (ready.native_segment) |call| call(ready.context, self.next_index, n, try self.collector.lastShard(), ledger_end);
        }
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
        if (self.on_ready) |ready| if (ready.terminal_ready) |call| call(ready.context, advice.terminal);
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
/// Diagnostic SHA-256 over EVERY advice family (events, keccak, secp, sha256,
/// arith256_mod, curves, bulk, sponge, initial, terminal), field by field
/// (never raw struct bytes, so padding cannot leak in). `captured_values_sha256`
/// covers only events/keccak/secp/initial/terminal; this one carries the M8
/// two-phase ledger parity for the other families. Report-only.
pub fn adviceDigest(advice: *const Collector.Advice) [32]u8 {
    const H = struct {
        hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
        buffer: [1 << 16]u8 = undefined,
        used: usize = 0,
        fn value(self: *@This(), item: anytype) void {
            const T = @TypeOf(item);
            switch (@typeInfo(T)) {
                .int => |info| {
                    if (self.used + 8 > self.buffer.len) {
                        self.hash.update(self.buffer[0..self.used]);
                        self.used = 0;
                    }
                    std.mem.writeInt(u64, self.buffer[self.used..][0..8], @as(std.meta.Int(.unsigned, info.bits), @bitCast(item)), .little);
                    self.used += 8;
                },
                .bool => self.value(@as(u8, @intFromBool(item))),
                .@"enum" => self.value(@intFromEnum(item)),
                .array => for (item) |entry| self.value(entry),
                .pointer => |info| {
                    if (info.size != .slice) @compileError("advice digest may not follow pointers");
                    self.value(@as(u64, item.len));
                    for (item) |entry| self.value(entry);
                },
                .@"struct" => |info| inline for (info.fields) |field| {
                    if (comptime !std.mem.eql(u8, field.name, "allocator")) self.value(@field(item, field.name));
                },
                else => @compileError("unsupported advice value " ++ @typeName(T)),
            }
        }
    };
    const h = std.heap.page_allocator.create(H) catch @panic("advice digest buffer");
    defer std.heap.page_allocator.destroy(h);
    h.* = .{};
    h.hash.update("stwo/rv64/ethereum/advice-all/v1\x00");
    h.value(advice.*);
    h.hash.update(h.buffer[0..h.used]);
    return h.hash.finalResult();
}
