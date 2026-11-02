//! Opt-in windowed producer pipeline: up to MAX_INFLIGHT packets are read and
//! captured concurrently, then consumed strictly in index order. Only decoded
//! packet allocations use the packet heap cap. Native capture uses the caller's
//! thread-safe allocator: its separate bound is `window` admitted batch_steps
//! captures, NOT a heap/RSS cap. Ordered collection remains the sole authority
//! for predecessor/service state; a packet's capture reads only that packet.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Pools = engine.work_pool;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Capture = @import("capture.zig");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Packet = @import("../../word16_execution/packet.zig");
const C = @import("../../word16_execution/coordinator.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const Coverage = @import("../../word16_execution/coverage.zig");
const Memory = @import("../../word16_execution/memory/statement.zig");
const Collector = @import("../services/collector.zig");
pub const MAX_INFLIGHT: u8 = 16;
pub const Options = struct {
    pool: ?*Pools.WorkPool = null,
    max_inflight_packets: u8 = 1,
    packet_heap_bytes: usize = 512 << 20,
    max_inflight_packet_heap_bytes: usize = 1 << 30,
    max_inflight_wire_bytes: u64 = 1 << 30,
};
fn path(buffer: *[32]u8, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "job-{d:0>6}.work", .{index});
}
fn wireBytes(jobs: std.fs.Dir, index: usize) !u64 {
    var buffer: [32]u8 = undefined;
    var file = try jobs.openFile(try path(&buffer, index), .{});
    defer file.close();
    return file.getEndPos();
}
const Slot = struct {
    budget: ?*Budget = null,
    packet: ?Packet.Packet = null,
    native: ?*Native = null,
    read_error: ?anyerror = null,
    capture_error: ?anyerror = null,
    fn deinit(self: *Slot, a: std.mem.Allocator) void {
        if (self.native) |n| {
            n.deinit();
            a.destroy(n);
        }
        if (self.packet) |*p| p.deinit();
        if (self.budget) |owner| owner.destroy();
        self.* = .{};
    }
};
const Window = struct {
    allocator: std.mem.Allocator,
    image: *const Image.Owner,
    program: *const Program,
    config: Request.Config,
    jobs: std.fs.Dir,
    first: usize,
    packet_heap_bytes: usize,
    sizes: [MAX_INFLIGHT]u64,
    slots: [MAX_INFLIGHT]Slot = @splat(.{}),
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        for (first..end) |ordinal| self.load(ordinal) catch |err| {
            self.slots[ordinal].read_error = err;
        };
    }
    fn load(self: *@This(), ordinal: usize) !void {
        const slot = &self.slots[ordinal];
        const index = self.first + ordinal;
        slot.budget = try Budget.createRetainingParent(self.allocator, self.packet_heap_bytes);
        var buffer: [32]u8 = undefined;
        var file = try self.jobs.openFile(try path(&buffer, index), .{});
        defer file.close();
        if (try file.getEndPos() != self.sizes[ordinal]) return error.EthereumPacketChanged;
        slot.packet = try Packet.read(slot.budget.?.allocator(), file, self.image, self.config);
        const p = &slot.packet.?;
        // Capture currently has no pool submissions (CPU metadata copy,
        // fact deduplication and JALR construction). Helpers inherit no pool
        // TLS; a held lease cannot recursively acquire or create a pool.
        const n = Capture.Owner.captureOne(self.allocator, self.program, p, index) catch |err| {
            slot.capture_error = err;
            return;
        };
        slot.native = n;
    }
    fn deinit(self: *@This()) void {
        for (&self.slots) |*slot| slot.deinit(self.allocator);
    }
};
pub fn run(a: std.mem.Allocator, image: *const Image.Owner, program: *const Program, config: Request.Config, jobs: std.fs.Dir, prefix_packets: u32, options: Options) !Capture.Owner {
    if (prefix_packets > 256) return error.TooManyEthereumPackets;
    if (options.max_inflight_packets < 2 or options.max_inflight_packets > MAX_INFLIGHT or options.packet_heap_bytes == 0 or options.packet_heap_bytes > options.max_inflight_packet_heap_bytes) return error.InvalidEthereumCaptureOptions;
    const pool = options.pool orelse return error.MissingEthereumCapturePool;
    var binding = try Pools.ScopedPoolBinding.initIfNeeded(pool);
    defer if (binding) |*value| value.deinit();
    var ordered = Capture.Ordered.init(a, image, config, prefix_packets);
    defer ordered.deinit();
    var stats = Capture.ScheduleStats{ .decoded_packet_heap_limit_bytes = options.packet_heap_bytes };
    var index: usize = 0;
    const limit = if (prefix_packets == 0) 256 else prefix_packets;
    while (index < limit) {
        var count: usize = 1;
        var sizes: [MAX_INFLIGHT]u64 = @splat(0);
        sizes[0] = try wireBytes(jobs, index);
        if (sizes[0] > options.max_inflight_wire_bytes) return error.EthereumCaptureWireBudgetExceeded;
        var wire_total = sizes[0];
        // Speculation cannot lower the current slot's cap or fail it because
        // an unneeded later file is absent/corrupt/too large: it only stops
        // widening the window. Every slot reserves a full packet heap cap.
        while (count < options.max_inflight_packets and index + count < limit and (count + 1) * options.packet_heap_bytes <= options.max_inflight_packet_heap_bytes) {
            const size = wireBytes(jobs, index + count) catch break;
            if (size > options.max_inflight_wire_bytes - wire_total) break;
            sizes[count] = size;
            wire_total += size;
            count += 1;
        }
        var window = Window{ .allocator = a, .image = image, .program = program, .config = config, .jobs = jobs, .first = index, .packet_heap_bytes = options.packet_heap_bytes, .sizes = sizes };
        defer window.deinit();
        // Existing pool only, nonblocking lease, cooperative/held fallback.
        // forEachRange joins every submission before any slot is consumed.
        const shards = engine.lookups.row_work.forEachRange(count, &window, .{ .max_shards = MAX_INFLIGHT, .min_rows_per_shard = 1 });
        stats.max_inflight_packets = @max(stats.max_inflight_packets, @as(u8, @intCast(count)));
        stats.max_worker_shards = @max(stats.max_worker_shards, @as(u8, @intCast(shards)));
        stats.max_reserved_decoded_packet_heap_bytes = @max(stats.max_reserved_decoded_packet_heap_bytes, count * options.packet_heap_bytes);
        for (window.slots[0..count]) |slot| if (slot.budget) |owner| {
            stats.max_single_packet_decoded_heap_bytes = @max(stats.max_single_packet_decoded_heap_bytes, owner.snapshot().peak_live_bytes);
        };
        for (window.slots[0..count]) |*slot| {
            if (slot.read_error) |err| return err;
            try ordered.admit(&slot.packet.?);
            if (slot.capture_error) |err| return err;
            const n = slot.native.?;
            slot.native = null;
            if (try ordered.accept(&slot.packet.?, n)) return ordered.finish(stats);
            // Free this packet promptly; its Native has copied its metadata.
            slot.deinit(a);
        }
        index += count;
    }
    return error.MissingEthereumTerminalPacket;
}
