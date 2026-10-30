//! One-at-a-time RAM witness/PCS retention with explicit aggregate disk bounds.
//! First-pass sorted-source completeness remains mandatory before global seal;
//! warm cached witnesses produce ordinary freshly verified RAM/range proofs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Range = @import("block_v5_range16_v1.zig");
const RangeProof = @import("block_v5_range16_proof_v1.zig");
const Raw = @import("block_v6_ram_witness_store_v1.zig");
const Store = @import("block_v6_provider_commitment_store_v1.zig");
const Retention = @import("block_v6_provider_commitment_staging_v1.zig");
pub const Policy = struct {
    /// Avoid coefficient recovery at the cost of one raw-sized payload per PCS.
    retain_coefficients: bool = false,
    storage: Retention.Policy = .{},
    witness: Raw.Limits = .{},
    max_records: usize = 4096,
    max_metadata_bytes: usize = 8 << 20,
};
pub const MemoryPin = struct { expected: Proof.Pin, witness: Raw.Pin, pcs: Store.Pin };
pub const RangePin = struct { shard: Range.Shard, plan_digest: [32]u8, roots: [2][32]u8, counter_digest: [32]u8, pcs: Store.Pin };
pub const Loaded = struct {
    trace: Trace,
    first: Proof.ForBackend(Cpu).FirstRound,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.first.deinit(a);
        self.trace.deinit();
        self.* = undefined;
    }
};
pub const Transport = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    policy: Policy,
    memory: std.ArrayList(MemoryPin) = .empty,
    ranges: std.ArrayList(RangePin) = .empty,
    statistics: Retention.Statistics = .{},
    raw_written_bytes: u64 = 0,
    raw_read_bytes: u64 = 0,
    max_live_bytes: usize = 0,
    pub fn deinit(self: *Transport) void {
        self.memory.deinit(self.a);
        self.ranges.deinit(self.a);
        self.* = undefined;
    }
    pub fn totalBytes(self: *const Transport) !u64 {
        return std.math.add(u64, self.raw_written_bytes, self.statistics.written_bytes);
    }
    fn requireRecord(self: *const Transport, memory_count: usize, range_count: usize) !void {
        const count = try std.math.add(usize, memory_count, range_count);
        const bytes = try std.math.add(usize, try std.math.mul(usize, memory_count, @sizeOf(MemoryPin)), try std.math.mul(usize, range_count, @sizeOf(RangePin)));
        if (count > self.policy.max_records or bytes > self.policy.max_metadata_bytes) return error.RamCheckpointResourceLimit;
    }
    pub fn saveMemory(self: *Transport, trace: *const Trace, first: *const Proof.ForBackend(Cpu).FirstRound) !void {
        if (first.pin.index != self.memory.items.len) return error.InvalidRamCheckpointOrder;
        try self.requireRecord(self.memory.items.len + 1, self.ranges.items.len);
        var raw_buffer: [64]u8 = undefined;
        var pcs_buffer: [64]u8 = undefined;
        const raw_name = try memoryName(first.pin.index, "columns", &raw_buffer);
        const pcs_name = try memoryName(first.pin.index, "pcs", &pcs_buffer);
        var timer = try std.time.Timer.start();
        const raw_owned = try Trace.ownedBytes(first.pin.claim);
        if (raw_owned >= self.policy.storage.storage.max_loaded_bytes) return error.RamCheckpointResourceLimit;
        const available = try self.policy.storage.remaining(try self.totalBytes());
        var raw_limits = self.policy.witness;
        raw_limits.max_file_bytes = @min(raw_limits.max_file_bytes, available.max_file_bytes);
        const raw = try Raw.write(self.a, self.dir, raw_name, trace, first.pin, raw_limits);
        errdefer self.dir.deleteFile(raw_name) catch {};
        var pcs_limits = try self.policy.storage.remaining(try std.math.add(u64, try self.totalBytes(), raw.bytes));
        pcs_limits.max_loaded_bytes -= raw_owned;
        const pcs = try Store.writeRam(self.a, self.dir, pcs_name, first, pcs_limits);
        errdefer self.dir.deleteFile(pcs_name) catch {};
        const live = try std.math.add(usize, try Trace.ownedBytes(first.pin.claim), pcs.loaded_bytes);
        if (live > self.policy.storage.storage.max_loaded_bytes) return error.RamCheckpointResourceLimit;
        try self.memory.ensureTotalCapacityPrecise(self.a, self.memory.items.len + 1);
        self.memory.appendAssumeCapacity(.{ .expected = first.pin, .witness = raw, .pcs = pcs });
        self.raw_written_bytes = try std.math.add(u64, self.raw_written_bytes, raw.bytes);
        self.max_live_bytes = @max(self.max_live_bytes, live);
        try self.statistics.wrote(pcs, timer.read());
    }
    pub fn loadMemory(self: *Transport, a: std.mem.Allocator, expected: Proof.Pin) !Loaded {
        if (expected.index >= self.memory.items.len or !std.meta.eql(expected, self.memory.items[expected.index].expected)) return error.InvalidRamCheckpointOrder;
        const saved = self.memory.items[expected.index];
        const live = try std.math.add(usize, try Trace.ownedBytes(expected.claim), saved.pcs.loaded_bytes);
        if (live > self.policy.storage.storage.max_loaded_bytes) return error.RamCheckpointResourceLimit;
        var raw_buffer: [64]u8 = undefined;
        var pcs_buffer: [64]u8 = undefined;
        var timer = try std.time.Timer.start();
        var trace = try Raw.load(a, self.dir, try memoryName(expected.index, "columns", &raw_buffer), expected, saved.witness, self.policy.witness);
        errdefer trace.deinit();
        var first = try Store.loadRam(a, self.dir, try memoryName(expected.index, "pcs", &pcs_buffer), expected, saved.pcs, self.policy.storage.storage);
        errdefer first.deinit(a);
        self.raw_read_bytes = try std.math.add(u64, self.raw_read_bytes, saved.witness.bytes);
        try self.statistics.restored(saved.pcs, timer.read());
        return .{ .trace = trace, .first = first };
    }
    pub fn saveRange(self: *Transport, shard: Range.Shard, plan_digest: [32]u8, counter: *const Range.Counter, first: *const RangeProof.ForBackend(Cpu).FirstRound) !void {
        if (shard.index != self.ranges.items.len) return error.InvalidRamCheckpointOrder;
        try self.requireRecord(self.memory.items.len, self.ranges.items.len + 1);
        var buffer: [64]u8 = undefined;
        var timer = try std.time.Timer.start();
        const name = try rangeName(shard.index, &buffer);
        const pin = try Store.writeRange(self.a, self.dir, name, shard, plan_digest, counter, first, try self.policy.storage.remaining(try self.totalBytes()));
        errdefer self.dir.deleteFile(name) catch {};
        try self.ranges.ensureTotalCapacityPrecise(self.a, self.ranges.items.len + 1);
        self.ranges.appendAssumeCapacity(.{ .shard = shard, .plan_digest = plan_digest, .roots = first.roots(), .counter_digest = counter.digest(), .pcs = pin });
        self.max_live_bytes = @max(self.max_live_bytes, pin.loaded_bytes);
        try self.statistics.wrote(pin, timer.read());
    }
    pub fn loadRange(self: *Transport, a: std.mem.Allocator, shard: Range.Shard, plan_digest: [32]u8, counter: *const Range.Counter, roots: [2][32]u8, config: core.pcs.PcsConfig) !RangeProof.ForBackend(Cpu).FirstRound {
        if (shard.index >= self.ranges.items.len) return error.InvalidRamCheckpointOrder;
        const saved = self.ranges.items[shard.index];
        if (!std.meta.eql(saved.shard, shard) or !std.meta.eql(saved.plan_digest, plan_digest) or !std.meta.eql(saved.roots, roots) or !std.meta.eql(saved.counter_digest, counter.digest())) return error.ChangedRamCheckpointRange;
        var buffer: [64]u8 = undefined;
        var timer = try std.time.Timer.start();
        var first = try Store.loadRange(a, self.dir, try rangeName(shard.index, &buffer), shard, plan_digest, counter, roots, config, saved.pcs, self.policy.storage.storage);
        errdefer first.deinit(a);
        try self.statistics.restored(saved.pcs, timer.read());
        return first;
    }
    pub fn requireRoster(self: *const Transport, pins: []const Proof.Pin, shards: []const Range.Shard) !void {
        if (pins.len != self.memory.items.len or shards.len != self.ranges.items.len) return error.IncompleteRamCheckpointRoster;
        for (pins, self.memory.items) |pin, record| if (!std.meta.eql(pin, record.expected)) return error.IncompleteRamCheckpointRoster;
        for (shards, self.ranges.items) |shard, record| if (!std.meta.eql(shard, record.shard)) return error.IncompleteRamCheckpointRoster;
    }
};
pub fn memoryName(index: u32, suffix: []const u8, buffer: *[64]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "ram-{d}.{s}", .{ index, suffix });
}
pub fn rangeName(index: u32, buffer: *[64]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "ram-range-{d}.pcs", .{index});
}
