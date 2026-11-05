//! Borrowed narrow ingress from the native execution capture, before MAIN is
//! materialized. The caller uploads each span once, keeps it alive until the
//! copy joins, and binds program/statement/root identities through its scoped
//! resident session. The formatter is not an ISA or boundary verifier.
const std = @import("std");
const Source = @import("stwo_riscv_cpu_integration").rv64_cpu_source.Source;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
/// M7 ingress: result/ROM/next-PC only. Register values and access clocks are
/// reconstructed on the GPU, independently per chunk, from first-touch seeds.
pub const compact_chunk_rows: usize = 256;
pub const CompactRecord = extern struct { result: u64, rom_row: u32, next_pc: u32 };
pub const CompactSeed = extern struct { values: [32]u64, clocks: [32]u32 };
pub const Compact = struct {
    allocator: std.mem.Allocator,
    records: []CompactRecord,
    seeds: []CompactSeed,
    pub fn deinit(self: *Compact) void {
        self.allocator.free(self.records);
        self.allocator.free(self.seeds);
    }
    pub fn bytes(self: Compact) usize {
        return self.records.len * @sizeOf(CompactRecord) + self.seeds.len * @sizeOf(CompactSeed);
    }
    /// Source.capture already checked each read/write against its register
    /// state. A chunk needs only the value and clock preceding its first use
    /// of each register; later values/clocks follow from these compact writes.
    pub fn fromCapture(allocator: std.mem.Allocator, source: *const Source) !Compact {
        const records = try allocator.alloc(CompactRecord, source.metadata.len);
        errdefer allocator.free(records);
        const seeds = try allocator.alloc(CompactSeed, std.math.divCeil(usize, records.len, compact_chunk_rows) catch unreachable);
        errdefer allocator.free(seeds);
        // Chunk seeds are independent. Bound the temporary worker count because
        // several native partitions can pack concurrently in the service.
        const workers: usize = if (records.len >= 1 << 20) @min(4, seeds.len) else 1;
        var jobs: [4]PackJob = undefined;
        var threads: [3]std.Thread = undefined;
        var launched: usize = 0;
        errdefer for (threads[0..launched]) |thread| thread.join();
        for (0..workers) |i| {
            jobs[i] = .{ .source = source, .records = records, .seeds = seeds,
                .first = seeds.len * i / workers, .end = seeds.len * (i + 1) / workers };
            if (i + 1 < workers) {
                threads[launched] = try std.Thread.spawn(.{}, PackJob.run, .{&jobs[i]});
                launched += 1;
            } else jobs[i].run();
        }
        for (threads[0..launched]) |thread| thread.join();
        launched = 0;
        for (jobs[0..workers]) |job| if (job.failure) |err| return err;
        return .{ .allocator = allocator, .records = records, .seeds = seeds };
    }
    const PackJob = struct {
        source: *const Source,
        records: []CompactRecord,
        seeds: []CompactSeed,
        first: usize,
        end: usize,
        failure: ?error{InvalidCompactCpuMetadata} = null,
        fn run(self: *PackJob) void {
            self.pack() catch |err| { self.failure = err; };
        }
        fn pack(self: *PackJob) error{InvalidCompactCpuMetadata}!void {
            for (self.seeds[self.first..self.end], self.first..) |*seed, chunk| {
                seed.* = .{ .values = @splat(0), .clocks = @splat(0) };
                var touched: u32 = 1;
                const start = chunk * compact_chunk_rows;
                const end = @min(start + compact_chunk_rows, self.records.len);
                for (self.source.metadata[start..end], self.records[start..end]) |meta, *record| {
                    if (meta.values[4] > std.math.maxInt(u32) or meta.rom_row >= self.source.program.row_to_entry.len) return error.InvalidCompactCpuMetadata;
                    record.* = .{ .result = meta.values[2], .rom_row = meta.rom_row, .next_pc = @intCast(meta.values[4]) };
                    const entry = self.source.program.entries[self.source.program.row_to_entry[meta.rom_row]];
                    for (entry.ids, 0..) |id, slot| {
                        const bit = @as(u32, 1) << id;
                        if (touched & bit != 0) continue;
                        touched |= bit;
                        seed.values[id] = meta.values[if (slot == 2) 3 else slot];
                        seed.clocks[id] = meta.clocks[slot];
                    }
                }
            }
        }
    };
};
comptime {
    std.debug.assert(@sizeOf(CompactRecord) == 16 and @sizeOf(CompactSeed) == 384);
}
pub const Input = struct {
    program_identity: [32]u8,
    log: u32,
    count: u32,
    rom_log: u32,
    final_pc: u32,
    metadata: []const u32,
    rom: []const u32,

    pub fn fromCapture(source: *const Source) !Input {
        if (!source.compact or !source.program.compact or source.main.len != 0 or
            source.main_projection_closed or source.program.fixed_retired or
            source.log_size < X.layout.MIN_LOG or source.log_size > X.layout.MAX_LOG or
            source.metadata.len != source.public.steps or source.public.steps >= source.size())
            return error.CpuDeviceIngressUnavailable;
        if (source.program.fixed.len != X.layout.rom.FIXED * source.program.size() or
            source.public.final_pc & 3 != 0 or !X.features.compactPcAdmitted(source.public.final_pc))
            return error.InvalidCpuDeviceIngress;
        return .{
            .program_identity = source.program.identity,
            .log = source.log_size,
            .count = @intCast(source.metadata.len),
            .rom_log = source.program.log_size,
            .final_pc = @intCast(source.public.final_pc),
            .metadata = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source.metadata)),
            .rom = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source.program.fixed)),
        };
    }
};

test "compact CPU ingress compiles against the native capture owner" {
    std.testing.refAllDecls(Input);
}
