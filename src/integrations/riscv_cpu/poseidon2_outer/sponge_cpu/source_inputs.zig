//! Bounded typed reader for the existing checkpointed GKR engine. The source
//! roster is independently derived; no dense fraction planes are allocated.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const Frame = @import("frame.zig");
const P = @import("provider.zig");
pub const Batch = struct {
    allocator: std.mem.Allocator,
    readers: []Reader,
    sources: []GP.MultiplicitiesSource,
    const Reader = struct {
        instance: Frame.Instance,
        challenges: P.Challenges,
        provider: P.Provider,
        lanes: usize,
        facts: usize,
        fn read(ctx: *const anyopaque, first: usize, n: []M, d: []O) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            if (n.len != d.len or n.len > 512 or first > self.facts or n.len > self.facts - first) return error.ShapeMismatch;
            @memset(n, M.zero());
            @memset(d, O.one());
            var at: usize = 0;
            while (at < n.len) {
                const fact = first + at;
                const lane = fact % self.lanes;
                const count = @min(self.lanes - lane, n.len - at);
                const actual = @min(count, self.instance.queries() -| lane);
                if (actual != 0) {
                    const physical = fact / self.lanes;
                    const log = self.instance.rowLog();
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, log), log);
                    self.provider.emitRange(self.instance, logical, lane, n[at..][0..actual], d[at..][0..actual], self.challenges) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidLayerStructure;
                }
                at += count;
            }
        }
    };
    pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: P.Challenges, provider: P.Provider) !Batch {
        if (instances.len == 0 or instances.len > 256) return error.SpongeCpuGeometry;
        const readers = try a.alloc(Reader, instances.len);
        errdefer a.free(readers);
        const sources = try a.alloc(GP.MultiplicitiesSource, instances.len);
        errdefer a.free(sources);
        for (instances, readers, sources) |instance, *reader, *out| {
            const variables = try instance.variables();
            reader.* = .{ .instance = instance, .challenges = challenges, .provider = provider, .lanes = @as(usize, 1) << @intCast(try instance.laneLog()), .facts = try instance.facts() };
            out.* = .{ .variables = variables, .context = reader, .wide_reads = true, .read_fn = Reader.read };
        }
        return .{ .allocator = a, .readers = readers, .sources = sources };
    }
    pub fn deinit(self: *Batch) void {
        self.allocator.free(self.sources);
        self.allocator.free(self.readers);
        self.* = undefined;
    }
};
