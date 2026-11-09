//! Bounded row/lane reader shared with the established source-checkpoint engine.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const Frame = @import("authority.zig");
pub const Challenges = @import("fractions.zig").Challenges;
pub fn Batch(comptime P: type) type {
    return struct {
        allocator: std.mem.Allocator,
        readers: []Reader,
        sources: []GP.MultiplicitiesSource,
        const Reader = struct {
            instance: Frame.Instance,
            challenges: Challenges,
            provider: P,
            lanes: usize,
            facts: usize,
            fn read(ctx: *const anyopaque, first: usize, n: []M, d: []O) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
                const self: *const @This() = @ptrCast(@alignCast(ctx));
                if (n.len != d.len or n.len > 512 or first > self.facts or n.len > self.facts - first) return error.ShapeMismatch;
                @memset(n, M.zero());
                @memset(d, O.one());
                var offset: usize = 0;
                while (offset < n.len) {
                    const fact = first + offset;
                    const lane = fact % self.lanes;
                    const count = @min(self.lanes - lane, n.len - offset);
                    const actual = @min(count, self.instance.queries() -| lane);
                    if (actual != 0) {
                        const physical = fact / self.lanes;
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.instance.row_log), self.instance.row_log);
                        self.provider.emitRange(self.instance, logical, lane, n[offset..][0..actual], d[offset..][0..actual], self.challenges) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidLayerStructure;
                    }
                    offset += count;
                }
            }
        };
        pub fn init(a: std.mem.Allocator, geometry: Frame.Geometry, challenges: Challenges, provider: P) !@This() {
            const instances = try geometry.instances();
            if (@hasDecl(P, "validate")) try provider.validate(geometry);
            const readers = try a.alloc(Reader, instances.len);
            errdefer a.free(readers);
            const sources = try a.alloc(GP.MultiplicitiesSource, instances.len);
            errdefer a.free(sources);
            for (instances, readers, sources) |instance, *reader, *source| {
                reader.* = .{ .instance = instance, .challenges = challenges, .provider = provider, .lanes = @as(usize, 1) << @intCast(instance.laneLog()), .facts = try instance.facts() };
                source.* = .{ .variables = try instance.variables(), .context = reader, .wide_reads = true, .read_fn = Reader.read };
            }
            return .{ .allocator = a, .readers = readers, .sources = sources };
        }
        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.sources);
            self.allocator.free(self.readers);
            self.* = undefined;
        }
    };
}
