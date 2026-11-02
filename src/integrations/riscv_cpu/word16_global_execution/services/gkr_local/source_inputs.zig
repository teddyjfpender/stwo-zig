//! Immutable row metadata to bounded opaque raw-fact spans. No full N/D planes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const Frame = @import("frame.zig");
const Challenges = @import("challenges.zig").For(O);
const Sink = @import("inputs.zig").RowSink;
pub fn Batch(comptime Provider: type) type {
    return struct {
        allocator: std.mem.Allocator,
        readers: []Reader,
        sources: []GP.MultiplicitiesSource,
        const Reader = struct {
            instance: Frame.Instance,
            challenges: *const Challenges,
            provider: Provider,
            lanes: usize,
            fn read(ctx: *const anyopaque, first: usize, n: []M, d: []O) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
                const self: *const @This() = @ptrCast(@alignCast(ctx));
                if (n.len != d.len or n.len > 64) return error.ShapeMismatch;
                var ns: [Frame.MAX_LOCAL_TERMS]M = undefined;
                var ds: [Frame.MAX_LOCAL_TERMS]O = undefined;
                var at: usize = 0;
                while (at < n.len) {
                    const fact = first + at;
                    const physical = fact / self.lanes;
                    const lane = fact % self.lanes;
                    @memset(ns[0..self.lanes], M.zero());
                    @memset(ds[0..self.lanes], O.one());
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.instance.row_log), self.instance.row_log);
                    var sink = Sink{ .challenges = self.challenges, .numerator = ns[0..self.instance.terms], .denominator = ds[0..self.instance.terms] };
                    self.provider.emit(self.instance, logical, &sink) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidLayerStructure;
                    if (sink.invalid or sink.count != self.instance.terms) return error.ShapeMismatch;
                    const count = @min(self.lanes - lane, n.len - at);
                    @memcpy(n[at..][0..count], ns[lane..][0..count]);
                    @memcpy(d[at..][0..count], ds[lane..][0..count]);
                    at += count;
                }
            }
        };
        pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const Challenges, provider: Provider) !@This() {
            const readers = try a.alloc(Reader, instances.len);
            errdefer a.free(readers);
            const sources = try a.alloc(GP.MultiplicitiesSource, instances.len);
            errdefer a.free(sources);
            for (instances, readers, sources) |instance, *reader, *source| {
                const variables = try instance.variables();
                reader.* = .{ .instance = instance, .challenges = challenges, .provider = provider, .lanes = @as(usize, 1) << @intCast(try instance.laneLog()) };
                source.* = .{ .variables = variables, .context = reader, .read_fn = Reader.read };
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
