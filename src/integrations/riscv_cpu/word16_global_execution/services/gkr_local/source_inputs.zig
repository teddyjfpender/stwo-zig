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
                if (n.len != d.len or n.len > 512) return error.ShapeMismatch;
                var ns: [Frame.MAX_LOCAL_TERMS]M = undefined;
                var ds: [Frame.MAX_LOCAL_TERMS]O = undefined;
                var at: usize = 0;
                while (at < n.len) {
                    const fact = first + at;
                    const physical = fact / self.lanes;
                    const lane = fact % self.lanes;
                    const count = @min(self.lanes - lane, n.len - at);
                    const whole_row = lane == 0 and count == self.lanes;
                    const row_n = if (whole_row) n[at..][0..count] else ns[0..self.lanes];
                    const row_d = if (whole_row) d[at..][0..count] else ds[0..self.lanes];
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.instance.row_log), self.instance.row_log);
                    var sink = Sink{ .challenges = self.challenges, .numerator = row_n[0..self.instance.terms], .denominator = row_d[0..self.instance.terms] };
                    self.provider.emit(self.instance, logical, &sink) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidLayerStructure;
                    if (sink.invalid or sink.count != self.instance.terms) return error.ShapeMismatch;
                    @memset(row_n[self.instance.terms..], M.zero());
                    @memset(row_d[self.instance.terms..], O.one());
                    if (!whole_row) {
                        @memcpy(n[at..][0..count], row_n[lane..][0..count]);
                        @memcpy(d[at..][0..count], row_d[lane..][0..count]);
                    }
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
                source.* = .{ .variables = variables, .context = reader, .wide_reads = true, .read_fn = Reader.read };
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
