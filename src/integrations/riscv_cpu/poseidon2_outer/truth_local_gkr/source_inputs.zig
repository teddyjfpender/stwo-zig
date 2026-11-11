//! Bounded streaming projection of original truth tuples, never dense N/D planes.
//! A partial read reconstructs only requested query lanes, including the 1920
//! Keccak terms; no full 2048-lane scratch row is materialized per 512-fact read.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const TF = @import("../../word16_global_execution/services/gkr_local/truth_fractions.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
pub const Challenges = TF.ChallengesFor(O);
const Sink = struct {
    challenges: *const Challenges,
    numerator: []M,
    denominator: []O,
    count: usize = 0,
    invalid: bool = false,
    pub fn emitBase(self: *@This(), relation: TF.Relation, tuple: anytype, weight: M) void {
        if (self.count >= self.numerator.len) {
            self.invalid = true;
            return;
        }
        self.numerator[self.count] = weight;
        self.denominator[self.count] = self.challenges.denominatorBase(relation, tuple);
        self.count += 1;
    }
};
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
            facts: usize,
            fn read(ctx: *const anyopaque, first: usize, n: []M, d: []O) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
                const self: *const @This() = @ptrCast(@alignCast(ctx));
                if (n.len != d.len or n.len > 512 or first > self.facts or n.len > self.facts - first) return error.ShapeMismatch;
                @memset(n, M.zero());
                @memset(d, O.one());
                var at: usize = 0;
                while (at < n.len) {
                    const fact = first + at;
                    const physical = fact / self.lanes;
                    const lane = fact % self.lanes;
                    const count = @min(self.lanes - lane, n.len - at);
                    const actual = @min(count, self.instance.queries -| lane);
                    if (actual != 0) {
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.instance.row_log), self.instance.row_log);
                        var sink = Sink{ .challenges = self.challenges, .numerator = n[at..][0..actual], .denominator = d[at..][0..actual] };
                        self.provider.emitRange(self.instance, logical, lane, actual, &sink) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidLayerStructure;
                        if (sink.invalid or sink.count != actual) return error.ShapeMismatch;
                    }
                    at += count;
                }
            }
        };
        pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const Challenges, provider: Provider) !@This() {
            if (instances.len != 3) return error.InvalidLocalGkrTruthShape;
            const readers = try a.alloc(Reader, instances.len);
            errdefer a.free(readers);
            const sources = try a.alloc(GP.MultiplicitiesSource, instances.len);
            errdefer a.free(sources);
            for (instances, readers, sources) |instance, *reader, *source| {
                const variables = try instance.variables();
                reader.* = .{ .instance = instance, .challenges = challenges, .provider = provider, .lanes = @as(usize, 1) << @intCast(try instance.laneLog()), .facts = try instance.facts() };
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
test "OP truth local GKR bounded source handles partial query and row boundaries" {
    const Provider = struct {
        pub fn emitRange(_: @This(), _: Frame.Instance, row: usize, first: usize, count: usize, sink: anytype) !void {
            for (first..first + count) |query| sink.emitBase(.byte, [1]M{M.fromCanonical(@intCast(query + 17 * row))}, M.one());
        }
    };
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    const challenges = Challenges.draw(&channel);
    const instances = [_]Frame.Instance{ .{ .role = .keccak, .row_log = 5, .queries = 1920 }, .{ .role = .chi, .row_log = 5, .queries = 1 }, .{ .role = .xor5, .row_log = 5, .queries = 1 } };
    var batch = try Batch(Provider).init(std.testing.allocator, &instances, &challenges, Provider{});
    defer batch.deinit();
    var n: [512]M = undefined;
    var d: [512]O = undefined;
    const reader = &batch.readers[0];
    for ([_]usize{ 0, 1536, 1792, 1919, 2047, 65024 }) |first| {
        try Batch(Provider).Reader.read(reader, first, &n, &d);
        for (n, d, 0..) |nn, dd, i| {
            const lane = (first + i) % 2048;
            const row = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex((first + i) / 2048, 5), 5);
            try std.testing.expect(nn.eql(if (lane < 1920) M.one() else M.zero()));
            const expected = if (lane < 1920) challenges.denominatorBase(.byte, [1]M{M.fromCanonical(@intCast(lane + 17 * row))}) else O.one();
            try std.testing.expect(dd.eql(expected));
        }
    }
    try std.testing.expectError(error.ShapeMismatch, Batch(Provider).Reader.read(reader, 65535, &n, &d));
    try std.testing.expectError(error.ShapeMismatch, Batch(Provider).Reader.read(reader, std.math.maxInt(usize), &n, &d));
}
