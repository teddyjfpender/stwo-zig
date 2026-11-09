//! Bounded source projection of existing Miller fractions. No dense N/D plane,
//! copied MAIN, free SSA values or replayed field multiplication is introduced.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.bn254_tower.narrow;
const Frame = @import("authority.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
pub const Challenges = N.equations.ChallengesFor(O);
pub const Provider = struct {
    frontier: *const N.trace.SourceForField(.frontier, O),
    arithmetic: *const N.trace.SourceForField(.arithmetic, O),
    pub fn validate(self: Provider, geometry: Frame.Geometry) !void {
        if (self.frontier.call_count != geometry.calls or self.arithmetic.call_count != geometry.calls or self.frontier.first_id != geometry.first_id or self.arithmetic.first_id != geometry.first_id or self.frontier.log_size != geometry.frontier_log or self.arithmetic.log_size != geometry.arithmetic_log) return error.MillerLocalSourceMismatch;
        if (self.frontier.advice_retired or self.arithmetic.advice_retired) return error.TowerAdviceRetired;
    }
    pub fn emitRange(self: Provider, instance: Frame.Instance, logical: usize, first: usize, numerator: []M, denominator: []O, ch: Challenges) !void {
        if (first > instance.queries() or numerator.len > instance.queries() - first or numerator.len != denominator.len or numerator.len > 128) return error.MillerLocalQuery;
        var n: [128]O = undefined;
        const nn = n[0..numerator.len];
        switch (instance.role) {
            .bytes => try self.arithmetic.fractionsAt(logical, ch, .range, first, nn, denominator),
            .carries => try self.arithmetic.fractionsAt(logical, ch, .range, 98 + first, nn, denominator),
            .arithmetic_ssa => try self.arithmetic.fractionsAt(logical, ch, .ssa, first, nn, denominator),
            .frontier_ssa => try self.frontier.fractionsAt(logical, ch, .ssa, first, nn, denominator),
        }
        for (nn, numerator) |weight, *out| {
            const coordinates = weight.toM31Array();
            for (coordinates[1..]) |coordinate| if (!coordinate.eql(M.zero())) return error.MillerLocalNonbaseWeight;
            out.* = coordinates[0];
        }
    }
};
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
test "Miller local GKR streaming source row padding and bounds" {
    const Fake = struct {
        pub fn emitRange(_: @This(), instance: Frame.Instance, row: usize, first: usize, n: []M, d: []O, _: Challenges) !void {
            for (n, d, 0..) |*nn, *dd, i| {
                nn.* = M.fromCanonical(@intCast(row + first + i));
                dd.* = O.fromBase(M.fromCanonical(@as(u32, @intFromEnum(instance.role)) + 13));
            }
        }
    };
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    const ch = Challenges{ .bytes = channel.drawSecureFelt(), .carries = channel.drawSecureFelt(), .ssa = A.crypto.curves.equations.WireFor(O).draw(&channel), .wire = A.crypto.curves.equations.WireFor(O).draw(&channel) };
    var batch = try Batch(Fake).init(std.testing.allocator, .{ .calls = 1, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 }, ch, Fake{});
    defer batch.deinit();
    var numerator: [512]M = undefined;
    var denominator: [512]O = undefined;
    const reader = &batch.readers[0];
    for ([_]usize{ 0, 97, 127, 511, reader.facts - 512 }) |first| {
        try Batch(Fake).Reader.read(reader, first, &numerator, &denominator);
        for (numerator, denominator, 0..) |nn, dd, i| {
            const lane = (first + i) % 128;
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex((first + i) / 128, 15), 15);
            try std.testing.expect(nn.eql(if (lane < 98) M.fromCanonical(@intCast(logical + lane)) else M.zero()));
            try std.testing.expect(dd.eql(if (lane < 98) O.fromBase(M.fromCanonical(13)) else O.one()));
        }
    }
    try std.testing.expectError(error.ShapeMismatch, Batch(Fake).Reader.read(reader, reader.facts, &numerator, &denominator));
    try std.testing.expectError(error.ShapeMismatch, Batch(Fake).Reader.read(reader, std.math.maxInt(usize), &numerator, &denominator));
}

test "Miller local GKR real fractions survive owned MAIN release and share SSA challenge" {
    const allocator = std.testing.allocator;
    const input = [_]N.trace.Input{@splat(1)};
    var frontier = try N.trace.SourceForField(.frontier, O).initWithoutFixed(allocator, &input, 7, 8);
    defer frontier.deinit();
    var arithmetic = try N.trace.SourceForField(.arithmetic, O).initWithoutFixed(allocator, &input, 7, 15);
    defer arithmetic.deinit();
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    const challenges = Challenges{ .bytes = channel.drawSecureFelt(), .carries = channel.drawSecureFelt(), .ssa = A.crypto.curves.equations.WireFor(O).draw(&channel), .wire = A.crypto.curves.equations.WireFor(O).draw(&channel) };
    const provider = Provider{ .frontier = &frontier, .arithmetic = &arithmetic };
    const geometry = Frame.Geometry{ .calls = 1, .first_id = 7, .frontier_log = 8, .arithmetic_log = 15 };
    var batch = try Batch(Provider).init(allocator, geometry, challenges, provider);
    defer batch.deinit();
    var before_n: [4][512]M = undefined;
    var before_d: [4][512]O = undefined;
    for (batch.readers, 0..) |*reader, i| try Batch(Provider).Reader.read(reader, 0, before_n[i][0..@min(512, reader.facts)], before_d[i][0..@min(512, reader.facts)]);
    const owned_frontier = try frontier.takeMain();
    defer allocator.free(owned_frontier);
    const owned_arithmetic = try arithmetic.takeMain();
    defer allocator.free(owned_arithmetic);
    for (batch.readers, 0..) |*reader, i| {
        var n: [512]M = undefined;
        var d: [512]O = undefined;
        const count = @min(512, reader.facts);
        try Batch(Provider).Reader.read(reader, 0, n[0..count], d[0..count]);
        for (before_n[i][0..count], n[0..count], before_d[i][0..count], d[0..count]) |bn, nn, bd, dd| {
            try std.testing.expect(bn.eql(nn));
            try std.testing.expect(bd.eql(dd));
        }
    }
    var closure = O.zero();
    const instances = try geometry.instances();
    for (instances[2..]) |instance| {
        const active: usize = if (instance.role == .frontier_ssa) 20 else 32;
        for (0..active) |row| {
            var n: [8]M = undefined;
            var d: [8]O = undefined;
            const count = instance.queries();
            try provider.emitRange(instance, row, 0, n[0..count], d[0..count], challenges);
            for (n[0..count], d[0..count]) |nn, dd| closure = closure.add(O.fromBase(nn).mul(try dd.inv()));
        }
    }
    try std.testing.expect(closure.eql(O.zero()));
    var wrong = geometry;
    wrong.first_id += 1;
    try std.testing.expectError(error.MillerLocalSourceMismatch, Batch(Provider).init(allocator, wrong, challenges, provider));
    try std.testing.expectError(error.MillerLocalQuery, provider.emitRange(instances[0], 0, 98, before_n[0][0..1], before_d[0][0..1], challenges));
}
