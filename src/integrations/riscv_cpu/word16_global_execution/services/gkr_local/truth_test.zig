const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("../roster.zig");
const F = @import("truth_fractions.zig");
const Frame = @import("truth_frame.zig");
const Metadata = @import("truth_metadata.zig");
const Inputs = @import("truth_inputs.zig").Inputs;
const Global = @import("truth_global.zig");
const GM = @import("truth_global_metadata.zig");
const GW = @import("truth_global_witness.zig");
const Classic = @import("classic_witness.zig");
const GP = engine.lookups.gkr_prover.ForField(O);
const GV = engine.lookups.gkr_verifier.ForField(O);
const a = std.testing.allocator;
const LIMIT = 64 * 1024 * 1024;
fn dense(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast(seed * 71 + i * 79 + 3));
    return O.fromM31Array(c);
}
fn lift(comptime n: usize, values: [n]M) [n]O {
    var out: [n]O = undefined;
    for (&out, values) |*v, m| v.* = O.fromBase(m);
    return out;
}
pub fn keccakSource() !R.TruthSource {
    return keccakSourceWithAllocator(a);
}
pub fn keccakSourceWithAllocator(allocator: std.mem.Allocator) !R.TruthSource {
    const T = @FieldType(R.TruthSource, "keccak");
    var input: [2]K.trace.State = undefined;
    for (&input, 0..) |*state, i| for (state, 0..) |*lane, j| {
        lane.* = @as(u64, @intCast(7919 * i + 31 * j));
    };
    return .{ .keccak = try T.initSpan(allocator, &input, 3, 5) };
}
pub fn secpSource(policy: S.layout.BytePolicy) !R.TruthSource {
    const input = [_]S.trace.Input{.{ .coordinates = .{ 1, 2, 3, 4, 5, 6 } }};
    const program = S.program.get(.add);
    var batch = try S.batch.Batch.initWithLogsForPolicy(a, program, &input, 5, try S.layout.logSize(.product, program, 1), try S.layout.logSize(.linear, program, 1), policy);
    errdefer batch.deinit();
    var counts: [256]u64 = undefined;
    for (&counts, batch.product.byte_counts, batch.linear.byte_counts) |*v, x, y| v.* = x + y;
    return .{ .secp = .{ .batch = batch, .bytes = try A.range.provider.Trace.init(a, &counts) } };
}
const Entry = struct { relation: F.Relation, tuple: [6]M, weight: M };
const Capture = struct {
    entries: []Entry,
    count: usize = 0,
    pub fn emitBase(self: *@This(), relation: F.Relation, tuple: anytype, weight: M) void {
        var e = Entry{ .relation = relation, .tuple = @splat(M.zero()), .weight = weight };
        for (tuple, 0..) |v, i| e.tuple[i] = v;
        self.entries[self.count] = e;
        self.count += 1;
    }
    pub fn emit(self: *@This(), relation: F.Relation, tuple: anytype, weight: O) void {
        var base: [tuple.len]M = undefined;
        for (tuple, &base) |v, *m| m.* = v.toM31Array()[0];
        self.emitBase(relation, base, weight.toM31Array()[0]);
    }
};
fn reference(source: *const R.TruthSource, instance: Frame.Instance, logical: usize, sink: *Capture) !void {
    switch (source.*) {
        .keccak => |s| switch (instance.role) {
            .keccak => {
                const trace = &s.permutation;
                const n = trace.size();
                const r = A.witness.physical(logical, trace.log_size);
                var fixed: [K.layout.FIXED]M = undefined;
                for (&fixed, 0..) |*v, c| v.* = trace.fixed[c * n + r];
                const main = try trace.metadataRow(logical);
                const next = try trace.metadataRow((logical + 1) % n);
                const fo = lift(K.layout.FIXED, fixed);
                const mo = lift(K.layout.MAIN, main);
                const no = lift(K.layout.STATE, next[0..K.layout.STATE].*);
                const row = K.equations.RowFor(O){ .fixed = &fo, .main = &mo, .state_minus_two = &no, .state_minus_one = &no, .state_plus_one = &no, .state_plus_two = &no };
                F.keccakFor(O, row, sink);
            },
            .chi, .xor5 => {
                const table = if (instance.role == .chi) &s.chi else &s.xor5;
                const r = A.witness.physical(logical, table.log_size);
                var tuple: [6]O = undefined;
                for (&tuple, 0..) |*v, c| v.* = O.fromBase(table.fixed[c * table.size() + r]);
                F.keccakTableFor(O, table.kind, tuple, O.fromBase(M.fromCanonical(table.multiplicities[logical])), sink);
            },
            else => return error.UnexpectedTruthRole,
        },
        .secp => |s| switch (instance.role) {
            .product, .linear => {
                const trace = if (instance.role == .product) &s.batch.product else &s.batch.linear;
                var row: [319]Q = undefined;
                try trace.metadataRow(logical, row[0..S.layout.main(trace.kind)]);
                var main: [319]O = undefined;
                for (main[0..S.layout.main(trace.kind)], row[0..S.layout.main(trace.kind)]) |*v, q| v.* = O.fromInner(q);
                F.secpFor(O, trace.kind, trace.byte_policy, main[0..S.layout.main(trace.kind)], sink);
            },
            .bytes => F.byteTableFor(O, O.fromBase(M.fromCanonical(@intCast(logical))), O.fromBase(s.bytes.main[A.witness.physical(logical, 8)]), sink),
            else => return error.UnexpectedTruthRole,
        },
    }
}
fn compareMetadata(source: *R.TruthSource) !void {
    const expected = Frame.forSource(source);
    const provider = try Metadata.Provider.init(source, expected, LIMIT);
    const x = try a.alloc(Entry, 1920);
    defer a.free(x);
    const y = try a.alloc(Entry, 1920);
    defer a.free(y);
    for (expected) |instance| for (0..try instance.rows()) |logical| {
        var got = Capture{ .entries = x };
        var want = Capture{ .entries = y };
        try provider.emit(instance, logical, &got);
        try reference(source, instance, logical, &want);
        try std.testing.expectEqual(@as(usize, instance.queries), got.count);
        try std.testing.expectEqualDeep(want.entries[0..want.count], got.entries[0..got.count]);
        // Concatenated bounded reads must reproduce the independent original
        // full-row tuple authority, including padded rows and mixed namespaces.
        got.count = 0;
        var first: usize = 0;
        while (first < instance.queries) {
            const count = @min(@as(usize, 37), instance.queries - first);
            try provider.emitRange(instance, logical, first, count, &got);
            first += count;
        }
        try std.testing.expectEqualDeep(want.entries[0..want.count], got.entries[0..got.count]);
        for ([_]usize{ 0, instance.queries / 2, instance.queries }) |start| {
            var part = Capture{ .entries = x };
            try provider.emitRange(instance, logical, start, 0, &part);
            try std.testing.expectEqual(@as(usize, 0), part.count);
            if (start < instance.queries) {
                const count = @min(@as(usize, 3), instance.queries - start);
                try provider.emitRange(instance, logical, start, count, &part);
                try std.testing.expectEqualDeep(want.entries[start..][0..count], part.entries[0..part.count]);
            }
        }
    };
    const commit = try source.takeMain();
    defer commit.deinit(a);
    for (expected) |instance| {
        var got = Capture{ .entries = x };
        try provider.emit(instance, 0, &got);
        try std.testing.expectEqual(@as(usize, instance.queries), got.count);
        got.count = 0;
        try provider.emitRange(instance, 0, instance.queries - 1, 1, &got);
        try std.testing.expectEqual(@as(usize, 1), got.count);
        got.count = 0;
        try std.testing.expectError(error.InvalidTruthGkrQueryRange, provider.emitRange(instance, 0, instance.queries + 1, 0, &got));
        try std.testing.expectError(error.InvalidTruthGkrQueryRange, provider.emitRange(instance, 0, instance.queries, 1, &got));
        try std.testing.expectError(error.InvalidTruthGkrQueryRange, provider.emitRange(instance, 0, 1, std.math.maxInt(usize), &got));
        try std.testing.expectError(error.InvalidTruthGkrRow, provider.emitRange(instance, try instance.rows(), 0, 0, &got));
        var changed = instance;
        changed.queries += 1;
        try std.testing.expectError(error.TruthGkrSourceGeometryMismatch, provider.emitRange(changed, 0, 0, 0, &got));
        try std.testing.expectEqual(@as(usize, 0), got.count);
    }
}
test "truth durable packed Keccak all padded queries equal original tuple authority after MAIN take" {
    var source = try keccakSource();
    defer source.deinit();
    try compareMetadata(&source);
}
test "truth durable secp local and inherited byte policies retain every padded query after MAIN take" {
    for ([_]S.layout.BytePolicy{ .local, .canonical_inputs }) |policy| {
        var source = try secpSource(policy);
        defer source.deinit();
        try compareMetadata(&source);
    }
}
fn proveClosed(source: *R.TruthSource) !void {
    const frames = Frame.forSource(source);
    const provider = try Metadata.Provider.init(source, frames, LIMIT);
    const transferred = try source.takeMain();
    transferred.deinit(a); // Real released MAIN; only durable metadata remains.
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = F.ChallengesFor(O).draw(&channel);
    var inputs = try Inputs.init(a, &provider, &challenges, LIMIT);
    defer inputs.deinit();
    var result = try GP.proveBatch(a, &channel, inputs.layers);
    defer result.deinit(a);
    var fresh = core.channel.raw_mod_m31.Om31Channel.init();
    _ = F.ChallengesFor(O).draw(&fresh);
    const gates = [_]GV.Gate{ .LogUp, .LogUp, .LogUp };
    var artifact = try GV.partiallyVerifyBatch(a, &gates, &result.proof, &fresh);
    defer artifact.deinit(a);
    try std.testing.expectEqualDeep(channel, fresh);
    var total = O.zero();
    for (result.proof.output_claims_by_instance) |root| {
        if (root[1].isZero()) return error.TruthLocalPole;
        total = total.add(try root[0].div(root[1]));
    }
    if (!total.isZero()) return error.TruthLocalClaimsNotClosed;
    var terminal: [3][2]O = undefined;
    var expected: [3][]const O = undefined;
    for (inputs.layers, 0..) |layer, i| {
        const mle = layer.LogUpMultiplicities;
        const n = artifact.n_variables_by_instance[i];
        const point = artifact.ood_point[artifact.ood_point.len - n ..];
        terminal[i] = .{ try mle.numerators.evalAtPoint(a, point), try mle.denominators.evalAtPoint(a, point) };
        expected[i] = &terminal[i];
    }
    try engine.lookups.verifier_kernel.verifyTerminalInputs(O, &artifact, &expected, GV.NativeChecks{});
}
test "truth actual OM31 GKR Keccak chi xor5 table closure proves and freshly verifies" {
    var source = try keccakSource();
    defer source.deinit();
    try proveClosed(&source);
}
test "truth actual OM31 GKR canonical secp BYTE provider closure proves and freshly verifies" {
    var source = try secpSource(.canonical_inputs);
    defer source.deinit();
    try proveClosed(&source);
}
test "truth source geometry and large Keccak resource bound reject before allocation" {
    const giant = [_]Frame.Instance{.{ .role = .keccak, .row_log = 18, .queries = 1920 }};
    try std.testing.expectError(error.TruthGkrBudgetExceeded, Frame.Plan.admit(&giant, 16 * 1024 * 1024 * 1024));
    const plan = try Frame.Plan.admit(&giant, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 73014444032), plan.peak_bytes);
    var source = try keccakSource();
    defer source.deinit();
    var expected = Frame.forSource(&source);
    expected[0].queries -= 1;
    try std.testing.expectError(error.TruthGkrSourceGeometryMismatch, Metadata.Provider.init(&source, expected, LIMIT));
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const provider = try Metadata.Provider.init(&source, Frame.forSource(&source), LIMIT);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = F.ChallengesFor(O).draw(&channel);
    try std.testing.expectError(error.TruthGkrBudgetExceeded, Inputs.init(fail.allocator(), &provider, &ch, 1));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
}
test "truth generic OM31 KIO Wire denominator methods and draws preserve all eight coordinates" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var expected = channel;
    const ch = K.equations.ChallengesFor(O).draw(&channel);
    const want_chi = K.equations.LookupFor(O).draw(&expected);
    const want_xor = K.equations.LookupFor(O).draw(&expected);
    const want_io = K.equations.IoFor(O).draw(&expected);
    try std.testing.expectEqualDeep(ch, K.equations.ChallengesFor(O){ .chi = want_chi, .xor5 = want_xor, .io = want_io });
    try std.testing.expectEqualDeep(channel, expected);
    var tuple: [11]O = undefined;
    for (&tuple, 0..) |*v, i| v.* = dense(i + 31);
    try std.testing.expect(ch.io.denominator(&tuple).eql(EvalDenom(ch.io, &tuple)));
    const sc = S.equations.ChallengesFor(O).draw(&channel);
    const poly = expected.drawSecureFelt();
    const bytes = expected.drawSecureFelt();
    const wire = S.equations.WireFor(O).draw(&expected);
    try std.testing.expectEqualDeep(sc, S.equations.ChallengesFor(O){ .polynomial = poly, .bytes = bytes, .wire = wire });
    try std.testing.expectEqualDeep(channel, expected);
    var t: [35]O = undefined;
    for (&t, 0..) |*v, i| v.* = dense(i + 71);
    try std.testing.expect(sc.wire.denominator(&t).eql(EvalDenom(sc.wire, &t)));
}
fn EvalDenom(ch: anytype, tuple: anytype) O {
    return A.evaluation.denominatorFor(O, ch.offset, &ch.coefficients, tuple, true);
}

fn checkGlobalRow(source: *const R.TruthSource, role: Frame.Role, logical: usize, witness: *const GW.Witness, ch: *const GW.Challenges) !bool {
    const rows = @as(usize, 1) << @intCast(witness.log_size);
    const width = witness.width();
    const r = A.witness.physical(logical, witness.log_size);
    const pr = A.witness.physical((logical + rows - 1) % rows, witness.log_size);
    var current: [208]O = undefined;
    var previous: [208]O = undefined;
    for (current[0..width], previous[0..width], 0..) |*v, *p, c| {
        v.* = O.fromBase(witness.data[c * rows + r]);
        p.* = O.fromBase(witness.data[c * rows + pr]);
    }
    var values: [32]O = undefined;
    var sink = A.evaluation.SinkFor(O){ .values = &values };
    const first = O.fromBase(M.fromCanonical(@intFromBool(logical == 0)));
    const last = O.fromBase(M.fromCanonical(@intFromBool(logical + 1 == rows)));
    switch (source.*) {
        .keccak => |s| {
            const trace = &s.permutation;
            var f: [K.layout.FIXED]M = undefined;
            for (&f, 0..) |*v, c| v.* = trace.fixed[c * rows + r];
            const fo = lift(K.layout.FIXED, f);
            const mo = lift(K.layout.MAIN, try trace.metadataRow(logical));
            const state: *const [K.layout.STATE]O = mo[0..K.layout.STATE];
            const row = K.equations.RowFor(O){ .fixed = &fo, .main = &mo, .state_minus_two = state, .state_minus_one = state, .state_plus_one = state, .state_plus_two = state };
            try Global.keccakFor(O, row, current[0..width], previous[0..width], first, last, witness.claimSlice()[0], ch.io, &sink);
        },
        .secp => |s| {
            const trace = if (role == .product) &s.batch.product else &s.batch.linear;
            var f: [S.layout.FIXED]M = undefined;
            for (&f, 0..) |*v, c| v.* = trace.fixed[c * rows + r];
            const fo = lift(S.layout.FIXED, f);
            var q: [319]Q = undefined;
            try trace.metadataRow(logical, q[0..S.layout.main(trace.kind)]);
            var main: [319]O = undefined;
            for (main[0..S.layout.main(trace.kind)], q[0..S.layout.main(trace.kind)]) |*v, value| v.* = O.fromInner(value);
            try Global.secpFor(O, trace.kind, trace.program, .{ .fixed = &fo, .main = main[0..S.layout.main(trace.kind)] }, current[0..width], previous[0..width], first, last, witness.claimSlice()[0], ch.wire, &sink);
        },
    }
    for (values[0..sink.count]) |v| if (!v.isZero()) return false;
    return true;
}
fn globalWitnesses(source: *R.TruthSource) !void {
    var provider = try GM.Provider.init(a, source, 4096);
    defer provider.deinit();
    const commit = try source.takeMain();
    defer commit.deinit(a);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = GW.Challenges{ .io = K.equations.IoFor(O).draw(&channel), .wire = S.equations.WireFor(O).draw(&channel) };
    for (Frame.forSource(source)) |instance| {
        if (instance.role != .keccak and instance.role != .product and instance.role != .linear) continue;
        var witness = try GW.generate(a, &provider, instance.role, &ch, LIMIT);
        defer witness.deinit();
        for (0..try instance.rows()) |logical| try std.testing.expect(try checkGlobalRow(source, instance.role, logical, &witness, &ch));
        const rows = @as(usize, 1) << @intCast(witness.log_size);
        const old = witness.data[7 * rows];
        witness.data[7 * rows] = old.add(M.one());
        try std.testing.expect(!try checkGlobalRow(source, instance.role, 0, &witness, &ch));
        witness.data[7 * rows] = old;
    }
}
test "truth global native OM8 witnesses survive MAIN take and satisfy original KIO Wire constraints" {
    var source = try keccakSource();
    defer source.deinit();
    try globalWitnesses(&source);
}
test "truth global native OM8 secp metadata shares exact column source and Wire tuple authority" {
    var source = try secpSource(.canonical_inputs);
    defer source.deinit();
    try globalWitnesses(&source);
}
const SmallProvider = struct {
    pub fn fill(_: @This(), row: usize, d: []O, n: []Classic.Numerator) !void {
        d[0] = dense(31).sub(O.fromBase(M.fromCanonical(@intCast(row))));
        n[0] = .{ .base = M.one() };
        d[1] = dense(37).add(O.fromBase(M.fromCanonical(@intCast(row))));
        n[1] = .{ .secure = dense(43) };
    }
};
test "shared classic witness groups are bounded and ownership take is failure atomic" {
    var fail = std.testing.FailingAllocator.init(a, .{});
    const allocator = fail.allocator();
    var witness = try Classic.Witness.init(allocator, 5, &.{ .{ .inverses = 1 }, .{ .inverses = 1 } }, SmallProvider{}, LIMIT);
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 32), witness.width());
    try std.testing.expectEqual(@as(usize, 2), witness.claimSlice().len);
    fail.fail_index = fail.alloc_index;
    try std.testing.expectError(error.OutOfMemory, witness.take());
    try std.testing.expectEqual(@as(usize, 32 * 32), witness.data.len);
    fail.fail_index = std.math.maxInt(usize);
    const owned = try witness.take();
    defer owned.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), witness.data.len);
    try std.testing.expectError(error.InvalidClassicWitnessPhase, witness.take());
    var none = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.ClassicWitnessBudgetExceeded, Classic.Witness.init(none.allocator(), 5, &.{ .{ .inverses = 1 }, .{ .inverses = 1 } }, SmallProvider{}, 1));
    try std.testing.expectEqual(@as(usize, 0), none.alloc_index);
}
test "shared classic witness refuses missing zero weight denominator obligations" {
    const Missing = struct {
        pub fn fill(_: @This(), _: usize, _: []O, _: []Classic.Numerator) !void {}
    };
    try std.testing.expectError(error.DivisionByZero, Classic.Witness.init(a, 5, &.{.{ .inverses = 1 }}, Missing{}, LIMIT));
}

test "truth actual GKR cannot accept changed secp bytes against sealed provider counts" {
    var source = try secpSource(.canonical_inputs);
    defer source.deinit();
    source.secp.batch.product.lookup_bytes[64] ^= 1;
    try std.testing.expectError(error.TruthLocalClaimsNotClosed, proveClosed(&source));
}
test "truth actual GKR cannot accept changed Keccak state against sealed chi xor5 counts" {
    var source = try keccakSource();
    defer source.deinit();
    source.keccak.permutation.metadata[2].state_a[0] ^= 1;
    try std.testing.expectError(error.TruthLocalClaimsNotClosed, proveClosed(&source));
}

test "shared classic chunk inversions preserve every coordinate and logical prefix across chunks" {
    const groups = &.{ Classic.Group{ .inverses = 1 }, Classic.Group{ .inverses = 1 } };
    var witness = try Classic.Witness.init(a, 10, groups, SmallProvider{}, LIMIT);
    defer witness.deinit();
    var sum = [_]O{ O.zero(), O.zero() };
    const rows = @as(usize, 1) << 10;
    for (0..rows) |logical| {
        var d: [2]O = undefined;
        var n: [2]Classic.Numerator = undefined;
        try (SmallProvider{}).fill(logical, &d, &n);
        const physical = A.witness.physical(logical, 10);
        for (0..2) |g| {
            const inverse = try d[g].inv();
            sum[g] = sum[g].add(n[g].multiply(inverse));
            for (inverse.toM31Array(), 0..) |coordinate, c|
                try std.testing.expectEqual(coordinate, witness.data[(16 * g + c) * rows + physical]);
            const prefix = sum[g].sub(witness.claims[g]);
            for (prefix.toM31Array(), 0..) |coordinate, c|
                try std.testing.expectEqual(coordinate, witness.data[(16 * g + 8 + c) * rows + physical]);
        }
    }
    for (sum, witness.claimSlice()) |expected, actual| try std.testing.expect(expected.eql(actual));
}
fn allocationClassic(allocator: std.mem.Allocator) !void {
    var witness = try Classic.Witness.init(allocator, 5, &.{ .{ .inverses = 1 }, .{ .inverses = 1 } }, SmallProvider{}, LIMIT);
    defer witness.deinit();
}
test "shared classic chunk allocation failures release all scratch and output" {
    try std.testing.checkAllAllocationFailures(a, allocationClassic, .{});
}
