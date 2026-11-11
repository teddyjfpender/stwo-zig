//! Correctness-only conditional ALU fragment: actual segmented GP child plus
//! ONE unchanged16-column binding and original ALU MAIN. No execution closure.
const std = @import("std");
const C = @import("stwo_core");
const E = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = @import("alu.zig");
const O = S.O;
const M = S.M;
const Role = @import("../../../word16_global_execution/services/gkr_local/role.zig");
const Inputs = @import("../../../word16_global_execution/services/gkr_local/inputs.zig");
const Fns = @import("../../../word16_global_execution/services/gkr_local/fractions.zig");
const W = @import("../../../word16_global_execution/services/gkr_local/witness.zig");
const Ch = C.channel.raw_mod_m31.Om31Channel;
const H = C.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = struct {
    pub fn mixRoot(c: *Ch, root: H.Hash) void {
        C.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const Prover = E.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Ch);
const Fault = enum { none, early_weights, balanced_source, eq, prefix };
fn config() !C.pcs.ForField(O).PcsConfig {
    return @import("../../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1.config();
}
fn actualRow(source: *const S.Source, logical: usize, ch: *const S.Challenges, n: *[13]M, d: *[13]O) !void {
    const p = A.witness.physical(logical, 5);
    var main: [47]M = undefined;
    for (&main, 0..) |*v, i| v.* = source.main[i * 32 + p];
    var sink = Inputs.RowSink{ .challenges = ch, .numerator = n, .denominator = d };
    const Adapter = struct {
        sink: *Inputs.RowSink,
        pub fn emit(self: *@This(), relation: Fns.Relation, tuple: anytype, weight: M) void {
            self.sink.emitBase(relation, tuple, weight);
        }
    };
    var adapter = Adapter{ .sink = &sink };
    Fns.aluFor(M, &main, &adapter);
    if (sink.invalid or sink.count != 13) return error.SegmentSource;
}
fn get(data: []const M, column: usize, physical: usize) O {
    var words: [8]M = undefined;
    for (&words, 0..) |*word, i| word.* = data[(column + i) * 32 + physical];
    return O.fromM31Array(words);
}
fn put(data: []M, column: usize, physical: usize, value: O) void {
    for (value.toM31Array(), 0..) |word, i| data[(column + i) * 32 + physical] = word;
}
fn witness(a: std.mem.Allocator, source: *const S.Source, data: *const Role.Data, row_point: []const O) ![]M {
    const out = try a.alloc(M, 16 * 32);
    errdefer a.free(out);
    try W.eqInto(out, 32, row_point);
    var sum = O.zero();
    for (0..32) |logical| {
        const p = A.witness.physical(logical, 5);
        var n: [13]M = undefined;
        var d: [13]O = undefined;
        try actualRow(source, logical, &data.challenges, &n, &d);
        var projection = O.zero();
        for (data.lane_weights[0..13], n, d) |weight, nn, dd| projection = projection.add(weight.mul(O.fromBase(nn).add(data.eta.mul(dd))));
        sum = sum.add(get(out, 0, p).mul(projection).sub(data.target_per_row));
        put(out, 8, p, sum);
    }
    // Do NOT "repair" the last prefix for a false source; the physical AIR
    // must reject its authentic nonzero cyclic discrepancy.
    return out;
}
fn initSource(a: std.mem.Allocator) !S.Source {
    const Fact = A.word16_v1.alu_experiment.source.Fact;
    var facts: [17]Fact = undefined;
    for (&facts, 0..) |*f, i| {
        const x: u64 = if (i % 2 == 0) std.math.maxInt(u64) - i * 17 else i * 77731;
        const y: u64 = i * 9079 + 2671;
        f.* = .{ .op = .add, .a = x, .b = y, .c = x +% y };
    }
    return S.Source.init(a, &facts, 5);
}
const Bundle = struct {
    stark: Prover.ExtendedProof,
    gkr: S.GP.ProveBatchResult,
    receipt: [32]u8,
    proof_live: bool = true,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.proof_live) self.stark.proof.deinit(a);
        self.stark.aux.deinit(a);
        self.gkr.deinit(a);
    }
};
fn produce(a: std.mem.Allocator, key: S.Key, fault: Fault) !Bundle {
    try key.validate();
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &ch);
    var src = try initSource(a);
    defer src.deinit();
    const main = try src.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, main, &ch);
    const challenges = try key.begin(&ch);
    var readers: [3]S.Reader = undefined;
    var srcs: [3]S.GP.MultiplicitiesSource = undefined;
    try S.sources(&readers, &srcs, &src, challenges, key, if (fault == .balanced_source) .balanced_denominators else .none);
    // Specialized source extraction is checked against the ORIGINAL MAIN
    // fraction emitter for every real row/lane, before producing any child.
    if (fault != .balanced_source) for (readers) |reader| {
        var copy = reader;
        for (0..reader.segment.width * 32) |flat| {
            var n: [1]M = undefined;
            var d: [1]O = undefined;
            try S.Reader.read(&copy, flat, &n, &d);
            const p = flat % 32;
            const logical = C.utils.circleDomainIndexToCosetIndex(C.utils.bitReverseIndex(p, 5), 5);
            var expected_n: [13]M = undefined;
            var expected_d: [13]O = undefined;
            try actualRow(&src, logical, &challenges, &expected_n, &expected_d);
            const lane = reader.segment.first + flat / 32;
            try std.testing.expectEqual(expected_n[lane], n[0]);
            try std.testing.expect(expected_d[lane].eql(d[0]));
        }
    };
    var gkr = try S.GP.proveBatchSourceCheckpointed(a, &ch, &srcs);
    errdefer gkr.deinit(a);
    const digest = try S.receipt(a, key, &gkr.proof, &gkr.artifact);
    const coins = S.late(&ch, digest);
    if (fault == .balanced_source) {
        var unweighted = O.zero();
        var weighted = O.zero();
        var power = O.one();
        for (readers, gkr.artifact.claims_to_verify_by_instance, 0..) |reader, claims, ordinal| {
            var honest = reader;
            honest.fault = .none;
            const vars = try reader.segment.variables();
            const point = gkr.artifact.ood_point[gkr.artifact.ood_point.len - vars ..];
            var actual_n = O.zero();
            var actual_d = O.zero();
            for (0..reader.segment.width * 32) |flat| {
                var n: [1]M = undefined;
                var d: [1]O = undefined;
                try S.Reader.read(&honest, flat, &n, &d);
                const e = S.eq(point, flat);
                actual_n = actual_n.add(e.mulM31(n[0]));
                actual_d = actual_d.add(e.mul(d[0]));
            }
            try std.testing.expect(actual_n.eql(claims[0]));
            const delta = claims[1].sub(actual_d);
            try std.testing.expect(delta.eql(if (ordinal == 0) O.one() else if (ordinal == 1) O.one().neg() else O.zero()));
            unweighted = unweighted.add(delta);
            weighted = weighted.add(power.mul(delta));
            power = power.mul(coins.rho);
        }
        try std.testing.expect(unweighted.isZero() and !weighted.isZero());
    }
    const data = try S.data(key, challenges, &gkr.artifact, coins);
    var witness_data = data;
    if (fault == .early_weights) witness_data = try S.data(key, challenges, &gkr.artifact, .{ .rho = O.one(), .mu = coins.mu });
    const row_point = gkr.artifact.ood_point[gkr.artifact.ood_point.len - 5 ..];
    const inter_data = try witness(a, &src, &witness_data, row_point);
    defer a.free(inter_data);
    if (fault == .eq) inter_data[7] = inter_data[7].add(M.one());
    if (fault == .prefix) inter_data[8 * 32 + 7] = inter_data[8 * 32 + 7].add(M.one());
    if (fault == .none or fault == .early_weights) try std.testing.expect(get(inter_data, 8, A.witness.physical(31, 5)).isZero());
    if (fault == .balanced_source) try std.testing.expect(!get(inter_data, 8, A.witness.physical(31, 5)).isZero());
    var inter: [16]E.pcs.ColumnEvaluation = undefined;
    for (&inter, 0..) |*column, i| column.* = .{ .log_size = 5, .values = inter_data[i * 32 ..][0..32] };
    try scheme.commit(a, &inter, &ch);
    const component = Role.Component{ .main = .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = 1 };
    try component.validate();
    owns = false;
    const proof = if (fault == .none) try Prover.prove(a, &.{component.asProverComponent()}, &ch, scheme, .{}) else blk: {
        var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
        var failed: ?Prover.ExtendedProof = null;
        break :blk Prover.proveDiagnosedRetainingFailure(a, &.{component.asProverComponent()}, &ch, scheme, .{}, &diagnostic, &failed) catch |err| switch (err) {
            error.ConstraintsNotSatisfied => failed orelse return error.MissingInvalidPhysicalProof,
            else => return err,
        };
    };
    return .{ .stark = proof, .gkr = gkr, .receipt = digest };
}
fn verify(a: std.mem.Allocator, bundle: *Bundle, key: S.Key) !void {
    try key.validate();
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try C.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const roots = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.SegmentProof;
    try receiver.commit(a, roots[0], &.{}, &ch);
    try receiver.commit(a, roots[1], &([_]u32{5} ** 47), &ch);
    const challenges = try key.begin(&ch);
    const raw = try S.Wire.encodeFor(a, &key.segments, &bundle.gkr.proof, S.MAGIC);
    defer a.free(raw);
    var decoded = try S.Wire.decodeFor(a, &key.segments, raw, S.MAGIC);
    defer decoded.deinit();
    try std.testing.expectError(error.LocalGkrWireProfile, S.Wire.decodeFor(a, &key.segments, raw, "OPSPCPU1"));
    var bad_count = try a.dupe(u8, raw);
    defer a.free(bad_count);
    std.mem.writeInt(u32, bad_count[12..16], 2, .little);
    try std.testing.expectError(error.LocalGkrReceiptShape, S.Wire.decodeFor(a, &key.segments, bad_count, S.MAGIC));
    var artifact = try S.GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp }, &decoded.proof, &ch);
    defer artifact.deinit(a);
    const digest = try S.receipt(a, key, &decoded.proof, &artifact);
    try std.testing.expectEqualSlices(u8, &bundle.receipt, &digest);
    const coins = S.late(&ch, digest);
    const data = try S.data(key, challenges, &artifact, coins);
    const component = Role.Component{ .main = .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = 1 };
    try receiver.commit(a, roots[2], &([_]u32{5} ** 16), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    bundle.proof_live = false;
    try C.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}

test "OP segmented lane ALU trusted cover version and weighted row suffix" {
    const key = S.Key{};
    try key.validate();
    try S.securityEnvelope();
    var bad = key;
    bad.version = 0;
    try std.testing.expectError(error.SegmentVersion, bad.validate());
    bad = key;
    bad.segments[1].first = 7;
    try std.testing.expectError(error.SegmentCover, bad.validate());
    bad = key;
    std.mem.swap(S.Segment, &bad.segments[0], &bad.segments[1]);
    try std.testing.expectError(error.SegmentCover, bad.validate());
    bad = key;
    bad.segments[2].width = 2;
    try std.testing.expectError(error.SegmentCover, bad.validate());
    try std.testing.expectEqual(@as(u32, 8), try key.segments[0].variables());
    try std.testing.expectEqual(@as(u32, 5), try key.segments[2].variables());
    var common: [11]O = undefined;
    for (&common, 0..) |*value, i| value.* = O.fromBase(M.fromCanonical(@intCast(2 + i)));
    for (key.segments) |segment| {
        const split = try S.splitPoint(segment, &common);
        try std.testing.expectEqualSlices(O, common[6..], split.rows);
        try std.testing.expectEqualSlices(O, common[11 - try segment.variables() .. 6], split.lanes);
    }
    // Changing lane width must not change the row suffix; an old row-prefix
    // split would give different row coordinates for these source lengths.
    try std.testing.expect(!(try S.splitPoint(key.segments[0], &common)).rows[0].eql(common[3]));
}
test "OP segmented lane ALU actual GP plus one physical binding fresh receiver" {
    if (std.posix.getenv("STWO_OP_SEGMENTED_ALU_PHYSICAL") == null) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    {
        var bundle = try produce(a, .{}, .none);
        defer bundle.deinit(a);
        var wrong = S.Key{};
        wrong.source_id = 8;
        var rejected = false;
        verify(a, &bundle, wrong) catch |err| switch (err) {
            error.InvalidSumcheck, error.CircuitCheckFailure => rejected = true,
            else => return err,
        };
        try std.testing.expect(rejected and bundle.proof_live);
        // Same unchanged valid proof then succeeds with independently pinned
        // correct source authority; a wrong-key refusal is not a garbage test.
        try verify(a, &bundle, .{});
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_SEGMENTED_ALU physical_positive=true instances=3 facts=416 oldfacts=512 MAIN=47 INTER=16 target_B4q72=true peak={} conditional_fragment_only=true\n", .{budget.snapshot().peak_live_bytes});
}
test "OP segmented lane ALU coherent GP source early weights Eq prefix physical rejection" {
    if (std.posix.getenv("STWO_OP_SEGMENTED_ALU_PHYSICAL") == null) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    for ([_]Fault{ .balanced_source, .early_weights, .eq, .prefix }) |fault| {
        var bundle = try produce(a, .{}, fault);
        defer bundle.deinit(a);
        verify(a, &bundle, .{}) catch |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => continue,
            else => return err,
        };
        return error.InvalidSegmentBindingAccepted;
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
