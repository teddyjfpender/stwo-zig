//! Closed lane-major ALU fragment prototype. Source version/roster are trusted
//! receiver authority; no live OP worker/codec/profile uses this module.
const std = @import("std");
const C = @import("stwo_core");
const E = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const Local = @import("../../../word16_global_execution/services/gkr_local/role.zig");
const Frame = @import("../../../word16_global_execution/services/gkr_local/frame.zig");
pub const O = C.fields.om31.OM31;
pub const M = C.fields.m31.M31;
pub const GP = E.lookups.gkr_prover.ForField(O);
pub const GV = E.lookups.gkr_verifier.ForField(O);
pub const Challenges = @import("../../../word16_global_execution/services/gkr_local/challenges.zig").For(O);
pub const Wire = @import("../../../word16_global_execution/services/gkr_local/wire.zig");
pub const instance = Frame.Instance{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 13, .fixed_offset = 0, .main_offset = 0 };
pub const Source = A.word16_v1.alu_experiment.source.Source;
pub const VERSION: u32 = 1;
pub const MAGIC = "OPLMSEG1";
pub const MAX_INSTANCES = 128;
pub const Segment = struct {
    first: u32,
    width: u32,
    pub fn variables(self: Segment) !u32 {
        if (!std.math.isPowerOfTwo(self.width) or self.width > 128) return error.SegmentGeometry;
        return 5 + std.math.log2_int(u32, self.width);
    }
};
pub const canonical = [_]Segment{ .{ .first = 0, .width = 8 }, .{ .first = 8, .width = 4 }, .{ .first = 12, .width = 1 } };
pub const Key = struct {
    version: u32 = VERSION,
    source_id: u32 = 7,
    segments: [3]Segment = canonical,
    pub fn validate(self: Key) !void {
        if (self.version != VERSION) return error.SegmentVersion;
        if (self.source_id == 0 or self.source_id > 128) return error.SegmentSource;
        if (!std.meta.eql(self.segments, canonical)) return error.SegmentCover;
        try securityEnvelope();
    }
    pub fn begin(self: Key, channel: anytype) !Challenges {
        try self.validate();
        channel.mixU32s(&.{ 0x4c4d5347, VERSION, self.source_id, 5, 13, 3, MAX_INSTANCES });
        for (self.segments) |segment| channel.mixU32s(&.{ segment.first, segment.width, try segment.variables() });
        // Explicit trusted relation version. Never infer v3 from CPUterms14.
        return Challenges.drawV3(channel);
    }
};
pub const Fault = enum { none, balanced_denominators };
pub const Reader = struct {
    source: *const Source,
    challenges: Challenges,
    segment: Segment,
    ordinal: usize,
    fault: Fault = .none,
    pub fn read(ctx: *const anyopaque, first: usize, n: []M, d: []O) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
        const self: *const Reader = @ptrCast(@alignCast(ctx));
        const size: usize = self.segment.width * 32;
        if (n.len != d.len or first > size or n.len > size - first) return error.ShapeMismatch;
        for (n, d, 0..) |*nn, *dd, i| {
            const flat = first + i;
            const lane = self.segment.first + @as(u32, @intCast(flat / 32));
            const physical = flat % 32;
            const logical = C.utils.circleDomainIndexToCosetIndex(C.utils.bitReverseIndex(physical, 5), 5);
            const meta = self.source.metadata[logical];
            // Source-specialized lane extraction: exactly ONE denominator per
            // fact, not reconstruction/denomination of all13 tuples per fact.
            if (lane < 12) {
                nn.* = M.one();
                dd.* = self.challenges.denominatorBase(.range16, [1]M{M.fromCanonical(meta.range_indices[lane])});
            } else if (lane == 12) {
                var payload: [13]M = undefined;
                for (meta.payload, &payload) |v, *out| out.* = M.fromCanonical(v);
                nn.* = M.fromCanonical(meta.multiplicity()).neg();
                dd.* = self.challenges.denominatorBase(.function, payload);
            } else return error.ShapeMismatch;
            // Coherent fake source: opposite CONSTANT D shifts cancel under
            // unweighted terminal aggregation, while the GP proof stays valid.
            if (self.fault == .balanced_denominators and self.ordinal < 2) dd.* = if (self.ordinal == 0) dd.add(O.one()) else dd.sub(O.one());
        }
    }
};
pub fn sources(readers: *[3]Reader, out: *[3]GP.MultiplicitiesSource, source: *const Source, challenges: Challenges, key: Key, fault: Fault) !void {
    try key.validate();
    for (key.segments, readers, out, 0..) |segment, *reader, *target, i| {
        reader.* = .{ .source = source, .challenges = challenges, .segment = segment, .ordinal = i, .fault = fault };
        target.* = .{ .variables = try segment.variables(), .context = reader, .wide_reads = true, .read_fn = Reader.read };
    }
}
fn hashField(h: anytype, value: O) void {
    var bytes: [32]u8 = undefined;
    for (value.toM31Array(), 0..) |v, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], v.v, .little);
    h.update(&bytes);
}
pub fn receipt(a: std.mem.Allocator, key: Key, proof: *const GV.GkrBatchProof, artifact: *const GV.GkrArtifact) ![32]u8 {
    try key.validate();
    if (artifact.claims_to_verify_by_instance.len != 3) return error.SegmentArtifact;
    const raw = try Wire.encodeFor(a, &key.segments, proof, MAGIC);
    defer a.free(raw);
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("op-lane-major-full-receipt/v1");
    var id: [4]u8 = undefined;
    std.mem.writeInt(u32, &id, key.source_id, .little);
    h.update(&id);
    h.update(raw);
    for (artifact.claims_to_verify_by_instance) |claims| {
        if (claims.len != 2) return error.SegmentArtifact;
        for (claims) |claim| hashField(&h, claim);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}
pub const Late = struct { rho: O, mu: O };
pub fn late(channel: anytype, digest: [32]u8) Late {
    channel.mixU32s(&.{ 0x4c4d4c54, VERSION, 3, 2 });
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
    return .{ .rho = channel.drawSecureFelt(), .mu = channel.drawSecureFelt() };
}
pub fn eq(point: []const O, index: usize) O {
    var out = O.one();
    for (point, 0..) |r, i| out = out.mul(if ((index >> @intCast(point.len - 1 - i)) & 1 != 0) r else O.one().sub(r));
    return out;
}
pub fn splitPoint(segment: Segment, common: []const O) !struct { lanes: []const O, rows: []const O } {
    const vars = try segment.variables();
    if (common.len < vars or common.len > 30) return error.SegmentArtifact;
    const point = common[common.len - vars ..];
    return .{ .lanes = point[0 .. vars - 5], .rows = point[vars - 5 ..] };
}
pub fn data(key: Key, challenges: Challenges, artifact: *const GV.GkrArtifact, coins: Late) !Local.Data {
    try key.validate();
    if (artifact.ood_point.len != 8 or artifact.claims_to_verify_by_instance.len != 3 or artifact.n_variables_by_instance.len != 3) return error.SegmentArtifact;
    var weights: [Frame.MAX_LOCAL_TERMS]O = @splat(O.zero());
    var target = O.zero();
    var power = O.one();
    for (key.segments, artifact.claims_to_verify_by_instance, artifact.n_variables_by_instance) |segment, claims, vars| {
        const expected = try segment.variables();
        if (vars != expected or claims.len != 2) return error.SegmentArtifact;
        const split = try splitPoint(segment, artifact.ood_point);
        for (0..segment.width) |i| weights[segment.first + i] = power.mul(eq(split.lanes, i));
        target = target.add(power.mul(claims[0].add(coins.mu.mul(claims[1]))));
        power = power.mul(coins.rho);
    }
    const row_point = artifact.ood_point[artifact.ood_point.len - 5 ..];
    // Original16-slot physical binding,13real coefficients and3zeros. The
    // existing projection adds precisely ZERO for removed dummy lanes.
    return .{ .instance = instance, .point = try @import("../../../logup_gkr/mle_point.zig").MleEvalPointFor(O).init(row_point), .lane_weights = weights, .lane_count = 16, .challenges = challenges, .eta = coins.mu, .target_per_row = target.mulM31(try M.fromCanonical(32).inv()) };
}

/// Additive conditional bound on top of the unchanged conservative native
/// cap ledger. No legacy term is subtracted, and this is not certification of
/// FRI/Fiat-Shamir/hash assumptions or closure of this conditional fragment.
pub fn securityEnvelope() !void {
    const Policy = @import("../../../word16_execution/om31_security_candidate.zig");
    var ledger = try Policy.ledgerAtBlowup(Policy.Facts.caps(), 2);
    const gkr = @import("../security.zig").GkrReport{
        .scopes = 1,
        .instances = 3,
        .max_variables = 8,
        .sumcheck_rounds = 28,
        .sumcheck_degree_weight = 3 * 3 * 28,
        .instance_mix_degree_weight = (3 + 2) * 8,
        .late_binding_degree_weight = 3, // covers fresh N/D mu (degree1)
        .degenerate_point_degree_weight = 2 * 3 * 5,
    };
    try gkr.addTo(&ledger);
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.gkr_late_binding)] += 2; // rho powers degree3-1
    try ledger.requireRawModuloBits(151); // existing target128+2+21 reserve
}
