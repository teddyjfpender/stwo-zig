//! Owning exact prefix and public-supply equation of an independently compiled
//! child root. No constructor accepts a producer-nominated expected key.
const std = @import("std");
const core = @import("stwo_core");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Universal = @import("air/universal_challenges.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const Admission = struct {
    pub const pinned_public_supply = true;
    key: @import("blake3_execution_parent_protocol.zig").Key,
    expected_id: [32]u8,
    public_id: [32]u8,
    seal: [32]u8,
    prefix: Frames.Statement,
    claim_tag: u32,
    source: struct { terms: []const Term },
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn validate(v: *const Admission) !void {
        _ = try v.key.identity();
        if (!std.meta.eql(v.seal, try v.identity())) return error.MutatedB8WindowChildAdmission;
        if (v.source.terms.len == 0 or v.claim_tag == 0) return error.InvalidB8WindowChildAdmission;
    }
    pub fn identity(v: *const Admission) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42385741, 1, v.claim_tag });
        ch.mixRoot(v.expected_id);
        ch.mixRoot(v.public_id);
        ch.mixRoot(try v.key.identity());
        try v.prefix.replay(&ch, v.prefix.first);
        ch.mixU64(v.source.terms.len);
        for (v.source.terms) |term| {
            ch.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
            ch.mixFelts(&.{core.fields.qm31.QM31.fromM31Array(term.coordinates)});
        }
        return ch.digestBytes();
    }
    pub fn config(v: *const Admission) !core.pcs.PcsConfig {
        try v.validate();
        return v.key.config;
    }
    pub fn admitRoot(v: *const Admission, root: [32]u8) !void {
        if (!std.meta.eql(v.key.preprocessed_root, root)) return error.UntrustedB8WindowChildRoot;
    }
    pub fn publicInputIdentity(v: *const Admission) ![32]u8 {
        try v.validate();
        return v.public_id;
    }
    pub fn mix(v: *const Admission, ch: anytype) !void {
        try v.validate();
        try v.prefix.replay(ch, v.prefix.first);
    }
    pub fn mixClaims(v: *const Admission, ch: anytype, claims: []const core.fields.qm31.QM31) !void {
        if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        ch.mixU32s(&.{ v.claim_tag, 1, @intCast(claims.len) });
        ch.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(v: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: Universal.UniversalRelations) !void {
        try v.validate();
        var sum = core.fields.qm31.QM31.zero();
        const r = try relations.getExact(.recursion_wire);
        for (v.source.terms) |term| {
            const d = try r.combineBase(&(.{ core.fields.m31.M31.fromCanonical(term.circuit), core.fields.m31.M31.fromCanonical(term.wire) } ++ term.coordinates));
            const q = core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical(term.uses)).mul(try d.inv());
            sum = if (term.negative) sum.sub(q) else sum.add(q);
        }
        for (claims) |q| sum = sum.add(q);
        if (!sum.isZero()) return error.InvalidB8WindowChildPublicSupply;
    }
};
/// Private to the independently compiling Profile factory. The original
/// protocol is replayed before erasing its concrete public roster type.
pub fn snapshot(a: std.mem.Allocator, original: anytype, values: anytype, claim_tag: u32) !Admission {
    try original.validate();
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_words = 1 << 22, .max_felts = 1 << 20 };
    defer b.deinit();
    try original.mix(&b);
    try b.check();
    const terms = try a.alloc(Term, original.wires.len);
    errdefer a.free(terms);
    for (terms, original.wires) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try values.at(wire) };
    var result = Admission{ .seal = undefined, .key = .{ .profile = original.key.profile, .config = original.key.config, .context = original.key.context, .log_sizes = original.key.log_sizes, .preprocessed_root = original.key.preprocessed_root }, .expected_id = original.expected_id, .public_id = try original.publicInputIdentity(), .claim_tag = claim_tag, .prefix = .{ .allocator = a, .words = try b.data.toOwnedSlice(a), .felts = try b.fields.toOwnedSlice(a), .first = try b.steps.toOwnedSlice(a), .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) }, .source = .{ .terms = terms } };
    result.seal = try result.identity();
    return result;
}
