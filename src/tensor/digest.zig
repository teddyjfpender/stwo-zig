//! Proof digest: Blake2s over every field of a `protocol.Proof`, used to
//! compare proofs produced by different execution paths (CPU vs device).
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const proto = @import("protocol.zig");

const QM31 = f.QM31;
const Blake2s = std.crypto.hash.blake2.Blake2s256;

fn hashFelts(h: *Blake2s, v: []const QM31) void {
    for (v) |x| {
        const l = f.limbs(x);
        h.update(std.mem.asBytes(&l));
    }
}

/// Digest over every field of a proof (structure and values).
pub fn proofDigest(p: proto.Proof) [32]u8 {
    var h = Blake2s.init(.{});
    h.update(&p.witness_root);
    if (p.gkr) |g| hashGkr(&h, g);
    hashFelts(&h, p.lookup_in_values);
    for (p.op_sumchecks) |s| for (s.rounds) |r| hashFelts(&h, r.evals[0..s.deg]);
    for (p.op_finals) |x| hashFelts(&h, x);
    for (p.batch_sumcheck.rounds) |r| hashFelts(&h, r.evals[0..p.batch_sumcheck.deg]);
    hashFelts(&h, &.{p.witness_value});
    hashOpening(&h, p.witness_opening);
    hashFelts(&h, p.weight_values);
    if (p.weight_opening) |w| hashOpening(&h, w);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashGkr(h: *Blake2s, g: anytype) void {
    for (g.sumcheck_proofs) |sp| for (sp.round_polys) |rp| hashFelts(h, rp.coeffsSlice());
    for (g.layer_masks_by_instance) |ms| for (ms) |m| for (m.columnsSlice()) |c| hashFelts(h, &c);
    for (g.output_claims_by_instance) |c| hashFelts(h, c);
}

/// Digest over every field of an offline weight-key proof.
pub fn keyProofDigest(p: @import("weight_key.zig").KeyProof) [32]u8 {
    var h = Blake2s.init(.{});
    h.update(std.mem.sliceAsBytes(&p.histogram));
    hashGkr(&h, p.gkr);
    hashFelts(&h, &.{p.value});
    hashOpening(&h, p.opening);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashOpening(h: *Blake2s, o: pcs.OpeningProof) void {
    for (o.rows) |r| hashFelts(h, r);
    h.update(std.mem.asBytes(&o.pow_nonce));
    for (o.columns) |c| {
        h.update(std.mem.asBytes(&c.index));
        h.update(std.mem.sliceAsBytes(c.values));
        for (c.path) |p| h.update(&p);
    }
}

