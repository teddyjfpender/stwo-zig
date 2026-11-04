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
    if (p.witness_ood) |v| hashFelts(&h, &.{v});
    if (p.weight_opening) |w| hashOpening(&h, w);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Digest over the ext (transformer op) part of a proof: values, sumchecks, finals.
pub fn extDigest(p: proto.Proof) [32]u8 {
    var h = Blake2s.init(.{});
    h.update(std.mem.asBytes(&p.ext.values.len));
    hashFelts(&h, p.ext.values);
    for (p.ext.sumchecks) |s| {
        h.update(std.mem.asBytes(&s.rounds.len));
        for (s.rounds) |r| hashFelts(&h, r.evals[0..s.deg]);
    }
    for (p.ext.finals) |x| hashFelts(&h, &x);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// proofDigest and extDigest together.
pub fn fullDigest(p: proto.Proof) [32]u8 {
    var h = Blake2s.init(.{});
    h.update(&proofDigest(p));
    h.update(&extDigest(p));
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

/// Digest over a per-request serving batch: every request's own part (as
/// `proofDigest`) and salt, every shared slot, and the shared weight opening.
pub fn batchDigest(b: @import("serve.zig").Batch) [32]u8 {
    var h = Blake2s.init(.{});
    for (b.requests) |r| {
        h.update(&r.salt);
        h.update(&proofDigest(r.core));
    }
    for (b.shared.requests) |s| {
        h.update(&s.digest);
        for (s.points) |p| hashFelts(&h, p);
        h.update(std.mem.sliceAsBytes(s.w));
        h.update(std.mem.sliceAsBytes(s.point_of));
        hashFelts(&h, s.values);
    }
    if (b.shared.reduction) |p| for (p.rounds) |rp| hashFelts(&h, rp.evals[0..p.deg]);
    hashFelts(&h, &.{b.shared.reduced_value});
    if (b.shared.opening) |op| hashOpening(&h, op);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hashOpening(h: *Blake2s, op: proto.Opening) void {
    switch (op) {
        .flat => |o| hashFlat(h, o),
        .two => |o| for (o.levels) |lv| {
            h.update(std.mem.asBytes(&lv.pow_nonce));
            h.update(std.mem.sliceAsBytes(lv.col_values));
            for (lv.decommit) |d| h.update(&d);
            for (lv.rows) |r| hashFelts(h, r);
            h.update(&lv.inner_root);
            for (lv.sumcheck.rounds) |rp| hashFelts(h, rp.evals[0..lv.sumcheck.deg]);
            hashFelts(h, &lv.limb_vals);
        },
    }
}

fn hashFlat(h: *Blake2s, o: pcs.OpeningProof) void {
    for (o.rows) |r| hashFelts(h, r);
    h.update(std.mem.asBytes(&o.pow_nonce));
    for (o.columns) |c| {
        h.update(std.mem.asBytes(&c.index));
        h.update(std.mem.sliceAsBytes(c.values));
        for (c.path) |p| h.update(&p);
    }
}

