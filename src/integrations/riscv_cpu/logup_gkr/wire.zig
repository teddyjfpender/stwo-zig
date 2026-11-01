//! Canonical bounded wire encoding for the experimental LogUp-GKR proof.
//! Shared by the bundle prover and receiver; no transcript operations occur here.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lookups = @import("stwo_prover_engine").lookups;
const gkr_verifier = lookups.gkr_verifier;
const sumcheck = lookups.sumcheck;
const lookup_utils = lookups.utils;
pub const MAX_INSTANCES: usize = 2;
const MAX_LAYERS: usize = 32;

pub fn putU32(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(a, &b);
}
pub fn putQ(out: *std.ArrayList(u8), a: std.mem.Allocator, q: QM31) !void {
    for (q.toM31Array()) |m| try putU32(out, a, m.v);
}

pub fn encodeGkr(a: std.mem.Allocator, proof: *const gkr_verifier.GkrBatchProof) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    const n = proof.layer_masks_by_instance.len;
    try putU32(&out, a, @intCast(n));
    for (0..n) |i| {
        try putU32(&out, a, @intCast(proof.layer_masks_by_instance[i].len));
        try putU32(&out, a, @intCast(proof.output_claims_by_instance[i].len));
        for (proof.output_claims_by_instance[i]) |q| try putQ(&out, a, q);
    }
    try putU32(&out, a, @intCast(proof.sumcheck_proofs.len));
    for (proof.sumcheck_proofs) |sc| {
        try putU32(&out, a, @intCast(sc.round_polys.len));
        for (sc.round_polys) |poly| {
            const coeffs = poly.coeffsSlice();
            if (coeffs.len > sumcheck.MAX_DEGREE + 1) return error.GkrRoundPolyTooLong;
            for (0..sumcheck.MAX_DEGREE + 1) |k| try putQ(&out, a, if (k < coeffs.len) coeffs[k] else QM31.zero());
        }
    }
    for (proof.layer_masks_by_instance) |masks| for (masks) |mask| {
        try putU32(&out, a, @intCast(mask.columns.len));
        for (mask.columns) |col| {
            try putQ(&out, a, col[0]);
            try putQ(&out, a, col[1]);
        }
    };
    return out.toOwnedSlice(a);
}

pub const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    pub fn u32_(self: *Reader) !u32 {
        if (self.at + 4 > self.bytes.len) return error.TruncatedGkrProof;
        const v = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        self.at += 4;
        return v;
    }
    pub fn bounded(self: *Reader, max: usize) !usize {
        const v = try self.u32_();
        if (v > max) return error.GkrProofLimit;
        return v;
    }
    pub fn q(self: *Reader) !QM31 {
        var m: [4]M31 = undefined;
        for (&m) |*x| {
            const v = try self.u32_();
            if (v >= core.fields.m31.Modulus) return error.NonCanonicalField;
            x.* = M31.fromCanonical(v);
        }
        return QM31.fromM31Array(m);
    }
    pub fn take(self: *Reader, n: usize) ![]const u8 {
        if (self.at + n > self.bytes.len) return error.TruncatedGkrProof;
        const out = self.bytes[self.at .. self.at + n];
        self.at += n;
        return out;
    }
};

pub fn decodeGkr(a: std.mem.Allocator, bytes: []const u8) !gkr_verifier.GkrBatchProof {
    var r = Reader{ .bytes = bytes };
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const n = try r.bounded(MAX_INSTANCES);
    const n_masks = try arena.allocator().alloc(usize, n);
    var proof = gkr_verifier.GkrBatchProof{
        .sumcheck_proofs = try a.alloc(sumcheck.SumcheckProof, 0),
        .layer_masks_by_instance = try a.alloc([]gkr_verifier.GkrMask, n),
        .output_claims_by_instance = try a.alloc([]QM31, n),
    };
    for (proof.layer_masks_by_instance) |*m| m.* = try a.alloc(gkr_verifier.GkrMask, 0);
    for (proof.output_claims_by_instance) |*c| c.* = try a.alloc(QM31, 0);
    errdefer proof.deinit(a);
    for (0..n) |i| {
        n_masks[i] = try r.bounded(MAX_LAYERS);
        const nc = try r.bounded(2);
        a.free(proof.output_claims_by_instance[i]);
        proof.output_claims_by_instance[i] = try a.alloc(QM31, nc);
        for (proof.output_claims_by_instance[i]) |*c| c.* = try r.q();
    }
    const n_layers = try r.bounded(MAX_LAYERS);
    a.free(proof.sumcheck_proofs);
    proof.sumcheck_proofs = try a.alloc(sumcheck.SumcheckProof, n_layers);
    for (proof.sumcheck_proofs) |*sc| sc.* = .{ .round_polys = try a.alloc(lookup_utils.UnivariatePoly(QM31), 0) };
    for (proof.sumcheck_proofs) |*sc| {
        const rounds = try r.bounded(MAX_LAYERS);
        a.free(sc.round_polys);
        sc.round_polys = try a.alloc(lookup_utils.UnivariatePoly(QM31), 0);
        var polys = std.ArrayList(lookup_utils.UnivariatePoly(QM31)).empty;
        errdefer {
            for (polys.items) |*p| p.deinit(a);
            polys.deinit(a);
        }
        for (0..rounds) |_| {
            const coeffs = try a.alloc(QM31, sumcheck.MAX_DEGREE + 1);
            errdefer a.free(coeffs);
            for (coeffs) |*c| c.* = try r.q();
            try polys.append(a, lookup_utils.UnivariatePoly(QM31).initOwned(coeffs));
        }
        a.free(sc.round_polys);
        sc.round_polys = try polys.toOwnedSlice(a);
    }
    for (0..n) |i| {
        var masks = std.ArrayList(gkr_verifier.GkrMask).empty;
        errdefer {
            for (masks.items) |*m| m.deinit(a);
            masks.deinit(a);
        }
        for (0..n_masks[i]) |_| {
            const cols = try r.bounded(2);
            const columns = try a.alloc([2]QM31, cols);
            errdefer a.free(columns);
            for (columns) |*col| col.* = .{ try r.q(), try r.q() };
            try masks.append(a, gkr_verifier.GkrMask.initOwned(columns));
        }
        a.free(proof.layer_masks_by_instance[i]);
        proof.layer_masks_by_instance[i] = try masks.toOwnedSlice(a);
    }
    if (r.at != bytes.len) return error.TrailingGkrBytes;
    return proof;
}
