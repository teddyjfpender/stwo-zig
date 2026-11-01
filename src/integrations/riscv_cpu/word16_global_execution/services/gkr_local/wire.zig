//! Distinct bounded OM31 local-child codec. It carries a GKR proof, never an
//! acceptance bit or free terminal claims. The receiver derives terminal claims
//! itself and verifies physical MAIN binding before execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const L = @import("stwo_prover_engine").lookups;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const V = L.gkr_verifier.ForField(O);
const S = L.sumcheck.ForField(O);
const Instance = @import("frame.zig").Instance;
const MAX = @import("receipt.zig").MAX_INSTANCES;
pub const MAGIC = "RV64LGKO";
pub const MAX_BYTES = 16 << 20;
fn u32_(out: *std.ArrayList(u8), a: std.mem.Allocator, value: usize) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, std.math.cast(u32, value) orelse return error.LocalGkrProofLimit, .little);
    try out.appendSlice(a, &bytes);
}
fn field(out: *std.ArrayList(u8), a: std.mem.Allocator, value: O) !void {
    for (value.toM31Array()) |coordinate| {
        if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalLocalGkrCoordinate;
        try u32_(out, a, coordinate.v);
    }
}
pub fn encode(a: std.mem.Allocator, instances: []const Instance, proof: *const V.GkrBatchProof) ![]u8 {
    if (instances.len == 0 or instances.len > MAX or proof.output_claims_by_instance.len != instances.len or proof.layer_masks_by_instance.len != instances.len or proof.sumcheck_proofs.len > 30) return error.LocalGkrReceiptShape;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, MAGIC);
    try u32_(&out, a, 8);
    try u32_(&out, a, instances.len);
    for (instances, proof.layer_masks_by_instance, proof.output_claims_by_instance) |instance, masks, outputs| {
        if (masks.len != try instance.variables() or outputs.len != 2) return error.LocalGkrReceiptShape;
        try u32_(&out, a, masks.len);
        for (outputs) |value| try field(&out, a, value);
    }
    try u32_(&out, a, proof.sumcheck_proofs.len);
    for (proof.sumcheck_proofs) |sumcheck| {
        if (sumcheck.round_polys.len > 30) return error.LocalGkrReceiptShape;
        try u32_(&out, a, sumcheck.round_polys.len);
        for (sumcheck.round_polys) |poly| {
            const coefficients = poly.coeffsSlice();
            if (coefficients.len > 4) return error.LocalGkrReceiptShape;
            // Preserve the EXACT coefficient-vector length mixed by sumcheck.
            // Padding short polynomials would change transcript authority.
            try u32_(&out, a, coefficients.len);
            for (coefficients) |value| try field(&out, a, value);
        }
    }
    for (proof.layer_masks_by_instance) |masks| for (masks) |mask| {
        if (mask.columns.len != 2) return error.LocalGkrReceiptShape;
        for (mask.columns) |pair| for (pair) |value| try field(&out, a, value);
    };
    if (out.items.len > MAX_BYTES) return error.LocalGkrProofLimit;
    return out.toOwnedSlice(a);
}
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn u32_(self: *@This()) !u32 {
        if (self.bytes.len - self.at < 4) return error.TruncatedLocalGkrProof;
        const value = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        self.at += 4;
        return value;
    }
    fn bounded(self: *@This(), max: usize) !usize {
        const value = try self.u32_();
        if (value > max) return error.LocalGkrProofLimit;
        return value;
    }
    fn field(self: *@This()) !O {
        var coordinates: [8]M = undefined;
        for (&coordinates) |*c| {
            const v = try self.u32_();
            if (v >= core.fields.m31.Modulus) return error.NoncanonicalLocalGkrCoordinate;
            c.* = M.fromCanonical(v);
        }
        return O.fromM31Array(coordinates);
    }
};
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    proof: V.GkrBatchProof,
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn decode(a: std.mem.Allocator, instances: []const Instance, bytes: []const u8) !Owned {
    if (bytes.len > MAX_BYTES or instances.len == 0 or instances.len > MAX) return error.LocalGkrProofLimit;
    if (bytes.len < MAGIC.len or !std.mem.eql(u8, bytes[0..MAGIC.len], MAGIC)) return error.LocalGkrWireProfile;
    var r = Reader{ .bytes = bytes, .at = MAGIC.len };
    if (try r.u32_() != 8) return error.LocalGkrWireProfile;
    const count = try r.bounded(MAX);
    if (count != instances.len) return error.LocalGkrReceiptShape;
    var owned = Owned{ .arena = .init(a), .proof = undefined };
    errdefer owned.arena.deinit();
    const allocator = owned.arena.allocator();
    var mask_counts: [MAX]usize = undefined;
    const outputs = try allocator.alloc([]O, count);
    const masks = try allocator.alloc([]V.GkrMask, count);
    for (instances, outputs, 0..) |instance, *pair, i| {
        mask_counts[i] = try r.bounded(30);
        if (mask_counts[i] != try instance.variables()) return error.LocalGkrReceiptShape;
        pair.* = try allocator.alloc(O, 2);
        for (pair.*) |*v| v.* = try r.field();
    }
    const n_layers = try r.bounded(30);
    const sumchecks = try allocator.alloc(S.SumcheckProof, n_layers);
    for (sumchecks) |*sumcheck| {
        const rounds = try r.bounded(30);
        sumcheck.round_polys = try allocator.alloc(L.utils.UnivariatePoly(O), rounds);
        for (sumcheck.round_polys) |*poly| {
            const coefficients = try allocator.alloc(O, try r.bounded(4));
            for (coefficients) |*v| v.* = try r.field();
            // Transcript framing includes the exact declared vector length.
            // initOwned normalizes trailing zeros and would silently change it.
            poly.* = .{ .coeffs = coefficients, .len = coefficients.len };
        }
    }
    for (masks, mask_counts[0..count]) |*instance_masks, n_masks| {
        instance_masks.* = try allocator.alloc(V.GkrMask, n_masks);
        for (instance_masks.*) |*mask| {
            const columns = try allocator.alloc([2]O, 2);
            for (columns) |*pair| pair.* = .{ try r.field(), try r.field() };
            mask.* = V.GkrMask.initOwned(columns);
        }
    }
    if (r.at != bytes.len) return error.TrailingLocalGkrBytes;
    owned.proof = .{ .sumcheck_proofs = sumchecks, .layer_masks_by_instance = masks, .output_claims_by_instance = outputs };
    return owned;
}
