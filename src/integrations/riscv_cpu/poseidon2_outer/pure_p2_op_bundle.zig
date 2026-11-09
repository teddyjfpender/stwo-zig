//! Bounded durable native OP bundle. Receiver-owned Inventory is mandatory;
//! this frame supplies no program, image, key or acceptance authority.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Inventory = @import("pure_p2_op_inventory.zig");
const Manifest = @import("pure_p2_manifest.zig");
const MW = @import("pure_p2_manifest_wire.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
pub const Proof = struct {
    bytes: []u8,
    claims: []O,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const Bundle = struct {
    stage_one: []u8,
    proofs: []Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.proofs) |*proof| proof.deinit(a);
        a.free(self.proofs);
        a.free(self.stage_one);
        self.* = undefined;
    }
    /// Freshly decode/check GKR and every physical proof before zero-sum closure.
    pub fn verify(self: *const Bundle, a: std.mem.Allocator, inventory: *const Inventory.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inventory.MillerDeclaration) !void {
        if (setups.len != inventory.cpu_count or requests.len != setups.len or keys.len != setups.len or spans.len != setups.len or truths.len != inventory.truth_count or truths.len != truth_keys.len or self.proofs.len != inventory.workers.len or setups.len + truths.len + miller.len != self.proofs.len) return error.InvalidOpNativeBundle;
        var stages = try MW.decode(a, inventory.execution, inventory.workers, self.stage_one);
        defer stages.deinit();
        var pending = try stages.verifyAndSeal(a, inventory.execution, inventory.workers);
        defer pending.deinit(a);
        const claims = try a.alloc(Manifest.Claims, self.proofs.len);
        defer a.free(claims);
        for (setups, requests, spans, keys, 0..) |setup, request, span, key, i| {
            const proof = CPU.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims };
            claims[i] = try CPU.verifyForOp(a, setup, request, span, inventory.workers[i], inventory.first_ids[i], &pending, i, key, &proof, null);
        }
        for (truths, truth_keys, 0..) |truth, key, j| {
            const i = setups.len + j;
            const proof = Truth.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims };
            claims[i] = try Truth.verify(a, key, truth, inventory.workers[i], &pending, i, &proof);
        }
        for (miller, 0..) |item, j| {
            const i = setups.len + truths.len + j;
            if (self.proofs[i].claims.len != 4) return error.InvalidOpNativeBundle;
            const proof = Miller.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims[0..4].* };
            claims[i] = try Miller.verify(a, item.key, item.span, inventory.workers[i], &pending, i, &proof);
        }
        try pending.checkGlobalClosure(claims);
    }
};
const MAGIC = "OPP2B001";
pub const Limits = struct { bytes: usize, proof_bytes: usize, claims: usize = 4096 };
const Reader = struct {
    data: []const u8,
    at: usize = 0,
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.data.len - self.at) return error.TruncatedOpNativeBundle;
        const out = self.data[self.at..][0..n];
        self.at += n;
        return out;
    }
    fn word(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
};
fn word(a: std.mem.Allocator, out: *std.ArrayList(u8), n: usize) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, std.math.cast(u32, n) orelse return error.OpNativeBundleLimit, .little);
    try out.appendSlice(a, &bytes);
}
pub fn encode(a: std.mem.Allocator, bundle: *const Bundle, limits: Limits) ![]u8 {
    if (bundle.proofs.len == 0 or bundle.proofs.len > Manifest.MAX_WORKERS or bundle.stage_one.len > MW.MAX_BYTES) return error.OpNativeBundleLimit;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.appendSlice(a, MAGIC);
    try word(a, &out, bundle.proofs.len);
    try word(a, &out, bundle.stage_one.len);
    try out.appendSlice(a, bundle.stage_one);
    for (bundle.proofs) |proof| {
        if (proof.bytes.len == 0 or proof.bytes.len > limits.proof_bytes or proof.claims.len > limits.claims) return error.OpNativeBundleLimit;
        try word(a, &out, proof.claims.len);
        try word(a, &out, proof.bytes.len);
        for (proof.claims) |claim| for (claim.toM31Array()) |v| {
            if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalOpNativeClaim;
            try word(a, &out, v.v);
        };
        try out.appendSlice(a, proof.bytes);
        if (out.items.len > limits.bytes) return error.OpNativeBundleLimit;
    }
    return out.toOwnedSlice(a);
}
/// Validate ALL lengths, count, canonical claims and trailing bytes before any
/// owned allocation. The caller's complete source inventory fixes proof count.
fn preflight(bytes: []const u8, count: usize, limits: Limits) !void {
    if (bytes.len > limits.bytes or count == 0 or count > Manifest.MAX_WORKERS) return error.OpNativeBundleLimit;
    var r = Reader{ .data = bytes };
    if (!std.mem.eql(u8, try r.take(MAGIC.len), MAGIC) or try r.word() != count) return error.InvalidOpNativeBundle;
    const stage = try r.word();
    if (stage > MW.MAX_BYTES) return error.OpNativeBundleLimit;
    _ = try r.take(stage);
    for (0..count) |_| {
        const claims = try r.word();
        const n = try r.word();
        if (claims > limits.claims or n == 0 or n > limits.proof_bytes) return error.OpNativeBundleLimit;
        for (0..claims * 8) |_| if (try r.word() >= core.fields.m31.Modulus) return error.NoncanonicalOpNativeClaim;
        _ = try r.take(n);
    }
    if (r.at != bytes.len) return error.TrailingOpNativeBundle;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, count: usize, limits: Limits) !Bundle {
    try preflight(bytes, count, limits);
    var r = Reader{ .data = bytes };
    _ = try r.take(MAGIC.len);
    _ = try r.word();
    const stage = try r.word();
    const stage_one = try a.dupe(u8, try r.take(stage));
    errdefer a.free(stage_one);
    const proofs = try a.alloc(Proof, count);
    errdefer a.free(proofs);
    var done: usize = 0;
    errdefer for (proofs[0..done]) |*proof| proof.deinit(a);
    for (proofs) |*proof| {
        const claim_count = try r.word();
        const n = try r.word();
        const claims = try a.alloc(O, claim_count);
        errdefer a.free(claims);
        for (claims) |*claim| {
            var coordinates: [8]M = undefined;
            for (&coordinates) |*v| v.* = M.fromCanonical(try r.word());
            claim.* = O.fromM31Array(coordinates);
        }
        const data = try a.dupe(u8, try r.take(n));
        proof.* = .{ .bytes = data, .claims = claims };
        done += 1;
    }
    return .{ .stage_one = stage_one, .proofs = proofs };
}
