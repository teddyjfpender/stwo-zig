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
const TruthLocal = @import("truth_local_gkr/worker.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const MillerLocal = @import("miller_local_gkr/worker.zig");
const SuiteWire = @import("pure_p2_source_suite.zig");
const Suite = SuiteWire.Suite;
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
pub const Capture = core.pcs.ForField(O).verifier.VerifiedProofCapture(@import("pure_p2_worker_protocol.zig").W.H);
/// All callback views are borrowed until callback return. They authenticate one
/// fragment only: durable leaf outputs are pending until whole closure/terminal.
pub const CpuVerified = struct {
    setup: *const R.CpuSetup,
    request: P.Request,
    span: T.OpTowerSpan,
    first_ids: [T.FAMILIES]u32,
    key: *const Key,
    expected: Manifest.Expected,
    manifest: *const Manifest.Pending,
    ordinal: usize,
    encoded: *const CPU.Encoded,
    capture: *const Capture,
    stage_one: Manifest.StageOne,
};
pub const TruthVerified = struct {
    truth: R.Truth,
    key: *const Truth.Key,
    expected: Manifest.Expected,
    manifest: *const Manifest.Pending,
    ordinal: usize,
    encoded: *const Truth.Encoded,
    capture: *const Capture,
    stage_one: Manifest.StageOne,
};
pub const LocalTruthVerified = struct {
    truth: R.Truth,
    key: *const TruthLocal.Key,
    expected: Manifest.Expected,
    manifest: *const Manifest.Pending,
    ordinal: usize,
    encoded: *const TruthLocal.Encoded,
    capture: *const Capture,
    stage_one: Manifest.StageOne,
};
pub const MillerVerified = struct {
    span: Miller.Span,
    key: *const Miller.Key,
    expected: Manifest.Expected,
    manifest: *const Manifest.Pending,
    ordinal: usize,
    encoded: *const Miller.Encoded,
    capture: *const Capture,
    stage_one: Manifest.StageOne,
};
pub const MillerLocalVerified = struct {
    span: MillerLocal.Span,
    key: *const MillerLocal.Key,
    expected: Manifest.Expected,
    manifest: *const Manifest.Pending,
    ordinal: usize,
    encoded: *const MillerLocal.Encoded,
    capture: *const Capture,
    stage_one: Manifest.StageOne,
};
pub const Hooks = struct {
    context: ?*anyopaque = null,
    cpu: ?*const fn (?*anyopaque, std.mem.Allocator, CpuVerified) anyerror!void = null,
    truth: ?*const fn (?*anyopaque, std.mem.Allocator, TruthVerified) anyerror!void = null,
    truth_local: ?*const fn (?*anyopaque, std.mem.Allocator, LocalTruthVerified) anyerror!void = null,
    miller: ?*const fn (?*anyopaque, std.mem.Allocator, MillerVerified) anyerror!void = null,
    miller_local: ?*const fn (?*anyopaque, std.mem.Allocator, MillerLocalVerified) anyerror!void = null,
};
/// Complete native closure, still pending the application's independently
/// expected terminal/output policy. Owns all stage-one/local proof custody.
pub const Closed = struct {
    stages: MW.Owned,
    manifest: Manifest.Pending,
    claims: []Manifest.Claims,
    pub fn deinit(self: *Closed, a: std.mem.Allocator) void {
        a.free(self.claims);
        self.manifest.deinit(a);
        self.stages.deinit();
        self.* = undefined;
    }
};
pub const Bundle = struct {
    source_suite: ?Suite = null,
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
        var closed = try self.verifyWithHooks(a, inventory, setups, requests, spans, keys, truths, truth_keys, miller, .{});
        defer closed.deinit(a);
    }
    pub fn verifyWithHooks(self: *const Bundle, a: std.mem.Allocator, inventory: *const Inventory.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inventory.MillerDeclaration, hooks: Hooks) !Closed {
        if (inventory.truth_local_keys.len != 0) return error.OpTruthLocalRequiresExplicitReceiver;
        return self.verifyWithHooksForTruthLocal(a, inventory, setups, requests, spans, keys, truths, truth_keys, miller, hooks);
    }
    pub fn verifyWithHooksForTruthLocal(self: *const Bundle, a: std.mem.Allocator, inventory: *const Inventory.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inventory.MillerDeclaration, hooks: Hooks) !Closed {
        if (inventory.source_suite != null or self.source_suite != null) return error.OpSourceSuiteRequiresExplicitReceiver;
        return self.verifyImpl(a, inventory, setups, requests, spans, keys, truths, truth_keys, miller, hooks);
    }
    pub fn verifyWithHooksForSourceSuite(self: *const Bundle, a: std.mem.Allocator, inventory: *const Inventory.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inventory.MillerDeclaration, expected_suite: Suite, hooks: Hooks) !Closed {
        const selected = inventory.source_suite orelse return error.OpSourceSuiteRequiresExplicitReceiver;
        try selected.requireExpected(expected_suite);
        try (self.source_suite orelse return error.OpSourceSuitePolicyMismatch).requireExpected(expected_suite);
        return self.verifyImpl(a, inventory, setups, requests, spans, keys, truths, truth_keys, miller, hooks);
    }
    fn verifyImpl(self: *const Bundle, a: std.mem.Allocator, inventory: *const Inventory.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inventory.MillerDeclaration, hooks: Hooks) !Closed {
        if (inventory.truth_local_keys.len != 0 and inventory.truth_local_keys.len != truths.len) return error.InvalidOpTruthLocalInventory;
        if (setups.len != inventory.cpu_count or requests.len != setups.len or keys.len != setups.len or spans.len != setups.len or truths.len != inventory.truth_count or truths.len != truth_keys.len or self.proofs.len != inventory.workers.len or setups.len + truths.len + miller.len != self.proofs.len) return error.InvalidOpNativeBundle;
        var stages = try MW.decode(a, inventory.execution, inventory.workers, self.stage_one);
        errdefer stages.deinit();
        var pending = try stages.verifyAndSeal(a, inventory.execution, inventory.workers);
        errdefer pending.deinit(a);
        const claims = try a.alloc(Manifest.Claims, self.proofs.len);
        errdefer a.free(claims);
        for (setups, requests, spans, keys, 0..) |setup, request, span, key, i| {
            const proof = CPU.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims };
            if (hooks.cpu) |hook| {
                var capture: Capture = undefined;
                claims[i] = try CPU.verifyForOp(a, setup, request, span, inventory.workers[i], inventory.first_ids[i], &pending, i, key, &proof, &capture);
                defer capture.deinit(a);
                try hook(hooks.context, a, .{ .setup = setup, .request = request, .span = span, .first_ids = inventory.first_ids[i], .key = key, .expected = inventory.workers[i], .manifest = &pending, .ordinal = i, .encoded = &proof, .capture = &capture, .stage_one = stages.stages[i] });
            } else claims[i] = try CPU.verifyForOp(a, setup, request, span, inventory.workers[i], inventory.first_ids[i], &pending, i, key, &proof, null);
        }
        for (truths, truth_keys, 0..) |truth, key, j| {
            const i = setups.len + j;
            if (if (inventory.truth_local_keys.len == 0) null else inventory.truth_local_keys[j]) |local_key| {
                var local = try TruthLocal.decode(a, self.proofs[i].bytes, self.proofs[i].bytes.len);
                defer local.deinit(a);
                if (self.proofs[i].claims.len != 2 or !std.meta.eql(self.proofs[i].claims[0..2].*, local.claims)) return error.OpTruthLocalClaimEnvelope;
                if (hooks.truth_local) |hook| {
                    var capture: Capture = undefined;
                    claims[i] = try TruthLocal.verifyWithCapture(a, local_key, truth, inventory.workers[i], &pending, i, &local, &capture);
                    defer capture.deinit(a);
                    try hook(hooks.context, a, .{ .truth = truth, .key = local_key, .expected = inventory.workers[i], .manifest = &pending, .ordinal = i, .encoded = &local, .capture = &capture, .stage_one = stages.stages[i] });
                } else claims[i] = try TruthLocal.verify(a, local_key, truth, inventory.workers[i], &pending, i, &local);
                continue;
            }
            const proof = Truth.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims };
            if (hooks.truth) |hook| {
                var capture: Capture = undefined;
                claims[i] = try Truth.verifyWithCapture(a, key, truth, inventory.workers[i], &pending, i, &proof, &capture);
                defer capture.deinit(a);
                try hook(hooks.context, a, .{ .truth = truth, .key = key, .expected = inventory.workers[i], .manifest = &pending, .ordinal = i, .encoded = &proof, .capture = &capture, .stage_one = stages.stages[i] });
            } else claims[i] = try Truth.verify(a, key, truth, inventory.workers[i], &pending, i, &proof);
        }
        for (miller, 0..) |item, j| {
            const i = setups.len + truths.len + j;
            if (item.local_key) |local_key| {
                const suite = inventory.source_suite orelse return error.OpSourceSuiteRequiresExplicitReceiver;
                if (suite.miller != .local_gkr) return error.OpMillerSourceSuitePolicy;
                var local = try MillerLocal.decode(a, self.proofs[i].bytes, self.proofs[i].bytes.len);
                defer local.deinit(a);
                if (self.proofs[i].claims.len != 2 or !std.meta.eql(self.proofs[i].claims[0..2].*, local.claims)) return error.OpMillerLocalClaimEnvelope;
                if (hooks.miller_local) |hook| {
                    var capture: Capture = undefined;
                    claims[i] = try MillerLocal.verifyWithCapture(a, local_key, item.span, inventory.workers[i], &pending, i, &local, &capture);
                    defer capture.deinit(a);
                    try hook(hooks.context, a, .{ .span = item.span, .key = local_key, .expected = inventory.workers[i], .manifest = &pending, .ordinal = i, .encoded = &local, .capture = &capture, .stage_one = stages.stages[i] });
                } else claims[i] = try MillerLocal.verify(a, local_key, item.span, inventory.workers[i], &pending, i, &local);
                continue;
            }
            if (inventory.source_suite) |suite| if (suite.miller != .classic) return error.OpMillerSourceSuitePolicy;
            if (self.proofs[i].claims.len != 4) return error.InvalidOpNativeBundle;
            const proof = Miller.Encoded{ .bytes = self.proofs[i].bytes, .claims = self.proofs[i].claims[0..4].* };
            if (hooks.miller) |hook| {
                var capture: Capture = undefined;
                claims[i] = try Miller.verifyWithCapture(a, item.key, item.span, inventory.workers[i], &pending, i, &proof, &capture);
                defer capture.deinit(a);
                try hook(hooks.context, a, .{ .span = item.span, .key = item.key, .expected = inventory.workers[i], .manifest = &pending, .ordinal = i, .encoded = &proof, .capture = &capture, .stage_one = stages.stages[i] });
            } else claims[i] = try Miller.verify(a, item.key, item.span, inventory.workers[i], &pending, i, &proof);
        }
        try pending.checkGlobalClosure(claims);
        return .{ .stages = stages, .manifest = pending, .claims = claims };
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
    if (bundle.source_suite != null) return error.OpSourceSuiteRequiresExplicitEncoder;
    return encodeImpl(a, bundle, limits, null);
}
pub fn encodeForSuite(a: std.mem.Allocator, bundle: *const Bundle, limits: Limits, expected_suite: Suite) ![]u8 {
    try (bundle.source_suite orelse return error.OpSourceSuitePolicyMismatch).requireExpected(expected_suite);
    return encodeImpl(a, bundle, limits, expected_suite);
}
fn encodeImpl(a: std.mem.Allocator, bundle: *const Bundle, limits: Limits, source_suite: ?Suite) ![]u8 {
    if (bundle.proofs.len == 0 or bundle.proofs.len > Manifest.MAX_WORKERS or bundle.stage_one.len > MW.MAX_BYTES) return error.OpNativeBundleLimit;
    // Determine the complete wire size before acquiring a potentially large
    // buffer. Grow-and-copy would retain two block-sized buffers transiently.
    var size = try std.math.add(usize, MAGIC.len + 8 + (if (source_suite != null) @as(usize, SuiteWire.BYTES) else 0), bundle.stage_one.len);
    for (bundle.proofs) |proof| {
        if (proof.bytes.len == 0 or proof.bytes.len > limits.proof_bytes or proof.claims.len > limits.claims or proof.bytes.len > std.math.maxInt(u32) or proof.claims.len > std.math.maxInt(u32)) return error.OpNativeBundleLimit;
        const claim_bytes = try std.math.mul(usize, proof.claims.len, 8 * @sizeOf(u32));
        size = try std.math.add(usize, size, try std.math.add(usize, 8, try std.math.add(usize, claim_bytes, proof.bytes.len)));
        if (size > limits.bytes) return error.OpNativeBundleLimit;
        for (proof.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalOpNativeClaim;
    }
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    try out.ensureTotalCapacityPrecise(a, size);
    try out.appendSlice(a, if (source_suite != null) SuiteWire.WIRE_MAGIC else MAGIC);
    if (source_suite) |suite| try out.appendSlice(a, &try suite.encode());
    try word(a, &out, bundle.proofs.len);
    try word(a, &out, bundle.stage_one.len);
    try out.appendSlice(a, bundle.stage_one);
    for (bundle.proofs) |proof| {
        try word(a, &out, proof.claims.len);
        try word(a, &out, proof.bytes.len);
        for (proof.claims) |claim| for (claim.toM31Array()) |v| {
            try word(a, &out, v.v);
        };
        try out.appendSlice(a, proof.bytes);
    }
    std.debug.assert(out.items.len == size);
    return out.toOwnedSlice(a);
}
/// Validate ALL lengths, count, canonical claims and trailing bytes before any
/// owned allocation. The caller's complete source inventory fixes proof count.
fn preflight(bytes: []const u8, count: usize, limits: Limits, source_suite: ?Suite) !void {
    if (bytes.len > limits.bytes or count == 0 or count > Manifest.MAX_WORKERS) return error.OpNativeBundleLimit;
    var r = Reader{ .data = bytes };
    if (!std.mem.eql(u8, try r.take(MAGIC.len), if (source_suite != null) SuiteWire.WIRE_MAGIC else MAGIC)) return error.InvalidOpNativeBundle;
    if (source_suite) |suite| try (try Suite.decode((try r.take(SuiteWire.BYTES))[0..SuiteWire.BYTES].*)).requireExpected(suite);
    if (try r.word() != count) return error.InvalidOpNativeBundle;
    const stage = try r.word();
    if (stage > MW.MAX_BYTES) return error.OpNativeBundleLimit;
    _ = try r.take(stage);
    for (0..count) |_| {
        const claims = try r.word();
        const n = try r.word();
        if (claims > limits.claims or n == 0 or n > limits.proof_bytes) return error.OpNativeBundleLimit;
        const coordinates = try std.math.mul(usize, claims, 8);
        const claim_words = try r.take(try std.math.mul(usize, coordinates, 4));
        for (0..coordinates) |j| if (std.mem.readInt(u32, claim_words[4 * j ..][0..4], .little) >= core.fields.m31.Modulus) return error.NoncanonicalOpNativeClaim;
        _ = try r.take(n);
    }
    if (r.at != bytes.len) return error.TrailingOpNativeBundle;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, count: usize, limits: Limits) !Bundle {
    return decodeImpl(a, bytes, count, limits, null);
}
pub fn decodeForSuite(a: std.mem.Allocator, bytes: []const u8, count: usize, limits: Limits, expected_suite: Suite) !Bundle {
    try expected_suite.validate();
    return decodeImpl(a, bytes, count, limits, expected_suite);
}
fn decodeImpl(a: std.mem.Allocator, bytes: []const u8, count: usize, limits: Limits, source_suite: ?Suite) !Bundle {
    try preflight(bytes, count, limits, source_suite);
    var r = Reader{ .data = bytes };
    _ = try r.take(MAGIC.len);
    if (source_suite != null) _ = try r.take(SuiteWire.BYTES);
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
    return .{ .stage_one = stage_one, .proofs = proofs, .source_suite = source_suite };
}

test "OP bundle encoding preflights the whole byte cap before allocation" {
    const a = std.testing.allocator;
    var claim = [_]O{O.one()};
    var payload = [_]u8{ 1, 2, 3 };
    var stage = [_]u8{0x81};
    var proofs = [_]Proof{.{ .bytes = &payload, .claims = &claim }};
    const bundle = Bundle{ .stage_one = &stage, .proofs = &proofs };
    const limits = Limits{ .bytes = 60, .proof_bytes = 3, .claims = 1 };
    try std.testing.expectError(error.OpNativeBundleLimit, encode(std.testing.failing_allocator, &bundle, .{ .bytes = 59, .proof_bytes = 3, .claims = 1 }));
    try std.testing.expectError(error.OpNativeBundleLimit, encode(std.testing.failing_allocator, &bundle, .{ .bytes = 60, .proof_bytes = 2, .claims = 1 }));
    try std.testing.expectError(error.OpNativeBundleLimit, encode(std.testing.failing_allocator, &bundle, .{ .bytes = 60, .proof_bytes = 3, .claims = 0 }));
    const wire = try encode(a, &bundle, limits);
    defer a.free(wire);
    try std.testing.expectEqual(@as(usize, 60), wire.len);
    var decoded = try decode(a, wire, 1, limits);
    defer decoded.deinit(a);
    try std.testing.expectEqualSlices(u8, &stage, decoded.stage_one);
    try std.testing.expectEqualSlices(u8, &payload, decoded.proofs[0].bytes);
    try std.testing.expect(decoded.proofs[0].claims[0].eql(claim[0]));
}

fn suiteCodecAllocations(a: std.mem.Allocator, bundle: *const Bundle, suite: Suite) !void {
    const wire = try encodeForSuite(a, bundle, .{ .bytes = 4096, .proof_bytes = 4096 }, suite);
    defer a.free(wire);
    var received = try decodeForSuite(a, wire, 1, .{ .bytes = 4096, .proof_bytes = 4096 }, suite);
    defer received.deinit(a);
    try std.testing.expectEqualDeep(suite, received.source_suite.?);
    try std.testing.expectEqualSlices(u8, bundle.proofs[0].bytes, received.proofs[0].bytes);
}
test "OP source suite bundle requires independent version policy before allocation" {
    const a = std.testing.allocator;
    var claim = [_]O{O.one()};
    var payload = [_]u8{ 1, 2, 3 };
    var stage = [_]u8{0x81};
    var proofs = [_]Proof{.{ .bytes = &payload, .claims = &claim }};
    const suite = Suite.millerGkr();
    const bundle = Bundle{ .source_suite = suite, .stage_one = &stage, .proofs = &proofs };
    try std.testing.checkAllAllocationFailures(a, suiteCodecAllocations, .{ &bundle, suite });
    const limits = Limits{ .bytes = 4096, .proof_bytes = 4096 };
    try std.testing.expectError(error.OpSourceSuiteRequiresExplicitEncoder, encode(std.testing.failing_allocator, &bundle, limits));
    const wire = try encodeForSuite(a, &bundle, limits, suite);
    defer a.free(wire);
    try std.testing.expectEqual(@as(usize, 80), wire.len);
    try std.testing.expectError(error.InvalidOpNativeBundle, decode(std.testing.failing_allocator, wire, 1, limits));
    try std.testing.expectError(error.OpSourceSuitePolicyMismatch, decodeForSuite(std.testing.failing_allocator, wire, 1, limits, Suite{}));
    var bad = try a.dupe(u8, wire);
    defer a.free(bad);
    std.mem.writeInt(u32, bad[8..12], 2, .little);
    try std.testing.expectError(error.UnsupportedOpSourceSuite, decodeForSuite(std.testing.failing_allocator, bad, 1, limits, suite));
    try std.testing.expectError(error.TruncatedOpNativeBundle, decodeForSuite(std.testing.failing_allocator, wire[0..20], 1, limits, suite));
}
