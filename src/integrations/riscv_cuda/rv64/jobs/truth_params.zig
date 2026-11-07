//! Truth kernel parameters assembled ON DEVICE (GPU-native TruthJob).
//!
//! Every truth kernel (witness projection, composition role) reads its
//! parameters from the 43-slot "semantic" vector of truth_codegen
//! (`nativeMetadata` / `nativeMetadataV3`): span (calls, first id,
//! non-empty), the proof-local challenges, the shared kio/wire challenges and
//! the role's claims. On the legacy path that vector is built on the host
//! from host challenges. Here the challenges and claims never leave the
//! device, so a parameter list is a GATHER PROGRAM: one `Entry` per kernel
//! parameter naming its source buffer and felt index:
//!
//!   staged  per-job constant felts (zero, one, then per role calls/first/nonempty)
//!   local   the local challenge buffer (truth_challenges layout)
//!   shared  the shared challenge buffer (truth_challenges layout)
//!   claim   the job's claims buffer (5 felts classic, 1 delegated)
//!
//! `NAT/rv64/jobs/truth_ops.cu` `stwo_rv64_truth_params_gather_v1_on` runs a
//! program (one launch per parameter list, enqueue only) and `gather` below is
//! its host model. The tests pin both programs to the legacy metadata
//! functions on random inputs, so a gathered parameter is the legacy value by
//! construction.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const T = @import("../truth_codegen.zig");
const X = @import("truth_challenges.zig");

const O = X.O;
const M = core.fields.m31.M31;
pub const semantic_count = T.slots.count;

pub const Source = enum(u32) { staged = 0, local = 1, shared = 2, claim = 3 };
/// Device ABI (NAT/rv64/jobs/truth_ops.cu): 8 bytes per parameter.
pub const Entry = extern struct { source: u32, index: u32 };
comptime {
    if (@sizeOf(Entry) != 8) @compileError("truth parameter entry ABI");
}

/// Staged constant felts of one job: [0] zero, [1] one, then per role
/// r: [2 + 3r] calls, [3 + 3r] first id, [4 + 3r] non-empty.
pub const staged_zero: u32 = 0;
pub const staged_one: u32 = 1;
pub fn stagedSpan(role: u32, k: u32) u32 {
    return 2 + 3 * role + k;
}
pub fn stagedFelts(roles: u32) u32 {
    return 2 + 3 * roles;
}

/// One role's span (legacy: crypto roles carry the truth's calls/first id,
/// table roles calls 0 / first id 1).
pub const Span = struct { calls: u32, first_id: u32 };

/// Per-job staged felt words (8 per felt) for `spans` (one per role).
pub fn stageConstants(spans: []const Span, out: []u32) !void {
    const n = stagedFelts(@intCast(spans.len));
    if (out.len < @as(usize, n) * 8) return error.TruthParamStageTooSmall;
    @memset(out[0 .. @as(usize, n) * 8], 0);
    out[8] = 1; // one
    for (spans, 0..) |s, r| {
        const base = 8 * @as(usize, stagedSpan(@intCast(r), 0));
        if (s.calls >= core.fields.m31.Modulus or s.first_id >= core.fields.m31.Modulus) return error.NoncanonicalTruthSpan;
        out[base] = s.calls;
        out[base + 8] = s.first_id;
        out[base + 16] = @intFromBool(s.calls != 0);
    }
}

pub const Role = union(enum) {
    /// Classic (keccak) role `index` of 3 (keccak, chi, xor5). `claims`:
    /// false for the witness projection (legacy builds it with zero claims),
    /// true for the composition role (claim = claims[index], global claim =
    /// claims[3] on role 0).
    classic: struct { index: u32, claims: bool },
    /// The single delegated (v3) role; `claims` as above (claim = claims[0]).
    delegated: struct { claims: bool },
};

fn zero() Entry {
    return .{ .source = @intFromEnum(Source.staged), .index = staged_zero };
}
fn of(source: Source, index: u32) Entry {
    return .{ .source = @intFromEnum(source), .index = index };
}

/// Source of semantic slot `slot` of `role`.
pub fn semanticSource(role: Role, slot: u32) !Entry {
    if (slot >= semantic_count) return error.InvalidTruthParameterSlot;
    const r: u32 = switch (role) {
        .classic => |c| c.index,
        .delegated => 0,
    };
    if (slot < 3) return of(.staged, stagedSpan(r, slot));
    if (slot >= T.slots.wire and slot < T.slots.claim) return of(.shared, X.wire_first + (slot - T.slots.wire));
    switch (role) {
        .classic => |c| {
            if (c.index >= 3) return error.InvalidTruthParameterSlot;
            if (slot == T.slots.polynomial) return of(.local, 0);
            if (slot >= T.slots.offsets and slot < T.slots.coefficients) return of(.local, X.classicOffset(slot - T.slots.offsets));
            if (slot >= T.slots.coefficients and slot < T.slots.kio) {
                const k = slot - T.slots.coefficients;
                const relation = k / 6;
                const j = k % 6;
                if (X.classicCoefficient(relation, j)) |i| return of(.local, i);
                return if (relation == 2 and j == 0) of(.staged, staged_one) else zero();
            }
            if (slot >= T.slots.kio and slot < T.slots.wire) return of(.shared, X.kio_first + (slot - T.slots.kio));
            if (slot == T.slots.claim) return if (c.claims) of(.claim, c.index) else zero();
            if (slot == T.slots.global_claim) return if (c.claims and c.index == 0) of(.claim, 3) else zero();
        },
        .delegated => |d| {
            if (slot == T.slots.polynomial) return of(.local, 0);
            if (slot == T.slots.claim) return if (d.claims) of(.claim, 0) else zero();
            return zero();
        },
    }
    return error.InvalidTruthParameterSlot;
}

/// The gather program of one parameter list: `parameter_slots[i]` is the
/// semantic slot of kernel parameter i (artifact.parameter_slots).
pub fn program(a: std.mem.Allocator, role: Role, parameter_slots: []const u32) ![]Entry {
    const out = try a.alloc(Entry, parameter_slots.len);
    errdefer a.free(out);
    for (out, parameter_slots) |*e, slot| e.* = try semanticSource(role, slot);
    return out;
}

/// Felt counts of the four sources (bounds the device kernel checks).
pub const Bounds = struct { staged: u32, local: u32, shared: u32 = X.shared_felts, claim: u32 };

pub fn validate(entries: []const Entry, bounds: Bounds) !void {
    for (entries) |e| {
        const limit: u32 = switch (std.meta.intToEnum(Source, e.source) catch return error.InvalidTruthParameterSource) {
            .staged => bounds.staged,
            .local => bounds.local,
            .shared => bounds.shared,
            .claim => bounds.claim,
        };
        if (e.index >= limit) return error.TruthParameterOutOfRange;
    }
}

/// Host model of the device gather (8 words per felt).
pub fn gather(entries: []const Entry, sources: [4][]const u32, out: []u32) !void {
    if (out.len < entries.len * 8) return error.TruthParamOutputTooSmall;
    for (entries, 0..) |e, i| {
        const src = sources[e.source];
        if ((@as(usize, e.index) + 1) * 8 > src.len) return error.TruthParameterOutOfRange;
        @memcpy(out[8 * i ..][0..8], src[8 * @as(usize, e.index) ..][0..8]);
    }
}

// ---------------------------------------------------------------------------
// Tests: programs reproduce the legacy metadata on random inputs.
// ---------------------------------------------------------------------------

fn randomFelt(r: std.Random) O {
    var limbs: [8]M = undefined;
    for (&limbs) |*l| l.* = M.fromCanonical(r.uintLessThan(u32, core.fields.m31.Modulus));
    return O.fromM31Array(limbs);
}
fn feltWords(values: []const O, out: []u32) void {
    for (values, 0..) |v, i| @memcpy(out[8 * i ..][0..8], &X.words(v));
}

const Inputs = struct {
    local_felts: [X.classic_felts]O,
    shared_felts: [X.shared_felts]O,
    claims: [5]O,
    fn init(r: std.Random) Inputs {
        var self: Inputs = undefined;
        for (&self.local_felts) |*v| v.* = randomFelt(r);
        for (&self.shared_felts) |*v| v.* = randomFelt(r);
        for (&self.claims) |*v| v.* = randomFelt(r);
        return self;
    }
};

fn checkRole(role: Role, legacy: [semantic_count]O, in: *const Inputs, spans: []const Span) !void {
    var all: [semantic_count]u32 = undefined;
    for (&all, 0..) |*s, i| s.* = @intCast(i);
    const entries = try program(std.testing.allocator, role, &all);
    defer std.testing.allocator.free(entries);
    var staged: [8 * 11]u32 = undefined;
    try stageConstants(spans, &staged);
    var local: [8 * X.classic_felts]u32 = undefined;
    var shared: [8 * X.shared_felts]u32 = undefined;
    var claims: [8 * 5]u32 = undefined;
    feltWords(&in.local_felts, &local);
    feltWords(&in.shared_felts, &shared);
    feltWords(&in.claims, &claims);
    try validate(entries, .{ .staged = stagedFelts(@intCast(spans.len)), .local = X.classic_felts, .claim = 5 });
    var got: [8 * semantic_count]u32 = undefined;
    try gather(entries, .{ &staged, &local, &shared, &claims }, &got);
    for (legacy, 0..) |v, slot| {
        const want = X.words(v);
        if (!std.mem.eql(u32, &want, got[8 * slot ..][0..8])) {
            std.debug.print("truth param mismatch role={any} slot={}\n", .{ role, slot });
            return error.TestTruthParamMismatch;
        }
    }
}

test "classic gather programs equal truth_codegen.nativeMetadata (projection and composition)" {
    var prng = std.Random.DefaultPrng.init(0x7472_7574);
    const r = prng.random();
    for (0..8) |_| {
        const in = Inputs.init(r);
        const local = try X.classicFrom(&in.local_felts);
        const shared = try X.sharedFrom(&in.shared_felts);
        const calls = r.uintLessThan(u32, 1 << 20);
        const first = 1 + r.uintLessThan(u32, 1 << 20);
        const spans = [3]Span{ .{ .calls = calls, .first_id = first }, .{ .calls = 0, .first_id = 1 }, .{ .calls = 0, .first_id = 1 } };
        const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
        for (kinds, 0..) |kind, i| for ([_]bool{ false, true }) |with_claims| {
            const claim = if (with_claims) in.claims[i] else O.zero();
            const global = if (with_claims and i == 0) in.claims[3] else O.zero();
            const c = T.Role.Component{ .kind = kind, .log_size = 8, .calls = spans[i].calls, .first_id = spans[i].first_id, .keccak_policy = .triple_v2, .local = local, .shared = shared, .claim = claim, .global_claim = global, .split = 2 };
            try checkRole(.{ .classic = .{ .index = @intCast(i), .claims = with_claims } }, T.nativeMetadata(&c), &in, &spans);
        };
    }
}

test "delegated gather program equals truth_codegen.nativeMetadataV3" {
    var prng = std.Random.DefaultPrng.init(0x7633);
    const r = prng.random();
    const Truth = CPU.rv64_services_roster.Truth;
    for (0..8) |_| {
        const in = Inputs.init(r);
        const shared = try X.sharedFrom(&in.shared_felts);
        const calls = 1 + r.uintLessThan(u32, 1 << 16);
        const first = 1 + r.uintLessThan(u32, 1 << 16);
        // count()/first() read only the span fields (no setup dereference).
        const truth = Truth{ .sha256 = .{ .setup = undefined, .first_id = first, .calls = calls } };
        for ([_]bool{ false, true }) |with_claims| {
            const c = T.V3Role.Component{ .truth = truth, .wire = shared.wire, .bytes = in.local_felts[0], .claim = if (with_claims) in.claims[0] else O.zero() };
            try checkRole(.{ .delegated = .{ .claims = with_claims } }, T.nativeMetadataV3(&c), &in, &.{.{ .calls = calls, .first_id = first }});
        }
    }
}

test "programs refuse out-of-range sources and noncanonical spans" {
    const bad = [_]Entry{.{ .source = 1, .index = 16 }};
    try std.testing.expectError(error.TruthParameterOutOfRange, validate(&bad, .{ .staged = 5, .local = 16, .claim = 5 }));
    const unknown = [_]Entry{.{ .source = 7, .index = 0 }};
    try std.testing.expectError(error.InvalidTruthParameterSource, validate(&unknown, .{ .staged = 5, .local = 16, .claim = 5 }));
    var out: [40]u32 = undefined;
    try std.testing.expectError(error.NoncanonicalTruthSpan, stageConstants(&.{.{ .calls = core.fields.m31.Modulus, .first_id = 1 }}, &out));
    try std.testing.expectError(error.InvalidTruthParameterSlot, semanticSource(.{ .classic = .{ .index = 0, .claims = true } }, semantic_count));
}
