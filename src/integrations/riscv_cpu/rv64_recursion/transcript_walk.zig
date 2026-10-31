//! The one definition of the RV64 Ethereum batch transcript prefix: which
//! words the receiver mixes before the fixed and main commitments, which
//! tagged draws it makes afterwards, and which claim felts it mixes before
//! the interaction commitment. The walkers mirror `A.mixPublicView`,
//! `A.drawView` and `A.mixClaims` call for call, but emit through a sink so
//! the native replay (parity check, statement digest) and the in-circuit
//! statement (guessed and constant wires) share exactly one order.
//!
//! Word kinds: a `layout` word fixes the circuit topology (policies, rosters,
//! log sizes, opcode flags, tags) and is a constant in-circuit; a `free` word
//! varies per batch (roots, identities, endpoints, counts) and is a guessed
//! wire bound by the leaf's output digest.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const rv = A.rv;
const P = A.P;
const T = A.T;
const Q = A.Q;

/// A `layout` word is a constant in-circuit; every other kind is a free
/// (guessed) word, the named kinds being the public scalars the constraint
/// code reads (`rv64_point_layout.Publics`).
pub const Kind = enum { layout, free, steps, keccak_calls, first_call_id, secp_calls_add, secp_first_add, secp_calls_double, secp_first_double, division_requests, multiplication_requests };

/// The sink duck type shared by the native replay and the circuit statement:
///
/// | member | meaning |
/// |---|---|
/// | `words(kinds, values)` | one `mixU32s` call of layout/free words |
/// | `u64Free(value)` | one `mixU64` of a free value (pc, register) |
/// | `digestFree([9]u32)` | one `mixU32s` of a RAM root (free) |
/// | `clockFree(u32)` | one `mixU32s` of a register clock (free) |
/// | `configFelt()` | the PCS configuration felt |
/// | `tag(values)` | one `mixU32s` of layout words in the draw/claim phases |
/// | `draws(n)` | `n` single `drawSecureFelt` calls |
/// | `drawBulk(n)` | one `drawSecureFelts(n)` call |
/// | `claims(values)` | one `mixFelts` call of claim felts |
const L = Kind.layout;
const F = Kind.free;

/// Mirrors `A.mixPublicView`, `CS.mixPublicView`, `Metadata.mix` and
/// `Statement.mixWithProfile`. `identity` is the immutable ROM identity the
/// receiver supplies (`view.cpu.base.program.identity`).
pub fn walkPublic(sink: anytype, view: A.VerificationView, public: A.Public) !void {
    if (public.cpu.statement.cells.len != 0 or public.cpu.statement.memory_clocks.len != 0) return error.UnsupportedRv64RecursionStatement;
    try sink.words(&.{ L, L, L, L }, &.{ 0x52414558, 1, @intFromBool(public.ram != null), public.geometry.logBytes() });
    try sink.digestFree(public.before);
    try sink.digestFree(public.after);
    for (public.policy_identity) |byte| try sink.words(&.{F}, &.{byte});
    if (public.ram) |c| try sink.words(&(.{L} ** 6), &.{ c.hashes, c.common_chunks, c.edge_chunks, c.nodes, c.sides, c.edge_permits });
    const cpu = public.cpu;
    try sink.words(&.{ L, L, L, .division_requests, .keccak_calls, .first_call_id, L, L, L }, &.{ 0x52564b43, 1, @intFromEnum(cpu.arithmetic_policy), cpu.division_requests, cpu.keccak_calls, cpu.first_call_id, cpu.division_log, cpu.keccak_log, cpu.bridge_log });
    if (cpu.arithmetic_policy == .division_multiplication_services_v3) try sink.words(&.{ L, L, .multiplication_requests, L }, &.{ 0x4d554c43, 1, cpu.multiplication_requests, cpu.multiplication_log });
    if (cpu.roster != .paired) try sink.words(&.{ L, L, L }, &.{ 0x4b524f53, 1, @intFromEnum(cpu.roster) });
    if (cpu.state_policy != .inverse_v1) try sink.words(&.{ L, L, L }, &.{ 0x43535441, 2, @intFromEnum(cpu.state_policy) });
    if (cpu.control_policy != .bytes_v1) try sink.words(&.{ L, L, L }, &.{ 0x4354524c, 2, @intFromEnum(cpu.control_policy) });
    if (cpu.execution_profile != .keccak_service_v1) {
        try sink.words(&.{ L, L, L }, &.{ 0x45544853, 1, @intFromEnum(cpu.execution_profile) });
        for (cpu.secp.groups(), 0..) |g, k| try sink.words(&.{ L, if (k == 0) .secp_calls_add else .secp_calls_double, if (k == 0) .secp_first_add else .secp_first_double, L, L, L }, &.{ @intFromEnum(g.roster), g.calls, g.first_id, g.geometry.product_log, g.geometry.linear_log, g.geometry.bridge_log });
    }
    if (cpu.division_roster == .none or cpu.multiplication_roster == .none) try sink.words(&.{ L, L, L, L }, &.{ 0x41524f53, 1, @intFromEnum(cpu.division_roster), @intFromEnum(cpu.multiplication_roster) });
    const statement = cpu.statement;
    if (cpu.execution_profile != .rv64im) try sink.words(&.{ L, L, L }, &.{ 0x52565052, 1, @intFromEnum(cpu.execution_profile) });
    try sink.words(&.{ L, L, L, .steps, L }, &.{ 0x52563634, 0x46554c4c, 1, statement.steps, statement.logSize() });
    try sink.configFelt();
    for (view.cpu.base.program.identity) |byte| try sink.words(&.{F}, &.{byte});
    try sink.u64Free(statement.initial_pc);
    try sink.u64Free(statement.final_pc);
    for (statement.initial_registers) |value| try sink.u64Free(value);
    for (statement.final_registers) |value| try sink.u64Free(value);
    for (statement.register_clocks) |clock| try sink.clockFree(clock);
    for (statement.opcodes) |enabled| try sink.words(&.{L}, &.{@intFromBool(enabled)});
    try sink.words(&.{ L, L }, &.{ 0, 0 });
}

/// Mirrors `A.drawView`: every tag mix and every secure-felt draw, in order.
/// `sink.draws(n)` is `n` single `drawSecureFelt` calls; `sink.drawBulk(n)`
/// is one `drawSecureFelts(n)` call (two felts per hash).
pub fn walkDraws(sink: anytype, view: A.VerificationView) !void {
    const plan = view.cpu.base.plan;
    if (rv.state_policy.isCyclic(plan.state_policy)) {
        try sink.tag(&.{ 0x52563634, 0x43535441, @intFromEnum(plan.state_policy) });
    } else {
        try sink.tag(&.{ 0x52563634, 0x53544154, 1 });
    }
    try sink.draws(1 + rv.relations.ARITY);
    if (plan.control_policy == .bytes_v1) {
        try sink.tag(&.{ 0x52563634, 0x524f4d43, 1, rv.program.compact.COUNT });
        try sink.draws(1 + rv.program.compact.COUNT);
    } else {
        try sink.tag(&.{ 0x52563634, 0x524f4d43, 2, rv.program.packed_control.COUNT });
        try sink.draws(1 + rv.program.packed_control.COUNT);
    }
    try sink.tag(&.{ 0x52563634, 0x42595445, 1 });
    try sink.draws(1);
    if (view.cpu.base.has_and) {
        try sink.tag(&.{ 0x52563634, 0x414e4438, 1 });
        try sink.draws(1 + rv.providers.tables.MAX_ARITY);
    }
    if (view.cpu.base.has_shift) {
        try sink.tag(&.{ 0x52563634, 0x53484638, 1 });
        try sink.draws(1 + rv.providers.tables.MAX_ARITY);
    }
    try sink.tag(&.{ 0x44495632, rv.arithmetic.division.layout.TUPLE });
    try sink.draws(1 + rv.arithmetic.division.layout.TUPLE);
    if (plan.arithmetic_policy == .division_multiplication_services_v3) {
        try sink.tag(&.{ 0x4d554c31, rv.arithmetic.multiplication.layout.TUPLE });
        try sink.draws(1 + rv.arithmetic.multiplication.layout.TUPLE);
    }
    // Keccak: chi and xor5 lookups, then the io relation; none is tagged.
    try sink.draws(1 + rv.providers.tables.MAX_ARITY);
    try sink.draws(1 + rv.providers.tables.MAX_ARITY);
    try sink.draws(1 + rv.crypto.keccak.layout.IO_ARITY);
    try sink.tag(&.{ 0x4b43414c, 1, 10 });
    try sink.draws(11);
    if (plan.execution_profile != .keccak_service_v1) {
        try sink.draws(1);
        try sink.tag(&.{0x53575031});
        try sink.draws(1 + rv.crypto.secp256k1.layout.WIRE_ARITY);
        try sink.tag(&.{ 0x5343414c, 1, 11 });
        try sink.draws(12);
    }
    if (view.has_ram) {
        try sink.drawBulk(poseidon_relation_draws);
        try sink.tag(&.{ 0x52414d32, 0x494e544c, rv.memory.internal_relations.ARITY });
        try sink.draws(1 + rv.memory.internal_relations.ARITY);
        try sink.tag(&.{ 0x52565032, 0x504f4c59 });
        try sink.draws(1 + 18);
    }
}

/// `relation_challenges.Relations.DRAW_COUNT`: twelve `(z, alpha)` pairs.
pub const poseidon_relation_draws: usize = 24;

/// Mirrors `A.mixClaims`: tags and the claim felts, in order. Claim values
/// come from `claims`; the sink receives them one `mixFelts` call at a time.
pub fn walkClaims(sink: anytype, view: A.VerificationView, public: A.Public, claims: A.Claims) !void {
    const cpu = claims.cpu;
    try sink.tag(&.{ 0x52563634, 0x434c414d, 1, 5 });
    try sink.claims(&.{ cpu.cpu.state, cpu.cpu.rom, cpu.cpu.bytes, cpu.cpu.bitwise, cpu.cpu.shifts });
    try sink.tag(&.{ 0x4b434c4d, 1, 7 });
    try sink.claims(&.{ cpu.division, cpu.header, cpu.permutation, cpu.chi, cpu.xor5, cpu.bridge, cpu.bytes });
    if (public.cpu.execution_profile != .keccak_service_v1) {
        try sink.tag(&.{ 0x53454350, 1 });
        try sink.claims(&.{ cpu.secp_header, cpu.secp_add.product, cpu.secp_add.linear, cpu.secp_add.bridge, cpu.secp_double.product, cpu.secp_double.linear, cpu.secp_double.bridge });
    }
    if (public.cpu.arithmetic_policy == .division_multiplication_services_v3) {
        try sink.tag(&.{ 0x4d554c43, 1 });
        try sink.claims(&.{ cpu.multiplication, cpu.multiplication_provider });
    }
    if (view.has_ram != (claims.ram != null)) return error.InvalidAuthenticatedRamClaims;
    if (claims.ram) |*ram| {
        for (T.TABLES) |table| try sink.claims(ram.callers.slice(table));
        try sink.claims(&ram.provider);
        try sink.claims(&.{ram.policy});
    }
}

/// The native replay sink: drives a real channel and records the free words
/// (the leaf's statement preimage) and the drawn challenges in order.
pub const NativeReplay = struct {
    allocator: std.mem.Allocator,
    channel: *P.Channel,
    free: std.ArrayListUnmanaged(u32) = .empty,
    drawn: std.ArrayListUnmanaged(Q) = .empty,
    claim_felts: std.ArrayListUnmanaged(Q) = .empty,

    pub fn deinit(self: *NativeReplay) void {
        self.free.deinit(self.allocator);
        self.drawn.deinit(self.allocator);
        self.claim_felts.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn words(self: *NativeReplay, kinds: []const Kind, values: []const u32) !void {
        std.debug.assert(kinds.len == values.len);
        for (kinds, values) |kind, value| if (kind != .layout) try self.free.append(self.allocator, value);
        self.channel.mixU32s(values);
    }
    pub fn u64Free(self: *NativeReplay, value: u64) !void {
        try self.free.appendSlice(self.allocator, &.{ @truncate(value), @truncate(value >> 32) });
        self.channel.mixU64(value);
    }
    pub fn digestFree(self: *NativeReplay, digest: [9]u32) !void {
        try self.words(&(.{Kind.free} ** 9), &digest);
    }
    pub fn clockFree(self: *NativeReplay, clock: u32) !void {
        try self.words(&.{Kind.free}, &.{clock});
    }
    pub fn configFelt(self: *NativeReplay) !void {
        P.config().mixInto(self.channel);
    }
    pub fn tag(self: *NativeReplay, values: []const u32) !void {
        self.channel.mixU32s(values);
    }
    pub fn draws(self: *NativeReplay, n: usize) !void {
        for (0..n) |_| try self.drawn.append(self.allocator, self.channel.drawSecureFelt());
    }
    pub fn drawBulk(self: *NativeReplay, n: usize) !void {
        const values = try self.channel.drawSecureFelts(self.allocator, n);
        defer self.allocator.free(values);
        try self.drawn.appendSlice(self.allocator, values);
    }
    pub fn claims(self: *NativeReplay, values: []const Q) !void {
        try self.claim_felts.appendSlice(self.allocator, values);
        self.channel.mixFelts(values);
    }
};

/// Blake2s-256 of the free words as little-endian bytes: the leaf's
/// statement digest, as eight little-endian words.
pub fn statementDigest(free: []const u32) [8]u32 {
    var hasher = A.core.vcs.blake2_hash.Blake2sHasher.init();
    for (free) |word| {
        var le: [4]u8 = undefined;
        std.mem.writeInt(u32, &le, word, .little);
        hasher.update(&le);
    }
    return A.core.vcs.blake2_hash.digestToU32s(hasher.finalize());
}

/// Replays the native receiver's transcript prefix up to the interaction
/// commitment with the real functions and with the walkers; returns the
/// recorded replay when every intermediate digest agrees.
pub fn checkParity(a: std.mem.Allocator, view: A.VerificationView, public: A.Public, claims: A.Claims, fixed_root: [32]u8, main_root: [32]u8, fixed_logs: []const u32, main_logs: []const u32) !NativeReplay {
    var expected = P.Channel{};
    var actual = P.Channel{};
    var replay = NativeReplay{ .allocator = a, .channel = &actual };
    errdefer replay.deinit();
    try A.mixPublicView(&expected, view, public);
    try walkPublic(&replay, view, public);
    if (!std.mem.eql(u8, &expected.digest, &actual.digest)) return error.PublicTranscriptMismatch;
    for ([_]*P.Channel{ &expected, &actual }) |channel| {
        var verifier = try A.core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel).init(a, P.config());
        defer verifier.deinit(a);
        try verifier.commit(a, fixed_root, fixed_logs, channel);
        try verifier.commit(a, main_root, main_logs, channel);
    }
    const drawn = try A.drawView(a, &expected, view);
    _ = drawn;
    try walkDraws(&replay, view);
    if (!std.mem.eql(u8, &expected.digest, &actual.digest)) return error.DrawTranscriptMismatch;
    A.mixClaims(&expected, public, claims);
    try walkClaims(&replay, view, public, claims);
    if (!std.mem.eql(u8, &expected.digest, &actual.digest)) return error.ClaimTranscriptMismatch;
    return replay;
}
