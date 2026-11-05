//! M6 hint-tape v1 (HT1, /workspace/m3/M6-INTERFACES.md): the seed tape of a
//! v2 fold, recorded WITHOUT building the fold's verifier graph.
//!
//! A v2 fold's topology (gates, levels, constants, seed variables) is a
//! function of its geometry class (`om31_outer.classKey`); the only per-node
//! inputs of its device assignment are the seed-origin values, i.e. the guessed
//! child-proof words, in variable order. `buildFoldMode` creates every one of
//! them in the per-child guess prologue (proof capture, identity words, outputs,
//! output words, claims); the in-circuit verifier body adds gates, constants and
//! hint origins only. `record` emits exactly those values in that order straight
//! from the converted capture (`recordReplay` = the same prologue through the
//! builder, kept as the reference). The device factory pairs them with its class template (tasks, levels,
//! seed variables, constants) and refuses on any doubt (`SeedTapeClassMiss`).
//!
//! Proof-neutral: equal seeds are the equal assignment, hence equal MAIN and an
//! identical proof. A wrong tape cannot produce an accepted proof (the fold
//! circuit constrains the child verification; the prover checks the output
//! lookup sum and the pipeline re-verifies every fold proof before publishing).
//! STWO_RV64_FOLD_SEED_TAPE=0 restores the M5 path; =check builds both and
//! compares every seed value before proving from the full graph.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const V = @import("mod.zig");
const C = V.common;
const F = V.F;
const Q = C.Q;
const M = core.fields.m31.M31;
const B = circuit.builder;
const Bridge = @import("../om31_outer.zig");

pub const Mode = enum { off, on, check };
pub fn mode() Mode {
    const value = std.posix.getenv("STWO_RV64_FOLD_SEED_TAPE") orelse return .on;
    if (std.mem.eql(u8, value, "0")) return .off;
    if (std.mem.eql(u8, value, "check")) return .check;
    return .on;
}

/// Seed-origin values (QM31 limbs) in variable order. Caller frees.
///
/// Production emitter: writes the values `V.proof.guess` and the fold's
/// identity/output/claim guesses would record, in the same order, straight
/// from the converted capture (no builder context). Each guess maps to seeds:
/// guessU32(w) -> (w & 0xffff), (w >> 16) as base coordinates; guessHash ->
/// guessU32 over the 8 little-endian digest words; guessM31(v) -> (v);
/// F.guess(o) -> o.c0, o.c1; ctx.guess(q) -> q. `recordReplay` is the
/// builder-call reference; check mode and the qualification test compare
/// this emitter against the full graph.
pub fn record(a: std.mem.Allocator, children: []const Bridge.Child) ![][4]u32 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var out: std.ArrayListUnmanaged([4]u32) = .empty;
    errdefer out.deinit(a);
    try out.ensureTotalCapacity(a, 360_000 * children.len);
    var e = Emit{ .a = a, .out = &out };
    for (children) |child| {
        try Outer.protocol.validateConfig(child.produced.proof.proof.commitment_scheme_proof.config);
        const geometry = try Bridge.shape(scratch, child.authority);
        const captured = try V.proof.fromNativeCapped(scratch, &child.produced.proof.proof, child.capture, &geometry, Outer.protocol.active().foldMerkleCapLog());
        try e.proof(&captured);
        for (0..8) |i| try e.word(std.mem.readInt(u32, child.authority.identity[4 * i ..][0..4], .little));
        for (child.produced.outputs) |value| try e.q(value);
        // unpackQm31sToU32Words: hint origins only (no seeds).
        for (child.produced.claims.toArray()) |value| try e.om(value);
    }
    return out.toOwnedSlice(a);
}

const Emit = struct {
    a: std.mem.Allocator,
    out: *std.ArrayListUnmanaged([4]u32),
    fn put(self: *Emit, value: [4]u32) !void {
        try self.out.append(self.a, value);
    }
    fn q(self: *Emit, value: Q) !void {
        try self.put(B.ivalue.limbs(value));
    }
    fn om(self: *Emit, value: C.O) !void {
        try self.q(value.c0);
        try self.q(value.c1);
    }
    fn m31(self: *Emit, value: M) !void {
        try self.q(Q.fromBase(value));
    }
    fn word(self: *Emit, value: u32) !void {
        try self.put(.{ value & 0xFFFF, 0, 0, 0 });
        try self.put(.{ value >> 16, 0, 0, 0 });
    }
    fn hash(self: *Emit, digest: [32]u8) !void {
        for (core.vcs.blake2_hash.digestToU32s(digest)) |w| try self.word(w);
    }
    fn paths(self: *Emit, source: []const []const [32]u8) !void {
        for (source) |path| for (path) |node| try self.hash(node);
    }
    /// Same order as om31_native/proof.zig `guess`.
    fn proof(self: *Emit, source: *const V.Captured) !void {
        for (source.commitments) |root| try self.hash(root);
        for (source.sampled_values, source.queried_values, source.auth_paths) |tree_samples, tree_queried, tree_paths| {
            for (tree_samples, tree_queried) |samples, bases| {
                for (samples) |value| try self.om(value);
                for (bases) |value| try self.m31(value);
            }
            try self.paths(tree_paths);
        }
        // M6 integrate: diet-wire's Merkle cap (empty when the profile's cap log is 0).
        for (source.caps) |cap| for (cap) |node| try self.hash(node);
        for (source.layers) |layer| {
            for (layer.cosets) |coset| for (coset) |value| try self.om(value);
            for (layer.cap) |node| try self.hash(node);
            try self.hash(layer.commitment);
            try self.paths(layer.auth_paths);
        }
        try self.word(@truncate(source.pow_nonce));
        try self.word(@truncate(source.pow_nonce >> 32));
        for (source.last_layer_coefs) |value| try self.om(value);
    }
};

/// Reference: the fold's guess prologue replayed through the builder (same
/// calls, same order as om31_outer.buildFoldMode, minus V.verify).
pub fn recordReplay(a: std.mem.Allocator, children: []const Bridge.Child) ![][4]u32 {
    var ctx = try C.Context.initTraceOnly(a, 8);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var lane_open = true;
    defer if (lane_open) C.lane.finish() catch {};
    for (children) |child| {
        try Outer.protocol.validateConfig(child.produced.proof.proof.commitment_scheme_proof.config);
        const geometry = try Bridge.shape(ctx.scratch(), child.authority);
        const captured = try V.proof.fromNativeCapped(ctx.scratch(), &child.produced.proof.proof, child.capture, &geometry, Outer.protocol.active().foldMerkleCapLog());
        _ = try V.proof.guess(&ctx, &captured, &geometry);
        for (0..8) |i| _ = try B.wrappers.guessU32(Q, &ctx, B.wrappers.u32Value(Q, std.mem.readInt(u32, child.authority.identity[4 * i ..][0..4], .little)));
        const outputs = try ctx.scratch().alloc(C.Var, child.produced.outputs.len);
        for (outputs, child.produced.outputs) |*out, value| out.* = try ctx.guess(value);
        _ = try B.blake.unpackQm31sToU32Words(Q, &ctx, outputs);
        for (child.produced.claims.toArray()) |value| _ = try F.guess(&ctx, value);
    }
    try C.lane.check();
    lane_open = false;
    try C.lane.finish();
    return seedValues(a, &ctx);
}

fn seedValues(a: std.mem.Allocator, ctx: *const C.Context) ![][4]u32 {
    const origins = (ctx.witness_metadata orelse return error.TraceOnlyGraphRequired).origins.items;
    var count: usize = 0;
    for (origins) |origin| count += @intFromBool(origin.kind == .seed);
    const values = try a.alloc([4]u32, count);
    var i: usize = 0;
    for (origins) |origin| if (origin.kind == .seed) {
        values[i] = B.ivalue.limbs(origin.value);
        i += 1;
    };
    return values;
}

/// check mode: the tape must equal the full graph's seed origins exactly.
pub fn compare(a: std.mem.Allocator, tape: []const [4]u32, graph: *const C.Context) !void {
    const expected = try seedValues(a, graph);
    defer a.free(expected);
    if (expected.len != tape.len) {
        std.debug.print("FOLD_SEED_TAPE check_mismatch tape={} graph={}\n", .{ tape.len, expected.len });
        return error.FoldSeedTapeMismatch;
    }
    for (expected, tape, 0..) |e, t, i| if (!std.mem.eql(u32, &e, &t)) {
        std.debug.print("FOLD_SEED_TAPE check_mismatch at={} of={}\n", .{ i, tape.len });
        return error.FoldSeedTapeMismatch;
    };
    std.debug.print("FOLD_SEED_TAPE check_ok seeds={}\n", .{tape.len});
}

/// The graph stand-in a tape-backed fold hands to the device path: flags only
/// (trace-only, finalized, recording), no gates, no values. Its variable count
/// is set from the class template once the factory consumed the tape.
pub fn stub(a: std.mem.Allocator, digest: [32]u8) !Bridge.Graph {
    var ctx = try C.Context.initTraceOnly(a, 8);
    errdefer ctx.deinit();
    ctx.finalized = true;
    return .{ .ctx = ctx, .output_digest = digest };
}

test "fold seed tape mode parsing defaults on" {
    // Only the env-free default is asserted here; the end-to-end gate is the
    // byte-identical dev-block receipts (vectors/reports/rv64-m6-20261105/hint-tape/).
    if (std.posix.getenv("STWO_RV64_FOLD_SEED_TAPE") == null) try std.testing.expectEqual(Mode.on, mode());
}
