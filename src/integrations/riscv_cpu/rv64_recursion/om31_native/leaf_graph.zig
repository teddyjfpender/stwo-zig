//! Concrete current-services leaf construction. Every graph starts with fresh
//! native physical admission; it is not a recursive proof until outer.prove.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const V = @import("mod.zig");
const C = V.common;
const Cpu = @import("cpu_leaf.zig");
const Capture = @import("cpu_capture.zig");
const Truth = @import("truth_leaf.zig");
const Keccak = @import("keccak_leaf.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const CpuWorker = @import("../../word16_global_execution/services/gkr_local/cpu_worker.zig");
const TruthWorker = @import("../../word16_global_execution/services/gkr_local/truth_worker.zig");
pub const Graph = struct {
    allocator: std.mem.Allocator,
    ctx: *C.Context,
    words: []u32,
    digest: [32]u8,
    pub fn deinit(self: *Graph) void {
        self.ctx.deinit();
        self.allocator.destroy(self.ctx);
        self.allocator.free(self.words);
        self.* = undefined;
    }
};
fn context(a: std.mem.Allocator) !*C.Context {
    const ctx = try a.create(C.Context);
    errdefer a.destroy(ctx);
    ctx.* = try C.Context.init(a, circuit.common.component_list.N_RESERVED);
    return ctx;
}
fn binding(value: ?*const Fixed.Binding) ?V.frame.Binding {
    return if (value) |b| .{ .identity = b.fixed_identity, .root = b.fixed_root, .profile = b.profile } else null;
}
fn finish(a: std.mem.Allocator, ctx: *C.Context, output: C.Hash, words: []const u32) !Graph {
    // Exactly eight raw-u32 outputs. They commit all exposed frame words; the
    // execution receiver must independently admit the words and their topology.
    var output_vars: [8]circuit.builder.Var = undefined;
    for (&output_vars, output.words) |*out, word| out.* = word.get();
    try ctx.setOutputs(&output_vars);
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    for (words) |word| {
        std.mem.writeInt(u32, &bytes, word, .little);
        h.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    for (output.words, 0..) |word, i| {
        const actual = circuit.builder.ivalue.unpackU32(C.Q, ctx.get(word.get()));
        if (actual != std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) return error.CurrentOm31FrameDigest;
    }
    try C.lane.finish();
    try ctx.finalize(false);
    if (!try ctx.isCircuitValid()) return error.CurrentOm31LeafRejects;
    return .{ .allocator = a, .ctx = ctx, .words = try a.dupe(u32, words), .digest = digest };
}
pub const CpuInput = struct {
    setup: *const R.CpuSetup,
    request: P.Request,
    expected: M.ExpectedWorker,
    first: [T.FAMILIES]u32,
    manifest: *const M.PendingManifest,
    index: usize,
    stage: *const M.StageOne,
    config: W.PcsConfig,
    encoded: *const CpuWorker.CpuEncoded,
    fixed: ?*const Fixed.Binding = null,
};
pub fn cpu(a: std.mem.Allocator, input: CpuInput) !Graph {
    var admitted = try Capture.verify(a, input.setup, input.request, input.expected, input.first, input.manifest, input.index, input.config, input.encoded, input.fixed);
    defer admitted.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try Capture.geometry(arena.allocator(), input.setup, input.config);
    const values = try V.proof.fromNative(arena.allocator(), &admitted.proof, &admitted.capture, &shape);
    const ctx = try context(a);
    errdefer {
        ctx.deinit();
        a.destroy(ctx);
    }
    C.lane.begin(ctx);
    errdefer C.lane.finish() catch {};
    const proof = try V.proof.guess(ctx, &values, &shape);
    var frame = V.frame.Frame.init(ctx);
    const local = input.manifest.entries[input.index].local orelse return error.WideCpuLocalRequired;
    var statement = try Cpu.Statement.init(&frame, input.setup, input.request, input.first, input.expected, input.manifest.digest, input.encoded.claims, &proof, (input.stage.local orelse return error.WideCpuLocalRequired).proof, input.config, binding(input.fixed));
    defer statement.deinit(ctx);
    _ = try V.verify(ctx, &shape, &proof, &statement);
    const words = try Cpu.expectedWords(arena.allocator(), input.setup, input.request, input.first, input.expected, input.manifest.digest, admitted.proof.commitment_scheme_proof.commitments.items[1], local.digest, input.encoded.claims);
    return finish(a, ctx, try frame.finish(), words);
}
pub const TruthInput = struct {
    truth: R.Truth,
    expected: M.ExpectedWorker,
    manifest: *const M.PendingManifest,
    config: W.PcsConfig,
    encoded: *const TruthWorker.TruthEncoded,
    fixed: ?*const Fixed.Binding = null,
};
pub fn truth(a: std.mem.Allocator, input: TruthInput) !Graph {
    var capture: V.proof.NativeCapture = undefined;
    var native = if (input.truth == .keccak)
        try Keccak.capture(a, input.truth, input.expected, input.manifest, input.config, input.encoded, input.fixed, &capture)
    else
        try Truth.capture(a, input.truth, input.expected, input.manifest, input.config, input.encoded, input.fixed, &capture);
    defer native.deinit(a);
    defer capture.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = if (input.truth == .keccak) try Keccak.shape(arena.allocator(), input.truth, input.config) else try Truth.shape(arena.allocator(), input.truth, input.config);
    const values = try V.proof.fromNative(arena.allocator(), &native, &capture, &shape);
    const ctx = try context(a);
    errdefer {
        ctx.deinit();
        a.destroy(ctx);
    }
    C.lane.begin(ctx);
    errdefer C.lane.finish() catch {};
    const main_root = native.commitment_scheme_proof.commitments.items[1];
    if (input.truth == .keccak) {
        if (input.encoded.claims.len != 5) return error.InvalidWideTruthClaims;
        const public = Keccak.Public{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claims = input.encoded.claims[0..5].* };
        const leaf = try Keccak.build(ctx, input.truth, input.config, binding(input.fixed), public, &values);
        const words = Keccak.statementWords(input.truth, public, main_root);
        return finish(a, ctx, leaf.output, &words);
    }
    if (input.encoded.claims.len != 1) return error.InvalidWideTruthClaims;
    const public = Truth.Public{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claim = input.encoded.claims[0] };
    const leaf = try Truth.build(ctx, input.truth, input.config, binding(input.fixed), public, &values);
    const words = Truth.statementWords(input.truth, public, main_root);
    return finish(a, ctx, leaf.output, &words);
}
