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
const Tape = @import("leaf_tape.zig");
const Outer = @import("outer_wrap.zig");
pub const Graph = struct {
    allocator: std.mem.Allocator,
    ctx: *C.Context,
    words: []u32,
    digest: [32]u8,
    class: ?[32]u8 = null,
    seed_tape: ?[][4]u32 = null,
    pub fn deinit(self: *Graph) void {
        self.ctx.deinit();
        self.allocator.destroy(self.ctx);
        self.allocator.free(self.words);
        if (self.seed_tape) |values| self.allocator.free(values);
        self.* = undefined;
    }
};
fn digestWords(words: []const u32) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    for (words) |word| {
        std.mem.writeInt(u32, &bytes, word, .little);
        h.update(&bytes);
    }
    var result: [32]u8 = undefined;
    h.final(&result);
    return result;
}
fn stub(a: std.mem.Allocator, words: []const u32, class: [32]u8, seeds: [][4]u32) !Graph {
    const ctx = try context(a, true);
    errdefer {
        ctx.deinit();
        a.destroy(ctx);
    }
    ctx.finalized = true;
    return .{ .allocator = a, .ctx = ctx, .words = try a.dupe(u32, words), .digest = digestWords(words), .class = class, .seed_tape = seeds };
}
fn finishClass(a: std.mem.Allocator, ctx: *C.Context, output: C.Hash, words: []const u32, label: []const u8, class: ?[32]u8, seeds: ?[][4]u32) !Graph {
    var graph = try finish(a, ctx, output, words, label);
    errdefer a.free(graph.words);
    if (seeds) |values| try Tape.compare(a, values, ctx);
    graph.class = class;
    return graph;
}
fn context(a: std.mem.Allocator, trace_only: bool) !*C.Context {
    const ctx = try a.create(C.Context);
    errdefer a.destroy(ctx);
    ctx.* = if (trace_only) try C.Context.initTraceOnly(a, circuit.common.component_list.N_RESERVED) else try C.Context.init(a, circuit.common.component_list.N_RESERVED);
    return ctx;
}
fn binding(value: ?*const Fixed.Binding) ?V.frame.Binding {
    return if (value) |b| .{ .identity = b.fixed_identity, .root = b.fixed_root, .profile = b.profile } else null;
}
const Census = @import("topology_fingerprint.zig");
fn finish(a: std.mem.Allocator, ctx: *C.Context, output: C.Hash, words: []const u32, label: []const u8) !Graph {
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
    if (!ctx.trace_only) for (output.words, 0..) |word, i| {
        const actual = circuit.builder.ivalue.unpackU32(C.Q, ctx.get(word.get()));
        if (actual != std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) return error.CurrentOm31FrameDigest;
    };
    try C.lane.finish();
    Census.report(ctx, label, "pre_finalize");
    try ctx.finalize(false);
    if (!ctx.trace_only and !try ctx.isCircuitValid()) return error.CurrentOm31LeafRejects;
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
    return cpuMode(a, input, false, null);
}
pub fn cpuTraceOnly(a: std.mem.Allocator, input: CpuInput) !Graph {
    return cpuMode(a, input, true, null);
}
pub fn cpuTraceWithTape(a: std.mem.Allocator, input: CpuInput, factory: ?Outer.Device.Factory) !Graph {
    return cpuMode(a, input, true, factory);
}
fn cpuMode(a: std.mem.Allocator, input: CpuInput, trace_only: bool, factory: ?Outer.Device.Factory) !Graph {
    var admitted = try Capture.verify(a, input.setup, input.request, input.expected, input.first, input.manifest, input.index, input.config, input.encoded, input.fixed);
    defer admitted.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try Capture.geometry(arena.allocator(), input.setup, input.config);
    const values = try V.proof.fromNative(arena.allocator(), &admitted.proof, &admitted.capture, &shape);
    const local = input.manifest.entries[input.index].local orelse return error.WideCpuLocalRequired;
    const words = try Cpu.expectedWords(arena.allocator(), input.setup, input.request, input.first, input.expected, input.manifest.digest, admitted.proof.commitment_scheme_proof.commitments.items[1], local.digest, input.encoded.claims);
    const class = if (factory != null and Tape.mode() != .off) try Tape.cpuClass(input, &shape) else null;
    if (class) |key| if (Tape.mode() == .on and Outer.tapeReady(factory.?, key)) {
        const seeds = try Tape.cpu(a, input, &values);
        errdefer a.free(seeds);
        return stub(a, words, key, seeds);
    };
    const seeds = if (class != null and Tape.mode() == .check) try Tape.cpu(a, input, &values) else null;
    defer if (seeds) |s| a.free(s);
    const ctx = try context(a, trace_only);
    errdefer {
        ctx.deinit();
        a.destroy(ctx);
    }
    C.lane.begin(ctx);
    errdefer C.lane.finish() catch {};
    const proof = try V.proof.guess(ctx, &values, &shape);
    var frame = V.frame.Frame.init(ctx);
    var statement = try Cpu.Statement.init(&frame, input.setup, input.request, input.first, input.expected, input.manifest.digest, input.encoded.claims, &proof, (input.stage.local orelse return error.WideCpuLocalRequired).proof, input.config, binding(input.fixed));
    defer statement.deinit(ctx);
    _ = try V.verify(ctx, &shape, &proof, &statement);
    var label: [48]u8 = undefined;
    return finishClass(a, ctx, try frame.finish(), words, try std.fmt.bufPrint(&label, "leaf-cpu-{d:0>4}", .{input.index}), class, seeds);
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
    return truthMode(a, input, false, null);
}
pub fn truthTraceOnly(a: std.mem.Allocator, input: TruthInput) !Graph {
    return truthMode(a, input, true, null);
}
pub fn truthTraceWithTape(a: std.mem.Allocator, input: TruthInput, factory: ?Outer.Device.Factory) !Graph {
    return truthMode(a, input, true, factory);
}
fn truthMode(a: std.mem.Allocator, input: TruthInput, trace_only: bool, factory: ?Outer.Device.Factory) !Graph {
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
    const class = if (factory != null and Tape.mode() != .off) Tape.truthClass(input, &shape) else null;
    if (class) |key| if (Tape.mode() == .on and Outer.tapeReady(factory.?, key)) {
        const seeds = try Tape.truth(a, input, &values);
        errdefer a.free(seeds);
        const main = native.commitment_scheme_proof.commitments.items[1];
        if (input.truth == .keccak) {
            if (input.encoded.claims.len != 5) return error.InvalidWideTruthClaims;
            const words = Keccak.statementWords(input.truth, .{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claims = input.encoded.claims[0..5].* }, main);
            return stub(a, &words, key, seeds);
        }
        if (input.encoded.claims.len != 1) return error.InvalidWideTruthClaims;
        const words = Truth.statementWords(input.truth, .{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claim = input.encoded.claims[0] }, main);
        return stub(a, &words, key, seeds);
    };
    const seeds = if (class != null and Tape.mode() == .check) try Tape.truth(a, input, &values) else null;
    defer if (seeds) |s| a.free(s);
    const ctx = try context(a, trace_only);
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
        var label: [48]u8 = undefined;
        return finishClass(a, ctx, leaf.output, &words, try std.fmt.bufPrint(&label, "leaf-keccak-{d:0>4}", .{input.expected.ordinal}), class, seeds);
    }
    if (input.encoded.claims.len != 1) return error.InvalidWideTruthClaims;
    const public = Truth.Public{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claim = input.encoded.claims[0] };
    const leaf = try Truth.build(ctx, input.truth, input.config, binding(input.fixed), public, &values);
    const words = Truth.statementWords(input.truth, public, main_root);
    var label: [48]u8 = undefined;
    return finishClass(a, ctx, leaf.output, &words, try std.fmt.bufPrint(&label, "leaf-{s}-{d:0>4}", .{ @tagName(std.meta.activeTag(input.truth)), input.expected.ordinal }), class, seeds);
}
