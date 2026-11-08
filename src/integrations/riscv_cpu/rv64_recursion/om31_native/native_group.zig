//! Bounded native-verifier composition before any outer STARK is produced.
//! This is a graph construction, not an accepting execution receiver. A root
//! receiver must admit the native inventory, exact member frames, manifest,
//! closure and terminal output independently, just as for the tree route.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const V = @import("mod.zig");
const C = V.common;
const G = @import("leaf_graph.zig");
const Capture = @import("cpu_capture.zig");
const Cpu = @import("cpu_leaf.zig");
const Truth = @import("truth_leaf.zig");
const Keccak = @import("keccak_leaf.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
pub const MAX_MEMBERS = 4;
pub const MAX_NATIVE_WORKERS = 256;
pub const DOMAIN = "STWO/RV64/GROUP1";
pub const Member = union(enum) { cpu: G.CpuInput, truth: G.TruthInput };
pub const Range = struct { first: u32, total: u32 };
pub const Kind = enum(u32) { cpu = 0, keccak = 1, delegation = 2 };
pub const Appended = struct {
    words: []u32,
    digest: [32]u8,
    output: C.Hash,
    kind: Kind,
    ordinal: u32,
    pub fn deinit(self: *Appended, a: std.mem.Allocator) void {
        a.free(self.words);
    }
};
fn binding(value: ?*const Fixed.Binding) ?V.frame.Binding {
    return if (value) |b| .{ .identity = b.fixed_identity, .root = b.fixed_root, .profile = b.profile } else null;
}
pub fn digestWords(words: []const u32) [32]u8 {
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
fn appended(a: std.mem.Allocator, ctx: *C.Context, words: []const u32, output: C.Hash, kind: Kind, ordinal: u32) !Appended {
    const digest = digestWords(words);
    if (!ctx.trace_only) for (output.words, 0..) |word, i| {
        if (circuit.builder.ivalue.unpackU32(C.Q, ctx.get(word.get())) != std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) return error.NativeGroupFrameDigest;
    };
    return .{ .words = try a.dupe(u32, words), .digest = digest, .output = output, .kind = kind, .ordinal = ordinal };
}
/// Caller has activated the shared lane. The same native physical admission,
/// statement authority and verifier primitive as the existing CPU leaf.
pub fn appendCpu(a: std.mem.Allocator, ctx: *C.Context, input: G.CpuInput) !Appended {
    var admitted = try Capture.verify(a, input.setup, input.request, input.expected, input.first, input.manifest, input.index, input.config, input.encoded, input.fixed);
    defer admitted.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try Capture.geometry(arena.allocator(), input.setup, input.config);
    const values = try V.proof.fromNative(arena.allocator(), &admitted.proof, &admitted.capture, &shape);
    const local = input.stage.local orelse return error.WideCpuLocalRequired;
    const words = try Cpu.expectedWords(arena.allocator(), input.setup, input.request, input.first, input.expected, input.manifest.digest, admitted.proof.commitment_scheme_proof.commitments.items[1], local.receipt_digest, input.encoded.claims);
    const proof = try V.proof.guess(ctx, &values, &shape);
    var frame = V.frame.Frame.init(ctx);
    var statement = try Cpu.Statement.init(&frame, input.setup, input.request, input.first, input.expected, input.manifest.digest, input.encoded.claims, &proof, local.proof, input.config, binding(input.fixed));
    defer statement.deinit(ctx);
    _ = try V.verify(ctx, &shape, &proof, &statement);
    return appended(a, ctx, words, try frame.finish(), .cpu, input.expected.ordinal);
}
pub fn appendTruth(a: std.mem.Allocator, ctx: *C.Context, input: G.TruthInput) !Appended {
    var capture: V.proof.NativeCapture = undefined;
    var native = if (input.truth == .keccak) try Keccak.capture(a, input.truth, input.expected, input.manifest, input.config, input.encoded, input.fixed, &capture) else try Truth.capture(a, input.truth, input.expected, input.manifest, input.config, input.encoded, input.fixed, &capture);
    defer native.deinit(a);
    defer capture.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = if (input.truth == .keccak) try Keccak.shape(arena.allocator(), input.truth, input.config) else try Truth.shape(arena.allocator(), input.truth, input.config);
    const values = try V.proof.fromNative(arena.allocator(), &native, &capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    if (input.truth == .keccak) {
        if (input.encoded.claims.len != 5) return error.InvalidWideTruthClaims;
        const public = Keccak.Public{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claims = input.encoded.claims[0..5].* };
        const leaf = try Keccak.build(ctx, input.truth, input.config, binding(input.fixed), public, &values);
        const words = Keccak.statementWords(input.truth, public, main);
        return appended(a, ctx, &words, leaf.output, .keccak, input.expected.ordinal);
    }
    if (input.encoded.claims.len != 1) return error.InvalidWideTruthClaims;
    const public = Truth.Public{ .ordinal = input.expected.ordinal, .statement = input.expected.statement, .manifest = input.manifest.digest, .claim = input.encoded.claims[0] };
    const leaf = try Truth.build(ctx, input.truth, input.config, binding(input.fixed), public, &values);
    const words = Truth.statementWords(input.truth, public, main);
    return appended(a, ctx, &words, leaf.output, .delegation, input.expected.ordinal);
}
pub const Graph = struct {
    a: std.mem.Allocator,
    ctx: *C.Context,
    frames: []Appended,
    words: []u32,
    digest: [32]u8,
    range: Range,
    pub fn deinit(self: *Graph) void {
        for (self.frames) |*frame| frame.deinit(self.a);
        self.a.free(self.frames);
        self.a.free(self.words);
        self.ctx.deinit();
        self.a.destroy(self.ctx);
        self.* = undefined;
    }
};
fn memberOrdinal(member: Member) u32 {
    return switch (member) {
        .cpu => |v| v.expected.ordinal,
        .truth => |v| v.expected.ordinal,
    };
}
fn memberManifest(member: Member) [32]u8 {
    return switch (member) {
        .cpu => |v| v.manifest.digest,
        .truth => |v| v.manifest.digest,
    };
}
fn appendHeader(ctx: *C.Context, frame: *V.frame.Frame, words: *std.ArrayList(u32), a: std.mem.Allocator, value: u32) !void {
    const word = try circuit.builder.wrappers.constU32(C.Q, ctx, value);
    try frame.free_words.append(ctx.scratch(), word);
    try words.append(a, value);
}
pub fn build(a: std.mem.Allocator, members: []const Member, range: Range, trace_only: bool) !Graph {
    if (members.len == 0 or members.len > MAX_MEMBERS or range.total == 0 or range.total > MAX_NATIVE_WORKERS or @as(u64, range.first) + members.len > range.total) return error.NativeGroupRange;
    const manifest = memberManifest(members[0]);
    for (members, 0..) |member, i| {
        if (memberOrdinal(member) != @as(u64, range.first) + i) return error.NativeGroupOrder;
        if (!std.mem.eql(u8, &manifest, &memberManifest(member))) return error.NativeGroupManifest;
    }
    const ctx = try a.create(C.Context);
    errdefer a.destroy(ctx);
    ctx.* = if (trace_only) try C.Context.initTraceOnly(a, circuit.common.component_list.N_RESERVED) else try C.Context.init(a, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const frames = try a.alloc(Appended, members.len);
    errdefer a.free(frames);
    var made: usize = 0;
    errdefer for (frames[0..made]) |*frame| frame.deinit(a);
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(a);
    C.lane.begin(ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    var frame = V.frame.Frame.init(ctx);
    for (0..4) |i| try appendHeader(ctx, &frame, &words, a, std.mem.readInt(u32, DOMAIN[4 * i ..][0..4], .little));
    try appendHeader(ctx, &frame, &words, a, range.first);
    try appendHeader(ctx, &frame, &words, a, @intCast(members.len));
    try appendHeader(ctx, &frame, &words, a, range.total);
    for (members, frames) |member, *out| {
        out.* = switch (member) {
            .cpu => |input| try appendCpu(a, ctx, input),
            .truth => |input| try appendTruth(a, ctx, input),
        };
        made += 1;
        try appendHeader(ctx, &frame, &words, a, @intFromEnum(out.kind));
        try appendHeader(ctx, &frame, &words, a, out.ordinal);
        try appendHeader(ctx, &frame, &words, a, @intCast(out.words.len));
        // Reuse the verifier's computed digest wires. Reguessing these words
        // without equality would sever authentication of the native frames.
        try frame.free_words.appendSlice(ctx.scratch(), &out.output.words);
        for (0..8) |j| try words.append(a, std.mem.readInt(u32, out.digest[4 * j ..][0..4], .little));
    }
    const output = try frame.finish();
    const digest = digestWords(words.items);
    if (!trace_only) for (output.words, 0..) |word, i| if (circuit.builder.ivalue.unpackU32(C.Q, ctx.get(word.get())) != std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) return error.NativeGroupFrameDigest;
    var outputs: [8]C.Var = undefined;
    for (&outputs, output.words) |*var_id, word| var_id.* = word.get();
    try ctx.setOutputs(&outputs);
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    if (!trace_only and !try ctx.isCircuitValid()) return error.NativeGroupCircuitRejects;
    return .{ .a = a, .ctx = ctx, .frames = frames, .words = try words.toOwnedSlice(a), .digest = digest, .range = range };
}
