//! Scoped recursive constructor qualification. The admitted leaf class echoes
//! fixed fixture summaries; it is deliberately not an Ethereum native leaf.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const S = CPU.rv64_om31_typed_summary;
const T = CPU.rv64_vk_table;
const Fold = CPU.rv64_om31_typed_fold;
const R = CPU.rv64_outer_hybrid_receiver;
const Device = CPU.rv64_outer_hybrid_device;
const Wire = CPU.rv64_outer_hybrid_wire;
const Wrap = CPU.rv64_om31_outer_wrap;
const RV = CPU.rv64_root_verify;
const Native = @import("rv64/pcs_native.zig");
const Trace = @import("rv64/trace_commit.zig");
const Composition = @import("rv64/resident_composition.zig");
const Source = @import("rv64/outer_source.zig");
const a = std.heap.page_allocator;
const Q = Outer.protocol.Q;
const Context = Circuit.builder.Context(Q);
const profile: Outer.protocol.Profile = .m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1;
fn summaries(header: [32]u8) [2]S.Native {
    var first = S.Native{ .tnat = @splat(11), .trec = header, .image = @splat(12), .statement = @splat(13), .chi = @splat(14), .lo = 0, .hi = 0, .count = 1, .m_in = @splat(21), .m_out = @splat(22), .s_in = @splat(31), .s_out = @splat(32), .bus = @splat(Outer.protocol.O.zero()), .mass = .{ 1, 2, 3 }, .ctr_in = @splat(0), .ctr_out = @splat(0), .steps_in = 0, .steps_out = 5, .expected = @splat(15), .output = @splat(0), .output_seen = false, .depth = 0 };
    first.ctr_out[0] = 1;
    var last = first;
    last.lo = 1;
    last.hi = 1;
    last.m_in = first.m_out;
    last.m_out = @splat(23);
    last.s_in = first.s_out;
    last.s_out = @splat(33);
    last.ctr_in = first.ctr_out;
    last.ctr_out[0] = 2;
    last.steps_in = first.steps_out;
    last.steps_out = 9;
    last.mass = .{ 4, 5, 6 };
    last.output_seen = true;
    last.output = @splat(41);
    return .{ first, last };
}
fn outputs(summary: S.Native) [S.N_WORDS]Q {
    var out: [S.N_WORDS]Q = undefined;
    for (&out, summary.words()) |*value, word| value.* = Circuit.builder.ivalue.packU32(Q, word);
    return out;
}
fn echoGraph(summary: S.Native) !Context {
    var ctx = try Context.initTraceOnly(a, S.N_WORDS);
    errdefer ctx.deinit();
    var vars: [S.N_WORDS]Circuit.builder.Var = undefined;
    for (&vars, outputs(summary)) |*out, value| out.* = try ctx.guess(value);
    try ctx.setOutputs(&vars);
    try ctx.finalize(false);
    try Circuit.common.finalize.padToTargets(Q, &ctx, Circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    return ctx;
}
fn file(dir: std.fs.Dir, name: []const u8) ![]u8 {
    return dir.readFileAlloc(a, name, Wire.MAX_BYTES);
}
fn received(key: *const R.Key, bytes: []const u8, expected: S.Native) !Wire.Owned {
    var result = try Wire.decode(a, key, bytes);
    errdefer result.deinit();
    try Wrap.requireOutputs(result.base.outputs, &outputs(expected));
    var capture = try key.verify(a, result.base.outputs, result.base.claims, &result.section, &result.base.proof);
    defer capture.deinit(a);
    return result;
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const proving = args.len == 4 and std.mem.eql(u8, args[1], "--prove");
    const deriving = args.len == 3 and std.mem.eql(u8, args[1], "--derive");
    const verifying = args.len == 4 and std.mem.eql(u8, args[1], "--verify");
    if (!proving and !deriving and !verifying) return error.UsageTypedPair;
    if (Outer.protocol.active() != profile) return error.TypedPairProfileRequired;
    const directory = if (proving) args[3] else args[2];
    try std.fs.cwd().makePath(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    // The echo PP is independent of the public summary words. Derive its key
    // first, then use that source-derived key in the fixture admission table.
    var prototype = try echoGraph(summaries(@splat(0))[0]);
    defer prototype.deinit();
    var pp = try Circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &prototype.circuit);
    defer pp.deinit(a);
    var authority = try Outer.prove.Authority.init(a, &pp);
    defer authority.deinit();
    var key = try R.Key.init(a, &authority, 256);
    defer key.deinit();
    const entry = T.RecEntry{ .kind = .leaf, .family = 1, .rung = 0, .profile = @intFromEnum(profile) + 1, .identity = key.identity, .fixed_root = authority.fixedRoot() };
    var table = try T.buildRec(a, &.{entry});
    defer table.deinit();
    const expected = summaries(T.recHeader(&table));
    const combined = try S.Native.combine(&expected);
    if (verifying) {
        const artifact = try file(dir, "derived-key.json");
        defer a.free(artifact);
        // The caller supplies the independent derivation artifact's hash.
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(artifact, &digest, .{});
        var wanted: [32]u8 = undefined;
        if (args[3].len != 64) return error.TypedPairKeyPin;
        _ = try std.fmt.hexToBytes(&wanted, args[3]);
        if (!std.mem.eql(u8, &digest, &wanted)) return error.TypedPairKeyPin;
        const parsed = try std.json.parseFromSlice(RV.VerifierKey, a, artifact, .{});
        defer parsed.deinit();
        var stub: Circuit.common.preprocessed.PreprocessedCircuit = undefined;
        var root_source = try parsed.value.authority(a, &stub);
        defer root_source.deinit();
        var root_key = try R.Key.init(a, &root_source, 256);
        defer root_key.deinit();
        const proof = try file(dir, "root.hom31");
        defer a.free(proof);
        var decoded = try received(&root_key, proof, combined);
        defer decoded.deinit();
        std.debug.print("HYBRID_TYPED_PAIR_ROOT_ONLY_OK outputs={} leaves=2 depth={} bytes={}\n", .{ S.N_WORDS, combined.depth, proof.len });
        return;
    }
    var native: ?Native.Context = if (proving) try Native.Context.init(args[2], 0, 28 << 30) else null;
    defer if (native) |*value| value.deinit();
    var trace: ?Trace.Context = if (native) |*value| try Trace.Context.init(value) else null;
    defer if (trace) |*value| value.deinit();
    var composition: ?Composition.Context = if (native) |*value| try Composition.Context.initNumerical(a, value) else null;
    defer if (composition) |*value| value.deinit();
    var source: ?Source.Context = if (native) |*value| try Source.Context.init(a, value, &trace.?, &composition.?) else null;
    defer if (source) |*value| value.deinit();
    const factory = if (source) |*value| try value.factoryForHybrid() else null;
    if (proving) for (expected, 0..) |summary, i| {
        var ctx = try echoGraph(summary);
        defer ctx.deinit();
        var result = try Device.proveFromCircuit(a, &key, &ctx, &outputs(summary), @intCast(i), factory.?, null);
        defer result.deinit();
        const bytes = try Wire.encode(a, &key, result.base.outputs, result.base.claims, &result.section, &result.base.proof.proof);
        defer a.free(bytes);
        const name = if (i == 0) "left.hom31" else "right.hom31";
        try dir.writeFile(.{ .sub_path = name, .data = bytes });
    };
    const left_bytes = try file(dir, "left.hom31");
    defer a.free(left_bytes);
    const right_bytes = try file(dir, "right.hom31");
    defer a.free(right_bytes);
    var left = try received(&key, left_bytes, expected[0]);
    defer left.deinit();
    var right = try received(&key, right_bytes, expected[1]);
    defer right.deinit();
    var cap_left = try key.verify(a, left.base.outputs, left.base.claims, &left.section, &left.base.proof);
    defer cap_left.deinit(a);
    var cap_right = try key.verify(a, right.base.outputs, right.base.claims, &right.section, &right.base.proof);
    defer cap_right.deinit(a);
    // Borrow the real decoded STARK proof. Wire.Owned retains sole ownership;
    // these views are never deinitialized, and no prover auxiliary is needed.
    const asProduced = struct {
        fn get(value: *const Wire.Owned) Outer.prove.Produced {
            return .{ .allocator = a, .outputs = value.base.outputs, .claims = value.base.claims, .proof = .{ .proof = value.base.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = .{ .items = &.{} }, .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } } };
        }
    }.get;
    const left_produced = asProduced(&left);
    const right_produced = asProduced(&right);
    const children = [_]Fold.Child{
        .{ .proof = .{ .authority = &authority, .produced = &left_produced, .capture = &cap_left, .hybrid = .{ .key = &key, .section = &left.section } }, .entry = entry, .index = 0 },
        .{ .proof = .{ .authority = &authority, .produced = &right_produced, .capture = &cap_right, .hybrid = .{ .key = &key, .section = &right.section } }, .entry = entry, .index = 0 },
    };
    var graph = try Fold.build(a, &children, &table, true);
    defer graph.deinit();
    if (!std.mem.eql(u32, &graph.summary.words(), &combined.words())) return error.TypedPairSummary;
    try Circuit.common.finalize.padToTargets(Q, &graph.ctx, Circuit.common.finalize.computePaddedSizes(.fromBuilder(&graph.ctx.circuit)));
    if (deriving) {
        var root_pp = try Circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &graph.ctx.circuit);
        defer root_pp.deinit(a);
        var root_source = try Outer.prove.Authority.init(a, &root_pp);
        defer root_source.deinit();
        const compact = try RV.VerifierKey.fromAuthority(&root_source);
        const encoded = try std.json.Stringify.valueAlloc(a, compact, .{});
        defer a.free(encoded);
        try dir.writeFile(.{ .sub_path = "derived-key.json", .data = encoded });
        std.debug.print("HYBRID_TYPED_PAIR_DERIVED outputs={} vars={} source_only_echo_class=true\n", .{ S.N_WORDS, graph.ctx.circuit.n_vars });
        return;
    }
    var prep = try Wrap.prepareHostForOutputs(a, &graph.ctx, factory.?, S.N_WORDS);
    defer prep.deinit(a);
    var staged = try Wrap.proveDeviceForOutputs(a, &graph.ctx, &prep, &outputs(combined), 2, factory.?, true);
    var owned = true;
    defer if (owned) staged.deinit(a);
    var result = try Wrap.finishProvedForOutputs(a, &staged, &outputs(combined), @splat(0));
    owned = false;
    defer result.deinit();
    const bytes = try result.serialize(a);
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = "root.hom31", .data = bytes });
    std.debug.print("HYBRID_TYPED_PAIR_PROVED outputs={} vars={} bytes={} leaves={} depth={}\n", .{ S.N_WORDS, graph.ctx.circuit.n_vars, bytes.len, combined.count, combined.depth });
}
