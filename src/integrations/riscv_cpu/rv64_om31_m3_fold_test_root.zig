//! M3 recursion-size qualification on the CPU outer prover:
//! - per outer profile (r1 b2/q108/p20, m3 b4/q51/p26, m3 b8/q34/p26) and
//!   fold arity (2, 4), the exact fold verifier circuit size (variables,
//!   padded rows, assignment tasks, dependency levels, Blake G gates);
//! - an m3 4-ary fold root proved on CPU and accepted by a fresh receiver
//!   whose authority is rebuilt from its own trace-only graph, with tamper,
//!   cross-profile and wrong-arity rejection.
//! Prints `M3_FOLD_CENSUS {json}` lines; the receipt is copied from the log.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Bridge = @import("rv64_recursion/om31_outer.zig");
const Census = @import("rv64_recursion/om31_native/schedule_census.zig");
const Q = Outer.protocol.Q;
const B = circuit.builder;
const Word = B.wrappers.U32Wrapper(B.Var);

const Child = struct {
    ctx: B.Context(Q),
    pp: circuit.common.preprocessed.PreprocessedCircuit,
    authority: Outer.prove.Authority,
    produced: Outer.prove.Produced,
    capture: Outer.prove.Capture,
    vars: usize,
    fn deinit(self: *Child, a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.produced.deinit();
        self.authority.deinit();
        self.pp.deinit(a);
        self.ctx.deinit();
    }
    fn view(self: *const Child) Bridge.Child {
        return .{ .authority = &self.authority, .produced = &self.produced, .capture = &self.capture };
    }
};

/// A child circuit with `blocks` chained Blake2s compressions (a stand-in for
/// a leaf wrapper's dominant gadget) and 8 public digest outputs.
fn makeChild(a: std.mem.Allocator, blocks: usize, seed: u32) !*Child {
    const self = try a.create(Child);
    errdefer a.destroy(self);
    self.ctx = try B.Context(Q).init(a, 8);
    errdefer self.ctx.deinit();
    var state: [8]Word = undefined;
    for (&state, 0..) |*w, i| w.* = .newUnsafe(try self.ctx.guess(B.wrappers.u32Value(Q, seed +% @as(u32, @intCast(i)) *% 0x9e3779b9).get()));
    for (0..blocks) |b| {
        var message: [16]Word = undefined;
        @memcpy(message[0..8], &state);
        for (message[8..], 0..) |*w, i| w.* = .newUnsafe(try self.ctx.guess(B.wrappers.u32Value(Q, @as(u32, @intCast(b * 8 + i)) ^ seed).get()));
        state = (try B.blake.blake2sU32s(Q, &self.ctx, &message, 64)).words;
    }
    var outputs: [8]B.Var = undefined;
    for (&outputs, state) |*out, w| out.* = w.get();
    try self.ctx.setOutputs(&outputs);
    try self.ctx.finalize(true);
    try circuit.common.finalize.padToTargets(Q, &self.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&self.ctx.circuit)));
    self.vars = self.ctx.circuit.n_vars;
    self.pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &self.ctx.circuit);
    errdefer self.pp.deinit(a);
    self.authority = try Outer.prove.Authority.init(a, &self.pp);
    errdefer self.authority.deinit();
    self.produced = try Outer.prove.prove(a, &self.authority, self.ctx.values());
    errdefer self.produced.deinit();
    self.capture = try Outer.prove.verify(a, &self.authority, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    self.authority.retireProverData();
    return self;
}

const Row = struct {
    profile: []const u8,
    arity: usize,
    child_blocks: usize,
    child_padded_vars: usize,
    child_max_log: u32,
    fold_vars: usize,
    fold_padded_vars: usize,
    fold_max_log: u32,
    tasks: usize,
    levels: usize,
    blake_g_gates: usize,
    qm31_rows: usize,
    graph_ns: u64,
    plan_ns: u64,
};

fn census(a: std.mem.Allocator, profile: Outer.protocol.Profile, kids: []const Bridge.Child, blocks: usize, child: *const Child) !Row {
    var timer = try std.time.Timer.start();
    var graph = try Bridge.buildFoldTraceOnly(a, kids);
    defer graph.deinit();
    const graph_ns = timer.lap();
    const vars = graph.ctx.circuit.n_vars;
    const blake = graph.ctx.circuit.blake_g_gate.items.len;
    const qm31 = graph.ctx.circuit.nQm31OpsRows();
    try circuit.common.finalize.padToTargets(Q, &graph.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&graph.ctx.circuit)));
    timer.reset();
    var plan = try B.witness_plan.build(a, &graph.ctx);
    defer plan.deinit();
    const plan_ns = timer.lap();
    const c = try Census.inspect(plan.level_ends, plan.tasks.len);
    _ = c;
    var fold_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &graph.ctx.circuit);
    defer fold_pp.deinit(a);
    const fold_layout = fold_pp.layout();
    const fold_logs = try circuit.common.component_list.circuitComponentLogSizes(&fold_layout);
    const child_layout = child.pp.layout();
    const child_logs = try circuit.common.component_list.circuitComponentLogSizes(&child_layout);
    return .{ .profile = profile.name(), .arity = kids.len, .child_blocks = blocks, .child_padded_vars = child.vars, .child_max_log = std.mem.max(u32, &child_logs.toArray()), .fold_vars = vars, .fold_padded_vars = graph.ctx.circuit.n_vars, .fold_max_log = std.mem.max(u32, &fold_logs.toArray()), .tasks = plan.tasks.len, .levels = plan.level_ends.len, .blake_g_gates = blake, .qm31_rows = qm31, .graph_ns = graph_ns, .plan_ns = plan_ns };
}

fn blocksFromEnv() usize {
    var buffer: [16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const text = std.process.getEnvVarOwned(fba.allocator(), "STWO_M3_CHILD_BLOCKS") catch return 4;
    return std.fmt.parseInt(usize, text, 10) catch 4;
}

test "M3 fold census: profile x arity verifier circuit sizes" {
    const a = std.heap.smp_allocator;
    const before = Outer.protocol.active();
    defer Outer.protocol.selectForTesting(before);
    var sizes: [2]usize = .{ 4, blocksFromEnv() };
    const n_sizes: usize = if (sizes[1] == sizes[0]) 1 else 2;
    for (sizes[0..n_sizes]) |blocks| {
        for ([_]Outer.protocol.Profile{ .r1_b2_q108_p20_fold4, .m3_b4_q51_p26_fold4, .m3_b8_q34_p26_fold4 }) |profile| {
            Outer.protocol.selectForTesting(profile);
            var kids: [4]*Child = undefined;
            var made: usize = 0;
            defer for (kids[0..made]) |k| {
                k.deinit(a);
                a.destroy(k);
            };
            for (&kids, 0..) |*k, i| {
                k.* = try makeChild(a, blocks, 0x1000 * @as(u32, @intCast(i + 1)));
                made += 1;
            }
            var views: [4]Bridge.Child = undefined;
            for (&views, kids) |*v, k| v.* = k.view();
            for ([_]usize{ 2, 4 }) |arity| {
                const row = try census(a, profile, views[0..arity], blocks, kids[0]);
                std.debug.print("M3_FOLD_CENSUS {f}\n", .{std.json.fmt(row, .{})});
            }
        }
    }
}

test "M3 4-ary fold root proves on CPU and a fresh receiver accepts only the m3 statement" {
    const a = std.heap.smp_allocator;
    const before = Outer.protocol.active();
    defer Outer.protocol.selectForTesting(before);
    Outer.protocol.selectForTesting(.m3_b4_q51_p26_fold4);
    var kids: [4]*Child = undefined;
    var made: usize = 0;
    defer for (kids[0..made]) |k| {
        k.deinit(a);
        a.destroy(k);
    };
    for (&kids, 0..) |*k, i| {
        k.* = try makeChild(a, 2, 0x77 + @as(u32, @intCast(i)));
        made += 1;
    }
    var views: [4]Bridge.Child = undefined;
    for (&views, kids) |*v, k| v.* = k.view();
    // Wrong arity of the same children is a different digest.
    try std.testing.expect(!std.mem.eql(u8, &(try Bridge.expectedDigest(views[0..2])), &(try Bridge.expectedDigest(views[0..4]))));
    try std.testing.expectError(error.InvalidRecursiveFoldArity, Bridge.expectedDigest(views[0..1]));
    // M4 port: binary folds keep the v2 message word; k-ary words bind arity.
    try std.testing.expectEqual(Bridge.version, try Bridge.versionWord(2));
    try std.testing.expectEqual(@as(u32, 0x302), try Bridge.versionWord(3));
    try std.testing.expectEqual(@as(u32, 0x402), try Bridge.versionWord(4));
    try std.testing.expectError(error.InvalidRecursiveFoldArity, Bridge.versionWord(5));
    // M4 port: fold v2 classKey over N children. Same-geometry children with
    // different key values share a class at every arity; arities never do.
    const key2 = try Bridge.classKey(views[0..2]);
    const key3 = try Bridge.classKey(views[0..3]);
    const key4 = try Bridge.classKey(views[0..4]);
    try std.testing.expect(!std.mem.eql(u8, &key2, &key3));
    try std.testing.expect(!std.mem.eql(u8, &key3, &key4));
    try std.testing.expect(!std.mem.eql(u8, &key2, &key4));
    try std.testing.expectEqualSlices(u8, &key2, &(try Bridge.classKey(views[2..4])));
    const swapped = [4]Bridge.Child{ views[3], views[2], views[1], views[0] };
    try std.testing.expectEqualSlices(u8, &key4, &(try Bridge.classKey(&swapped)));
    try std.testing.expectError(error.InvalidRecursiveFoldArity, Bridge.classKey(views[0..1]));
    // A tampered child output must make the 4-ary fold graph unsatisfiable.
    kids[3].produced.outputs[0] = kids[3].produced.outputs[0].add(Q.one());
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, &views));
    kids[3].produced.outputs[0] = kids[3].produced.outputs[0].sub(Q.one());

    var timer = try std.time.Timer.start();
    var graph = try Bridge.buildFold(a, &views);
    defer graph.deinit();
    if (try graph.ctx.circuit.check(a, graph.ctx.values())) |failure| {
        std.debug.print("M3 fold failure={any}\n", .{failure});
        return error.InvalidOuterGraph;
    }
    try circuit.common.finalize.padToTargets(Q, &graph.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&graph.ctx.circuit)));
    var root_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &graph.ctx.circuit);
    defer root_pp.deinit(a);
    var root_key = try Outer.prove.Authority.init(a, &root_pp);
    defer root_key.deinit();
    var root = try Outer.prove.prove(a, &root_key, graph.ctx.values());
    defer root.deinit();
    const prove_ns = timer.lap();
    try std.testing.expect(std.meta.eql(root.proof.proof.commitment_scheme_proof.config, Outer.protocol.Profile.m3_b4_q51_p26_fold4.config()));
    const encoded = try Outer.wire.encode(a, root_key.identity, root.outputs, root.claims, &root.proof.proof);
    defer a.free(encoded);

    // Fresh receiver: its own trace-only fold graph, its own PP and authority.
    var receiver_graph = try Bridge.buildFoldTraceOnly(a, &views);
    defer receiver_graph.deinit();
    try std.testing.expectEqual(@as(usize, 0), receiver_graph.ctx.value_table.capacity);
    try circuit.common.finalize.padToTargets(Q, &receiver_graph.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&receiver_graph.ctx.circuit)));
    var receiver_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &receiver_graph.ctx.circuit);
    defer receiver_pp.deinit(a);
    var receiver_key = try Outer.prove.Authority.init(a, &receiver_pp);
    defer receiver_key.deinit();
    try std.testing.expectEqual(root_key.identity, receiver_key.identity);
    var decoded = try Outer.wire.decode(a, receiver_key.identity, 8, encoded);
    defer decoded.deinit();
    var fresh = try Outer.prove.verify(a, &receiver_key, decoded.outputs, decoded.claims, &decoded.proof);
    defer fresh.deinit(a);
    try Bridge_requireDigest(decoded.outputs, receiver_graph.output_digest);
    const verify_ns = timer.lap();

    // Output tamper is rejected.
    decoded.outputs[0] = decoded.outputs[0].add(Q.one());
    if (Outer.prove.verify(a, &receiver_key, decoded.outputs, decoded.claims, &decoded.proof)) |bad| {
        var owned = bad;
        owned.deinit(a);
        return error.ExpectedRootTamperRejection;
    } else |err| if (err == error.OutOfMemory) return err;
    decoded.outputs[0] = decoded.outputs[0].sub(Q.one());
    // An r1 receiver refuses the m3 wire (profile header) and the m3 config.
    Outer.protocol.selectForTesting(.r1_b2_q108_p20_fold4);
    try std.testing.expectError(error.Om31CircuitWireProfile, Outer.wire.decode(a, receiver_key.identity, 8, encoded));
    try std.testing.expectError(error.InvalidOm31CircuitProof, Outer.prove.verify(a, &receiver_key, decoded.outputs, decoded.claims, &decoded.proof));
    Outer.protocol.selectForTesting(.m3_b4_q51_p26_fold4);
    // A PoW nonce flip is rejected.
    decoded.proof.commitment_scheme_proof.proof_of_work ^= 1;
    if (Outer.prove.verify(a, &receiver_key, decoded.outputs, decoded.claims, &decoded.proof)) |bad| {
        var owned = bad;
        owned.deinit(a);
        return error.ExpectedPowTamperRejection;
    } else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("M3_FOLD_ROOT {f}\n", .{std.json.fmt(.{ .profile = Outer.protocol.active().name(), .arity = 4, .fold_padded_vars = graph.ctx.circuit.n_vars, .fresh_receiver_accepted = true, .output_tamper_rejected = true, .r1_receiver_rejected = true, .pow_tamper_rejected = true, .root_wire_bytes = encoded.len, .prove_ns = prove_ns, .receiver_ns = verify_ns }, .{})});
}

fn Bridge_requireDigest(outputs: []const Q, digest: [32]u8) !void {
    for (outputs, 0..) |actual, i| {
        const value = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        if (!std.meta.eql(B.wrappers.u32Value(Q, value).get(), actual)) return error.M3RootDigestMismatch;
    }
}
