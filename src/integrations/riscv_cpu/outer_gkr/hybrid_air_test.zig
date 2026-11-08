const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_circuit_cpu_integration");
const circuit = @import("stwo_circuit_frontend");
const H = @import("hybrid_air.zig");
const T = @import("tuples.zig");
const P = @import("profile.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
test "outer GKR hybrid authority keeps original MAIN roots, commits128 INTER columns, and bounds added binding roots to degree2" {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var template = try CPU.om31.prove.parsePinnedAir(a, bytes);
    defer template.deinit();
    var total: usize = 0;
    const expected = [_]usize{ 1, 11, 0, 2, 8, 1, 0, 1, 1, 1, 1 };
    for (template.components, 0..) |*source, i| {
        var artifact = try H.record(a, source, @enumFromInt(i));
        defer artifact.deinit();
        try std.testing.expectEqual(expected[i], artifact.main_constraints);
        try artifact.validate();
        total += artifact.program.roots.len;
        if (P.gkrBound(@enumFromInt(i))) for (artifact.program.inputs) |input| {
            if (input.tree == 2) try std.testing.expect(input.column < 26);
        };
    }
    try std.testing.expectEqual(@as(usize, 39), total);
    try std.testing.expectEqual(@as(u32, 128), H.interactionColumns());
    try std.testing.expectError(error.HybridComponentMismatch, H.record(a, &template.components[2], .blake_g_gate));
}
fn same(actual: T.LookupFor(O), want: circuit.witness.components.Lookup) !void {
    try std.testing.expect(actual.numerator.eql(O.fromBase(want.numerator)));
    try std.testing.expectEqual(want.len, actual.len);
    for (actual.tuple[0..actual.len], want.tuple[0..want.len]) |x, y| try std.testing.expect(x.eql(O.fromBase(y)));
}
test "outer GKR affine OODS lookup authority equals every original lookup on arbitrary MAIN rows including XOR12 source-owned FIXED" {
    const K = circuit.witness.components;
    for (0..32) |r| {
        var c: [52]M = undefined;
        var p: [11]M = undefined;
        var co: [52]O = undefined;
        var po: [11]O = undefined;
        for (&c, &co, 0..) |*x, *y, i| {
            x.* = M.fromU64(r * 43 + i * 17);
            y.* = O.fromBase(x.*);
        }
        for (&p, &po, 0..) |*x, *y, i| {
            x.* = M.fromU64(r * 29 + i * 13);
            y.* = O.fromBase(x.*);
        }
        var storage: [26]T.LookupFor(O) = undefined;
        const tx = K.triple_xor.lookups(c[0..20], .{ .in0 = p[0], .in1 = p[1], .in2 = p[2], .out = p[3], .mults = p[4] });
        for (try T.rowFor(O, .triple_xor, co[0..20], po[0..5], &storage), tx) |x, y| try same(x, y);
        const split = K.m31_to_u32.lookups(c[0..4], .{ .input = p[0], .output = p[1], .mults = p[2] });
        for (try T.rowFor(O, .m_31_to_u_32, co[0..4], po[0..3], &storage), split) |x, y| try same(x, y);
        const bgpp = K.blake_g_gate.Pp{ .inputs = p[0..6].*, .outputs = p[6..10].*, .mults = p[10] };
        const bg = K.blake_g_gate.lookups(&c, bgpp);
        for (try T.rowFor(O, .blake_g_gate, &co, &po, &storage), bg) |x, y| try same(x, y);
        const row = (r * 31991) & ((1 << 20) - 1);
        po[0] = O.fromBase(M.fromU64(row >> 10));
        po[1] = O.fromBase(M.fromU64(row & 1023));
        po[2] = O.fromBase(M.fromU64((row >> 10) ^ (row & 1023)));
        for (try T.rowFor(O, .verify_bitwise_xor_12, co[0..16], po[0..3], &storage), 0..) |x, i| {
            var want = K.Lookup{ .numerator = c[i].neg(), .len = 4 };
            want.tuple[0..4].* = K.xor_12.tupleAt(i, row);
            try same(x, want);
        }
    }
}

const HC = @import("hybrid_component.zig");
const S = @import("section.zig");
const Legacy = @import("binding.zig");
const Binding = @import("binding_v2.zig");
fn maskValue(comp: *const HC.Component, mask: *const core.air.components.ForField(O).MaskValues, tree: u8, column: usize, offset: i8) !O {
    const global = if (tree == 0) comp.source.preprocessed_indices[column] else if (tree == 1) (try CPU.om31.geometry.span(comp.source.*, 1)).start + column else H.interactionStart(comp.artifact.component) + column;
    var shifts: [8]i8 = undefined;
    var n: usize = 0;
    for (comp.artifact.program.inputs) |input| if (input.tree == tree and input.column == column) {
        var found = false;
        for (shifts[0..n]) |v| if (v == input.offset) {
            found = true;
            break;
        };
        if (!found) {
            shifts[n] = input.offset;
            n += 1;
        }
    };
    for (shifts[0..n], mask.items[tree][global]) |shift, v| if (shift == offset) return v;
    return error.MissingTestMask;
}
fn secureMask(comp: *const HC.Component, mask: *const core.air.components.ForField(O).MaskValues, column: usize, offset: i8) !O {
    var values: [8]O = undefined;
    for (&values, 0..) |*v, i| v.* = try maskValue(comp, mask, 2, column + i, offset);
    return O.fromPartialEvals(values);
}
const OriginalRead = struct {
    component: *const HC.Component,
    mask: *const core.air.components.ForField(O).MaskValues,
    fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
        const self: *const @This() = @ptrCast(@alignCast(raw));
        if (tree == 2) return O.zero();
        return maskValue(self.component, self.mask, tree, column, @intCast(offset));
    }
};
test "outer GKR hybrid PCS hook authenticates original MAIN and binding masks with source-derived OODS auxiliaries and verified terminal targets" {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var template = try CPU.om31.prove.parsePinnedAir(a, bytes);
    defer template.deinit();
    const class = P.TEST_SMALL.withBindingV2();
    var inputs = try S.synthetic(a, &class, 9813, false);
    defer inputs.deinit(a);
    var channel = S.RawChannel.init();
    var section = try S.proveCpu(a, &channel, &class, &inputs);
    defer section.deinit(a);
    var verified = try S.verify(a, &channel, &section);
    defer verified.deinit(a);
    var strict = S.StrictChannel{ .inner = channel };
    const ch = Legacy.drawChallenges(&strict, class.instances.len);
    try std.testing.expect(!strict.rejected);
    const z = channel.drawSecureFelt();
    const alpha = channel.drawSecureFelt();
    const point = try core.circle.randomSecureFieldPointFor(O, &channel);
    const fixed_logs: [45]u32 = @splat(4);
    for ([_]P.Component{ .triple_xor, .m_31_to_u_32, .blake_g_gate, .verify_bitwise_xor_12 }) |kind| {
        const source = &template.components[@intFromEnum(kind)];
        source.trace_log_size = class.row_logs[@intFromEnum(kind)];
        source.evaluation_log_size = source.trace_log_size + 1;
        var artifact = try H.record(a, source, kind);
        defer artifact.deinit();
        const params = try artifact.parameters(a, source, z, alpha, &class, &verified, &ch, O.zero());
        defer a.free(params);
        var comp = HC.Component{ .allocator = a, .source = source, .artifact = &artifact, .fixed_logs = &fixed_logs, .class = &class, .verified = &verified, .parameters = params };
        const air = comp.asVerifierComponent();
        try std.testing.expectEqual(source.trace_log_size + 1, air.maxConstraintLogDegreeBound());
        const global_log = source.trace_log_size + 2;
        var points = try comp.maskPoints(a, point, global_log);
        defer points.deinitDeep(a);
        var trees: [3][][]O = .{ try a.alloc([]O, 45), try a.alloc([]O, 114), try a.alloc([]O, 128) };
        defer for (trees) |tree| {
            for (tree) |col| a.free(col);
            a.free(tree);
        };
        for (trees) |tree| @memset(tree, &.{});
        for (points.items, 0..) |tree, t| for (tree, 0..) |col, c| {
            const global = if (t == 0) source.preprocessed_indices[c] else if (t == 1) (try CPU.om31.geometry.span(source.*, 1)).start + c else H.interactionStart(kind) + c;
            trees[t][global] = try a.alloc(O, col.len);
            for (trees[t][global]) |*v| v.* = channel.drawSecureFelt();
        };
        var mask = core.air.components.ForField(O).MaskValues{ .items = &trees };
        const actual = try comp.valuesAtPoint(a, point, &mask, global_log);
        defer a.free(actual);
        const original_params = try CPU.om31.program.parameters(a, source, z, alpha, O.zero());
        defer a.free(original_params);
        const read = OriginalRead{ .component = &comp, .mask = &mask };
        var at: usize = 0;
        for (source.parts) |part| {
            const original = try CPU.om31.program.evaluate(a, part.program, .{ .context = &read, .get = OriginalRead.get }, original_params);
            defer a.free(original);
            const keep = try H.mainRoots(a, part.program);
            defer a.free(keep);
            for (original, keep) |v, yes| if (yes) {
                try std.testing.expect(v.eql(actual[at]));
                at += 1;
            };
        }
        try std.testing.expectEqual(artifact.main_constraints, at);
        var main: [52]O = undefined;
        var pp: [11]O = undefined;
        const count = P.FACTS[@intFromEnum(kind)].main;
        for (main[0..count], 0..) |*v, c| v.* = try maskValue(&comp, &mask, 1, c, 0);
        const pn: usize = if (kind == .triple_xor) 5 else if (kind == .blake_g_gate) 11 else 3;
        for (pp[0..pn], 0..) |*v, c| v.* = try maskValue(&comp, &mask, 0, if (kind == .blake_g_gate) ([11]u8{ 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 7 })[c] else c, 0);
        var storage: [26]T.LookupFor(O) = undefined;
        const tuples = try T.rowFor(O, kind, main[0..count], pp[0..pn], &storage);
        const elements = CPU.om31.witness.Elements.init(z, alpha);
        var projection = O.zero();
        var first: usize = 0;
        for (class.instances, 0..) |inst, g| {
            if (inst.component != kind) continue;
            const weights = try Legacy.eqTable(a, verified.artifact.ood_point[class.layers() - inst.variables() .. class.layers() - inst.row_log]);
            defer a.free(weights);
            for (weights, 0..) |weight, lane| {
                const lookup = tuples[first + lane];
                var d = z.neg();
                for (lookup.tuple[0..lookup.len], elements.powers[0..lookup.len]) |v, power| d = d.add(v.mul(power));
                projection = projection.add(ch.rho[g].mul(weight).mul(lookup.numerator.add(ch.gamma.mul(d))));
            }
            first += inst.lanes_used;
        }
        var expected: [3]O = undefined;
        var sink = @import("stwo_riscv_frontend").rv64_air.evaluation.SinkFor(O){ .values = &expected };
        try Binding.evaluateFor(O, &class, kind, verified.artifact.ood_point, point, global_log, .{ .eq = try secureMask(&comp, &mask, 0, 0), .eq_next2 = try secureMask(&comp, &mask, 0, 2), .prefix = try secureMask(&comp, &mask, 8, 0), .prefix_previous = try secureMask(&comp, &mask, 8, -1) }, projection, Legacy.expectedBoundary(&class, kind, verified.artifact.claims_to_verify_by_instance, &ch), &sink);
        for (expected, actual[at..], 0..) |x, y, i| {
            if (!x.eql(y)) std.debug.print("HYBRID mismatch kind={s} root={} expected={any} actual={any}\n", .{ @tagName(kind), i, x.toM31Array(), y.toM31Array() });
            try std.testing.expect(x.eql(y));
        }
        // The actual source-owned OODS reader is also instantiated over the
        // octic child-verifier lane, rather than a duplicate binding formula.
        const Lane = @import("../rv64_recursion/om31_circuit_lane.zig");
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        Lane.begin(&ctx);
        var opened = true;
        defer if (opened) Lane.finish() catch {};
        var wire_trees: [3][][]Lane.Lane = .{ try a.alloc([]Lane.Lane, 45), try a.alloc([]Lane.Lane, 114), try a.alloc([]Lane.Lane, 128) };
        defer for (wire_trees) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        };
        for (&wire_trees, trees) |*tree, original| for (tree.*, original) |*column, values| {
            column.* = try a.alloc(Lane.Lane, values.len);
            for (column.*, values) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        };
        const wire_point = try a.alloc(Lane.Lane, verified.artifact.ood_point.len);
        defer a.free(wire_point);
        for (wire_point, verified.artifact.ood_point) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        const wire_claims = try a.alloc([]const Lane.Lane, verified.artifact.claims_to_verify_by_instance.len);
        defer {
            for (wire_claims) |values| a.free(values);
            a.free(wire_claims);
        }
        for (wire_claims, verified.artifact.claims_to_verify_by_instance) |*out, values| {
            const wires = try a.alloc(Lane.Lane, values.len);
            for (wires, values) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
            out.* = wires;
        }
        const wire_verified = struct { artifact: struct { ood_point: []const Lane.Lane, claims_to_verify_by_instance: []const []const Lane.Lane } }{ .artifact = .{ .ood_point = wire_point, .claims_to_verify_by_instance = wire_claims } };
        var wire_ch = struct { rho: [P.MAX_INSTANCES]Lane.Lane, gamma: Lane.Lane }{ .rho = undefined, .gamma = try Lane.Lane.guess(&ctx, ch.gamma) };
        for (wire_ch.rho[0..class.instances.len], ch.rho[0..class.instances.len]) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        const wire_params = try artifact.parametersFor(Lane.Lane, a, source, try Lane.Lane.guess(&ctx, z), try Lane.Lane.guess(&ctx, alpha), &class, &wire_verified, &wire_ch, Lane.Lane.zero());
        defer a.free(wire_params);
        for (wire_params, params) |wire, value| {
            try ctx.eq(wire.c0.v, try ctx.constant(value.c0));
            try ctx.eq(wire.c1.v, try ctx.constant(value.c1));
        }
        var wire_mask = core.air.components.ForField(Lane.Lane).MaskValues{ .items = &wire_trees };
        const circuit_values = try comp.valuesAtPointFor(Lane.Lane, a, .{ .x = try Lane.Lane.guess(&ctx, point.x), .y = try Lane.Lane.guess(&ctx, point.y) }, &wire_mask, global_log, wire_point, wire_params);
        defer a.free(circuit_values);
        for (circuit_values, actual) |wire, value| {
            try ctx.eq(wire.c0.v, try ctx.constant(value.c0));
            try ctx.eq(wire.c1.v, try ctx.constant(value.c1));
        }
        opened = false;
        try Lane.finish();
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        // Public auxiliary columns are excluded from PCS masks. Missing Eq is terminal.
        a.free(trees[2][H.interactionStart(kind)]);
        trees[2][H.interactionStart(kind)] = &.{};
        try std.testing.expectError(error.MissingHybridMask, comp.valuesAtPoint(a, point, &mask, global_log));
    }
}
test "outer GKR source-derived receiver key binds all hybrid IR and refuses incomplete PCS proofs before publication" {
    const R = @import("hybrid_receiver.zig");
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var template = try CPU.om31.prove.parsePinnedAir(a, bytes);
    defer template.deinit();
    var logs: [P.N_COMPONENTS]u32 = undefined;
    for (&logs, template.components) |*v, c| v.* = c.trace_log_size;
    var pp: circuit.common.preprocessed.PreprocessedCircuit = undefined;
    pp.n_outputs = 0;
    var source: CPU.om31.prove.Authority = undefined;
    source.pp = &pp;
    source.bound = template;
    source.logs = circuit.common.component_list.PerComponent(u32).fromArray(logs);
    source.identity = @splat(17);
    var key = try R.Key.init(a, &source, 1);
    defer key.deinit();
    try std.testing.expectEqual(@as(usize, 8), key.class.instances.len);
    const inter = try key.interLogs(a);
    defer a.free(inter);
    try std.testing.expectEqual(@as(usize, 128), inter.len);
    var proof: CPU.om31.protocol.Proof = undefined;
    proof.commitment_scheme_proof.commitments = .{ .items = &.{} };
    const claims = CPU.om31.witness.Claims.fromArray(@splat(O.zero()));
    var section: S.Section = undefined;
    try std.testing.expectError(error.InvalidHybridProof, key.verify(a, &.{}, claims, &section, &proof));
}
test "outer GKR hybrid device extension refuses wrong tags and contexts before casts and requires an explicit GPU backend" {
    const Device = @import("hybrid_device.zig");
    const Native = CPU.om31.device_prove;
    const Never = struct {
        fn prepare(_: *anyopaque, _: std.mem.Allocator, _: *const CPU.om31.prove.Authority, _: []const CPU.om31.protocol.Q, _: @import("stwo_prover_api").device_pcs.Scope) !Native.Source {
            return error.UnexpectedHostFallback;
        }
    };
    var context: u8 = 0;
    var other: u8 = 0;
    var factory = Native.Factory{ .context = &context, .prepare = Never.prepare };
    try std.testing.expectError(error.HybridFactoryRequired, Device.extension(factory));
    var key: @import("hybrid_receiver.zig").Key = undefined;
    var graph: circuit.builder.Context(CPU.om31.protocol.Q) = undefined;
    try std.testing.expectError(error.HybridFactoryRequired, Device.proveFromCircuit(a, &key, &graph, &.{}, 0, factory, null));
    factory.extension = .{ .tag = @splat(1), .base_context = &context, .context = &other, .interface = @ptrFromInt(1) };
    try std.testing.expectError(error.InvalidHybridFactoryExtension, Device.extension(factory));
    factory.extension.?.tag = Device.TAG;
    factory.extension.?.base_context = &other;
    try std.testing.expectError(error.InvalidHybridFactoryExtension, Device.extension(factory));
}
