//! M9 outer GKR node prototype (STWO_RV64_M9_OUTER_GKR, default off): flag, run-time classes for
//! the real D2 leaf shape, end-to-end CPU node round from the original tuple authority, tamper
//! rejection, and the shape-only verifier cost pinned against an honest section.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("profile.zig");
const S = @import("section.zig");
const CG = @import("circuit.zig");
const N = @import("m9_node.zig");
const O = core.fields.om31.OM31;
const a = std.testing.allocator;

/// CPU-provable copy of the real D2 CPU leaf roster (every row log - 12; lane groups unchanged).
const SHIFT: u8 = 12;

test "outer GKR m9 flag: default off, 1 on, anything else refused" {
    try std.testing.expectEqual(N.Selection.off, try N.selectionFrom(null));
    try std.testing.expectEqual(N.Selection.off, try N.selectionFrom("0"));
    try std.testing.expectEqual(N.Selection.on, try N.selectionFrom("1"));
    try std.testing.expectError(error.InvalidM9OuterGkrFlag, N.selectionFrom("true"));
    try std.testing.expectError(error.InvalidM9OuterGkrFlag, N.selectionFrom(""));
}

test "outer GKR m9 real D2 leaf class: row logs, roster, layers, facts, id and versions" {
    const logs = N.rowLogs(N.LEAF_CPU_D2_RAW);
    try std.testing.expectEqualSlices(u8, &.{ 18, 23, 19, 20, 22, 16, 20, 8, 14, 18, 16 }, &logs);
    var v2 = try N.classFor(a, "leaf-cpu-d2", logs, .cyclic_eq_v2);
    defer v2.deinit(a);
    var v1 = try N.classFor(a, "leaf-cpu-d2", logs, .legacy_v1);
    defer v1.deinit(a);
    // blake 26 = 16+8+2, triple 12 = 8+4, m31 5 = 4+1, xor12 16: 8 instances, as the M5 classes.
    try std.testing.expectEqual(@as(usize, 8), v2.class.instances.len);
    try std.testing.expectEqual(@as(u32, 26), v2.class.layers());
    // 26*2^22 + 12*2^19 + 5*2^20 + 16*2^20 fractions.
    try std.testing.expectEqual(@as(u64, 26 << 22) + (12 << 19) + (5 << 20) + (16 << 20), N.facts(&v2.class));
    try std.testing.expectEqual(@as(u32, 0x9), v2.class.id >> 28);
    try std.testing.expect(N.classId(N.scaled(logs, 1)) != v2.class.id);
    var h1: [12 + P.MAX_INSTANCES]u32 = undefined;
    var h2: [12 + P.MAX_INSTANCES]u32 = undefined;
    const x1 = try v1.class.header(&h1);
    const x2 = try v2.class.header(&h2);
    try std.testing.expect(!std.mem.eql(u32, x1, x2));
    // The scaled copy keeps the roster (same components, groups and lane logs).
    var small = try N.classFor(a, "leaf-cpu-d2-s12", N.scaled(logs, SHIFT), .cyclic_eq_v2);
    defer small.deinit(a);
    for (small.class.instances, v2.class.instances) |s, r| {
        try std.testing.expectEqual(r.component, s.component);
        try std.testing.expectEqual(r.group, s.group);
        try std.testing.expectEqual(r.lane_log, s.lane_log);
    }
}

test "outer GKR m9 node round on the real D2 leaf roster: tuples -> section -> receiver -> v2 binding -> circuit" {
    var small = try N.classFor(a, "leaf-cpu-d2-s12", N.scaled(N.rowLogs(N.LEAF_CPU_D2_RAW), SHIFT), .cyclic_eq_v2);
    defer small.deinit(a);
    const r = try N.runNode(a, &small.class, 0x24628607);
    try std.testing.expect(r.native_verified and r.closure_ok and r.terminal_ok);
    try std.testing.expect(r.closure_wrong_rejected);
    try std.testing.expectEqual(@as(u32, 4), r.binding_components);
    try std.testing.expect(r.binding_wrong_target_rejected);
    try std.testing.expect(r.circuit_valid);
    try std.testing.expect(r.circuit_tamper_rejected);
    std.debug.print("\nOUTER_GKR_M9_NODE {f}\n", .{std.json.fmt(r, .{})});
}

test "outer GKR m9 every round-coefficient word tamper of a node section is rejected natively and in circuit" {
    var small = try N.classFor(a, "leaf-cpu-d2-s15", N.scaled(N.rowLogs(N.LEAF_CPU_D2_RAW), 15), .cyclic_eq_v2);
    defer small.deinit(a);
    const class = &small.class;
    const elements = blk: {
        const W = @import("stwo_circuit_cpu_integration").om31.witness;
        break :blk W.Elements.init(O.fromBase(core.fields.m31.M31.fromCanonical(77)), O.fromBase(core.fields.m31.M31.fromCanonical(1234567)));
    };
    var inputs = try N.nodeInputs(a, class, &elements, 9);
    defer inputs.deinit(a);
    const start = S.benchChannel();
    var section = try S.proveCpu(a, &start, class, &inputs);
    defer section.deinit(a);
    const words = try S.encode(a, &section);
    defer a.free(words);
    var c0 = S.benchChannel();
    var honest = try S.verify(a, &c0, &section);
    defer honest.deinit(a);
    const external = honest.root_sum.neg();
    const terminal = try S.terminalExpected(a, &inputs, &honest);
    defer a.free(terminal);
    // Round-coefficient words: after header (5), salt (8), roots (16 per instance); sample every 7th.
    const first = 5 + 8 + 16 * class.instances.len;
    var checked: usize = 0;
    var i: usize = first;
    while (i < words.len) : (i += 7) {
        const saved = words[i];
        words[i] = (saved + 1) % core.fields.m31.Modulus;
        defer words[i] = saved;
        var bad = S.decode(a, class, words) catch {
            checked += 1;
            continue;
        };
        defer bad.deinit(a);
        var ch = S.benchChannel();
        const native_ok = blk: {
            var v = S.verify(a, &ch, &bad) catch break :blk false;
            defer v.deinit(a);
            S.requireClosure(&v, external) catch break :blk false;
            S.requireTerminal(&v, terminal) catch break :blk false;
            break :blk true;
        };
        try std.testing.expect(!native_ok);
        if (checked % 16 == 0) {
            const cost = try CG.measure(a, &bad, external, terminal);
            try std.testing.expect(!cost.valid);
        }
        checked += 1;
    }
    try std.testing.expect(checked > 20);
}

test "outer GKR m9 shape-only verifier cost equals the honest section's gate counts (v1 and v2)" {
    for ([_]P.BindingVersion{ .legacy_v1, .cyclic_eq_v2 }) |version| {
        for ([_]u8{ 12, 14 }) |shift| {
            var small = try N.classFor(a, "leaf-cpu-d2-scaled", N.scaled(N.rowLogs(N.LEAF_CPU_D2_RAW), shift), version);
            defer small.deinit(a);
            const elements = @import("stwo_circuit_cpu_integration").om31.witness.Elements.init(O.fromBase(core.fields.m31.M31.fromCanonical(5)), O.fromBase(core.fields.m31.M31.fromCanonical(11)));
            var inputs = try N.nodeInputs(a, &small.class, &elements, shift);
            defer inputs.deinit(a);
            const start = S.benchChannel();
            var section = try S.proveCpu(a, &start, &small.class, &inputs);
            defer section.deinit(a);
            var c = S.benchChannel();
            var v = try S.verify(a, &c, &section);
            defer v.deinit(a);
            const honest = try CG.measure(a, &section, v.root_sum.neg(), null);
            try std.testing.expect(honest.valid);
            const shape = try N.verifierCost(a, &small.class);
            try std.testing.expectEqual(honest.blake_g_gate, shape.blake_g_gate);
            try std.testing.expectEqual(honest.qm31_ops, shape.qm31_ops);
            try std.testing.expectEqual(honest.m31_to_u32, shape.m31_to_u32);
            try std.testing.expectEqual(honest.triple_xor, shape.triple_xor);
            try std.testing.expectEqual(honest.eq, shape.eq);
            try std.testing.expectEqual(honest.draws, shape.draws);
        }
    }
}
