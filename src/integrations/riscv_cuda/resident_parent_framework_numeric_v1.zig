//! Offline numerical oracle. Expected values are test artifacts, never inputs
//! to the resident prover or its dynamic parameter assembly.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const U = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");
const Program = @import("resident_parent_program_v1.zig");
const Plan = @import("resident_parent_framework_plan_v1.zig");
const Base = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
pub fn exportVectors(a: std.mem.Allocator, path: []const u8) !void {
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    const prog = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer prog.deinit();
    const generated = try @import("resident_parent_framework_codegen_v1.zig").generate(a, prog);
    defer a.free(generated);
    try source.writer.writeAll(generated);
    try dir.writeFile(.{ .sub_path = "framework_util.cu", .data = source.written() });
    try dir.writeFile(.{ .sub_path = "numeric_runner.cu", .data = @embedFile("resident_parent_framework_numeric_runner_v1.cpp") });
    const p = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var plan = try Plan.Plan.init(a, p, .{});
    defer plan.deinit();
    var bytes: std.Io.Writer.Allocating = .init(a);
    defer bytes.deinit();
    try word(&bytes.writer, 75);
    for (0..3) |variant| {
        var draws: [94]Q = undefined;
        for (&draws, 0..) |*q, i| q.* = if (variant == 0) Q.one() else Q.fromU32Unchecked(@intCast(0x7ffffffe - i), @intCast(i * 13 + variant), @intCast(i * 123 + 19), @intCast(i * 7 + 33));
        const relations = U.UniversalRelations.fromDraws(&draws);
        for (plan.cohorts, p.view().cohorts, 0..) |c, cohort, index| {
            try qs(&bytes.writer, &draws);
            try words(&bytes.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(c.routes)));
            var expected: std.ArrayList(Q) = .empty;
            defer expected.deinit(a);
            for (c.routes) |r| {
                const e = &relations.elements[r.domain];
                try expected.append(a, e.z);
                try expected.appendSlice(a, e.alpha_powers[0..r.arity]);
            }
            try qs(&bytes.writer, expected.items);
            const count: u32 = @intCast(1 + index * 17);
            try word(&bytes.writer, count);
            const alpha = draws[(index * 3) % 94];
            try qs(&bytes.writer, &.{alpha});
            const powers = try a.alloc(Q, count);
            defer a.free(powers);
            var v = Q.one();
            for (powers) |*q| {
                q.* = v;
                v = v.mul(alpha);
            }
            try qs(&bytes.writer, powers);
            const factor: u32 = if (index < 23) @as(u32, 1) << @intCast(31 - cohort.trace_log) else 1;
            try word(&bytes.writer, factor);
            try qs(&bytes.writer, &.{draws[index]});
            try qs(&bytes.writer, &.{draws[index].mulM31(core.fields.m31.M31.fromCanonical(factor))});
        }
    }
    try counterCases(a, &bytes.writer, &plan);
    try dir.writeFile(.{ .sub_path = "numeric.bin", .data = bytes.written() });
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source.written(), &hash, .{});
    const doc = .{ .schema = "stwo-resident-framework-parameters-v1", .source_sha256 = std.fmt.bytesToHex(hash, .lower), .cases = 75, .scope = "GPU relation and composition parameter assembly; complete resident proof pending", .cpu_challenges_as_ingress = "numeric oracle only" };
    const json = try std.json.Stringify.valueAlloc(a, doc, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = "source_manifest.json", .data = json });
}
fn word(w: anytype, x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try w.writeAll(&b);
}
fn words(w: anytype, x: []align(1) const u32) !void {
    try word(w, @intCast(x.len));
    for (x) |v| try word(w, v);
}
fn qs(w: anytype, x: []const Q) !void {
    try word(w, @intCast(x.len * 4));
    for (x) |q| for (q.toM31Array()) |m| try word(w, m.toU32());
}

fn counterCases(a: std.mem.Allocator, w: anytype, plan: *const Plan.Plan) !void {
    const M = core.fields.m31.M31;
    const Counter = @import("../../frontends/riscv/air/lookups/tables/counter.zig").Counter;
    const p = plan.program.view();
    try word(w, 23);
    for (p.programs[0..23], plan.cohorts[0..23], p.cohorts[0..23], 0..) |*pr, c, cohort, index| {
        const rows = @as(usize, 1) << @intCast(cohort.trace_log);
        const source = try a.alloc(u32, (cohort.columns[0] + cohort.columns[1]) * rows);
        defer a.free(source);
        @memset(source, 0);
        const input = try a.alloc(M, pr.inputs.len);
        defer a.free(input);
        const nodes = try a.alloc(M, pr.lookup_nodes.len);
        defer a.free(nodes);
        var tables = [_]Counter{ try Counter.init(a, .bitwise), try Counter.init(a, .range_check_8_8) };
        defer for (&tables) |*t| t.deinit(a);
        for (0..rows) |row| {
            for (pr.inputs, input, 0..) |entry, *v, i| v.* = switch (entry) {
                .profile_parameter => |k| M.fromCanonical(c.profile[k]),
                .trace_column => M.fromCanonical(source[@as(usize, @intCast(c.offsets_trace[i])) + row]),
            };
            for (pr.lookup_nodes, 0..) |n, i| nodes[i] = switch (n.op) {
                .constant => M.fromCanonical(n.value),
                .column => input[n.value],
                .add => nodes[n.lhs].add(nodes[n.rhs]),
                .sub => nodes[n.lhs].sub(nodes[n.rhs]),
                .mul => nodes[n.lhs].mul(nodes[n.rhs]),
                .neg => nodes[n.lhs].neg(),
            };
            for (pr.entries) |e| {
                const ti: usize = if (e.domain == 6) 0 else if (e.domain == 10) 1 else continue;
                var tuple: [4]M = undefined;
                for (tuple[0..e.arity], e.values[0..e.arity]) |*v, k| v.* = nodes[k];
                try tables[ti].registerBase(nodes[e.numerator], tuple[0..e.arity]);
            }
        }
        try word(w, @intCast(index));
        try word(w, @intCast(rows));
        try words(w, source);
        try words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(c.offsets_trace)));
        try words(w, c.profile);
        try word(w, c.relation_count * 4);
        for (&tables) |*t| {
            const col = try t.committedColumn(a);
            defer a.free(col);
            var sparse: std.ArrayList(u32) = .empty;
            defer sparse.deinit(a);
            for (col, 0..) |m, i| if (!m.isZero()) {
                try sparse.append(a, @intCast(i));
                try sparse.append(a, m.v);
            };
            try words(w, sparse.items);
        }
    }
}
