const std = @import("std");
const core = @import("stwo_core");
const P = @import("resident_native_projection_program_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Shape = @import("../../frontends/riscv/air/statement.zig").Blake3ExecutionStatement;
const Canonical = @import("../../frontends/riscv/prover/block_v7_native_relation_layout_v1.zig");
const Q2 = @import("../../frontends/riscv/prover/block_v7_degree_bounded_relation_layout_v1.zig");
const U = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub fn shapeFor(family: Trace.OpcodeFamily) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = family, .log_size = 1, .n_rows = 1, .n_columns = @intCast(Trace.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../frontends/riscv/air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../frontends/riscv/air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}
fn value(i: usize) Q {
    return Q.fromM31Array(.{ M.fromU64(i * 7 + 11), M.fromU64(i * 13 + 19), M.fromU64(i * 23 + 29), M.fromU64(i * 31 + 37) });
}
test "resident native projections exact original every physical slot q3 q2" {
    const a = std.testing.allocator;
    var count: usize = 0;
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try U.UniversalRelations.draw(a, &channel);
    inline for (.{ Canonical, Q2 }) |Layout| for (0..Trace.N_FAMILIES) |fi| {
        var shape = shapeFor(@enumFromInt(fi));
        var layout = try Layout.Layout.init(a, &shape, 0, 1);
        defer layout.deinit();
        for (layout.slots) |slot| for ([_]P.Mode{ .fractions, .equation }) |mode| {
            var p = try P.Owned.init(a, slot, mode);
            defer p.deinit();
            try p.validate();
            const flat = try a.alloc(Q, p.bindings.len);
            defer a.free(flat);
            const main = try a.alloc(Q, slot.width);
            defer a.free(main);
            for (main, 0..) |*out, i| out.* = value(i);
            var current: [4]Q = undefined;
            var previous: [4]Q = undefined;
            for (&current, &previous, 0..) |*out, *prior, i| {
                out.* = value(512 + i);
                prior.* = value(520 + i);
            }
            const normalized = value(530);
            const relation = relations.get(P.domain(slot));
            for (flat, p.bindings) |*out, b| out.* = switch (b.kind) {
                .main => main[b.index],
                .current => current[b.index],
                .previous => previous[b.index],
                .z => relation.z,
                .alpha => relation.alpha,
                .normalized => normalized,
            };
            const values = try a.alloc(Q, p.circuit.nodes.len);
            defer a.free(values);
            p.circuit.evaluateInto(flat, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
            const pair = try P.Source.fromCommittedMain(slot, main, &relations);
            const expected = if (mode == .fractions) [2]Q{ pair.numerator(), pair.denominator() } else [2]Q{ Q.fromPartialEvals(current).sub(Q.fromPartialEvals(previous)).add(normalized).mul(pair.denominator()).sub(pair.numerator()), Q.zero() };
            for (p.circuit.outputs, 0..) |root, i| try std.testing.expect(expected[i].eql(values[root]));
            if (mode == .equation) {
                flat[flat.len - 1] = normalized.add(Q.one());
                p.circuit.evaluateInto(flat, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
                try std.testing.expect(values[p.circuit.outputs[0]].sub(expected[0]).eql(pair.denominator()));
            }
            const old = p.slot.degree;
            p.slot.degree += 1;
            try std.testing.expectError(error.InvalidNativeProjectionProgram, p.validate());
            p.slot.degree = old;
            count += 1;
        };
    };
    std.debug.print("native projection exact physical programs={d}\n", .{count});
}
