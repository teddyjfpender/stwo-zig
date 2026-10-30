const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const P = @import("resident_native_projection_counter_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const A = @import("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig");
const Original = @import("resident_native_projection_program_v1.zig");
const Test = @import("resident_native_projection_test_v1.zig");
const Canonical = @import("../../frontends/riscv/prover/block_v7_native_relation_layout_v1.zig");
const Q2 = @import("../../frontends/riscv/prover/block_v7_degree_bounded_relation_layout_v1.zig");
test "resident native table counter exact original tuples and signed weights" {
    const a = std.testing.allocator;
    var count: usize = 0;
    var covered: [6]bool = @splat(false);
    inline for (.{ Canonical, Q2 }) |L| for (0..Trace.N_FAMILIES) |fi| {
        var shape = Test.shapeFor(@enumFromInt(fi));
        var layout = try L.Layout.init(a, &shape, 0, 1);
        defer layout.deinit();
        for (layout.slots) |slot| {
            _ = P.kind(slot) catch continue;
            var p = try P.Owned.init(a, slot);
            defer p.deinit();
            try p.validate();
            covered[@intFromEnum(p.table)] = true;
            const main = try a.alloc(Q, slot.width);
            defer a.free(main);
            for (main, 0..) |*v, i| v.* = Q.fromBase(M.fromU64(i * 123 + 17));
            var rec = P.Recorder(Q){ .selected = Original.domain(slot) };
            const pair = try A.Algebra(Q).projection(slot, main, &rec);
            const values = try a.alloc(Q, p.circuit.nodes.len);
            defer a.free(values);
            p.circuit.evaluateInto(main, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
            const stride = 1 + P.Schema.arity(p.table);
            for (0..p.entries) |i| {
                try std.testing.expect(values[p.circuit.outputs[i * stride]].eql(pair.numerators[i]));
                for (rec.tuples[i][0 .. stride - 1], 0..) |value, j| try std.testing.expect(values[p.circuit.outputs[i * stride + j + 1]].eql(value));
            }
            var w = std.Io.Writer.Allocating.init(a);
            defer w.deinit();
            try P.emit(&w.writer, "counter_test", &p);
            try std.testing.expect(std.mem.indexOf(u8, w.written(), "atomicCAS") != null);
            const identity = p.identity;
            p.identity[0] ^= 1;
            try std.testing.expectError(error.InvalidNativeTableProjection, p.validate());
            p.identity = identity;
            count += 1;
        }
    };
    for (covered) |yes| try std.testing.expect(yes);
    std.debug.print("native table counter physical programs={d}\n", .{count});
}
