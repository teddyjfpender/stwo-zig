//! Debug-only native-domain residual audit using the physical component
//! authorities. It proves neither degree bounds nor off-domain correctness.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.word16_execution.types;
const Eval = A.evaluation;
const Q = core.fields.qm31.QM31;
const G = @import("geometry.zig");
const C = @import("components.zig").Components;
const S = @import("sources.zig").Source;
pub const Failure = struct { role: G.Role, row: usize, constraint: usize, value: Q };
pub fn inspect(a: std.mem.Allocator, components: *const C, source: *const S) !?Failure {
    const fixed = try source.materials.fixedColumns(a);
    defer a.free(fixed);
    const main = try source.columns(a, 1);
    defer a.free(main);
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    for (source.materials.shapes()) |shape| {
        if (!shape.present()) continue;
        const n = @as(usize, 1) << @intCast(shape.log);
        for (0..n) |logical| {
            const pos = A.word16_execution.layout.physical(logical, shape.log);
            const previous = A.word16_execution.layout.physical((logical + n - 1) % n, shape.log);
            var f: [34]Q = undefined;
            var m: [1200]Q = undefined;
            var pm: [1200]Q = undefined;
            var i: [A.arithmetic.multiplication.degree3_layout.INTERACTION]Q = undefined;
            var pi: [A.arithmetic.multiplication.degree3_layout.INTERACTION]Q = undefined;
            const fs = f[0..shape.widths[0]];
            const ms = m[0..shape.widths[1]];
            const pms = pm[0..shape.widths[1]];
            const is = i[0..shape.widths[2]];
            const pis = pi[0..shape.widths[2]];
            for (fs, 0..) |*v, c| v.* = Q.fromBase(fixed[shape.offsets[0] + c].values[pos]);
            for (ms, pms, 0..) |*v, *pv, c| {
                v.* = Q.fromBase(main[shape.offsets[1] + c].values[pos]);
                pv.* = Q.fromBase(main[shape.offsets[1] + c].values[previous]);
            }
            for (is, pis, 0..) |*v, *pv, c| {
                v.* = Q.fromBase(inter[shape.offsets[2] + c].values[pos]);
                pv.* = Q.fromBase(inter[shape.offsets[2] + c].values[previous]);
            }
            var values: [1600]Q = undefined;
            var sink = Eval.Sink{ .values = &values };
            switch (shape.role) {
                .cpu => components.cpu.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .rom => components.rom.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .boundary => components.boundary.emitFor(Q, fs, ms, is, pms, pis, &sink),
                .range16 => components.range16.emitFor(Q, fs, ms, is, pms, pis, &sink),
                .range8 => components.range8.emitFor(Q, fs, ms, is, pms, pis, &sink),
                .alu => components.alu.emitFor(Q, fs, ms, is, pis, &sink),
                .binary => components.binary.emitFor(Q, fs, ms, is, pis, &sink),
                .and_table => components.and_table.emitFor(Q, fs, ms, is, pis, &sink),
                .shift => components.shift.emitFor(Q, fs, ms, is, pis, &sink),
                .shift_table => components.shift_table.emitFor(Q, fs, ms, is, pis, &sink),
                .jalr => components.jalr.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .division => {
                    const D = A.arithmetic.division;
                    D.provider.evaluate(fs[0..3].*, ms[0..D.layout.MAIN], is[0..D.layout.INTERACTION], pis[0..D.layout.INTERACTION], pms[D.layout.COUNT], components.division.base.count, components.division.base.challenges, components.division.base.claim, &sink);
                },
                .multiplication => {
                    const M = A.arithmetic.multiplication;
                    M.degree3_provider.evaluateFor(Q, fs[0..3].*, ms[0..M.degree3_layout.MAIN], is[0..M.degree3_layout.INTERACTION], Q.fromPartialEvals(pis[M.degree3_layout.PREFIX..][0..4].*), pms[M.layout.COUNT], Eval.q(components.multiplication.count), components.multiplication.challenges, components.multiplication.byte_alpha, components.multiplication.claim, &sink);
                },
                .ls => components.ls.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .ls_tail => components.ls_tail.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .initial => components.initial.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .terminal => components.terminal.emitFor(Q, fs, ms, pms, is, pis, &sink),
                .selection => components.selection.emitFor(Q, fs, ms, pms, is, pis, &sink),
            }
            for (values[0..sink.count], 0..) |value, c| if (!value.isZero()) return .{ .role = shape.role, .row = logical, .constraint = c, .value = value };
        }
    }
    return null;
}
