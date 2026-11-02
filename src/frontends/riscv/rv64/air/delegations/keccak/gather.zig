//! Bounded native coset read tile. No witness/layout/polynomial authority lives
//! here: mask indices use core utilities and every promoted row goes to E.emit.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const C = @import("component.zig");
const Eval = @import("../../full/coset_evaluation.zig").Evaluation;
pub const ROWS = 16;
pub const Row = struct {
    fixed: [L.FIXED]M,
    main: [L.MAIN]M,
    shifted: [4][L.STATE]M,
    previous_header: [3]M,
    interaction: [L.INTERACTION]M,
    previous_final: [4]M,
    pub fn promote(self: *const Row, scratch: *C.Scratch) Q {
        for (&scratch.fixed, &self.fixed) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.main, &self.main) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.shifted, &self.shifted) |*target, source| for (target, source) |*v, b| {
            v.* = Q.fromBase(b);
        };
        for (&scratch.previous_header, &self.previous_header) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.interaction, 0..) |*v, batch| v.* = secure(self.interaction[4 * batch ..][0..4]);
        return secure(&self.previous_final);
    }
};
fn secure(values: *const [4]M) Q {
    return Q.fromM31(values[0], values[1], values[2], values[3]);
}
const Halo = struct { row: usize, partner: bool };
pub fn fill(evaluation: *const Eval, part: usize, start: usize, rows: []Row) void {
    std.debug.assert(rows.len != 0 and rows.len <= ROWS and start + rows.len <= evaluation.size and part < 4);
    const current = evaluation.current_values;
    const previous = evaluation.previous_values;
    const fm = L.FIXED + L.MAIN;
    var prior: [ROWS]usize = undefined;
    var halos: [4][ROWS]Halo = undefined;
    for (0..rows.len) |i| {
        const global = evaluation.globalRow(part, start + i);
        prior[i] = evaluation.previousRow(part, start + i);
        for (L.MASK_OFFSETS[1..], 0..) |offset, j| {
            const shifted = core.utils.offsetBitReversedCircleDomainIndex(global, evaluation.trace_log, evaluation.trace_log + 2, offset);
            const target = shifted / evaluation.size;
            std.debug.assert(target == part or target == part ^ 1);
            halos[j][i] = .{ .row = shifted % evaluation.size, .partner = target != part };
        }
    }
    // Each source column stays hot across this bounded set of destination rows.
    // The transposed tile is private to one worker and never survives the wave.
    for (current[0..L.FIXED], 0..) |column, c| for (rows, 0..) |*row, i| {
        row.fixed[c] = column[start + i];
    };
    for (current[L.FIXED..fm], 0..) |column, c| for (rows, 0..) |*row, i| {
        row.main[c] = column[start + i];
    };
    for (0..4) |j| for (0..L.STATE) |c| {
        const own = current[L.FIXED + c];
        const partner = previous[L.FIXED + c];
        for (rows, 0..) |*row, i| {
            const halo = halos[j][i];
            row.shifted[j][c] = (if (halo.partner) partner else own)[halo.row];
        }
    };
    for (previous[L.FIXED + L.ACTIVE_A ..][0..3], 0..) |column, c| for (rows, 0..) |*row, i| {
        row.previous_header[c] = column[prior[i]];
    };
    for (current[fm..][0..L.INTERACTION], 0..) |column, c| for (rows, 0..) |*row, i| {
        row.interaction[c] = column[start + i];
    };
    for (previous[fm + L.INTERACTION - 4 ..][0..4], 0..) |column, c| for (rows, 0..) |*row, i| {
        row.previous_final[c] = column[prior[i]];
    };
}
