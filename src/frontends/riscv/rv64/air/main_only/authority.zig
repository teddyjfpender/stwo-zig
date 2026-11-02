//! MAIN-only arithmetic for the new wide-local-GKR route. Local lookup and
//! global RAM/KIO/Wire closure are separate mandatory components, never zeros.
const std = @import("std");
const E = @import("../evaluation.zig");
const CPU = @import("../word16_execution/equations.zig");
const CT = @import("../word16_execution/types.zig");
const CL = @import("../word16_execution/layout.zig");
const AL = @import("../word16_v1/alu_lookup.zig");
const A = @import("../word16_v1/alu.zig");
const BL = @import("../word16_v1/binary_lookup.zig");
const B = @import("../word16_v1/binary.zig");
const S = @import("../word16_v1/shift_word.zig");
const LS = @import("../memory/load_store_v1/mod.zig");
const LL = @import("../memory/load_store_v2/layout.zig");
const J = @import("../word16_execution/jalr_equations.zig");
const MUL = @import("../delegations/multiplication/provider.zig");
const ML = @import("../delegations/multiplication/degree3_layout.zig");
const DIV = @import("../delegations/division/word16_product/equations.zig");
const DL = @import("../delegations/division/word16_product/layout.zig");
pub const Role = enum { cpu, alu, binary, shift, ls, jalr, mul, div };
pub fn CountFor(comptime C: type) type {
    return struct { count: E.CountFor(C), nonempty: E.FlagFor(C) = E.flagDefault(C) };
}
pub fn PublicFor(comptime C: type) type {
    return union(Role) { cpu: CT.InputsFor(C), alu: void, binary: void, shift: void, ls: CountFor(C), jalr: void, mul: CountFor(C), div: CountFor(C) };
}
pub const Shape = struct { fixed: usize, main: usize, constraints: usize, max_degree: u8 = 3 };
pub fn shape(role: Role) Shape {
    return switch (role) {
        .cpu => .{ .fixed = 3, .main = CL.main.COUNT, .constraints = CPU.MAIN_CONSTRAINTS },
        .alu => .{ .fixed = 0, .main = AL.MAIN, .constraints = A.PROJECTED_CONSTRAINTS + 1 },
        .binary => .{ .fixed = 0, .main = BL.MAIN, .constraints = B.PROJECTED_CONSTRAINTS + 1, .max_degree = 2 },
        .shift => .{ .fixed = 0, .main = S.LOCAL_MAIN + 1, .constraints = S.PROJECTED_CONSTRAINTS + 1 },
        // Original projected LS local residuals plus final address-limb identity.
        .ls => .{ .fixed = 3, .main = LL.MAIN, .constraints = 247 },
        .jalr => .{ .fixed = 0, .main = J.MAIN, .constraints = J.MAIN_CONSTRAINTS, .max_degree = 2 },
        .mul => .{ .fixed = 3, .main = ML.MAIN, .constraints = ML.ARITHMETIC_CONSTRAINTS },
        .div => .{ .fixed = 3, .main = DL.MAIN, .constraints = DL.ARITHMETIC_CONSTRAINTS },
    };
}
pub fn previousMain(role: Role, column: usize) bool {
    return switch (role) {
        .cpu => column == CL.main.active or (column >= CL.main.next_pc and column < CL.main.next_pc + 4),
        .ls => column == 0,
        .mul => column == ML.COUNT,
        .div => column == DL.COUNT,
        else => false,
    };
}
pub fn emitFor(comptime F: type, public: PublicFor(E.ConstFor(F)), fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    const role = std.meta.activeTag(public);
    const s = shape(role);
    if (fixed.len != s.fixed or main.len != s.main or previous.len != s.main) return error.InvalidMainOnlyShape;
    switch (public) {
        .cpu => |p| CPU.emitMainFor(F, fixed, main, previous, p, sink),
        .alu => {
            const row = AL.rowFromColumnsFor(F, main);
            A.emitProjectedFor(F, &row, sink);
            sink.emit(F.one().sub(row.active).mul(main[A.LOCAL_MAIN]));
        },
        .binary => {
            const row = BL.rowFromColumnsFor(F, main);
            B.emitProjectedFor(F, &row, sink);
            sink.emit(F.one().sub(row.active).mul(main[B.LOCAL_MAIN]));
        },
        .shift => {
            const row = S.rowFromColumnsFor(F, main);
            S.emitProjectedFor(F, &row, sink);
            sink.emit(F.one().sub(row.active).mul(main[S.LOCAL_MAIN]));
        },
        .ls => |p| {
            const logical = LL.projection.expandFor(F, main);
            var prev: [LL.projection.LOGICAL_MAIN]F = @splat(F.zero());
            prev[0] = previous[0];
            LS.equations.emitLocalWithPublicFor(F, fixed, &logical, &prev, E.scalarFor(F, p.count), try E.nonzeroFor(F, p.count, p.nonempty), sink);
            sink.emit(logical[3].sub(logical[12]).sub(logical[13].mul(E.qFor(F, 65536))));
        },
        .jalr => J.emitMainFor(F, main, sink),
        .mul => |p| MUL.arithmeticFor(F, fixed[0..3].*, main[0..ML.MAIN], previous[ML.COUNT], E.scalarFor(F, p.count), sink),
        .div => |p| DIV.emitFor(F, fixed, main, previous[DL.COUNT], E.scalarFor(F, p.count), sink),
    }
}
