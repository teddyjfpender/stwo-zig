//! One explicit dispatch for prover row projections and authenticated masks.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const Frame = @import("frame.zig");
const Fns = @import("fractions.zig");
pub fn emitFor(comptime F: type, origin: Frame.Origin, fixed: []const F, main: []const F, epoch: F, boundary: A.word16_cpu.boundary.PublicFor(E.ConstFor(F)), sink: anytype) !void {
    switch (origin) {
        .bridge => |family| switch (family) {
            .keccak => Fns.keccakBridgeFor(F, fixed, main, sink),
            .add => Fns.secpBridgeFor(F, .add, fixed, main, sink),
            .double => Fns.secpBridgeFor(F, .double, fixed, main, sink),
            .sha256 => Fns.secpBridgeFor(F, .sha256, fixed, main, sink),
        },
        .core => |role| switch (role) {
            .cpu => Fns.cpuFor(F, fixed, main, epoch, sink),
            .rom => Fns.romFor(F, fixed, main, sink),
            .boundary => Fns.registerBoundaryFor(F, fixed, boundary, sink),
            .alu, .alu_tail => Fns.aluFor(F, main, sink),
            .binary, .binary_tail => Fns.binaryFor(F, main, sink),
            .shift, .shift_tail => Fns.shiftFor(F, main, sink),
            .ls, .ls_tail => Fns.lsFor(F, main, sink),
            .jalr => Fns.jalrFor(F, main, sink),
            .division => Fns.divisionFor(F, main, sink),
            .multiplication => Fns.multiplicationFor(F, main[0..A.arithmetic.multiplication.layout.MAIN], sink),
            .range16 => Fns.scalarTableFor(F, .range16, fixed, main, sink),
            .range8 => Fns.scalarTableFor(F, .range8, fixed, main, sink),
            .and_table => Fns.andTableFor(F, fixed, main, sink),
            .shift_table => Fns.shiftTableFor(F, fixed, main, sink),
            .selection => Fns.selectionTableFor(F, fixed, main, sink),
            .initial, .terminal => return error.GlobalOnlyRoleHasNoLocalGkr,
        },
    }
}
