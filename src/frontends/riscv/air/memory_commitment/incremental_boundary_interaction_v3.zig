//! LogUp constraints for a full-state incremental RW-memory boundary.
//!
//! Unlike the legacy boundary table, Merkle membership and memory-bus
//! multiplicity are independent here. Every active row range-checks and opens
//! its four bytes under the committed full-state root. The memory tuple may be
//! emitted with multiplicity `-1`, suppressed with `0` when an authenticated
//! public-I/O tuple supplies that side, or emitted with `+1`.
//!
//! This module deliberately reuses the frozen eight-column row and sixteen
//! interaction-column encodings. Only the two multiplicity constraints differ
//! from V1, so existing transport and trace writers cannot silently acquire a
//! new column interpretation.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const boundary = @import("boundary.zig");
const legacy = @import("interaction.zig");

pub const PRODUCTION_ACTIVE = false;
pub const PROFILE = "riscv-incremental-full-state-boundary-v3";

pub const N_SUMS = legacy.N_SUMS;
pub const N_COLUMNS = legacy.N_COLUMNS;
pub const N_CONSTRAINTS: usize = N_SUMS + 2;

pub const Claims = legacy.Claims;
pub const Result = legacy.Result;

pub const generate = legacy.generate;
pub const rowPairs = legacy.rowPairs;
pub const entriesFromRow = legacy.entriesFromRow;
pub const paddingPairs = legacy.paddingPairs;
pub const entries = legacy.entries;
pub const entriesGeneric = legacy.entriesGeneric;
pub const diagnosticSum = legacy.diagnosticSum;

pub fn evaluate(
    main: [8]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(
        QM31,
        main,
        is_active,
        is_first,
        sums,
        previous,
        claims,
        relations,
    );
}

pub fn evaluateGeneric(
    comptime S: type,
    main: [8]S,
    is_active: S,
    is_first: S,
    sums: [N_SUMS]S,
    previous: [N_SUMS]S,
    claims: [N_SUMS]S,
    relations: anytype,
) [N_CONSTRAINTS]S {
    const list = legacy.entriesGeneric(S, main, is_active);
    const pairs = [N_SUMS]logup.RowPairFor(S){
        list.pairWith(0, relations) catch unreachable,
        list.pairWith(1, relations) catch unreachable,
        list.pairWith(2, relations) catch unreachable,
        list.pairWith(3, relations) catch unreachable,
    };
    var result: [N_CONSTRAINTS]S = undefined;
    for (0..N_SUMS) |index| {
        result[index] = logup.pairConstraintGeneric(
            S,
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }

    const multiplicity = main[6];
    const multiplicity_squared = multiplicity.square();
    // Exact ternary range: m is one of {-1, 0, +1}.
    result[N_SUMS] = multiplicity.mul(
        multiplicity_squared.sub(S.one()),
    );
    // Padding cannot emit a memory tuple. Active Merkle rows may still use
    // multiplicity zero when public-data compensation owns that boundary side.
    result[N_SUMS + 1] = multiplicity.mul(
        is_active.sub(S.one()),
    );
    return result;
}

test "incremental boundary V3 permits active zero memory multiplicity" {
    const relations = relations_mod.Relations.dummy();
    const zero = QM31.zero();
    const one = QM31.one();
    var main = [_]QM31{zero} ** 8;
    main[0] = QM31.fromBase(M31.fromU64(0x1000));
    main[2] = QM31.fromBase(M31.fromU64(1));
    main[3] = QM31.fromBase(M31.fromU64(2));
    main[4] = QM31.fromBase(M31.fromU64(3));
    main[5] = QM31.fromBase(M31.fromU64(4));
    main[7] = QM31.fromBase(M31.fromU64(99));

    const constraints = evaluate(
        main,
        one,
        one,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try @import("std").testing.expect(constraints[N_SUMS].isZero());
    try @import("std").testing.expect(constraints[N_SUMS + 1].isZero());

    const legacy_constraints = legacy.evaluate(
        main,
        one,
        one,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try @import("std").testing.expect(
        !legacy_constraints[legacy.N_SUMS + 1].isZero(),
    );
}

test "incremental boundary V3 rejects nonzero memory multiplicity on padding" {
    const relations = relations_mod.Relations.dummy();
    const zero = QM31.zero();
    const one = QM31.one();
    var main = [_]QM31{zero} ** 8;
    main[6] = one;
    const constraints = evaluate(
        main,
        zero,
        one,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try @import("std").testing.expect(!constraints[N_SUMS + 1].isZero());
}

test "incremental boundary V3 keeps Merkle lookup active when memory is suppressed" {
    const relations = relations_mod.Relations.dummy();
    const row = boundary.Row{
        .addr = 0x2000,
        .clock = 0,
        .value = .{ 9, 8, 7, 6 },
        .multiplicity = M31.zero(),
        .root = 123,
    };
    const memory_sum = try diagnosticSum(&.{row}, .memory_access, &relations);
    const merkle_sum = try diagnosticSum(&.{row}, .merkle, &relations);
    try @import("std").testing.expect(memory_sum.isZero());
    try @import("std").testing.expect(!merkle_sum.isZero());

    var emitted = row;
    emitted.multiplicity = M31.one();
    const emitted_memory = try diagnosticSum(
        &.{emitted},
        .memory_access,
        &relations,
    );
    const emitted_merkle = try diagnosticSum(&.{emitted}, .merkle, &relations);
    try @import("std").testing.expect(!emitted_memory.isZero());
    try @import("std").testing.expect(emitted_merkle.eql(merkle_sum));
}
