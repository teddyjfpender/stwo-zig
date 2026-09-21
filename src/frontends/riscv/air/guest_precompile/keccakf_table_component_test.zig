//! Exact xor5 recurrence and χ/xor component-geometry tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const authority = @import("keccakf_authority.zig");
const component_mod = @import("keccakf_table_component.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const interaction_mod = @import("keccakf_table_interaction.zig");
const relations_mod = @import("keccakf_relations.zig");
const tables = @import("keccakf_tables.zig");
const trace_mod = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

fn state(seed: u64) authority.State {
    var result: authority.State = undefined;
    for (&result, 0..) |*lane, index|
        lane.* = seed +% @as(u64, @intCast(index * 0x10007));
    return result;
}

fn placement() component_mod.Placement {
    return .{
        .is_first_col_idx = 0,
        .tuple_col_indices = .{ 1, 2, 3, 4, 5, 6 },
        .main_col_offset = 0,
        .interaction_col_offset = 0,
    };
}

test "keccak table component: xor5 full recurrence and mutation rejection" {
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    const slot = try witness.buildSlot(state(1), state(2));
    try counters.recordSlot(&slot);
    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var generated = try interaction_mod.generate(
        std.testing.allocator,
        .xor5,
        &counters,
        &relations,
        &pool,
    );
    defer generated.deinit(std.testing.allocator);
    const component = try component_mod.KeccakTableComponent.initProver(
        .xor5,
        placement(),
        &relations,
        generated.claim,
    );
    const size = tables.size(.xor5);
    for (0..size) |logical_row| {
        const tuple_base = try tables.tupleAt(.xor5, logical_row);
        var tuple: [tables.arity]QM31 = undefined;
        for (&tuple, tuple_base) |*value, base| value.* = QM31.fromBase(base);
        const current_row = trace_mod.committedRow(logical_row, tables.logSize(.xor5));
        const previous_row = trace_mod.committedRow(
            (logical_row + size - 1) % size,
            tables.logSize(.xor5),
        );
        try std.testing.expect((try component.evaluateRow(
            &tuple,
            QM31.fromBase(counters.xor5[logical_row]),
            secureAt(&generated.columns, current_row),
            secureAt(&generated.columns, previous_row),
            QM31.fromBase(M31.fromCanonical(@intFromBool(logical_row == 0))),
        )).isZero());
    }

    var active_row: usize = 0;
    while (active_row < counters.xor5.len and counters.xor5[active_row].isZero())
        active_row += 1;
    try std.testing.expect(active_row < counters.xor5.len);
    const tuple = try tables.tupleAt(.xor5, active_row);
    var secure_tuple: [tables.arity]QM31 = undefined;
    for (&secure_tuple, tuple) |*value, base| value.* = QM31.fromBase(base);
    secure_tuple[0] = secure_tuple[0].add(QM31.one());
    const row = trace_mod.committedRow(active_row, tables.logSize(.xor5));
    const previous = trace_mod.committedRow(
        (active_row + size - 1) % size,
        tables.logSize(.xor5),
    );
    try std.testing.expect(!(try component.evaluateRow(
        &secure_tuple,
        QM31.fromBase(counters.xor5[active_row]),
        secureAt(&generated.columns, row),
        secureAt(&generated.columns, previous),
        QM31.zero(),
    )).isZero());
}

test "keccak table component: χ and xor5 expose the same closed adapter" {
    const relations = relations_mod.Relations.dummy();
    const zero = QM31.zero();
    const chi = try component_mod.KeccakTableComponent.initVerifier(
        .chi,
        placement(),
        &relations,
        zero,
    );
    const xor5 = try component_mod.KeccakTableComponent.initVerifier(
        .xor5,
        placement(),
        &relations,
        zero,
    );
    try std.testing.expectEqual(@as(u32, 14), chi.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 11), xor5.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(usize, 1), chi.asVerifierComponent().nConstraints());
    var bounds = try chi.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 7), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[2].len);

    var displaced_placement = placement();
    displaced_placement.is_first_col_idx = 31;
    displaced_placement.tuple_col_indices = .{ 32, 33, 34, 35, 36, 37 };
    displaced_placement.main_col_offset = 2140;
    displaced_placement.interaction_col_offset = 3844;
    const displaced = try component_mod.KeccakTableComponent.initVerifier(
        .chi,
        displaced_placement,
        &relations,
        zero,
    );
    var displaced_bounds = try displaced.traceLogDegreeBounds(std.testing.allocator);
    defer displaced_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(bounds.items[0].len, displaced_bounds.items[0].len);
    try std.testing.expectEqual(bounds.items[1].len, displaced_bounds.items[1].len);
    try std.testing.expectEqual(bounds.items[2].len, displaced_bounds.items[2].len);

    var bad = placement();
    bad.tuple_col_indices[5] = bad.tuple_col_indices[0];
    try std.testing.expectError(
        error.InvalidPlacement,
        component_mod.KeccakTableComponent.initVerifier(.chi, bad, &relations, zero),
    );
}

fn secureAt(columns: *const [4][]M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
