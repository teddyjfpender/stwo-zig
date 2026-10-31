//! Failure-only native residual localization. This is not another AIR: every
//! polynomial is evaluated by the same concrete authority as domain/OODS.
//! Must run before narrow source metadata retires. Caller checks need no wide
//! copy; provider checks explicitly take an original pre-commit debug snapshot.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const E = A.rv.evaluation;
const R = A.R;
const T = R.private_trace;
const Q = A.Q;
const M = A.core.fields.m31.M31;
const physical = A.rv.witness.physical;
pub const Failure = struct { table: T.Table, row: usize, residual: usize, value: Q };

/// Audits all eight RAM callers, including padding, against the ACTUAL shared
/// challenges and generated physical interactions. Provider/policy components
/// are separate; null is only an eight-caller native-domain diagnostic result.
pub fn audit(source: *const A.RAM.Source, ch: *const A.I.Challenges, inter: *const A.I.Interaction) !?Failure {
    const trace = source.metadata orelse return error.RamDiagnosticNeedsMetadata;
    try trace.validateMetadata();
    if (!std.meta.eql(source.rows.shapes, trace.shapes)) return error.InvalidPrivateRamTracePhase;
    for (T.TABLES) |table| {
        const log = T.tableLog(trace.shapes, table);
        const size = @as(usize, 1) << @intCast(log);
        const width = T.mainWidth(table);
        const sums = T.sumCount(table);
        const fields = sums * 4;
        const interaction = inter.tables[@intFromEnum(table)];
        if (interaction.len != fields * size) return error.InvalidPrivateRamRows;
        const claims = inter.claims.slice(table);
        var native: [111]M = undefined;
        var main: [111]Q = undefined;
        var previous: [111]Q = undefined;
        try trace.restoreRow(table, size - 1, native[0..width]);
        for (native[0..width], previous[0..width]) |value, *lifted| lifted.* = Q.fromBase(value);
        for (0..size) |i| {
            const at = physical(i, log);
            const prior = physical((i + size - 1) % size, log);
            try trace.restoreRow(table, i, native[0..width]);
            for (native[0..width], main[0..width]) |value, *lifted| lifted.* = Q.fromBase(value);
            var fixed: [8]Q = undefined;
            var base_fixed: [8]M = undefined;
            T.fixedAt(trace.shapes, table, i, base_fixed[0..T.fixedWidth(table)]);
            for (base_fixed[0..T.fixedWidth(table)], fixed[0..T.fixedWidth(table)]) |value, *lifted| lifted.* = Q.fromBase(value);
            var current: [52]Q = undefined;
            var old: [52]Q = undefined;
            for (0..fields) |j| {
                current[j] = Q.fromBase(interaction[j * size + at]);
                old[j] = Q.fromBase(interaction[j * size + prior]);
            }
            var residuals: [63]Q = undefined;
            var sink = E.Sink{ .values = &residuals };
            const C = R.chunk_air;
            const Cell = R.cell_air;
            const Leaf = R.leaf_air;
            const Node = R.node_air;
            const Side = R.side_air;
            const Permit = R.permit_air;
            switch (table) {
                .chunk => C.evaluate(trace.shapes.chunk, fixed[0..C.FIXED], main[0..C.MAIN], previous[0..C.MAIN], current[0..C.INTERACTION], old[0..C.INTERACTION], claims[0..C.SUMS].*, &.{ .ram = ch.ram, .io = ch.permutations.poseidon2_io }, &sink),
                .common_cells, .edge_cells => Cell.evaluate(if (table == .common_cells) trace.shapes.common_cells else trace.shapes.edge_cells, fixed[0..Cell.FIXED], main[0..Cell.MAIN], previous[0..Cell.MAIN], current[0..Cell.INTERACTION], old[0..Cell.INTERACTION], claims[0..Cell.SUMS].*, &.{ .ram = ch.ram, .state = ch.state, .bytes = ch.bytes }, &sink),
                .leaf => Leaf.evaluate(trace.shapes.leaf, fixed[0..Leaf.FIXED], main[0..Leaf.MAIN], previous[0..Leaf.MAIN], current[0..Leaf.INTERACTION], old[0..Leaf.INTERACTION], claims[0..Leaf.SUMS].*, &.{ .ram = ch.ram, .bytes = ch.bytes }, &sink),
                .node => Node.evaluate(trace.shapes.node, fixed[0..Node.FIXED], main[0..Node.MAIN], previous[0..Node.MAIN], current[0..Node.INTERACTION], old[0..Node.INTERACTION], claims[0..Node.SUMS].*, &.{ .ram = ch.ram, .io = ch.permutations.poseidon2_io, .bytes = ch.bytes }, &sink),
                .side => Side.evaluate(trace.shapes.side, fixed[0..Side.FIXED], main[0..Side.MAIN], previous[0..Side.MAIN], current[0..Side.INTERACTION], old[0..Side.INTERACTION], claims[0..Side.SUMS].*, &.{ .ram = ch.ram, .bytes = ch.bytes }, &sink),
                .common_permits, .edge_permits => Permit.evaluate(if (table == .common_permits) trace.shapes.common_permits else trace.shapes.edge_permits, fixed[0..Permit.FIXED], main[0..Permit.MAIN], previous[0..Permit.MAIN], current[0..Permit.INTERACTION], old[0..Permit.INTERACTION], claims[0..Permit.SUMS].*, &.{ .bytes = ch.bytes, .policy = ch.policy, .permit = ch.ram.permitChallenge() }, &sink),
            }
            for (residuals[0..sink.count], 0..) |value, ordinal| if (!value.isZero()) return .{ .table = table, .row = i, .residual = ordinal, .value = value };
            @memcpy(previous[0..width], main[0..width]);
        }
    }
    return null;
}

pub const ProviderFailure = struct {
    component: enum { poseidon, policy },
    row: usize,
    residual: usize,
    value: Q,
};
/// original_provider is an explicit PRE-COMMIT snapshot of the actual303-column
/// witness. No hash/S-box is replayed. The retained policy owner contains the
/// original multiplicities and generated interaction, separate from the arena.
pub fn auditProviders(source: *const A.RAM.Source, ch: *const A.I.Challenges, inter: *const A.I.Interaction, original_provider: []const M, policy_trace: *const R.policy_provider.Trace) !?ProviderFailure {
    const trace = source.metadata orelse return error.RamDiagnosticNeedsMetadata;
    try trace.validateMetadata();
    if (!std.meta.eql(source.rows.shapes, trace.shapes)) return error.InvalidPrivateRamTracePhase;
    const P = A.frontend.air.memory_commitment.poseidon2_universal_degree3_v1;
    const log = trace.shapes.provider_log;
    const size = @as(usize, 1) << @intCast(log);
    if (original_provider.len != P.N_MAIN_COLUMNS * size or inter.provider.log_size != log or inter.provider.columns.len != P.N_INTERACTION_COLUMNS * size) return error.InvalidRamProviderInteractionShape;
    for (0..size) |i| {
        const at = physical(i, log);
        const prior = physical((i + size - 1) % size, log);
        var main: [P.N_MAIN_COLUMNS]Q = undefined;
        for (&main, 0..) |*value, col| value.* = Q.fromBase(original_provider[col * size + at]);
        for (P.evaluateGeneric(Q, main), 0..) |value, ordinal| if (!value.isZero()) return .{ .component = .poseidon, .row = i, .residual = ordinal, .value = value };
        var current: [P.N_INTERACTION_COLUMNS]Q = undefined;
        var previous: [P.N_INTERACTION_COLUMNS]Q = undefined;
        for (&current, &previous, 0..) |*value, *old, col| {
            value.* = Q.fromBase(inter.provider.columns[col * size + at]);
            old.* = Q.fromBase(inter.provider.columns[col * size + prior]);
        }
        var sums: [P.N_SUMS]Q = undefined;
        var old_sums: [P.N_SUMS]Q = undefined;
        for (&sums, &old_sums, 0..) |*value, *old, group| {
            value.* = R.policy_air.secure(&current, group);
            old.* = R.policy_air.secure(&previous, group);
        }
        const first = if (i == 0) Q.one() else Q.zero();
        for (P.interactionConstraintsGeneric(Q, main, first, sums, old_sums, inter.provider.claims, &ch.permutations), 0..) |value, ordinal| if (!value.isZero()) return .{ .component = .poseidon, .row = i, .residual = P.N_CONSTRAINTS + ordinal, .value = value };
    }
    const Policy = R.policy_provider;
    const n = policy_trace.shape.size();
    if (policy_trace.fixed.len != Policy.FIXED * n or policy_trace.main.len != Policy.MAIN * n or policy_trace.interaction.len != Policy.INTERACTION * n) return error.InvalidRamPolicyProviderShape;
    for (0..n) |i| {
        const at = physical(i, policy_trace.shape.log_size);
        const prior = physical((i + n - 1) % n, policy_trace.shape.log_size);
        var fixed: Policy.Fixed = undefined;
        var main: Policy.SecureRow = undefined;
        var previous_main: Policy.SecureRow = undefined;
        var current: [Policy.INTERACTION]Q = undefined;
        var previous: [Policy.INTERACTION]Q = undefined;
        for (&fixed, 0..) |*value, col| value.* = Q.fromBase(policy_trace.fixed[col * n + at]);
        for (&main, &previous_main, 0..) |*value, *old, col| {
            value.* = Q.fromBase(policy_trace.main[col * n + at]);
            old.* = Q.fromBase(policy_trace.main[col * n + prior]);
        }
        for (&current, &previous, 0..) |*value, *old, col| {
            value.* = Q.fromBase(policy_trace.interaction[col * n + at]);
            old.* = Q.fromBase(policy_trace.interaction[col * n + prior]);
        }
        var values: [Policy.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &values };
        Policy.evaluate(policy_trace.shape, &fixed, &main, &previous_main, &current, &previous, .{policy_trace.claim}, &.{ .policy = ch.policy }, &sink);
        for (values[0..sink.count], 0..) |value, ordinal| if (!value.isZero()) return .{ .component = .policy, .row = i, .residual = ordinal, .value = value };
    }
    return null;
}
