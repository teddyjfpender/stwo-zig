//! Allocation-free safety preflight for function-activation evaluation.
//!
//! This module owns only shape, canonicity, coefficient-bound, and alias
//! rejection before the evaluator's first write.

const std = @import("std");
const alias_check = @import("function_activation_alias.zig");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const logup = @import("../logup.zig");
const types = @import("types.zig");

const AddressRange = alias_check.AddressRange;
const objectAddress = alias_check.objectAddress;
const sliceAddress = alias_check.sliceAddress;

pub fn preflightEvaluation(
    comptime api: type,
    prepared: *const api.PreparedProtocol,
    batches: []const api.EventBatch,
    rows: []const api.ActivationRow,
    values: []const M31,
    denominators: []QM31,
    inverses: []QM31,
    row_pairs: []logup.RowPair,
    event_claims: []QM31,
    relation_claims: []QM31,
) api.EvaluateError!void {
    const ActivationRow = api.ActivationRow;
    const EventBatch = api.EventBatch;
    const EventDescriptor = api.EventDescriptor;
    const RelationDescriptor = api.RelationDescriptor;
    const SOURCE_COEFFICIENT_BOUND_EXCLUSIVE =
        api.SOURCE_COEFFICIENT_BOUND_EXCLUSIVE;
    const rangeSlice = api.PreflightHooks.rangeSlice;
    if (!prepared.active) {
        if (batches.len != 0 or rows.len != 0 or values.len != 0 or
            denominators.len != 0 or inverses.len != 0 or row_pairs.len != 0 or
            event_claims.len != 0 or relation_claims.len != 0)
        {
            return error.InvalidBatchShape;
        }
        return;
    }
    if (batches.len != prepared.events.len or
        denominators.len != rows.len or inverses.len != rows.len or
        row_pairs.len != rows.len or event_claims.len != prepared.events.len or
        relation_claims.len != prepared.relations.len)
    {
        return error.InvalidBatchShape;
    }

    var row_cursor: usize = 0;
    var value_cursor: usize = 0;
    var total_source_coefficients: u64 = 0;
    for (batches, 0..) |batch, event_index| {
        if (batch.event_index != event_index or batch.rows.start != row_cursor)
            return error.InvalidBatchShape;
        const batch_rows = rangeSlice(ActivationRow, batch.rows, rows) orelse
            return error.InvalidRange;
        const event = prepared.events[event_index];
        switch (event.kind) {
            .callee_consume, .caller_emit => {
                if (batch.origin != .trace) return error.InvalidRowOrigin;
            },
            .public_emit => {
                if (batch.origin != .public_statement)
                    return error.InvalidRowOrigin;
                if (batch_rows.len != 1) return error.InvalidPublicRootBatch;
            },
        }
        const arity = prepared.relations[event.relation_index].tuple_arity;
        for (batch_rows) |row| {
            if (row.tuple.start != value_cursor) return error.InvalidRange;
            const tuple = rangeSlice(M31, row.tuple, values) orelse
                return error.InvalidRange;
            if (tuple.len != arity) return error.InvalidBatchShape;
            if (row.multiplicity.toU32() >= fields.m31.Modulus or
                row.multiplicity.isZero())
            {
                return error.InvalidMultiplicity;
            }
            switch (event.weight) {
                .callee_enabler, .caller_enabler => if (!row.multiplicity.isOne())
                    return error.InvalidMultiplicity,
                .public_multiplicity => {},
            }
            const source_coefficient: u64 = switch (event.weight) {
                .callee_enabler, .caller_enabler => 1,
                .public_multiplicity => row.multiplicity.toU32(),
            };
            total_source_coefficients = std.math.add(
                u64,
                total_source_coefficients,
                source_coefficient,
            ) catch return error.CoefficientBoundExceeded;
            if (total_source_coefficients >=
                @as(u64, SOURCE_COEFFICIENT_BOUND_EXCLUSIVE))
            {
                return error.CoefficientBoundExceeded;
            }
            value_cursor += tuple.len;
        }
        row_cursor += batch_rows.len;
    }
    if (row_cursor != rows.len or value_cursor != values.len)
        return error.InvalidRange;

    const ranges = [_]?AddressRange{
        try sliceAddress(EventBatch, batches),
        try sliceAddress(ActivationRow, rows),
        try sliceAddress(M31, values),
        try sliceAddress(QM31, denominators),
        try sliceAddress(QM31, inverses),
        try sliceAddress(logup.RowPair, row_pairs),
        try sliceAddress(QM31, event_claims),
        try sliceAddress(QM31, relation_claims),
        try sliceAddress(RelationDescriptor, prepared.relations),
        try sliceAddress(QM31, prepared.alpha_powers),
        try sliceAddress(EventDescriptor, prepared.events),
        try sliceAddress(types.ValueId, prepared.tuple_values),
        try objectAddress(prepared),
    };
    for (ranges, 0..) |candidate, index| {
        const present = candidate orelse continue;
        for (ranges[0..index]) |prior| {
            if (prior != null and present.overlaps(prior.?))
                return error.AliasedBuffer;
        }
    }
}
