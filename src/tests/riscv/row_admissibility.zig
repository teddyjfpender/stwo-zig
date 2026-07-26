//! Row-local admissibility oracle for one committed opcode-family row.
//!
//! Adversarial witness tests need a single answer to "would the AIR accept this
//! row?". Evaluating `semantic_eval` alone understates the AIR: several
//! bindings — the signed-load sign residual, byte ranges, bitwise results —
//! exist only as lookup requests, so a row whose direct constraints vanish can
//! still be rejected by a preprocessed table. This module decides both halves.
//!
//! Bus relations (`memory_access`, `program_access`, `registers_state`) are
//! deliberately outside the verdict. Their soundness is the global LogUp
//! closure, not row-local table membership, so a row-local oracle must not
//! pretend to decide them. Callers that need to know whether a column reaches a
//! bus at all use `fingerprint` instead.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const entry_mod = @import("../../frontends/riscv/air/lookups/entry.zig");
const schema = @import("../../frontends/riscv/air/lookups/tables/schema.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");

const OpcodeFamily = trace_mod.OpcodeFamily;

/// True when every direct constraint of `family` vanishes on `columns` AND
/// every activated lookup tuple is present in its preprocessed table.
///
/// `columns` is a borrowed row of exactly `trace_mod.nColumnsForFamily(family)`
/// secure-field cells, evaluated as an active (non-padding) row. Errors report
/// a shape or compatibility mismatch, never a rejected witness.
pub fn accepts(family: OpcodeFamily, columns: []const QM31) !bool {
    const evaluation = try semantic_eval.evaluate(family, columns, QM31.one());
    if (!evaluation.allZero()) return false;

    const list = try opcode_entries.fromMain(family, columns);
    for (list.entries[0..list.len]) |emitted| {
        // A zero numerator switches the request off for this row.
        if (emitted.numerator.isZero()) continue;
        const kind = preprocessedKind(emitted.domain) orelse continue;
        const arity = schema.arity(kind);
        if (emitted.arity != arity) return false;

        var values: [schema.MAX_ARITY]M31 = undefined;
        for (values[0..arity], emitted.values[0..arity]) |*out, value| {
            out.* = value.tryIntoM31() catch return false;
        }
        _ = schema.indexBase(kind, values[0..arity]) catch return false;
    }
    return true;
}

/// Fingerprint of every relation entry the row emits: domain, numerator and
/// tuple elements, in emission order. Two rows with the same fingerprint ask
/// every bus and table for exactly the same thing, so a column change that
/// leaves this value fixed is invisible to the interaction layer.
pub fn fingerprint(family: OpcodeFamily, columns: []const QM31) !u64 {
    const list = try opcode_entries.fromMain(family, columns);
    var hasher = std.hash.Wyhash.init(0);
    for (list.entries[0..list.len]) |emitted| {
        hasher.update(std.mem.asBytes(&@intFromEnum(emitted.domain)));
        hasher.update(std.mem.asBytes(&emitted.numerator));
        hasher.update(std.mem.sliceAsBytes(emitted.values[0..emitted.arity]));
    }
    return hasher.final();
}

fn preprocessedKind(domain: entry_mod.Domain) ?schema.Kind {
    return switch (domain) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        // Bus relations: closed globally, not row-locally.
        else => null,
    };
}

test "row admissibility: canonical padding is accepted only as an inactive row" {
    // `accepts` evaluates the row as active, so an all-zero row must fail its
    // placement constraint for every family that commits a real opcode.
    var columns = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    for (0..trace_mod.N_FAMILIES) |index| {
        const family: OpcodeFamily = @enumFromInt(index);
        const width = trace_mod.nColumnsForFamily(family);
        try std.testing.expect(!try accepts(family, columns[0..width]));
    }
}

test "row admissibility: the fingerprint moves with an emitted tuple element" {
    var columns = [_]QM31{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
    const width = trace_mod.nColumnsForFamily(.base_alu_reg);
    const base = try fingerprint(.base_alu_reg, columns[0..width]);
    // The pc column reaches the program and registers-state tuples.
    columns[semantic_eval.pcColumn(.base_alu_reg)] = QM31.one();
    try std.testing.expect(try fingerprint(.base_alu_reg, columns[0..width]) != base);
}
