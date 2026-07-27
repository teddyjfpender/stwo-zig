//! Row-local admissibility oracle for one committed opcode-family row.
//!
//! Adversarial witness tests need a single answer to "would the AIR accept this
//! row?". Evaluating `semantic_eval` alone understates the AIR: several
//! bindings — the signed-load sign residual, byte ranges, bitwise results —
//! exist only as lookup requests, so a row whose direct constraints vanish can
//! still be rejected by a preprocessed table. This module decides both halves,
//! and `verdict` reports which of the two rejected so a test can attribute a
//! rejection to the specific check it claims to exercise.
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

/// The activated lookup request that rejected a row, in emission order.
pub const TableRejection = struct {
    /// Position in the row's emitted entry list. Two requests of one row can
    /// share a domain (`div` sends both its divisor byte pairs and its sign
    /// residual pair to `range_check_8_8`), so the domain alone does not name
    /// which obligation failed.
    index: usize,
    domain: entry_mod.Domain,
    arity: u8,
    values: [schema.MAX_ARITY]QM31 = .{QM31.zero()} ** schema.MAX_ARITY,

    /// The tuple as offered to the table. Truncated when `arity` disagrees with
    /// the schema, which is itself the rejection reason in that case.
    pub fn tuple(self: *const TableRejection) []const QM31 {
        return self.values[0..@min(@as(usize, self.arity), schema.MAX_ARITY)];
    }
};

/// Why the AIR rejects a row, or that it does not.
pub const Verdict = union(enum) {
    accepted,
    /// A direct constraint of the family does not vanish.
    direct_constraints,
    /// Every direct constraint vanishes; an activated request is absent from its
    /// preprocessed table. Attributing a rejection to a specific range check
    /// needs this distinction: a forgery that trips the carry chain and one that
    /// trips only a byte range are both "rejected", but only the second proves
    /// the byte range is load-bearing.
    table: TableRejection,
};

/// Decide `columns` on both the direct constraints and preprocessed lookup
/// membership, reporting which of the two rejected and which request.
///
/// `columns` is a borrowed row of exactly `trace_mod.nColumnsForFamily(family)`
/// secure-field cells, evaluated as an active (non-padding) row. Errors report
/// a shape or compatibility mismatch, never a rejected witness.
pub fn verdict(family: OpcodeFamily, columns: []const QM31) !Verdict {
    const evaluation = try semantic_eval.evaluate(family, columns, QM31.one());
    if (!evaluation.allZero()) return .direct_constraints;

    const list = try opcode_entries.fromMain(family, columns);
    for (list.entries[0..list.len], 0..) |emitted, index| {
        // A zero numerator switches the request off for this row.
        if (emitted.numerator.isZero()) continue;
        const kind = preprocessedKind(emitted.domain) orelse continue;
        const arity = schema.arity(kind);
        if (emitted.arity != arity) return rejection(index, emitted);

        var values: [schema.MAX_ARITY]M31 = undefined;
        for (values[0..arity], emitted.values[0..arity]) |*out, value| {
            out.* = value.tryIntoM31() catch return rejection(index, emitted);
        }
        _ = schema.indexBase(kind, values[0..arity]) catch return rejection(index, emitted);
    }
    return .accepted;
}

/// True when `verdict` accepts. Kept as the common spelling for tests that only
/// need a yes or no.
pub fn accepts(family: OpcodeFamily, columns: []const QM31) !bool {
    return switch (try verdict(family, columns)) {
        .accepted => true,
        else => false,
    };
}

fn rejection(index: usize, emitted: entry_mod.Entry) Verdict {
    var result = TableRejection{
        .index = index,
        .domain = emitted.domain,
        .arity = emitted.arity,
    };
    const copied = @min(@as(usize, emitted.arity), schema.MAX_ARITY);
    @memcpy(result.values[0..copied], emitted.values[0..copied]);
    return .{ .table = result };
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
