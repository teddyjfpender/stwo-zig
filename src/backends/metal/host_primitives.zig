//! Host-visible protocol primitives used by the Metal backend.
//!
//! These operations are defined by protocol `core`; they are not fallbacks to
//! another backend. Device-resident operations remain owned by the Metal
//! runtime modules.

const std = @import("std");
const core = @import("stwo_core");

pub fn ColumnType(comptime F: type) type {
    return []F;
}

pub fn batchInverse(
    comptime F: type,
    allocator: std.mem.Allocator,
    column: []const F,
) ![]F {
    return core.fields.batchInverse(F, allocator, column);
}

pub fn foldLine(
    allocator: std.mem.Allocator,
    eval: []core.fields.qm31.QM31,
    domain: anytype,
    alpha: core.fields.qm31.QM31,
    workspace: *core.fri.FoldLineWorkspace,
) !core.fri.FoldLineResult {
    return core.fri.foldLineInPlaceWithWorkspace(
        allocator,
        eval,
        domain,
        alpha,
        workspace,
    );
}

pub fn foldLineN(
    allocator: std.mem.Allocator,
    eval: []core.fields.qm31.QM31,
    domain: anytype,
    alpha: core.fields.qm31.QM31,
    workspace: *core.fri.FoldLineWorkspace,
    n_folds: u32,
) !core.fri.FoldLineResult {
    return core.fri.foldLineInPlaceNWithWorkspace(
        allocator,
        eval,
        domain,
        alpha,
        workspace,
        n_folds,
    );
}
