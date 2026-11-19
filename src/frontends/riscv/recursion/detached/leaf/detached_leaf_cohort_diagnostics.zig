//! Observational diagnostics for the canonical leaf cohort; no authority is minted.
const std = @import("std");
const tuple_diagnostic = @import("detached_leaf_tuple_diagnostic.zig");
const relation_interaction = @import("stwo_riscv_air_lang").framework.relation_interaction;
const RED_TUPLE_DOMAIN_MASK = tuple_diagnostic.RED_DOMAIN_MASK;

pub fn diagnoseRedTupleClosure(
    self: anytype,
    allocator: std.mem.Allocator,
) !tuple_diagnostic.Report {
    var ledger = relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try self.noncore.appendTupleContributions(
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
    try self.core.appendTupleContributions(
        allocator,
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
    return tuple_diagnostic.classify(
        allocator,
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
}
