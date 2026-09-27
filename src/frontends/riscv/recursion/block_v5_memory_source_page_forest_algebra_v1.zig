//! Original PAGE shared-epoch claims. Arithmetic only, never proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Old = @import("air/block_v5_memory_source_equations_v1.zig");
const Fold = @import("air/block_v5_memory_source_batch_equations_v1.zig");
const Batch = @import("../prover/block_v5_memory_source_batch_protocol_v1.zig");
pub const CLAIM_COUNT: usize = 22;
pub fn semanticClaimOffset(component_claim_first: u32) !u32 {
    return std.math.sub(u32, component_claim_first, @as(u32, CLAIM_COUNT)) catch error.UntrustedPageForestClaimLayout;
}
pub fn Claims(comptime S: type) type {
    return struct { source: Old.Algebra(S).Sums, indexed: S, fold: Fold.Algebra(S).Sums };
}
pub fn flatten(claims: Semantic.Claims) [CLAIM_COUNT]Q {
    var out: [CLAIM_COUNT]Q = undefined;
    var i: usize = 0;
    inline for (std.meta.fields(@TypeOf(claims.source))) |field| {
        out[i] = @field(claims.source, field.name);
        i += 1;
    }
    out[i] = claims.indexed;
    i += 1;
    inline for (std.meta.fields(@TypeOf(claims.fold))) |field| {
        out[i] = @field(claims.fold, field.name);
        i += 1;
    }
    std.debug.assert(i == CLAIM_COUNT);
    return out;
}
pub fn decode(comptime S: type, values: [CLAIM_COUNT]S) Claims(S) {
    var out: Claims(S) = undefined;
    var i: usize = 0;
    inline for (std.meta.fields(@TypeOf(out.source))) |field| {
        @field(out.source, field.name) = values[i];
        i += 1;
    }
    out.indexed = values[i];
    i += 1;
    inline for (std.meta.fields(@TypeOf(out.fold))) |field| {
        @field(out.fold, field.name) = values[i];
        i += 1;
    }
    std.debug.assert(i == CLAIM_COUNT);
    return out;
}
pub fn canonical(values: [CLAIM_COUNT]Q) !void {
    for (values) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalPageForestClaims;
}
/// PAGE-only closure. Initial/final RAM endpoint equations deliberately remain
/// OPEN exported terms until an actual lane/range verifier is joined above.
pub fn close(comptime S: type, admitted: *const Batch.Admission, values: [CLAIM_COUNT]S, sink: anytype) !void {
    const totals = decode(S, values);
    inline for (.{ "bytes", "input", "route", "roots", "ordering", "sha_chain" }) |field| try sink.zero(@field(totals.source, field));
    const records = Fold.Algebra(S).Sums{ .indexed = totals.indexed, .insertion = totals.source.insertion, .before = totals.source.before, .after = totals.source.after };
    try Fold.Algebra(S).closure(admitted, totals.fold, S.zero(), records, sink);
}

/// Original linear shared-epoch merge; each production operand is reconstructed
/// from actual byte sources by the forest graph, not a scalar receipt.
pub fn merge(comptime S: type, children: []const [CLAIM_COUNT]S, exported: [CLAIM_COUNT]S, sink: anytype) !void {
    if (children.len == 0 or children.len > 4) return error.InvalidPageForestTopology;
    var sums: [CLAIM_COUNT]S = @splat(S.zero());
    for (children) |child| for (&sums, child) |*sum, value| {
        sum.* = sum.add(value);
    };
    for (sums, exported) |sum, value| try sink.zero(value.sub(sum));
}
