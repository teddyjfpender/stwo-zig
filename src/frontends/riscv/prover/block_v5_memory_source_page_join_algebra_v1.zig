//! Original shared-epoch PAGE/fold/sorted-RAM closure equations. This algebra
//! grants no proof or source authority; only the fresh join owner calls it
//! after consuming every independently admitted original proof exactly once.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
pub const Totals = struct {
    raw: Source.Sums = .{},
    indexed: Q = .zero(),
    fold: Fold.Algebra(Q).Sums = .{},
    initial: Q = .zero(),
    endpoint: Q = .zero(),
    predecessor: Q = .zero(),
};
pub const Sink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnclosedSourcePageJoin;
    }
};
pub fn canonical(value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Q) {
        for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalSourcePageJoin;
    } else {
        inline for (std.meta.fields(T)) |field| try canonical(@field(value, field.name));
    }
}
pub fn close(admitted: *const Batch.Admission, totals: Totals) !void {
    try admitted.require();
    try canonical(totals);
    var sink = Sink{};
    // RAW has no old per-edit leaf/node/root rows. Initial-image and final
    // tree roots are proved by the simultaneous FOLD, never the old route71
    // or root36 telescoping target. These unused RAW coordinates must be zero.
    inline for (.{ "bytes", "input", "route", "roots", "ordering", "sha_chain" }) |field| try sink.zero(@field(totals.raw, field));
    const source_records = Fold.Algebra(Q).Sums{
        .indexed = totals.indexed,
        .insertion = totals.raw.insertion,
        .before = totals.raw.before,
        .after = totals.raw.after,
    };
    // Every FOLD PAGE proves hash97 requests+actual original core suppliers
    // locally. Zero here is mandatory; no cross-page free core sum is accepted.
    try Fold.Algebra(Q).closure(admitted, totals.fold, Q.zero(), source_records, &sink);
    try sink.zero(totals.predecessor);
    try sink.zero(totals.initial.add(totals.raw.initial));
    try sink.zero(totals.endpoint.sub(totals.raw.endpoint));
}
