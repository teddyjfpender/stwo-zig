//! Explicit native-input exclusion before any borrowed RAM main writes. No
//! allocator internals or hash-map allocation reflection enters admission.
const std = @import("std");
const T = @import("private_trace.zig");
const Owned = @import("openings.zig").Owned;
const values = @import("values.zig");
const batch = @import("batch.zig");
const Storage = @import("../crypto/main_storage.zig");
pub fn validate(buffers: T.MainBuffers, cache: *const values.Cache, preparation: *const T.Preparation, owned: *const Owned) !void {
    var slices = try inputs(buffers, preparation, owned);
    // Inline zero digests/cache descriptors are read inputs; private hash-map
    // allocation internals are intentionally not enumerated.
    try Storage.exclude(&slices, std.mem.asBytes(cache));
}
pub fn validatePreparedGraph(buffers: T.MainBuffers, native: *const @import("native_frontier.zig").Prepared, preparation: *const T.Preparation, owned: *const Owned) !void {
    try native.requireMovable();
    var slices = try inputs(buffers, preparation, owned);
    try Storage.exclude(&slices, std.mem.asBytes(native));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.witness.leaves));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.witness.before_nodes));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.witness.after_nodes));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.witness.sides));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.witness.patches));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(native.io));
}
fn inputs(buffers: T.MainBuffers, preparation: *const T.Preparation, owned: *const Owned) ![11]Storage.Slice {
    // A consumed preparation retains a historical source pointer. Reject its
    // phase before touching descriptors that the moved trace may have freed.
    if (!preparation.available or preparation.source.ptr != owned.chunks.ptr or preparation.source.len != owned.chunks.len) return error.InvalidPrivateRamPreparation;
    var slices: [11]Storage.Slice = undefined;
    for (buffers.callers, slices[0..8]) |data, *slice| slice.* = .{ .values = data, .cells = data.len };
    slices[8] = .{ .values = buffers.provider, .cells = buffers.provider.len };
    slices[9] = .{ .values = buffers.policy_tail, .cells = buffers.policy_tail.len };
    slices[10] = .{ .values = buffers.byte_tail, .cells = buffers.byte_tail.len };
    try Storage.exclude(&slices, std.mem.asBytes(owned));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(owned.words));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(owned.clocks));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(owned.rights));
    try openings(&slices, owned.chunks);
    try Storage.exclude(&slices, std.mem.asBytes(preparation));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.changes));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.indices));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.common_grants));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.edge_certificates));
    try Storage.exclude(&slices, std.mem.asBytes(preparation.mappings));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.mappings.regions));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(preparation.mappings.grants));
    return slices;
}
fn openings(slices: []const Storage.Slice, source: []const batch.Opening) !void {
    try Storage.exclude(slices, std.mem.sliceAsBytes(source));
    for (source) |opening| {
        try Storage.exclude(slices, std.mem.sliceAsBytes(opening.before));
        try Storage.exclude(slices, std.mem.sliceAsBytes(opening.after));
        try Storage.exclude(slices, std.mem.sliceAsBytes(opening.terminal_clocks));
        try Storage.exclude(slices, std.mem.sliceAsBytes(opening.rights));
    }
}
