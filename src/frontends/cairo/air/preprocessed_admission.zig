//! Shared CPU/Metal/CUDA selection of official preprocessed profiles.
const std = @import("std");
const claim = @import("../claim_generator.zig");
const preprocessed = @import("../preprocessed/trace.zig");
const templates = @import("template_library.zig");

pub fn select(allocator: std.mem.Allocator, geometry: *const claim.OwnedClaimGeometry, library: templates.Library, requested: preprocessed.Variant, automatic: bool) !preprocessed.Variant {
    if (requested != .canonical_small) return requested;
    var canonical = try preprocessed.Spec.init(allocator, .canonical);
    defer canonical.deinit();
    var small = try preprocessed.Spec.init(allocator, .canonical_small);
    defer small.deinit();
    for (geometry.components) |component| {
        const log = switch (component.log_size) {
            .known => |value| value,
            .deferred => continue,
        };
        if (log <= requested.maxLogSize()) continue;
        const source = try library.sourceFor(component.name, log, requested);
        const template = source.find(component.name) orelse return error.MissingAirTemplate;
        const spec = if (source.variant == .canonical) canonical else small;
        var buffer: [16]u8 = undefined;
        const sequence = try std.fmt.bufPrint(&buffer, "seq_{}", .{template.trace_log_size});
        const index = spec.indexOf(sequence) orelse return error.MissingSourceSequenceColumn;
        if (std.mem.indexOfScalar(u32, template.preprocessed_indices, index) == null) continue;
        if (!automatic) return error.ProvingProfileTooSmall;
        return .canonical;
    }
    return requested;
}
