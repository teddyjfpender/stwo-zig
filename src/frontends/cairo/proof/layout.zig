//! Official claim and committed-tree layout shared by proof transports.

const std = @import("std");
const registry = @import("../air/official_claim_registry.zig");
const composition = @import("../witness/composition_bundle.zig");

pub const segment_names = [_][]const u8{
    "output",
    "pedersen",
    "range_check_128",
    "ecdsa",
    "bitwise",
    "ec_op",
    "keccak",
    "poseidon",
    "range_check_96",
    "add_mod",
    "mul_mod",
};

pub const ComponentSpan = struct {
    start: usize = 0,
    len: usize = 0,
};

pub fn componentSpan(
    bundle: *const composition.Bundle,
    field_name: []const u8,
) ComponentSpan {
    var result = ComponentSpan{};
    for (bundle.components, 0..) |component, index| {
        if (!std.mem.eql(u8, canonicalName(component.label), field_name))
            continue;
        if (result.len == 0) result.start = index;
        result.len += 1;
    }
    return result;
}

/// Upstream always constructs the large-value memory claim. Its component
/// vector may be empty when an execution contains only small memory values.
pub fn claimFieldPresent(field_name: []const u8, span: ComponentSpan) bool {
    return span.len != 0 or std.mem.eql(u8, field_name, "memory_id_to_big");
}

pub fn validateComponents(bundle: *const composition.Bundle) !void {
    var seen = [_]bool{false} ** registry.claim_field_count;
    var last_field: ?usize = null;
    var last_instance: u32 = 0;
    for (bundle.components) |component| {
        const field_index = fieldIndex(canonicalName(component.label)) orelse
            return error.UnknownClaimComponent;
        if (last_field == field_index) {
            if (component.instance != last_instance + 1)
                return error.InvalidClaimGeometry;
        } else {
            if (seen[field_index] or component.instance != 0)
                return error.InvalidClaimGeometry;
            seen[field_index] = true;
        }
        last_field = field_index;
        last_instance = component.instance;
    }
}

pub fn treeLogs(
    allocator: std.mem.Allocator,
    bundle: *const composition.Bundle,
    tree: u32,
    column_count: usize,
) ![]u32 {
    const logs = try allocator.alloc(u32, column_count);
    errdefer allocator.free(logs);
    @memset(logs, 0);
    var cursor: usize = 0;
    for (bundle.components) |component| {
        const span = committedSpan(component, tree) orelse
            return error.MissingComponentTree;
        if (span.start != cursor or span.end > logs.len or span.start == span.end)
            return error.InvalidComponentTree;
        @memset(logs[span.start..span.end], component.trace_log_size);
        cursor = span.end;
    }
    if (cursor != logs.len) return error.InvalidComponentTree;
    return logs;
}

fn committedSpan(
    component: composition.Component,
    tree: u32,
) ?composition.TraceSpan {
    var found: ?composition.TraceSpan = null;
    for (component.trace_spans) |span| {
        if (span.tree != tree) continue;
        if (found != null) return null;
        found = span;
    }
    return found;
}

fn fieldIndex(name: []const u8) ?usize {
    for (registry.claim_fields, 0..) |field, index|
        if (std.mem.eql(u8, field.name, name)) return index;
    return null;
}

pub fn canonicalName(label: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, label, "memory_id_to_big["))
        "memory_id_to_big"
    else
        label;
}

test "proof layout canonicalizes split big-memory components" {
    try std.testing.expectEqualStrings(
        "memory_id_to_big",
        canonicalName("memory_id_to_big[15]"),
    );
}

test "proof layout preserves the required empty big-memory claim" {
    try std.testing.expect(claimFieldPresent("memory_id_to_big", .{}));
    try std.testing.expect(!claimFieldPresent("pedersen_builtin", .{}));
}
