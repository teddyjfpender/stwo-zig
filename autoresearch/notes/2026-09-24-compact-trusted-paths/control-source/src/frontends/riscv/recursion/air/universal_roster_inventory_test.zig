//! Cross-layer admission gate for the pinned universal-recursion roster.
//!
//! `universal_roster.zig` records protocol intent; `inventory.zig` records
//! executable typed-AIR substrate.  Keeping this check outside both modules
//! avoids an ownership cycle while making an overclaim in either direction a
//! test failure.

const std = @import("std");
const inventory = @import("inventory.zig");
const roster = @import("universal_roster.zig");

test "R-012 every typed logical roster row has exactly one admitted implementation" {
    var admitted = [_]u8{0} ** roster.COMPONENT_COUNT;

    for (inventory.DESCRIPTORS) |descriptor| {
        const row = descriptor.universal_row orelse continue;
        try std.testing.expect(row < admitted.len);
        try std.testing.expectEqual(
            inventory.Status.typed_logical_component,
            descriptor.status,
        );
        admitted[row] += 1;
        try std.testing.expectEqual(
            roster.Status.typed_logical,
            roster.DESCRIPTORS[row].status,
        );
    }

    for (roster.DESCRIPTORS, 0..) |descriptor, row| {
        const expected: u8 = @intFromBool(descriptor.status == .typed_logical);
        try std.testing.expectEqual(expected, admitted[row]);
    }
}

test "R-012 non-logical rows have no duplicate typed logical admission" {
    for (roster.DESCRIPTORS, 0..) |descriptor, row| {
        if (descriptor.status == .typed_logical) continue;
        for (inventory.DESCRIPTORS) |admitted| {
            try std.testing.expect(admitted.universal_row != @as(u8, @intCast(row)));
        }
    }
}

test "R-012 concrete adapters require typed ownership or authenticated delegation" {
    for (roster.DESCRIPTORS, 0..) |descriptor, row| {
        if (!descriptor.concrete_adapter and !descriptor.real_proof_gate)
            continue;
        try std.testing.expect(
            descriptor.status == .typed_logical or
                descriptor.status == .authenticated_shared_provider,
        );
        var matches: usize = 0;
        for (inventory.DESCRIPTORS) |admitted| {
            if (admitted.universal_row == @as(u8, @intCast(row))) matches += 1;
        }
        const expected_inventory_matches: usize = if (descriptor.status == .typed_logical) 1 else 0;
        try std.testing.expectEqual(expected_inventory_matches, matches);
        try std.testing.expect(!descriptor.real_proof_gate or descriptor.concrete_adapter);
    }
}
