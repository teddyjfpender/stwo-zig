//! One typed-specialization admission owner for canonical native infrastructure.
//! Protocol identities remain separate from this implementation-equivalence gate.
const std = @import("std");
const boundary_admission = @import("native_boundary_typed_admission.zig");

pub fn validateKind(kind: anytype, allocator: std.mem.Allocator) !void {
    switch (kind) {
        .program => try boundary_admission.validateProgram(allocator),
        .memory => try boundary_admission.validateMemory(allocator),
        .clock_update => try boundary_admission.validate(.clock, allocator),
        .bitwise => try boundary_admission.validate(.bitwise, allocator),
        .range_check_20 => try boundary_admission.validate(.range_check_20, allocator),
        .range_check_8_11 => try boundary_admission.validate(.range_check_8_11, allocator),
        .range_check_8_8_4 => try boundary_admission.validate(.range_check_8_8_4, allocator),
        .range_check_8_8 => try boundary_admission.validate(.range_check_8_8, allocator),
        .range_check_m31 => try boundary_admission.validate(.range_check_m31, allocator),
        .merkle => try @import("memory_commitment/merkle_typed_admission.zig").validate(allocator),
        .poseidon2 => try @import("memory_commitment/poseidon2_wide_typed_admission.zig").validate(allocator),
    }
}

/// Caller first admits statement shape; repeated shards share an equation kind.
pub fn validateStatement(statement: anytype, allocator: std.mem.Allocator) !void {
    var seen: u16 = 0;
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        const bit = @as(u16, 1) << @as(u4, @intCast(@intFromEnum(descriptor.kind)));
        if (seen & bit != 0) continue;
        try validateKind(descriptor.kind, allocator);
        seen |= bit;
    }
}
