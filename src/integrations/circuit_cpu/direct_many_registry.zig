//! Closed, reviewed source-kind and lookup-dependency registry for V4.
//!
//! The live preflight still reads geometry from actual verifier handles. This
//! independent admission check pins the relation dependencies and native AIR
//! sources that the existing V4 proof identity is allowed to describe. It is
//! deliberately outside the V4 template digest so this narrowing check does
//! not change existing proof or transcript bytes.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const many = @import("private_many_boundary.zig");
const chip = @import("tagged_many_chip.zig");
const bridge = @import("tagged_many_bridge.zig");
const preflight = @import("direct_many_preflight.zig");

pub const SourceKind = enum(u8) { bundled_circuit, tagged_chip, tagged_bridge };
pub const registry_version: u32 = 1;

const gate_relation_id: u32 = 378353459;
const tagged_relation_id: u32 = 0x53333103;
const chip_source_sha256 = parseDigest("94a0a4d9203a024209b5e7cdfb2912fe63c33c4c623832712c82e167d4b6efa6");
const bridge_source_sha256 = parseDigest("7a0b9b6c1353f55571ef31a10ebd8f9e4e4422c5ed5a33c8e48e580668a5f466");

comptime {
    if (circuit.common.component_list.GATE_RELATION_ID != gate_relation_id or
        many.relation_id != tagged_relation_id or
        chip.main_width != 9 or chip.interaction_width != 8 or many.chip_n_constraints != 6 or
        bridge.main_width != 8 or bridge.interaction_width != 20 or bridge.n_constraints != 13)
        @compileError("V4 registered AIR changed; review source kind and proof profile before updating the registry");
}

pub const Entry = struct {
    kind: SourceKind,
    component_kind: many.ComponentKind,
    relation_ids: [2]u32,
    relation_count: usize,
    /// The bound circuit comes from the pinned AIR bundle, not a Zig AIR file.
    native_air_source_sha256: ?[32]u8,
};

pub fn entry(kind: SourceKind) Entry {
    return switch (kind) {
        .bundled_circuit => .{
            .kind = kind,
            .component_kind = .circuit,
            .relation_ids = .{ gate_relation_id, 0 },
            .relation_count = 1,
            .native_air_source_sha256 = null,
        },
        .tagged_chip => .{
            .kind = kind,
            .component_kind = .chip,
            .relation_ids = .{ tagged_relation_id, 0 },
            .relation_count = 1,
            .native_air_source_sha256 = chip_source_sha256,
        },
        .tagged_bridge => .{
            .kind = kind,
            .component_kind = .bridge,
            .relation_ids = .{ gate_relation_id, tagged_relation_id },
            .relation_count = 2,
            .native_air_source_sha256 = bridge_source_sha256,
        },
    };
}

/// The registry, rather than a caller's candidate or a mutable legacy Plan,
/// selects the only V4 component sequence: circuit, N chips, N bridges.
pub fn canonicalKindAt(index: usize, count: u8) !SourceKind {
    if (count == 0 or count > many.max_calls or index >= 1 + 2 * @as(usize, count))
        return error.UnregisteredManyAirDependency;
    if (index == 0) return .bundled_circuit;
    if (index <= count) return .tagged_chip;
    return .tagged_bridge;
}

/// This is an admission invariant, not an extraction of dependencies from the
/// AIR evaluator. Each listed relation remains a reviewed formula obligation.
pub fn requireLiveFact(kind: SourceKind, fact: preflight.Fact) !void {
    const registered = entry(kind);
    if (fact.kind != registered.component_kind or
        fact.relation_count != registered.relation_count or
        !std.mem.eql(u32, fact.relationSlice(), registered.relation_ids[0..registered.relation_count]))
        return error.UnregisteredManyAirDependency;
    switch (kind) {
        .bundled_circuit => {
            if (fact.call_id != null or fact.chip_constant != null or fact.bridge_boundary != null or
                fact.preprocessed_count != circuit.common.direct_arithmetic.N_COLUMNS or
                !std.meta.eql(fact.air_source_sha256, [_]u8{0} ** 32))
                return error.UnregisteredManyAirDependency;
        },
        .tagged_chip => {
            if (fact.call_id == null or fact.chip_constant == null or fact.bridge_boundary != null or
                fact.main_columns != 9 or fact.interaction_columns != 8 or fact.n_constraints != 6 or
                fact.evaluation_log_size != fact.trace_log_size + 1 or fact.preprocessed_count != 0 or
                !std.meta.eql(fact.air_source_sha256, registered.native_air_source_sha256.?))
                return error.UnregisteredManyAirDependency;
        },
        .tagged_bridge => {
            if (fact.call_id == null or fact.chip_constant != null or fact.bridge_boundary == null or
                fact.main_columns != 8 or fact.interaction_columns != 20 or fact.n_constraints != 13 or
                fact.trace_log_size != bridge.log_size or
                fact.evaluation_log_size != fact.trace_log_size + 2 or fact.preprocessed_count != 0 or
                !std.meta.eql(fact.air_source_sha256, registered.native_air_source_sha256.?))
                return error.UnregisteredManyAirDependency;
        },
    }
}

fn parseDigest(comptime hex: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, hex) catch unreachable;
    return value;
}

test "V4 registry rejects changed source and lookup dependencies" {
    for (1..many.max_calls + 1) |n| {
        const count: u8 = @intCast(n);
        try std.testing.expectEqual(SourceKind.bundled_circuit, try canonicalKindAt(0, count));
        for (1..1 + n) |index|
            try std.testing.expectEqual(SourceKind.tagged_chip, try canonicalKindAt(index, count));
        for (1 + n..1 + 2 * n) |index|
            try std.testing.expectEqual(SourceKind.tagged_bridge, try canonicalKindAt(index, count));
        try std.testing.expectError(error.UnregisteredManyAirDependency, canonicalKindAt(1 + 2 * n, count));
    }
    try std.testing.expectError(error.UnregisteredManyAirDependency, canonicalKindAt(0, 0));

    var fact: preflight.Fact = .{
        .kind = .chip,
        .call_id = 0,
        .trace_log_size = 4,
        .evaluation_log_size = 5,
        .main_offset = 0,
        .main_columns = 9,
        .interaction_offset = 0,
        .interaction_columns = 8,
        .constraint_offset = 0,
        .n_constraints = 6,
        .relation_ids = .{ tagged_relation_id, 0 },
        .relation_count = 1,
        .air_source_sha256 = preflight.chipSourceDigest(),
        .chip_constant = 7,
    };
    try requireLiveFact(.tagged_chip, fact);
    fact.relation_ids[0] ^= 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_chip, fact));
    fact.relation_ids[0] ^= 1;
    fact.air_source_sha256[0] ^= 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_chip, fact));
    fact.air_source_sha256[0] ^= 1;
    fact.n_constraints += 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_chip, fact));
    fact.n_constraints -= 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_bridge, fact));

    var bridge_fact: preflight.Fact = .{
        .kind = .bridge,
        .call_id = 0,
        .trace_log_size = bridge.log_size,
        .evaluation_log_size = bridge.log_size + 2,
        .main_offset = 0,
        .main_columns = 8,
        .interaction_offset = 0,
        .interaction_columns = 20,
        .constraint_offset = 0,
        .n_constraints = 13,
        .relation_ids = .{ gate_relation_id, tagged_relation_id },
        .relation_count = 2,
        .air_source_sha256 = preflight.bridgeSourceDigest(),
        .bridge_boundary = .{
            .call_id = 0,
            .rounds = 16,
            .constant = @import("stwo_core").fields.m31.M31.fromCanonical(7),
            .input = .{ 3, 4, 5, 6 },
            .output = .{ 7, 8, 9, 10 },
        },
    };
    try requireLiveFact(.tagged_bridge, bridge_fact);
    bridge_fact.relation_count = 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_bridge, bridge_fact));
    bridge_fact.relation_count = 2;
    bridge_fact.air_source_sha256[0] ^= 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.tagged_bridge, bridge_fact));

    var circuit_fact: preflight.Fact = .{
        .kind = .circuit,
        .call_id = null,
        .trace_log_size = 4,
        .evaluation_log_size = 5,
        .main_offset = 0,
        .main_columns = 12,
        .interaction_offset = 0,
        .interaction_columns = 8,
        .constraint_offset = 0,
        .n_constraints = 1,
        .preprocessed_count = circuit.common.direct_arithmetic.N_COLUMNS,
        .relation_ids = .{ gate_relation_id, 0 },
        .relation_count = 1,
    };
    try requireLiveFact(.bundled_circuit, circuit_fact);
    circuit_fact.relation_ids[0] ^= 1;
    try std.testing.expectError(error.UnregisteredManyAirDependency, requireLiveFact(.bundled_circuit, circuit_fact));
}
