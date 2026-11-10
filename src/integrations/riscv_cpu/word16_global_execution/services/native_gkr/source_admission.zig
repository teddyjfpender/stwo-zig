//! Native-GKR admission reuses the receiver's M4 source-accounting authority.
//! A weighted provider's valid support is not unit negative integer mass: the
//! membership model bounds unit consumers, while consistency bounds both signs.
//! These are necessary engineering gates, not a whole-protocol certificate.
const std = @import("std");
const Bounds = @import("../gkr_local/source_bounds.zig");
const V2 = @import("v2.zig");
const R = @import("roster.zig");
const M = @import("stwo_core").fields.m31.Modulus;
pub fn characteristicMass(bound: Bounds.Bound) !u64 {
    if (bound.unit_consumer_mass >= M or bound.unit_positive_mass >= M or bound.unit_negative_mass >= M) return error.Om31CandidateCharacteristicWrap;
    const mass = switch (bound.model) {
        .unit_membership_valid_support => bound.unit_consumer_mass,
        .unit_consistency => @max(bound.unit_positive_mass, bound.unit_negative_mass),
    };
    if (mass >= M) return error.Om31CandidateCharacteristicWrap;
    return mass;
}
/// One source-derived row per physical proof, in exact CPU-then-truth order.
/// Global totals bound every proof without trusting a producer's per-proof mass.
pub fn requireInventory(rosters: []const R.Roster, source: *const Bounds.Report) !void {
    const count = try std.math.add(usize, source.cpu_scopes.len, source.truth_scopes.len);
    if (count == 0 or rosters.len != count or source.shape.native_proofs != count) return error.NativeGkrSourceInventory;
    // Source accounting includes every pair of tuples that can collide under
    // alpha compression. The generic outer ledger alone uses a linear N
    // estimate and is insufficient for this independently derived source gate.
    try source.conditional_degrees.requireLookupOnlyBits(V2.REQUIRED_BITS + V2.SALT_GRINDING_BITS);
    const globals = try source.global_signed.absolute();
    for (rosters, 0..) |*roster, index| {
        var masses = V2.RelationMasses{ .local = @splat(0), .ram = globals.ram, .kio = globals.kio, .wire = globals.wire };
        if (index < source.cpu_scopes.len) {
            const scope = source.cpu_scopes[index];
            if (scope.namespace_count > V2.LOCAL_RELATIONS) return error.NativeGkrSourceInventory;
            for (scope.relations, 0..) |bound, relation| masses.local[relation] = try characteristicMass(bound);
            // OWNER19 has a disjoint JD table partition in addition to ordinary
            // token consistency. Charge their union, never discard the table.
            const owner = @intFromEnum(@import("../gkr_local/fractions.zig").Relation.owner);
            masses.local[owner] = try std.math.add(u64, masses.local[owner], try characteristicMass(scope.owner_table));
        } else {
            for (source.truth_scopes[index - source.cpu_scopes.len].relations, 0..) |bound, relation| masses.local[relation] = try characteristicMass(bound);
        }
        try V2.requireNativeGkrSecurity(roster, @intCast(count), masses);
    }
}

test "native GKR source admission distinguishes weighted support from ordinary signed events" {
    try std.testing.expectEqual(@as(u64, 17), try characteristicMass(.{ .model = .unit_membership_valid_support, .unit_consumer_mass = 17, .valid_provider_support = 91, .unit_negative_mass = 13 }));
    try std.testing.expectEqual(@as(u64, 23), try characteristicMass(.{ .model = .unit_consistency, .unit_positive_mass = 19, .unit_negative_mass = 23 }));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, characteristicMass(.{ .model = .unit_consistency, .unit_positive_mass = M }));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, characteristicMass(.{ .unit_consumer_mass = M }));
}

pub const MAX_PROOFS: u64 = 256;
pub const CLASS_MIXING_BITS: u16 = 2;
pub const ClassCaps = struct {
    local: [V2.LOCAL_RELATIONS]Bounds.Bound,
    global_slots: [3]u64,
    instances: u32,
    variables: u32,
    pub fn require(self: *const @This()) !void {
        var degrees = Bounds.ConditionalDegrees{};
        for (self.local) |bound| {
            _ = try characteristicMass(bound);
            var one = Bounds.ConditionalDegrees{};
            try one.add(bound);
            inline for (std.meta.fields(Bounds.ConditionalDegrees)) |field| @field(degrees, field.name) = try std.math.add(u128, @field(degrees, field.name), try std.math.mul(u128, @field(one, field.name), MAX_PROOFS));
        }
        const arities = [_]usize{ 14, 11, 35 };
        for (self.global_slots, arities) |slots, arity| try degrees.addGlobal(.{ .arity = arity, .denominator_slots = try std.math.mul(u64, slots, MAX_PROOFS) });
        try degrees.requireLookupOnlyBits(V2.REQUIRED_BITS + V2.SALT_GRINDING_BITS + CLASS_MIXING_BITS);
        try @import("../../../word16_execution/om31_security_candidate.zig").requireOuterGkrBits(.{ .outer_proofs = MAX_PROOFS, .instances = self.instances, .max_variables = self.variables, .max_tuple_arity = V2.MAX_TUPLE_ARITY }, V2.REQUIRED_BITS + V2.SALT_GRINDING_BITS + CLASS_MIXING_BITS);
    }
};
/// Readonly physical geometry only: no request, producer report or claimed mass.
pub fn cpuClassCaps(a: std.mem.Allocator, setup: *const @import("../roster.zig").CpuSetup) !ClassCaps {
    const Legacy = @import("../gkr_local/cpu_components.zig");
    var slots = try Legacy.Plan.init(a, setup);
    defer slots.deinit();
    var native = try @import("native_roster.zig").cpu(a, setup);
    defer native.deinit();
    var scope = Bounds.emptyCpu();
    var global_slots: [3]u64 = @splat(0);
    for (slots.slots) |slot| {
        try Bounds.addCpuRoleMode(&scope, slot.origin, slot.log, setup.materials.geometry.cpu_u8_pairs);
        try Bounds.globalSlots(&global_slots, slot.origin, slot.log);
    }
    const owner = @intFromEnum(@import("../gkr_local/fractions.zig").Relation.owner);
    _ = try characteristicMass(scope.owner_table);
    if (scope.owner_table.unit_consumer_mass != 0 and scope.owner_table.valid_provider_support != @import("stwo_riscv_frontend").rv64_air.crypto.bulk_memory.types.TABLE_ENTRIES) return error.NativeGkrSourceInventory;
    // The disjoint owner-table partition shares its namespace and polynomial.
    // Include its counts and support without treating weighted support as mass.
    scope.relations[owner].unit_positive_mass = try std.math.add(u64, scope.relations[owner].unit_positive_mass, scope.owner_table.unit_consumer_mass);
    scope.relations[owner].unit_negative_mass = try std.math.add(u64, scope.relations[owner].unit_negative_mass, scope.owner_table.unit_consumer_mass);
    scope.relations[owner].valid_provider_support = try std.math.add(u64, scope.relations[owner].valid_provider_support, scope.owner_table.valid_provider_support);
    var out = ClassCaps{ .local = scope.relations, .global_slots = global_slots, .instances = @intCast(native.roster.instances.len), .variables = native.roster.layers() };
    try out.require();
    return out;
}
pub fn truthClassCaps(a: std.mem.Allocator, d: @import("../wire.zig").TruthDeclaration) !ClassCaps {
    const TF = @import("../gkr_local/truth_fractions.zig");
    var native = try @import("native_roster.zig").truth(a, d);
    defer native.deinit();
    var out = ClassCaps{ .local = @splat(.{}), .global_slots = @splat(0), .instances = @intCast(native.roster.instances.len), .variables = native.roster.layers() };
    for (std.enums.values(TF.Relation)) |relation| out.local[@intFromEnum(relation)].arity = relation.arity();
    if (d.family == .keccak) {
        const policy = try @import("../gkr_local/truth_profile.zig").fromDeclaration(d);
        const rows = @as(u64, 1) << @intCast(d.logs[0]);
        for ([_]TF.Relation{ .chi, .xor5 }, [_]usize{ policy.chiLookups(), policy.xor5Lookups() }) |relation, queries| {
            const bound = &out.local[@intFromEnum(relation)];
            bound.consumer_sign = .negative;
            bound.unit_consumer_mass = try std.math.mul(u64, rows, queries);
            bound.valid_provider_support = @as(u64, 1) << @intCast(policy.tableLog(if (relation == .chi) .chi else .xor5));
            bound.denominator_slots = try std.math.add(u64, bound.unit_consumer_mass, bound.valid_provider_support);
        }
        out.global_slots[1] = try std.math.mul(u64, rows, policy.ioLookups());
    } else {
        const q = try @import("../gkr_local/truth_catalog.zig").lookupCountsForDeclaration(d);
        const bound = &out.local[@intFromEnum(TF.Relation.byte)];
        bound.unit_consumer_mass = q.byte_unit_consumers;
        bound.valid_provider_support = q.byte_provider_support;
        bound.denominator_slots = q.byte_denominator_slots;
        out.global_slots[2] = q.wire_denominator_slots;
    }
    try out.require();
    return out;
}
/// Bind the static source envelope to the same class digest as the AIR/layout.
pub fn emitClassCaps(caps: *const ClassCaps, writer: anytype) void {
    writer.words(&.{ V2.REQUIRED_BITS, V2.SALT_GRINDING_BITS, CLASS_MIXING_BITS, @intCast(MAX_PROOFS), caps.instances, caps.variables });
    for (caps.local) |bound| {
        writer.words(&.{ @intFromEnum(bound.model), @intCast(bound.arity), @intFromEnum(bound.consumer_sign) });
        writer.int64(bound.unit_consumer_mass);
        writer.int64(bound.valid_provider_support);
        writer.int64(bound.unit_positive_mass);
        writer.int64(bound.unit_negative_mass);
        writer.int64(bound.denominator_slots);
    }
    for (caps.global_slots) |slots| writer.int64(slots);
}

test "every frozen truth class clears source-derived mixed-class 159-bit lookup envelope" {
    const Types = @import("../types.zig");
    for (@import("canonical_rungs.zig").TRUTH) |entry| for (entry.logs) |log| {
        const declaration = @import("../wire.zig").TruthDeclaration{ .family = @as(Types.Family, @enumFromInt(@intFromEnum(entry.family) - 16)), .first_id = 1, .calls = 1, .logs = .{ log, entry.aux } };
        const caps = try truthClassCaps(std.testing.allocator, declaration);
        try caps.require();
    };
}
