//! Packed challenge authority for planned opcode interaction evaluation.

const std = @import("std");
const fields = @import("stwo_core").fields;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const entry = @import("entry.zig");
const relations_mod = @import("../relation_challenges.zig");

const PackedM31 = fields.m31.PackedM31;
const PackedQM31 = fields.packed_qm31.PackedQM31;

pub const PreparedProgram = struct {
    const Entry = struct {
        lookup: prover_component.LookupPolynomialEntry,
        z: PackedQM31,
        power_offset: u32,
    };

    allocator: std.mem.Allocator,
    entries: []Entry,
    powers: []PackedQM31,

    pub fn init(
        allocator: std.mem.Allocator,
        lookups: []const prover_component.LookupPolynomialEntry,
        domains: []const entry.Domain,
        relations: *const relations_mod.Relations,
    ) !PreparedProgram {
        if (lookups.len != domains.len)
            return error.InvalidLookupPolynomialProgram;
        var power_count: usize = 0;
        for (lookups) |lookup|
            power_count = try std.math.add(usize, power_count, lookup.arity);
        const entries = try allocator.alloc(Entry, lookups.len);
        errdefer allocator.free(entries);
        const powers = try allocator.alloc(PackedQM31, power_count);
        errdefer allocator.free(powers);
        var power_cursor: usize = 0;
        for (lookups, domains, entries) |lookup, domain, *destination| {
            if (lookup.arity != entry.expectedArity(domain))
                return error.InvalidLookupPolynomialProgram;
            const start = power_cursor;
            const z = switch (domain) {
                .registers_state => populate(2, &relations.registers_state, powers, &power_cursor),
                .memory_access => populate(7, &relations.memory_access, powers, &power_cursor),
                .program_access => populate(5, &relations.program_access, powers, &power_cursor),
                .merkle => populate(4, &relations.merkle, powers, &power_cursor),
                .poseidon2 => populate(16, &relations.poseidon2, powers, &power_cursor),
                .poseidon2_io => populate(32, &relations.poseidon2_io, powers, &power_cursor),
                .bitwise => populate(4, &relations.bitwise, powers, &power_cursor),
                .range_check_20 => populate(1, &relations.range_check_20, powers, &power_cursor),
                .range_check_8_11 => populate(2, &relations.range_check_8_11, powers, &power_cursor),
                .range_check_8_8_4 => populate(3, &relations.range_check_8_8_4, powers, &power_cursor),
                .range_check_8_8 => populate(2, &relations.range_check_8_8, powers, &power_cursor),
                .range_check_m31 => populate(2, &relations.range_check_m31, powers, &power_cursor),
            };
            destination.* = .{
                .lookup = lookup,
                .z = z,
                .power_offset = std.math.cast(u32, start) orelse
                    return error.InvalidLookupPolynomialProgram,
            };
        }
        std.debug.assert(power_cursor == powers.len);
        return .{ .allocator = allocator, .entries = entries, .powers = powers };
    }

    pub fn deinit(self: *PreparedProgram) void {
        self.allocator.free(self.powers);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn denominator(
        self: *const PreparedProgram,
        entry_index: usize,
        nodes: []const PackedM31,
    ) PackedQM31 {
        const prepared = self.entries[entry_index];
        const start: usize = prepared.power_offset;
        const powers = self.powers[start..][0..prepared.lookup.arity];
        var result = PackedQM31.zero();
        for (powers, 0..) |power, value_index| {
            result = result.add(
                power.mulBase(nodes[prepared.lookup.values[value_index]]),
            );
        }
        return result.sub(prepared.z);
    }

    fn populate(
        comptime arity: usize,
        relation: *const relations_mod.RelationElements(arity),
        powers: []PackedQM31,
        cursor: *usize,
    ) PackedQM31 {
        std.debug.assert(cursor.* + arity <= powers.len);
        for (relation.alpha_powers, powers[cursor.*..][0..arity]) |power, *destination|
            destination.* = PackedQM31.splat(power);
        cursor.* += arity;
        return PackedQM31.splat(relation.z);
    }
};
