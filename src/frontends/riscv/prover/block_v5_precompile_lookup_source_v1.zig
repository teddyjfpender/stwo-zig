//! Exact shared-table extraction from authenticated SHA DAGs and shipped
//! generic Keccak/signer events. Arithmetic/private provider buses stay open.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const local_zero = @import("block_v5_precompile_protocol_v1.zig").circuit_profile.localZeroCustody();
const ShaProfile = @import("../air/guest_precompile/sha256_component_profile.zig");
const Sha = struct {
    pub const Airs = ShaProfile.AirsForRecipe(local_zero);
    pub const Roster = if (local_zero) ShaProfile.LocalZeroRoster else ShaProfile.Roster;
};
const Binding = @import("../recursion/air/universal_relation_binding.zig").Binding;
const Tables = @import("../air/lookups/tables/schema.zig");
const Relation = @import("../air/lang/relation.zig");
const Keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const Signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const Logup = @import("../air/logup.zig");
pub const Kind = enum { keccak, signer, sha_source, sha_schedule, sha_round, sha_feedforward, sha_caller };
pub const Partition = enum(u8) { bitwise, range_check_20, range_check_8_11, range_check_8_8_4, range_check_8_8, range_check_m31, register_memory };
pub const PARTITION_COUNT = Tables.KIND_COUNT + 1;
pub const Slot = struct {
    source: Kind,
    table: Partition,
    entries: [2]u8,
    entry_count: u8,
    degree: u8,
    log_size: u32,
    n_rows: u32,
    fixed_offset: usize,
    fixed_width: usize,
    main_offset: usize,
    width: usize,
};
pub const MAX_MAIN: usize = blk: {
    var width: usize = @max(Keccak.Layout.main_columns + @as(usize, if (local_zero) 2 else 0), Signer.Layout.main_columns + @as(usize, if (local_zero) 2 else 0));
    for (Sha.Airs) |Air| width = @max(width, Air.PHYSICAL_MAIN_COLUMN_COUNT);
    break :blk width;
};
pub const MAX_FIXED: usize = blk: {
    var width: usize = 0;
    for (Sha.Airs) |Air| width = @max(width, Air.PREPROCESSED_COLUMN_COUNT);
    break :blk width;
};
pub const Pair = Logup.RowPair;

pub const Owner = struct {
    sha: Sha.Roster.Tuple(.plan),
    pub fn init(a: std.mem.Allocator) !*Owner {
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        inline for (Sha.Airs, 0..) |Air, i| {
            var definition = try Air.build(a);
            defer definition.deinit();
            self.sha[i] = try Binding(Air).authenticate(&definition);
        }
        return self;
    }
    pub fn destroy(self: *Owner, a: std.mem.Allocator) void {
        a.destroy(self);
    }

    /// Dedicated family11 has no clock_update/accessChain helper component.
    /// Its only universal memory effects are the physical caller transitions.
    /// Check this exact census before treating the auxiliary partition as zero.
    pub fn memoryPairCensus(self: *const Owner, statement: *const Profile.admission.Statement) !u64 {
        var sha_memory_events: u64 = 0;
        inline for (Sha.Airs, 0..) |_, i| for (self.sha[i].events) |event| {
            if (event.domain != .memory_access) continue;
            if (i != 4 or event.arity != 7 or (event.role != .consume and event.role != .emit))
                return error.UnexpectedV5CallerAuxiliaryMemory;
            sha_memory_events += 1;
        };
        if (sha_memory_events != 52) return error.UnexpectedV5CallerAuxiliaryMemory;
        const keccak = try std.math.mul(u64, statement.ethereum.counts.keccak_calls, 1 + Keccak.word_count);
        const signer = try std.math.mul(u64, statement.ethereum.counts.signer_calls, 1 + Signer.input_word_count + Signer.output_word_count);
        const sha = try std.math.mul(u64, statement.sha.call_count, sha_memory_events / 2);
        const count = try std.math.add(u64, try std.math.add(u64, keccak, signer), sha);
        if (count != statement.ethereum.admission.memory_relation_terms or
            count != try @import("block_execution_external_trace_v2.zig").expectedEventCount(statement))
            return error.UnexpectedV5CallerAuxiliaryMemory;
        return count;
    }

    pub fn slots(self: *const Owner, a: std.mem.Allocator, statement: *const Profile.admission.Statement) ![]Slot {
        return self.slotsForMode(a, statement, 0);
    }
    pub fn slotsForMode(self: *const Owner, a: std.mem.Allocator, statement: *const Profile.admission.Statement, mode: u32) ![]Slot {
        if (mode > 1) return error.InvalidV5RegisterCustodyMode;
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
        var out: std.ArrayList(Slot) = .empty;
        errdefer out.deinit(a);
        var fixed_offset: usize = 0;
        var main_offset: usize = 0;
        for (Profile.descriptors(statement), 0..) |desc, component| {
            if (component == 0 or component == 13) {
                const is_keccak = component == 0;
                const words: usize = if (is_keccak) Keccak.word_count else Signer.input_word_count + Signer.output_word_count;
                if (mode == 1) try appendSlots(a, &out, if (is_keccak) .keccak else .signer, .register_memory, &.{ 3, 4 }, 3, desc, fixed_offset, main_offset);
                var selected: [51]u8 = undefined;
                selected[0] = 5;
                for (0..words) |word| selected[word + 1] = @intCast(8 + 3 * word);
                try appendSlots(a, &out, if (is_keccak) .keccak else .signer, .range_check_20, selected[0 .. words + 1], 3, desc, fixed_offset, main_offset);
                selected[0] = @intCast(6 + 3 * words);
                try appendSlots(a, &out, if (is_keccak) .keccak else .signer, .range_check_8_8, selected[0..1], 3, desc, fixed_offset, main_offset);
                selected[0] += 1;
                try appendSlots(a, &out, if (is_keccak) .keccak else .signer, .range_check_8_8_4, selected[0..1], 3, desc, fixed_offset, main_offset);
            } else if (component >= 14) {
                inline for (Sha.Airs, 0..) |Air, i| if (component == 14 + i) {
                    inline for (0..Tables.KIND_COUNT) |kind_id| {
                        const table: Partition = @enumFromInt(kind_id);
                        const domain = @field(Relation.Domain, @tagName(table));
                        var selected: [Air.RELATION_EVENT_COUNT]u8 = undefined;
                        var count: usize = 0;
                        for (self.sha[i].events) |event| if (event.domain == domain) {
                            selected[count] = event.ordinal;
                            count += 1;
                        };
                        const start = out.items.len;
                        try appendSlots(a, &out, @enumFromInt(@intFromEnum(Kind.sha_source) + i), table, selected[0..count], 1, desc, fixed_offset, main_offset);
                        for (out.items[start..]) |*slot| slot.degree = try projectedDegree(Air, &self.sha[i], slot.entries[0..slot.entry_count]);
                    }
                    if (mode == 1) {
                        var selected: [Air.RELATION_EVENT_COUNT]u8 = undefined;
                        var count: usize = 0;
                        for (self.sha[i].events) |event| {
                            if (event.domain != .memory_access) continue;
                            const space = constantSlot(&self.sha[i], event.value_slots[0]) orelse return error.UnknownV5CallerRegisterSpace;
                            if (space > 1) return error.UnknownV5CallerRegisterSpace;
                            if (space == 0) {
                                selected[count] = event.ordinal;
                                count += 1;
                            }
                        }
                        const start = out.items.len;
                        try appendSlots(a, &out, @enumFromInt(@intFromEnum(Kind.sha_source) + i), .register_memory, selected[0..count], 1, desc, fixed_offset, main_offset);
                        for (out.items[start..]) |*slot| slot.degree = try projectedDegree(Air, &self.sha[i], slot.entries[0..slot.entry_count]);
                    }
                };
            }
            fixed_offset += desc.preprocessed_columns;
            main_offset += desc.main_columns;
        }
        return out.toOwnedSlice(a);
    }

    pub fn pair(self: *const Owner, slot: Slot, fixed: []const Q, main: []const Q, relations: *const Profile.Relations) !Pair {
        return self.pairFor(Q, slot, fixed, main, relations);
    }

    /// Original shared request equations with typed recursive scalars.
    pub fn pairFor(self: *const Owner, comptime S: type, slot: Slot, fixed: []const S, main: []const S, relations: anytype) !Logup.RowPairFor(S) {
        if (main.len != slot.width or fixed.len != slot.fixed_width or slot.entry_count == 0 or slot.entry_count > 2)
            return error.InvalidV5CallerLookupSlot;
        var result = Logup.RowPairFor(S).single(S.zero(), S.one());
        switch (slot.source) {
            .keccak => {
                const witness = @import("../air/guest_precompile/keccakf_witness.zig");
                const zeros: [witness.state_cell_count]S = @splat(S.zero());
                const events = if (local_zero) try @import("../air/guest_precompile/keccakf_caller_local_zero_v1.zig").coreEvents(S, main, &zeros, &zeros, &relations.ethereum.keccak) else Keccak.coreEvents(S, main, &zeros, &zeros, &relations.ethereum.keccak);
                for (slot.entries[0..slot.entry_count], 0..) |index, i| setPairFor(S, &result, i, events[index].n1, events[index].d1);
            },
            .signer => {
                if (main.len != Signer.Layout.main_columns + @as(usize, if (local_zero) 2 else 0)) return error.InvalidV5CallerLookupSlot;
                const events = if (local_zero) try @import("../air/guest_precompile/secp256k1_caller_local_zero_v1.zig").rowEvents(S, main[0 .. Signer.Layout.main_columns + 2], &relations.ethereum.secp) else Signer.rowEvents(S, main[0..Signer.Layout.main_columns], &relations.ethereum.secp);
                for (slot.entries[0..slot.entry_count], 0..) |index, i| setPairFor(S, &result, i, events[index].n1, events[index].d1);
            },
            else => inline for (Sha.Airs, 0..) |Air, i| {
                if (@intFromEnum(slot.source) == @intFromEnum(Kind.sha_source) + i) {
                    const Runtime = Binding(Air).Runtime;
                    var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
                    if (main.len != Air.PHYSICAL_MAIN_COLUMN_COUNT or fixed.len != Air.PREPROCESSED_COLUMN_COUNT or
                        row.len != main.len + fixed.len) return error.InvalidV5CallerLookupSlot;
                    @memcpy(row[0..main.len], main);
                    @memcpy(row[main.len..], fixed);
                    var visitor = VisitorFor(S, @TypeOf(relations.sha)){ .slot = slot, .relations = &relations.sha, .out = &result };
                    try self.sha[i].visitPreparedEntriesFor(S, row, &visitor);
                    if (visitor.found != slot.entry_count) return error.InvalidV5CallerLookupSlot;
                }
            },
        }
        return result;
    }
};

fn VisitorFor(comptime S: type, comptime Relations: type) type {
    return struct {
        slot: Slot,
        relations: *const Relations,
        out: *Logup.RowPairFor(S),
        found: u8 = 0,
        pub fn accepts(self: *@This(), schema: @import("../air/lang/types.zig").RelationSchemaId) bool {
            return schema == Relation.id(tableDomain(self.slot.table));
        }
        pub fn visit(self: *@This(), ordinal: u8, domain: Relation.Domain, numerator: S, values: []const S) !void {
            for (self.slot.entries[0..self.slot.entry_count], 0..) |expected, index| if (ordinal == expected) {
                setPairFor(S, self.out, index, numerator, try self.relations.get(domain).combineSecure(values));
                self.found += 1;
            };
        }
    };
}
fn setPairFor(comptime S: type, out: *Logup.RowPairFor(S), index: usize, numerator: S, denominator: S) void {
    if (index == 0) {
        out.n1 = numerator;
        out.d1 = denominator;
    } else {
        out.n2 = numerator;
        out.d2 = denominator;
    }
}

fn appendSlots(a: std.mem.Allocator, out: *std.ArrayList(Slot), source: Kind, table: Partition, selected: []const u8, degree: u8, desc: Profile.Descriptor, fixed: usize, main: usize) !void {
    var at: usize = 0;
    while (at < selected.len) : (at += 2) try out.append(a, .{
        .source = source,
        .table = table,
        .entries = .{ selected[at], if (at + 1 < selected.len) selected[at + 1] else 0 },
        .entry_count = @intCast(@min(@as(usize, 2), selected.len - at)),
        .degree = degree,
        .log_size = desc.log_size,
        .n_rows = @as(u32, 1) << @intCast(desc.log_size),
        .fixed_offset = fixed,
        .fixed_width = if (source == .keccak or source == .signer) 0 else desc.preprocessed_columns,
        .main_offset = main + if (source == .keccak) @import("../air/guest_precompile/keccakf_trace.zig").Layout.caller else @as(usize, 0),
        .width = if (source == .keccak) Keccak.Layout.main_columns + @as(usize, if (local_zero) 2 else 0) else desc.main_columns,
    });
}

/// Bound the actual projected rational recurrence, including pairs whose
/// original AIR batch differs. Every degree comes from its authenticated DAG.
fn projectedDegree(comptime Air: type, plan: *const Binding(Air).Runtime.Plan, selected: []const u8) !u8 {
    var degrees: [Air.LOGICAL_INPUT_COUNT + @import("../recursion/air/relation_interaction_tuple_ledger.zig").MAX_COMPILED_NODES]u32 = @splat(1);
    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| degrees[node.destination] = switch (node.op) {
        .constant => 0,
        .add, .sub => |v| @max(degrees[v.lhs], degrees[v.rhs]),
        .mul => |v| try std.math.add(u32, degrees[v.lhs], degrees[v.rhs]),
        .neg => |v| degrees[v],
        .select => |v| try std.math.add(u32, degrees[v.selector], @max(degrees[v.when_true], degrees[v.when_false])),
        .machine => |v| blk: {
            var d: u32 = 0;
            const types = @import("../air/lang/types.zig");
            for (@import("../recursion/air/closed_machine_expression.zig").operands(v)) |operand| if (operand) |id| {
                d = @max(d, degrees[types.idIndex(id)]);
            };
            break :blk d;
        },
    };
    var numerator: [2]u32 = @splat(0);
    var denominator: [2]u32 = @splat(0);
    for (selected, 0..) |ordinal, index| {
        const event = plan.events[ordinal];
        numerator[index] = degrees[event.numerator_slot];
        for (event.value_slots[0..event.arity]) |slot| denominator[index] = @max(denominator[index], degrees[slot]);
    }
    const degree = @max(1 + denominator[0] + denominator[1], @max(numerator[0] + denominator[1], numerator[1] + denominator[0]));
    return std.math.cast(u8, degree) orelse error.V5CallerLookupDegreeOverflow;
}

fn tableDomain(kind: Partition) Relation.Domain {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        .register_memory => .memory_access,
    };
}

fn constantSlot(plan: anytype, slot: u16) ?u32 {
    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
        if (node.destination != slot) continue;
        return switch (node.op) {
            .constant => |value| value,
            else => null,
        };
    }
    return null;
}
