//! Complete, independently derived native relation partition. Every original
//! typed lookup appears once, or in an exact space/(1-space) partition.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Lookup = @import("block_v5_native_lookup_request_source_v1.zig");
const Interaction = @import("../air/lookups/opcode_interaction.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 3;
pub const Layout = struct {
    a: std.mem.Allocator,
    slots: []Source.Slot,
    digest: [32]u8,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32) !Layout {
        // The existing access witness format rejects this geometry too. Do not
        // interpret new x0 hint columns through a legacy memory projection.
        if (shape.localZeroCustody() and mode == 0) return error.UnsupportedPartitionedLocalZeroGlobalMemory;
        const original = try Source.slotsFromShapeForMode(a, shape, external, mode);
        defer a.free(original);
        var slots: std.ArrayList(Source.Slot) = .empty;
        errdefer slots.deinit(a);
        try slots.appendSlice(a, original);
        var offset: usize = 0;
        for (shape.component_descs[0..shape.n_components]) |desc| {
            var plan = try Interaction.Plan.initForRecipe(a, desc.family, shape.localZeroCustody());
            defer plan.deinit();
            const degrees = try Lookup.nodeDegrees(a, plan);
            defer a.free(degrees);
            var ordinals: [@import("../air/lookups/entry.zig").MAX_ENTRIES]u8 = undefined;
            var count: usize = 0;
            for (plan.program.entries, 0..) |entry, i| {
                if (plan.domains[i] != .memory_access) continue;
                const space = plan.program.nodes[entry.values[0]];
                if (mode == 1 and space.op == .constant and space.value == 0) continue;
                if (mode == 1 and ((space.op == .constant and space.value != 1) or
                    (space.op != .constant and desc.family != .load_store))) return error.UnknownPartitionedMemorySpace;
                ordinals[count] = @intCast(i);
                count += 1;
            }
            var at: usize = 0;
            while (at < count) : (at += 2) {
                const size = @min(@as(usize, 2), count - at);
                const selected: [2]u8 = .{ ordinals[at], if (size == 2) ordinals[at + 1] else 0 };
                var nd: [2]u32 = @splat(0);
                var dd: [2]u32 = @splat(0);
                for (selected[0..size], 0..) |ordinal, i| {
                    const entry = plan.program.entries[ordinal];
                    nd[i] = degrees[entry.numerator] + if (mode == 1) degrees[entry.values[0]] else 0;
                    for (entry.values[0..entry.arity]) |value| dd[i] = @max(dd[i], degrees[value]);
                }
                const degree = @max(1 + dd[0] + dd[1], @max(nd[0] + dd[1], nd[1] + dd[0]));
                if (degree > 255) return error.PartitionedDegreeOverflow;
                const lookup = Lookup.Slot{ .source = .{ .opcode = desc.family }, .partition = .ordinary_memory_access, .entries = selected, .entry_count = @intCast(size), .degree = @intCast(degree), .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset, .width = desc.n_columns, .register_custody_mode = mode };
                try slots.append(a, .{ .kind = .{ .lookup = lookup }, .degree = lookup.degree, .log_size = lookup.log_size, .n_rows = lookup.n_rows, .main_offset = offset, .width = lookup.width, .register_custody_mode = mode });
            }
            offset += desc.n_columns;
        }
        try requireCoverage(a, shape, external, mode, slots.items);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x4236524c, VERSION, mode, @intCast(slots.items.len) });
        for (slots.items) |slot| Source.mixSlot(&channel, slot);
        return .{ .a = a, .slots = try slots.toOwnedSlice(a), .digest = channel.digestBytes() };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
};

/// Validate symbolically by typed entry ordinal and exact partition weights,
/// never by comparing a zero witness or a sampled relation challenge.
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32, slots: []const Source.Slot) !void {
    try shape.validateBlake3ExecutionWithExternal(external);
    if (mode > 1 or (shape.localZeroCustody() and mode == 0)) return error.UnsupportedPartitionedRelationGeometry;
    var expected_offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        var plan = try Interaction.Plan.initForRecipe(a, desc.family, shape.localZeroCustody());
        defer plan.deinit();
        var full: [@import("../air/lookups/entry.zig").MAX_ENTRIES]usize = @splat(0);
        var ram = full;
        var reg = full;
        for (slots) |slot| {
            if (slot.main_offset != expected_offset) continue;
            if (slot.log_size != desc.log_size or slot.n_rows != desc.n_rows or slot.width != (if (slot.kind == .program) @import("../runner/trace.zig").nColumnsForFamily(desc.family) else desc.n_columns) or slot.register_custody_mode != mode) return error.InvalidPartitionedRelationGeometry;
            switch (slot.kind) {
                .program => |family| {
                    if (family != desc.family) return error.InvalidPartitionedRelationSource;
                    for (plan.domains[0..plan.program.entries.len], 0..) |domain, i| if (domain == .program_access) {
                        full[i] += 1;
                    };
                },
                .lookup => |lookup| {
                    if (std.meta.activeTag(lookup.source) != .opcode or lookup.source.opcode != desc.family or lookup.entry_count == 0 or lookup.entry_count > 2 or lookup.register_custody_mode != mode) return error.InvalidPartitionedRelationSource;
                    if (lookup.entry_count == 1 and lookup.entries[1] != 0) return error.InvalidPartitionedRelationEntry;
                    if (lookup.degree != slot.degree or lookup.log_size != slot.log_size or lookup.n_rows != slot.n_rows or lookup.main_offset != slot.main_offset or lookup.width != slot.width) return error.InvalidPartitionedRelationGeometry;
                    if (lookup.partition == .ordinary_memory_access) {
                        const degrees = try Lookup.nodeDegrees(a, plan);
                        defer a.free(degrees);
                        var nd: [2]u32 = @splat(0);
                        var dd: [2]u32 = @splat(0);
                        for (lookup.entries[0..lookup.entry_count], 0..) |entry_index, i| {
                            if (entry_index >= plan.program.entries.len) return error.InvalidPartitionedRelationEntry;
                            const entry = plan.program.entries[entry_index];
                            nd[i] = degrees[entry.numerator] + if (mode == 1) degrees[entry.values[0]] else 0;
                            for (entry.values[0..entry.arity]) |value| dd[i] = @max(dd[i], degrees[value]);
                        }
                        if (slot.degree != @max(1 + dd[0] + dd[1], @max(nd[0] + dd[1], nd[1] + dd[0]))) return error.InvalidPartitionedRelationDegree;
                    }
                    for (lookup.entries[0..lookup.entry_count]) |i| {
                        if (i >= plan.program.entries.len) return error.InvalidPartitionedRelationEntry;
                        const domain = plan.domains[i];
                        if (domain == .memory_access) {
                            if (lookup.partition == .ordinary_memory_access) {
                                if (mode == 0) full[i] += 1 else ram[i] += 1;
                            } else if (lookup.partition == .register_memory_access and mode == 1) reg[i] += 1 else return error.InvalidPartitionedRelationDomain;
                        } else {
                            const valid = switch (domain) {
                                .registers_state => lookup.partition == .registers_state,
                                .bitwise => lookup.partition == .bitwise,
                                .range_check_20 => lookup.partition == .range_check_20,
                                .range_check_8_11 => lookup.partition == .range_check_8_11,
                                .range_check_8_8_4 => lookup.partition == .range_check_8_8_4,
                                .range_check_8_8 => lookup.partition == .range_check_8_8,
                                .range_check_m31 => lookup.partition == .range_check_m31,
                                else => false,
                            };
                            if (!valid) return error.InvalidPartitionedRelationDomain;
                            full[i] += 1;
                        }
                    }
                },
            }
        }
        for (plan.program.entries, 0..) |entry, i| {
            if (plan.domains[i] != .memory_access or mode == 0) {
                if (full[i] != 1 or ram[i] != 0 or reg[i] != 0) return error.IncompletePartitionedRelation;
            } else {
                const space = plan.program.nodes[entry.values[0]];
                const expected_ram: u8 = @intFromBool(space.op != .constant or space.value == 1);
                const expected_reg: u8 = @intFromBool(space.op != .constant or space.value == 0);
                if (full[i] != 0 or ram[i] != expected_ram or reg[i] != expected_reg or expected_ram + expected_reg == 0) return error.IncompletePartitionedRelation;
            }
        }
        expected_offset += desc.n_columns;
    }
    // Clock coverage is the existing canonical schedule, including both
    // space partitions in mode one. Exact roster reconstruction below also
    // forbids extra sources, degree labels and noncanonical slot metadata.
    const canonical = try Source.slotsFromShapeForMode(a, shape, external, mode);
    defer a.free(canonical);
    if (slots.len < canonical.len) return error.IncompletePartitionedRelation;
    for (canonical, slots[0..canonical.len]) |want, got| if (!std.meta.eql(want, got)) return error.InvalidPartitionedRelationRoster;
    for (slots[canonical.len..]) |slot| switch (slot.kind) {
        .program => return error.InvalidPartitionedRelationRoster,
        .lookup => |lookup| if (std.meta.activeTag(lookup.source) != .opcode or lookup.partition != .ordinary_memory_access or slot.main_offset >= expected_offset) return error.InvalidPartitionedRelationRoster,
    };
}
