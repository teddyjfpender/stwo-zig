const std = @import("std");
const arena_plan = @import("../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../backends/metal/runtime.zig");
const adapter = @import("stwo_cairo_frontend").adapter;
const fixed_table_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;

const rc99_table_size: u32 = 1 << 18;
const rc99_lut_ordinal: u32 = 7;

pub const Error = error{
    DuplicateBinding,
    MissingBinding,
    InvalidSchedule,
    InvalidGeometry,
    InvalidPublicMemory,
    InvalidRc99Table,
};

pub const ValuePart = struct {
    source_offset: u32,
    row_count: u32,
    outputs: []arena_plan.Binding,
};

pub const Telemetry = struct {
    public_seed_gpu_ms: f64 = 0,
    trace_gpu_ms: f64 = 0,
    rc99_gpu_ms: f64 = 0,

    pub fn totalGpuMs(self: Telemetry) f64 {
        return self.public_seed_gpu_ms + self.trace_gpu_ms + self.rc99_gpu_ms;
    }
};

/// Exact native memory-witness graph. Its bindings come from the captured
/// proof schedule; no offset, row count, or trace-part split is inferred from
/// allocation order.
pub const CairoMemoryTrace = struct {
    allocator: std.mem.Allocator,
    raw_address: arena_plan.Binding,
    address_counts: arena_plan.Binding,
    address_outputs: []arena_plan.Binding,
    big_sources: []arena_plan.Binding,
    big_counts: arena_plan.Binding,
    big_parts: []ValuePart,
    small_sources: []arena_plan.Binding,
    small_counts: arena_plan.Binding,
    small_part: ValuePart,
    rc99_lut: arena_plan.Binding,
    rc99_counts: arena_plan.Binding,
    rc99_column_0: arena_plan.Binding,
    rc99_column_1: arena_plan.Binding,

    pub fn init(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        fixed_bundle: fixed_table_bundle.Bundle,
    ) !CairoMemoryTrace {
        const raw_address = try one(schedule, plan, "ExecutionTableRawAddressToId");
        const address_counts = try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_address_to_id", 21);
        const big_counts = try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 22);
        const small_counts = try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 23);
        const rc99_counts = try oneComponent(schedule, plan, "FixedMultiplicity", "range_check_9_9");
        const rc99_lut = try oneOrdinal(schedule, plan, "WitnessFeedLut", rc99_lut_ordinal);

        const address_outputs = try collectComponent(allocator, schedule, plan, "BaseTrace", "memory_address_to_id");
        errdefer allocator.free(address_outputs);
        const big_sources = try collect(allocator, schedule, plan, "ExecutionTableBigLimb");
        errdefer allocator.free(big_sources);
        const small_sources = try collect(allocator, schedule, plan, "ExecutionTableSmallLimb");
        errdefer allocator.free(small_sources);
        const groups = try collectComponentGroups(allocator, schedule, plan, "BaseTrace", "memory_id_to_big");
        defer allocator.free(groups);
        errdefer for (groups) |group| allocator.free(group);

        if (address_outputs.len != 32 or big_sources.len != 28 or small_sources.len != 8 or
            groups.len < 2 or rc99_lut.size_bytes != @as(u64, rc99_table_size) * 4 or
            rc99_counts.size_bytes != @as(u64, rc99_table_size) * 8 * 4)
            return Error.InvalidGeometry;

        var big_part_count: usize = 0;
        var small_group_index: ?usize = null;
        for (groups, 0..) |group, index| {
            if (group.len == 29) {
                if (small_group_index != null) return Error.InvalidGeometry;
                big_part_count += 1;
            } else if (group.len == 9 and small_group_index == null) {
                small_group_index = index;
            } else return Error.InvalidGeometry;
        }
        if (big_part_count == 0 or small_group_index == null or small_group_index.? != groups.len - 1)
            return Error.InvalidGeometry;

        const big_parts = try allocator.alloc(ValuePart, big_part_count);
        errdefer allocator.free(big_parts);
        var source_offset: u64 = 0;
        for (groups[0..small_group_index.?], 0..) |group, part_index| {
            const row_count = try uniformRows(group);
            big_parts[part_index] = .{
                .source_offset = std.math.cast(u32, source_offset) orelse return Error.InvalidGeometry,
                .row_count = row_count,
                .outputs = group,
            };
            source_offset += row_count;
        }
        const small_outputs = groups[small_group_index.?];
        const small_rows = try uniformRows(small_outputs);
        if (source_offset != big_counts.size_bytes / 4 or
            small_counts.size_bytes / 4 != small_rows or
            address_counts.size_bytes / 4 != @as(u64, try uniformRows(address_outputs)) * 16)
            return Error.InvalidGeometry;

        const rc99_column_0_ordinal = fixed_bundle.identityOrdinal("range_check_9_9_column_0") orelse return Error.MissingBinding;
        const rc99_column_1_ordinal = fixed_bundle.identityOrdinal("range_check_9_9_column_1") orelse return Error.MissingBinding;
        const rc99_column_0 = try oneOrdinal(schedule, plan, "PreprocessedEvaluations", rc99_column_0_ordinal);
        const rc99_column_1 = try oneOrdinal(schedule, plan, "PreprocessedEvaluations", rc99_column_1_ordinal);
        if (rc99_column_0.size_bytes != @as(u64, rc99_table_size) * 4 or
            rc99_column_1.size_bytes != @as(u64, rc99_table_size) * 4)
            return Error.InvalidGeometry;

        try validateNarrow(raw_address);
        try validateNarrow(address_counts);
        try validateNarrow(big_counts);
        try validateNarrow(small_counts);
        try validateNarrow(rc99_lut);
        try validateNarrow(rc99_counts);
        for (address_outputs) |binding| try validateNarrow(binding);
        for (big_sources) |binding| try validateNarrow(binding);
        for (big_parts) |part| for (part.outputs) |binding| try validateNarrow(binding);
        for (small_sources) |binding| try validateNarrow(binding);
        for (small_outputs) |binding| try validateNarrow(binding);

        const result = CairoMemoryTrace{
            .allocator = allocator,
            .raw_address = raw_address,
            .address_counts = address_counts,
            .address_outputs = address_outputs,
            .big_sources = big_sources,
            .big_counts = big_counts,
            .big_parts = big_parts,
            .small_sources = small_sources,
            .small_counts = small_counts,
            .small_part = .{ .source_offset = 0, .row_count = small_rows, .outputs = small_outputs },
            .rc99_lut = rc99_lut,
            .rc99_counts = rc99_counts,
            .rc99_column_0 = rc99_column_0,
            .rc99_column_1 = rc99_column_1,
        };
        return result;
    }

    /// Native memory kernels use Metal `uint` base offsets. Validate complete
    /// ranges before dispatch so indexed access cannot wrap at 2^32 words.
    pub fn validateNarrowAddresses(self: CairoMemoryTrace) !void {
        try validateNarrow(self.raw_address);
        try validateNarrow(self.address_counts);
        try validateNarrow(self.big_counts);
        try validateNarrow(self.small_counts);
        try validateNarrow(self.rc99_lut);
        try validateNarrow(self.rc99_counts);
        for (self.address_outputs) |binding| try validateNarrow(binding);
        for (self.big_sources) |binding| try validateNarrow(binding);
        for (self.big_parts) |part| for (part.outputs) |binding| try validateNarrow(binding);
        for (self.small_sources) |binding| try validateNarrow(binding);
        for (self.small_part.outputs) |binding| try validateNarrow(binding);
    }

    pub fn deinit(self: *CairoMemoryTrace) void {
        self.allocator.free(self.address_outputs);
        self.allocator.free(self.big_sources);
        self.allocator.free(self.small_sources);
        for (self.big_parts) |part| self.allocator.free(part.outputs);
        self.allocator.free(self.big_parts);
        self.allocator.free(self.small_part.outputs);
        self.* = undefined;
    }

    /// Builds the canonical input-to-row permutation from the already
    /// committed preprocessed columns. This is statement-independent and is
    /// uploaded once per resident proof session.
    pub fn populateRc99Lut(self: CairoMemoryTrace, resident_arena: *arena_plan.ResidentArena) !void {
        const lhs = try words(resident_arena, self.rc99_column_0);
        const rhs = try words(resident_arena, self.rc99_column_1);
        const lut = try words(resident_arena, self.rc99_lut);
        if (lhs.len != rc99_table_size or rhs.len != rc99_table_size or lut.len != rc99_table_size)
            return Error.InvalidGeometry;
        @memset(lut, std.math.maxInt(u32));
        for (lhs, rhs, 0..) |a, b, row| {
            if (a >= 512 or b >= 512) {
                std.log.err("invalid RC9_9 preprocessed row {d}: ({d}, {d}) is outside [0, 512)", .{ row, a, b });
                return Error.InvalidRc99Table;
            }
            const key = (a << 9) | b;
            if (lut[key] != std.math.maxInt(u32)) {
                std.log.err("invalid RC9_9 preprocessed row {d}: ({d}, {d}) duplicates row {d}", .{ row, a, b, lut[key] });
                return Error.InvalidRc99Table;
            }
            lut[key] = @intCast(row);
        }
        for (lut, 0..) |row, key| if (row == std.math.maxInt(u32)) {
            std.log.err("invalid RC9_9 preprocessed table: missing pair ({d}, {d})", .{ key >> 9, key & 511 });
            return Error.InvalidRc99Table;
        };
    }

    pub fn execute(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        input: *const adapter.ProverInput,
    ) !Telemetry {
        var telemetry: Telemetry = .{};
        telemetry.public_seed_gpu_ms = try self.seedPublicMemory(metal, resident_arena, input);
        telemetry.trace_gpu_ms += try self.executeAddress(metal, resident_arena, input);
        const values = try self.executeValues(metal, resident_arena);
        telemetry.trace_gpu_ms += values.trace_gpu_ms;
        telemetry.rc99_gpu_ms += values.rc99_gpu_ms;
        return telemetry;
    }

    pub fn seedPublicMemory(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        input: *const adapter.ProverInput,
    ) !f64 {
        if (self.raw_address.size_bytes != @as(u64, input.memory.address_to_id.len) * 4)
            return Error.InvalidGeometry;
        const public_pairs = try self.allocator.alloc([2]u32, input.public_memory_addresses.len);
        defer self.allocator.free(public_pairs);
        for (input.public_memory_addresses, public_pairs) |address, *pair| {
            if (address == 0 or address >= input.memory.address_to_id.len) return Error.InvalidPublicMemory;
            const id = input.memory.address_to_id[address];
            if (id.isEmpty() or (id.isSmall() and id.index() >= input.memory.small_values.len) or
                (id.isLarge() and id.index() >= input.memory.f252_values.len))
                return Error.InvalidPublicMemory;
            pair.* = .{ address, id.raw };
        }
        return metal.publicMemorySeed(
            resident_arena.buffer,
            public_pairs,
            try wordOffset(self.address_counts),
            try wordCount(self.address_counts),
            try wordOffset(self.big_counts),
            try wordCount(self.big_counts),
            try wordOffset(self.small_counts),
            try wordCount(self.small_counts),
        );
    }

    pub fn executeAddress(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        input: *const adapter.ProverInput,
    ) !f64 {
        if (self.raw_address.size_bytes != @as(u64, input.memory.address_to_id.len) * 4)
            return Error.InvalidGeometry;
        var address_offsets: [32]u32 = undefined;
        for (self.address_outputs, &address_offsets) |binding, *offset| offset.* = try wordOffset(binding);
        return metal.memoryAddressBaseTrace(
            resident_arena.buffer,
            try wordOffset(self.raw_address),
            @intCast(input.memory.address_to_id.len),
            try wordOffset(self.address_counts),
            try wordCount(self.address_counts),
            try uniformRows(self.address_outputs),
            &address_offsets,
        );
    }

    pub fn executeValues(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !Telemetry {
        return self.executeValuesMode(metal, resident_arena, true);
    }

    /// Rebuilds only the relation source columns during interaction replay.
    /// RC9_9 multiplicities were finalized in the base epoch and must not be
    /// counted a second time.
    pub fn executeValueTraces(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !f64 {
        return (try self.executeValuesMode(metal, resident_arena, false)).trace_gpu_ms;
    }

    fn executeValuesMode(
        self: CairoMemoryTrace,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        count_rc99: bool,
    ) !Telemetry {
        var telemetry: Telemetry = .{};
        var big_source_offsets: [28]u32 = undefined;
        for (self.big_sources, &big_source_offsets) |binding, *offset| offset.* = try wordOffset(binding);
        for (self.big_parts) |part| {
            var output_offsets: [29]u32 = undefined;
            for (part.outputs, &output_offsets) |binding, *offset| offset.* = try wordOffset(binding);
            telemetry.trace_gpu_ms += try metal.memoryValueBaseTrace(
                resident_arena.buffer,
                &big_source_offsets,
                try wordCount(self.big_sources[0]),
                part.source_offset,
                try wordOffset(self.big_counts),
                try wordCount(self.big_counts),
                part.row_count,
                &output_offsets,
            );
            if (count_rc99)
                telemetry.rc99_gpu_ms += try metal.memoryRc99Count(
                    resident_arena.buffer,
                    output_offsets[0..28],
                    part.row_count,
                    try wordOffset(self.rc99_lut),
                    rc99_table_size,
                    try wordOffset(self.rc99_counts),
                );
        }

        var small_source_offsets: [8]u32 = undefined;
        var small_output_offsets: [9]u32 = undefined;
        for (self.small_sources, &small_source_offsets) |binding, *offset| offset.* = try wordOffset(binding);
        for (self.small_part.outputs, &small_output_offsets) |binding, *offset| offset.* = try wordOffset(binding);
        telemetry.trace_gpu_ms += try metal.memoryValueBaseTrace(
            resident_arena.buffer,
            &small_source_offsets,
            try wordCount(self.small_sources[0]),
            0,
            try wordOffset(self.small_counts),
            try wordCount(self.small_counts),
            self.small_part.row_count,
            &small_output_offsets,
        );
        if (count_rc99)
            telemetry.rc99_gpu_ms += try metal.memoryRc99Count(
                resident_arena.buffer,
                small_output_offsets[0..8],
                self.small_part.row_count,
                try wordOffset(self.rc99_lut),
                rc99_table_size,
                try wordOffset(self.rc99_counts),
            );
        return telemetry;
    }
};

fn words(resident_arena: *arena_plan.ResidentArena, binding: arena_plan.Binding) ![]u32 {
    const bytes = try resident_arena.bytes(binding);
    if (bytes.len % 4 != 0) return Error.InvalidGeometry;
    const aligned: []align(4) u8 = @alignCast(bytes);
    return std.mem.bytesAsSlice(u32, aligned);
}

fn wordOffset(binding: arena_plan.Binding) !u32 {
    return arena_plan.narrowWordOffset(binding) catch {
        std.log.err("memory trace binding id={} exceeds the u32 word-addressed range: offset={} size={} end={}", .{
            binding.logical_id,
            binding.offset_bytes,
            binding.size_bytes,
            binding.offset_bytes + binding.size_bytes,
        });
        return Error.InvalidGeometry;
    };
}

fn validateNarrow(binding: arena_plan.Binding) !void {
    _ = try wordOffset(binding);
}

fn wordCount(binding: arena_plan.Binding) !u32 {
    if (binding.size_bytes % 4 != 0) return Error.InvalidGeometry;
    return std.math.cast(u32, binding.size_bytes / 4) orelse Error.InvalidGeometry;
}

fn uniformRows(bindings: []const arena_plan.Binding) !u32 {
    if (bindings.len == 0) return Error.InvalidGeometry;
    const result = try wordCount(bindings[0]);
    if (result == 0 or !std.math.isPowerOfTwo(result)) return Error.InvalidGeometry;
    for (bindings[1..]) |binding| if (try wordCount(binding) != result) return Error.InvalidGeometry;
    return result;
}

const OrderedBinding = struct { ordinal: u32, binding: arena_plan.Binding };

fn collect(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    wanted_purpose: []const u8,
) ![]arena_plan.Binding {
    var ordered = std.ArrayList(OrderedBinding).empty;
    defer ordered.deinit(allocator);
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose)) continue;
        try ordered.append(allocator, .{ .ordinal = try ordinal(entry), .binding = try entryBinding(entry, plan) });
    }
    if (ordered.items.len == 0) return Error.MissingBinding;
    std.mem.sortUnstable(OrderedBinding, ordered.items, {}, struct {
        fn lessThan(_: void, lhs: OrderedBinding, rhs: OrderedBinding) bool {
            return lhs.ordinal < rhs.ordinal;
        }
    }.lessThan);
    for (ordered.items, 0..) |item, expected| if (item.ordinal != expected) return Error.InvalidSchedule;
    const result = try allocator.alloc(arena_plan.Binding, ordered.items.len);
    for (ordered.items, result) |item, *output| output.* = item.binding;
    return result;
}

fn collectComponent(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    wanted_purpose: []const u8,
    wanted_component: []const u8,
) ![]arena_plan.Binding {
    var ordered = std.ArrayList(OrderedBinding).empty;
    defer ordered.deinit(allocator);
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose) or
            !std.mem.eql(u8, try component(entry), wanted_component)) continue;
        try ordered.append(allocator, .{ .ordinal = try ordinal(entry), .binding = try entryBinding(entry, plan) });
    }
    if (ordered.items.len == 0) return Error.MissingBinding;
    std.mem.sortUnstable(OrderedBinding, ordered.items, {}, struct {
        fn lessThan(_: void, lhs: OrderedBinding, rhs: OrderedBinding) bool {
            return lhs.ordinal < rhs.ordinal;
        }
    }.lessThan);
    for (ordered.items, 0..) |item, expected| if (item.ordinal != expected) return Error.InvalidSchedule;
    const result = try allocator.alloc(arena_plan.Binding, ordered.items.len);
    for (ordered.items, result) |item, *output| output.* = item.binding;
    return result;
}

fn collectComponentGroups(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    wanted_purpose: []const u8,
    wanted_component: []const u8,
) ![][]arena_plan.Binding {
    var groups = std.ArrayList([]arena_plan.Binding).empty;
    errdefer {
        for (groups.items) |group| allocator.free(group);
        groups.deinit(allocator);
    }
    var current = std.ArrayList(arena_plan.Binding).empty;
    defer current.deinit(allocator);
    var expected: u32 = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose) or
            !std.mem.eql(u8, try component(entry), wanted_component)) continue;
        const entry_ordinal = try ordinal(entry);
        if (entry_ordinal == 0 and current.items.len != 0) {
            try groups.append(allocator, try current.toOwnedSlice(allocator));
            expected = 0;
        }
        if (entry_ordinal != expected) return Error.InvalidSchedule;
        try current.append(allocator, try entryBinding(entry, plan));
        expected += 1;
    }
    if (current.items.len != 0) try groups.append(allocator, try current.toOwnedSlice(allocator));
    if (groups.items.len == 0) return Error.MissingBinding;
    return groups.toOwnedSlice(allocator);
}

fn one(schedule: []const std.json.Value, plan: arena_plan.Plan, wanted_purpose: []const u8) !arena_plan.Binding {
    var result: ?arena_plan.Binding = null;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose)) continue;
        if (result != null) return Error.DuplicateBinding;
        result = try entryBinding(entry, plan);
    }
    return result orelse Error.MissingBinding;
}

fn oneOrdinal(schedule: []const std.json.Value, plan: arena_plan.Plan, wanted_purpose: []const u8, wanted_ordinal: u32) !arena_plan.Binding {
    var result: ?arena_plan.Binding = null;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose) or try ordinal(entry) != wanted_ordinal) continue;
        if (result != null) return Error.DuplicateBinding;
        result = try entryBinding(entry, plan);
    }
    return result orelse Error.MissingBinding;
}

fn oneComponent(schedule: []const std.json.Value, plan: arena_plan.Plan, wanted_purpose: []const u8, wanted_component: []const u8) !arena_plan.Binding {
    return oneComponentOrdinalOptional(schedule, plan, wanted_purpose, wanted_component, null);
}

fn oneComponentOrdinal(schedule: []const std.json.Value, plan: arena_plan.Plan, wanted_purpose: []const u8, wanted_component: []const u8, wanted_ordinal: u32) !arena_plan.Binding {
    return oneComponentOrdinalOptional(schedule, plan, wanted_purpose, wanted_component, wanted_ordinal);
}

fn oneComponentOrdinalOptional(schedule: []const std.json.Value, plan: arena_plan.Plan, wanted_purpose: []const u8, wanted_component: []const u8, wanted_ordinal: ?u32) !arena_plan.Binding {
    var result: ?arena_plan.Binding = null;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), wanted_purpose) or
            !std.mem.eql(u8, try component(entry), wanted_component) or
            (wanted_ordinal != null and try ordinal(entry) != wanted_ordinal.?)) continue;
        if (result != null) return Error.DuplicateBinding;
        result = try entryBinding(entry, plan);
    }
    return result orelse Error.MissingBinding;
}

fn entryBinding(entry: std.json.Value, plan: arena_plan.Plan) !arena_plan.Binding {
    if (entry != .object) return Error.InvalidSchedule;
    const id = entry.object.get("id") orelse return Error.InvalidSchedule;
    if (id != .integer or id.integer < 0 or id.integer > std.math.maxInt(u32)) return Error.InvalidSchedule;
    return plan.binding(@intCast(id.integer)) catch Error.MissingBinding;
}

fn purpose(entry: std.json.Value) ![]const u8 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("purpose") orelse return Error.InvalidSchedule;
    if (value != .string) return Error.InvalidSchedule;
    return value.string;
}

fn component(entry: std.json.Value) ![]const u8 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("component") orelse return "";
    if (value != .string) return Error.InvalidSchedule;
    return value.string;
}

fn ordinal(entry: std.json.Value) !u32 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("ordinal") orelse return 0;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32)) return Error.InvalidSchedule;
    return @intCast(value.integer);
}
