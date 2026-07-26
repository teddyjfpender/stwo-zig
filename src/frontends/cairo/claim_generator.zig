//! Production Cairo component closure and claim-log geometry.
//!
//! This ports the statement-relevant part of pinned Rust stwo-cairo's
//! `create_cairo_claim_generator`. It consumes adapted execution resources,
//! never a proof. Dynamic subcomponent logs that depend on witness feeds remain
//! explicitly unresolved until the producing feed reports its cardinality.

const std = @import("std");
const adapter = @import("adapter/mod.zig");
const opcodes = @import("adapter/opcodes.zig");
const claim_registry = @import("air/official_claim_registry.zig");

pub const simd_log_lanes: u32 = 4;
pub const max_sequence_log_size: u32 = 25;
pub const log_memory_address_bound: u32 = 29;
pub const memory_address_to_id_split: usize = 1 << (log_memory_address_bound - max_sequence_log_size);
pub const max_memory_id_to_big_components: usize = claim_registry.memory_id_to_big_enable_slot_count;

pub const PreprocessedVariant = enum {
    canonical,
    canonical_without_pedersen,
    canonical_small,
};

pub const Options = struct {
    preprocessed_variant: PreprocessedVariant,
    memory_id_to_big_components: ?usize = null,
};

pub const Error = error{
    NoExecutionComponents,
    InvalidBuiltinSegment,
    UnsupportedPreprocessedVariant,
    EmptyMemoryTable,
    TooManyMemoryComponents,
    UnknownClaimComponent,
    IncompleteClaimGeometry,
    DuplicateFeedGeometry,
    UnexpectedFeedGeometry,
    MissingFeedGeometry,
    InvalidLogSize,
};

pub const DeferredReason = enum {
    witness_feed_cardinality,
};

pub const LogSize = union(enum) {
    known: u32,
    deferred: DeferredReason,
};

pub const ComponentGeometry = struct {
    name: []const u8,
    instance: u32 = 0,
    log_size: LogSize,
};

pub const FeedGeometry = struct {
    name: []const u8,
    instance: u32 = 0,
    log_size: u32,
};

pub const FlatClaimGeometry = struct {
    allocator: std.mem.Allocator,
    component_enable_bits: []bool,
    component_log_sizes: []u32,

    pub fn deinit(self: *FlatClaimGeometry) void {
        self.allocator.free(self.component_enable_bits);
        self.allocator.free(self.component_log_sizes);
        self.* = undefined;
    }
};

pub const OwnedClaimGeometry = struct {
    allocator: std.mem.Allocator,
    components: []ComponentGeometry,

    pub fn deinit(self: *OwnedClaimGeometry) void {
        self.allocator.free(self.components);
        self.* = undefined;
    }

    pub fn deferredCount(self: *const OwnedClaimGeometry) usize {
        var count: usize = 0;
        for (self.components) |component| if (component.log_size == .deferred) {
            count += 1;
        };
        return count;
    }

    /// Resolves only feed-dependent entries and rejects missing, duplicate, or
    /// extraneous feed reports. This is the witness-to-statement handoff.
    pub fn resolveFeedGeometry(
        self: *OwnedClaimGeometry,
        allocator: std.mem.Allocator,
        feeds: []const FeedGeometry,
    ) (Error || std.mem.Allocator.Error)!void {
        const consumed = try allocator.alloc(bool, feeds.len);
        defer allocator.free(consumed);
        @memset(consumed, false);
        const resolutions = try allocator.alloc(?u32, self.components.len);
        defer allocator.free(resolutions);
        @memset(resolutions, null);

        for (self.components, resolutions) |component, *resolution| switch (component.log_size) {
            .known => {},
            .deferred => {
                var found: ?usize = null;
                for (feeds, 0..) |feed, index| {
                    if (!std.mem.eql(u8, feed.name, component.name) or feed.instance != component.instance)
                        continue;
                    if (found != null) return Error.DuplicateFeedGeometry;
                    found = index;
                }
                const index = found orelse return Error.MissingFeedGeometry;
                if (feeds[index].log_size > 31) return Error.InvalidLogSize;
                consumed[index] = true;
                resolution.* = feeds[index].log_size;
            },
        };
        for (consumed) |used| if (!used) return Error.UnexpectedFeedGeometry;
        for (self.components, resolutions) |*component, resolution| {
            if (resolution) |log_size| component.log_size = .{ .known = log_size };
        }
    }

    pub fn flatten(self: *const OwnedClaimGeometry) (Error || std.mem.Allocator.Error)!FlatClaimGeometry {
        const enable_bits = try self.allocator.alloc(bool, claim_registry.enable_slot_count);
        errdefer self.allocator.free(enable_bits);
        @memset(enable_bits, false);
        const logs = try self.allocator.alloc(u32, self.components.len);
        errdefer self.allocator.free(logs);
        for (self.components, logs) |component, *log_size| {
            const field = findField(component.name) orelse return Error.UnknownClaimComponent;
            if (component.instance >= field.enable_slot_count) return Error.TooManyMemoryComponents;
            const enable_slot = @as(usize, field.first_enable_slot) + component.instance;
            if (enable_bits[enable_slot]) return Error.DuplicateFeedGeometry;
            enable_bits[enable_slot] = true;
            log_size.* = switch (component.log_size) {
                .known => |value| value,
                .deferred => return Error.IncompleteClaimGeometry,
            };
        }
        return .{
            .allocator = self.allocator,
            .component_enable_bits = enable_bits,
            .component_log_sizes = logs,
        };
    }
};

pub const ExecutionResources = struct {
    opcode_counts: [opcodes.N_OPCODES]usize,
    pc_count: usize,
    memory_address_count: usize,
    memory_big_value_count: usize,
    memory_small_value_count: usize,
    builtin_segments: adapter.BuiltinSegments,

    pub fn fromProverInput(input: *const adapter.ProverInput) ExecutionResources {
        var counts: [opcodes.N_OPCODES]usize = undefined;
        for (&counts, 0..) |*count, index| count.* = input.state_transitions.casm_states_by_opcode.states[index].items.len;
        return .{
            .opcode_counts = counts,
            .pc_count = input.pc_count,
            .memory_address_count = input.memory.address_to_id.len,
            .memory_big_value_count = input.memory.f252_values.len,
            .memory_small_value_count = input.memory.small_values.len,
            .builtin_segments = input.builtin_segments,
        };
    }
};

pub fn deriveFromProverInput(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    options: Options,
) (Error || std.mem.Allocator.Error)!OwnedClaimGeometry {
    return deriveFromResources(allocator, ExecutionResources.fromProverInput(input), options);
}

pub fn deriveFromResources(
    allocator: std.mem.Allocator,
    resources: ExecutionResources,
    options: Options,
) (Error || std.mem.Allocator.Error)!OwnedClaimGeometry {
    var active = [_]bool{false} ** claim_registry.claim_field_count;
    var known_logs = [_]?u32{null} ** claim_registry.claim_field_count;
    var root_count: usize = 0;

    for (resources.opcode_counts, 0..) |count, index| {
        if (count == 0) continue;
        root_count += 1;
        const tag: opcodes.OpcodeTag = @enumFromInt(index);
        try activateOpcodeClosure(&active, @tagName(tag));
        known_logs[(findField(@tagName(tag)) orelse return Error.UnknownClaimComponent).field_index] = paddedLog(count);
    }
    root_count += try activateBuiltinClosures(&active, &known_logs, resources.builtin_segments, options.preprocessed_variant);
    if (root_count == 0) return Error.NoExecutionComponents;

    inline for (always_active_components) |name| try activate(&active, name);
    try activate(&active, "memory_id_to_small");
    known_logs[(findField("verify_instruction") orelse unreachable).field_index] = paddedLog(resources.pc_count);
    known_logs[(findField("memory_address_to_id") orelse unreachable).field_index] = try memoryAddressLog(resources.memory_address_count);
    known_logs[(findField("memory_id_to_small") orelse unreachable).field_index] = try memoryValueLog(resources.memory_small_value_count);
    const big_logs = try memoryBigLogs(resources.memory_big_value_count, options.memory_id_to_big_components);

    var components = std.ArrayList(ComponentGeometry).empty;
    errdefer components.deinit(allocator);
    for (claim_registry.claim_fields) |field| {
        if (!active[field.field_index]) continue;
        if (std.mem.eql(u8, field.name, "memory_id_to_big")) {
            for (big_logs.slice(), 0..) |log_size, instance| try components.append(allocator, .{
                .name = field.name,
                .instance = @intCast(instance),
                .log_size = .{ .known = log_size },
            });
            continue;
        }
        const log_size: LogSize = if (field.fixed_log_size) |value|
            .{ .known = value }
        else if (known_logs[field.field_index]) |value|
            .{ .known = value }
        else
            .{ .deferred = .witness_feed_cardinality };
        try components.append(allocator, .{ .name = field.name, .log_size = log_size });
    }
    return .{ .allocator = allocator, .components = try components.toOwnedSlice(allocator) };
}

const always_active_components = [_][]const u8{
    "range_check_6",         "range_check_8",        "range_check_11",
    "range_check_12",        "range_check_18",       "range_check_20",
    "range_check_4_3",       "range_check_4_4",      "range_check_9_9",
    "range_check_7_2_5",     "range_check_3_6_6_3",  "range_check_4_4_4_4",
    "range_check_3_3_3_3_3", "verify_bitwise_xor_4", "verify_bitwise_xor_7",
    "verify_bitwise_xor_8",  "verify_bitwise_xor_9",
};

const common_opcode_dependencies = [_][]const u8{
    "memory_address_to_id",
    "range_check_9_9",
    "memory_id_to_big",
    "range_check_7_2_5",
    "range_check_4_3",
    "verify_instruction",
};

fn activateOpcodeClosure(active: *[claim_registry.claim_field_count]bool, root: []const u8) Error!void {
    inline for (common_opcode_dependencies) |name| try activate(active, name);
    if (std.mem.eql(u8, root, "generic_opcode")) {
        inline for (.{ "range_check_20", "range_check_18", "range_check_11" }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "add_ap_opcode")) {
        inline for (.{ "range_check_18", "range_check_11" }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "mul_opcode_small")) {
        try activate(active, "range_check_11");
    } else if (std.mem.eql(u8, root, "mul_opcode")) {
        try activate(active, "range_check_20");
    } else if (std.mem.eql(u8, root, "qm_31_add_mul_opcode")) {
        try activate(active, "range_check_4_4_4_4");
    } else if (std.mem.eql(u8, root, "blake_compress_opcode")) {
        inline for (.{
            "verify_bitwise_xor_8", "blake_round_sigma",    "verify_bitwise_xor_12",
            "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9",
            "blake_g",              "blake_round",          "triple_xor_32",
        }) |name| try activate(active, name);
    }
    try activate(active, root);
}

const BuiltinSpec = struct {
    name: []const u8,
    segment: ?adapter.MemorySegmentAddresses,
    cells_per_instance: usize,
};

fn activateBuiltinClosures(
    active: *[claim_registry.claim_field_count]bool,
    known_logs: *[claim_registry.claim_field_count]?u32,
    segments: adapter.BuiltinSegments,
    variant: PreprocessedVariant,
) Error!usize {
    const specs = [_]BuiltinSpec{
        .{ .name = "add_mod_builtin", .segment = segments.add_mod_builtin, .cells_per_instance = 7 },
        .{ .name = "bitwise_builtin", .segment = segments.bitwise_builtin, .cells_per_instance = 5 },
        .{ .name = "mul_mod_builtin", .segment = segments.mul_mod_builtin, .cells_per_instance = 7 },
        .{ .name = "poseidon_builtin", .segment = segments.poseidon_builtin, .cells_per_instance = 6 },
        .{ .name = "range_check96_builtin", .segment = segments.range_check96_builtin, .cells_per_instance = 1 },
        .{ .name = "range_check_builtin", .segment = segments.range_check_builtin, .cells_per_instance = 1 },
        .{ .name = "ec_op_builtin", .segment = segments.ec_op_builtin, .cells_per_instance = 7 },
    };
    var count: usize = 0;
    for (specs) |spec| if (spec.segment) |segment| {
        count += 1;
        try activateBuiltinClosure(active, spec.name);
        const field = findField(spec.name) orelse return Error.UnknownClaimComponent;
        known_logs[field.field_index] = try builtinLog(segment, spec.cells_per_instance);
    };
    if (segments.pedersen_builtin) |segment| {
        count += 1;
        const name = switch (variant) {
            .canonical => "pedersen_builtin",
            .canonical_small => "pedersen_builtin_narrow_windows",
            .canonical_without_pedersen => return Error.UnsupportedPreprocessedVariant,
        };
        try activateBuiltinClosure(active, name);
        const field = findField(name) orelse return Error.UnknownClaimComponent;
        known_logs[field.field_index] = try builtinLog(segment, 3);
    }
    if (segments.ec_op_builtin != null and variant == .canonical_small)
        return Error.UnsupportedPreprocessedVariant;
    return count;
}

fn activateBuiltinClosure(active: *[claim_registry.claim_field_count]bool, root: []const u8) Error!void {
    inline for (.{ "memory_address_to_id", "range_check_9_9", "memory_id_to_big" }) |name| try activate(active, name);
    if (std.mem.eql(u8, root, "bitwise_builtin")) {
        inline for (.{ "verify_bitwise_xor_9", "verify_bitwise_xor_8" }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "range_check96_builtin")) {
        try activate(active, "range_check_6");
    } else if (std.mem.eql(u8, root, "mul_mod_builtin")) {
        inline for (.{ "range_check_12", "range_check_3_6_6_3", "range_check_18" }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "poseidon_builtin")) {
        inline for (.{
            "range_check_20",            "cube_252",                        "poseidon_round_keys",      "range_check_3_3_3_3_3",
            "poseidon_full_round_chain", "range_check_18",                  "range_check_252_width_27", "range_check_4_4_4_4",
            "range_check_4_4",           "poseidon_3_partial_rounds_chain", "poseidon_aggregator",
        }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "pedersen_builtin")) {
        inline for (.{
            "range_check_8",                 "pedersen_points_table_window_bits_18", "range_check_20",
            "partial_ec_mul_window_bits_18", "pedersen_aggregator_window_bits_18",
        }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "pedersen_builtin_narrow_windows")) {
        inline for (.{
            "range_check_8",                "pedersen_points_table_window_bits_9", "range_check_20",
            "partial_ec_mul_window_bits_9", "pedersen_aggregator_window_bits_9",
        }) |name| try activate(active, name);
    } else if (std.mem.eql(u8, root, "ec_op_builtin")) {
        inline for (.{ "range_check_8", "range_check_20", "partial_ec_mul_generic" }) |name| try activate(active, name);
    }
    try activate(active, root);
}

fn activate(active: *[claim_registry.claim_field_count]bool, name: []const u8) Error!void {
    const field = findField(name) orelse return Error.UnknownClaimComponent;
    active[field.field_index] = true;
}

fn findField(name: []const u8) ?claim_registry.ClaimField {
    for (claim_registry.claim_fields) |field| if (std.mem.eql(u8, name, field.name)) return field;
    return null;
}

pub fn isFixedComponent(name: []const u8) bool {
    const field = findField(name) orelse return false;
    return field.fixed_log_size != null;
}

fn paddedLog(count: usize) u32 {
    const padded = @max(count, @as(usize, 1) << simd_log_lanes);
    return std.math.log2_int_ceil(usize, padded);
}

fn builtinLog(segment: adapter.MemorySegmentAddresses, cells_per_instance: usize) Error!u32 {
    if (segment.stop_ptr < segment.begin_addr) return Error.InvalidBuiltinSegment;
    const length = segment.stop_ptr - segment.begin_addr;
    if (length == 0 or length % cells_per_instance != 0) return Error.InvalidBuiltinSegment;
    const instances = length / cells_per_instance;
    if (!std.math.isPowerOfTwo(instances)) return Error.InvalidBuiltinSegment;
    return std.math.log2_int(usize, instances);
}

fn memoryAddressLog(count: usize) Error!u32 {
    if (count <= 1) return Error.EmptyMemoryTable;
    const rows = std.math.divCeil(usize, count - 1, memory_address_to_id_split) catch
        return Error.InvalidLogSize;
    return paddedLog(rows);
}

fn memoryValueLog(count: usize) Error!u32 {
    if (count == 0) return Error.EmptyMemoryTable;
    return paddedLog(count);
}

const BigLogs = struct {
    values: [max_memory_id_to_big_components]u32 = [_]u32{0} ** max_memory_id_to_big_components,
    len: usize = 0,

    fn slice(self: *const BigLogs) []const u32 {
        return self.values[0..self.len];
    }
};

fn memoryBigLogs(count: usize, requested_components: ?usize) Error!BigLogs {
    if (count == 0) return Error.EmptyMemoryTable;
    const padded_count = std.mem.alignForward(usize, count, 1 << simd_log_lanes);
    const max_rows: usize = @as(usize, 1) << max_sequence_log_size;
    const natural_components = std.math.divCeil(usize, padded_count, max_rows) catch
        return Error.TooManyMemoryComponents;
    const component_count = requested_components orelse natural_components;
    if (component_count < natural_components or component_count > max_memory_id_to_big_components)
        return Error.TooManyMemoryComponents;
    var result = BigLogs{ .len = component_count };
    var remaining = padded_count;
    for (0..natural_components) |index| {
        const rows = @min(remaining, max_rows);
        result.values[index] = paddedLog(rows);
        remaining -= rows;
    }
    for (natural_components..component_count) |index| result.values[index] = simd_log_lanes;
    return result;
}
