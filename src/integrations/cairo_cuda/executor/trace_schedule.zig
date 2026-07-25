//! Canonical trace-generation dispatch plan for one Cairo CUDA proof.
//!
//! This module is intentionally a preparation boundary. It binds every
//! authenticated base-writer entry to an existing strict-AOT/native CUDA API,
//! preserves the proof graph's producer dependencies, and makes buffer and
//! launch ownership explicit. Resident buffer materialization remains the
//! executor's responsibility.

const std = @import("std");
const proof_plan = @import("../../../frontends/cairo/proof_plan.zig");
const catalog_module = @import("../base_writer_plan/catalog.zig");
const recorded_witness = @import("../recorded_witness.zig");
const native_ec = @import("../native_ec.zig");
const fixed_tables = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/fixed_tables.zig",
);
const memory = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/memory.zig",
);

pub const expected_entry_count = 58;
pub const expected_recorded_count = 32;
pub const expected_native_count = 2;
pub const expected_fixed_count = 21;
pub const expected_memory_count = 3;
pub const expected_launch_count = expected_entry_count - 1;

const ec_name = "ec_op_builtin";
const partial_name = "partial_ec_mul_generic";

/// The only trace-generation entry points admitted by this schedule.
pub const PrepareApi = enum(u8) {
    recorded_witness_prepare,
    fixed_table_materialize,
    memory_address_base,
    memory_value_base_big,
    memory_value_base_small,
    native_ec_prepare,
    native_ec_member,
};

pub const Execution = enum(u8) {
    standalone,
    composite_root,
    composite_member,
};

pub const DependencyKind = enum(u8) {
    producer_words,
    capacity,
    native_ec_workspace,
};

pub const Dependency = struct {
    producer_component_index: u32,
    kind: DependencyKind,
    word_base: u32,
    words_per_instance: u32,
    instances: u32,
};

/// Component indices owning each resident output family. The native fields
/// describe the sole cross-component alias in the base-writer graph.
pub const BufferOwnership = struct {
    trace_outputs: u32,
    lookup_outputs: u32,
    subword_outputs: u32,
    multiplicity_outputs: u32,
    native_partial_workspace: ?u32,
    native_partial_inputs: ?u32,
};

pub const Entry = struct {
    component_index: u32,
    canonical_ordinal: u32,
    name: []const u8,
    instance: u32,
    writer: proof_plan.WriterKind,
    prepare_api: PrepareApi,
    execution: Execution,
    launch_owner: u32,
    buffers: BufferOwnership,
    catalog_identity: [32]u8,
    dependencies: []const Dependency,
};

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    dependency_storage: []Dependency,
    launch_order: []u32,
    writer_counts: [std.meta.fields(proof_plan.WriterKind).len]u32,
    identity: [32]u8,

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.launch_order);
        self.allocator.free(self.dependency_storage);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn find(
        self: Schedule,
        name: []const u8,
        instance: u32,
    ) ?*const Entry {
        for (self.entries) |*entry| {
            if (entry.instance == instance and
                std.mem.eql(u8, entry.name, name))
            {
                return entry;
            }
        }
        return null;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    catalog: catalog_module.Catalog,
) !Schedule {
    try validateInventoryShape(proof, catalog);
    const ec_index = try uniqueComponentIndex(proof, ec_name, 0);
    const partial_index = try uniqueComponentIndex(proof, partial_name, 0);

    var dependency_count: usize = 1;
    for (proof.components) |component| {
        dependency_count = std.math.add(
            usize,
            dependency_count,
            component.producer_edges.len,
        ) catch return error.TraceScheduleOverflow;
        dependency_count = std.math.add(
            usize,
            dependency_count,
            component.capacity_feeds.len,
        ) catch return error.TraceScheduleOverflow;
    }

    const entries = try allocator.alloc(Entry, proof.components.len);
    errdefer allocator.free(entries);
    const dependencies = try allocator.alloc(Dependency, dependency_count);
    errdefer allocator.free(dependencies);

    var writer_counts =
        [_]u32{0} ** std.meta.fields(proof_plan.WriterKind).len;
    var dependency_cursor: usize = 0;
    for (proof.canonical_order, 0..) |component_index, canonical_ordinal| {
        const index: usize = component_index;
        if (index >= proof.components.len)
            return error.InvalidCanonicalTraceSchedule;
        const component = proof.components[index];
        if (component.canonical_ordinal != canonical_ordinal)
            return error.InvalidCanonicalTraceSchedule;
        const admitted = try uniqueCatalogEntry(catalog, component_index);
        try validateCatalogEntry(component, admitted);
        writer_counts[@intFromEnum(component.writer)] += 1;

        const dependency_start = dependency_cursor;
        for (component.producer_edges) |edge| {
            dependencies[dependency_cursor] = .{
                .producer_component_index = try uniqueProducerIndex(
                    proof,
                    edge.producer,
                ),
                .kind = .producer_words,
                .word_base = edge.word_base,
                .words_per_instance = edge.words_per_instance,
                .instances = edge.instances,
            };
            dependency_cursor += 1;
        }
        for (component.capacity_feeds) |feed| {
            dependencies[dependency_cursor] = .{
                .producer_component_index = try uniqueProducerIndex(
                    proof,
                    feed.producer,
                ),
                .kind = .capacity,
                .word_base = 0,
                .words_per_instance = 0,
                .instances = feed.instances,
            };
            dependency_cursor += 1;
        }
        if (component_index == partial_index) {
            dependencies[dependency_cursor] = .{
                .producer_component_index = ec_index,
                .kind = .native_ec_workspace,
                .word_base = 0,
                .words_per_instance = 0,
                .instances = 1,
            };
            dependency_cursor += 1;
        }

        const dispatch = try dispatchFor(
            component,
            component_index,
            ec_index,
            partial_index,
        );
        entries[canonical_ordinal] = .{
            .component_index = component_index,
            .canonical_ordinal = component.canonical_ordinal,
            .name = component.name,
            .instance = component.instance,
            .writer = component.writer,
            .prepare_api = dispatch.prepare_api,
            .execution = dispatch.execution,
            .launch_owner = dispatch.launch_owner,
            .buffers = dispatch.buffers,
            .catalog_identity = admitted.identity,
            .dependencies = dependencies[dependency_start..dependency_cursor],
        };
    }
    if (dependency_cursor != dependencies.len)
        return error.InvalidCanonicalTraceSchedule;
    try validateWriterCounts(writer_counts, catalog.writer_counts);

    const launch_order = try buildLaunchOrder(
        allocator,
        proof,
        entries,
    );
    errdefer allocator.free(launch_order);
    const identity = scheduleIdentity(
        catalog.identity,
        entries,
        dependencies,
        launch_order,
    );
    return .{
        .allocator = allocator,
        .entries = entries,
        .dependency_storage = dependencies,
        .launch_order = launch_order,
        .writer_counts = writer_counts,
        .identity = identity,
    };
}

const Dispatch = struct {
    prepare_api: PrepareApi,
    execution: Execution,
    launch_owner: u32,
    buffers: BufferOwnership,
};

fn dispatchFor(
    component: proof_plan.Component,
    component_index: u32,
    ec_index: u32,
    partial_index: u32,
) !Dispatch {
    const common = BufferOwnership{
        .trace_outputs = component_index,
        .lookup_outputs = component_index,
        .subword_outputs = component_index,
        .multiplicity_outputs = component_index,
        .native_partial_workspace = null,
        .native_partial_inputs = null,
    };
    return switch (component.writer) {
        .recorded_aot => .{
            .prepare_api = .recorded_witness_prepare,
            .execution = .standalone,
            .launch_owner = component_index,
            .buffers = common,
        },
        .fixed_table => .{
            .prepare_api = .fixed_table_materialize,
            .execution = .standalone,
            .launch_owner = component_index,
            .buffers = common,
        },
        .memory_trace => .{
            .prepare_api = try memoryApi(component.name),
            .execution = .standalone,
            .launch_owner = component_index,
            .buffers = common,
        },
        .native_backend => blk: {
            if (component_index == ec_index and
                std.mem.eql(u8, component.name, ec_name))
            {
                var buffers = common;
                buffers.native_partial_workspace = component_index;
                break :blk .{
                    .prepare_api = .native_ec_prepare,
                    .execution = .composite_root,
                    .launch_owner = component_index,
                    .buffers = buffers,
                };
            }
            if (component_index == partial_index and
                std.mem.eql(u8, component.name, partial_name))
            {
                var buffers = common;
                buffers.native_partial_inputs = ec_index;
                break :blk .{
                    .prepare_api = .native_ec_member,
                    .execution = .composite_member,
                    .launch_owner = ec_index,
                    .buffers = buffers,
                };
            }
            return error.UnsupportedNativeBaseWriter;
        },
    };
}

fn memoryApi(name: []const u8) !PrepareApi {
    const mappings = [_]struct {
        name: []const u8,
        api: PrepareApi,
    }{
        .{
            .name = "memory_address_to_id",
            .api = .memory_address_base,
        },
        .{
            .name = "memory_id_to_big",
            .api = .memory_value_base_big,
        },
        .{
            .name = "memory_id_to_small",
            .api = .memory_value_base_small,
        },
    };
    for (mappings) |mapping| {
        if (std.mem.eql(u8, name, mapping.name)) return mapping.api;
    }
    return error.UnsupportedMemoryBaseWriter;
}

fn validateInventoryShape(
    proof: *const proof_plan.CairoProofPlan,
    catalog: catalog_module.Catalog,
) !void {
    if (proof.components.len != expected_entry_count or
        proof.canonical_order.len != expected_entry_count or
        catalog.entries.len != expected_entry_count or
        std.mem.allEqual(u8, &catalog.identity, 0))
    {
        return error.BaseWriterInventoryMismatch;
    }
}

fn validateWriterCounts(
    actual: [std.meta.fields(proof_plan.WriterKind).len]u32,
    declared: [std.meta.fields(proof_plan.WriterKind).len]u32,
) !void {
    if (!std.meta.eql(actual, declared) or
        actual[@intFromEnum(proof_plan.WriterKind.recorded_aot)] !=
            expected_recorded_count or
        actual[@intFromEnum(proof_plan.WriterKind.native_backend)] !=
            expected_native_count or
        actual[@intFromEnum(proof_plan.WriterKind.fixed_table)] !=
            expected_fixed_count or
        actual[@intFromEnum(proof_plan.WriterKind.memory_trace)] !=
            expected_memory_count)
    {
        return error.BaseWriterInventoryMismatch;
    }
}

fn uniqueCatalogEntry(
    catalog: catalog_module.Catalog,
    component_index: u32,
) !catalog_module.Entry {
    var found: ?catalog_module.Entry = null;
    for (catalog.entries) |entry| {
        if (entry.component_index != component_index) continue;
        if (found != null) return error.DuplicateBaseWriter;
        found = entry;
    }
    return found orelse error.MissingBaseWriter;
}

fn validateCatalogEntry(
    component: proof_plan.Component,
    entry: catalog_module.Entry,
) !void {
    if (entry.instance != component.instance or
        entry.writer != component.writer or
        !std.mem.eql(u8, entry.name, component.name))
    {
        return error.BaseWriterPlanMismatch;
    }
    if (std.mem.allEqual(u8, &entry.identity, 0))
        return error.EmptyBaseWriterIdentity;
}

fn uniqueComponentIndex(
    proof: *const proof_plan.CairoProofPlan,
    name: []const u8,
    instance: u32,
) !u32 {
    var found: ?u32 = null;
    for (proof.components, 0..) |component, index| {
        if (!std.mem.eql(u8, component.name, name)) continue;
        if (component.instance != instance or found != null)
            return error.DuplicateBaseWriter;
        found = @intCast(index);
    }
    return found orelse error.MissingBaseWriter;
}

fn uniqueProducerIndex(
    proof: *const proof_plan.CairoProofPlan,
    producer: []const u8,
) !u32 {
    var found: ?u32 = null;
    for (proof.components, 0..) |component, index| {
        if (!std.mem.eql(u8, component.name, producer)) continue;
        if (found != null) return error.AmbiguousTraceProducer;
        found = @intCast(index);
    }
    return found orelse error.MissingTraceProducer;
}

fn buildLaunchOrder(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    entries: []const Entry,
) ![]u32 {
    const output = try allocator.alloc(u32, expected_launch_count);
    errdefer allocator.free(output);
    const seen = try allocator.alloc(bool, entries.len);
    defer allocator.free(seen);
    @memset(seen, false);

    var cursor: usize = 0;
    for (proof.levels) |level| {
        for (entries) |entry| {
            if (!containsIndex(
                level.component_indices,
                entry.component_index,
            )) continue;
            if (seen[entry.component_index])
                return error.InvalidCanonicalTraceSchedule;
            seen[entry.component_index] = true;
            if (entry.execution == .composite_member) continue;
            if (cursor >= output.len)
                return error.InvalidCanonicalTraceSchedule;
            output[cursor] = entry.component_index;
            cursor += 1;
        }
    }
    if (cursor != output.len or !std.mem.allEqual(bool, seen, true))
        return error.InvalidCanonicalTraceSchedule;
    return output;
}

fn containsIndex(indices: []const u32, target: u32) bool {
    for (indices) |index| if (index == target) return true;
    return false;
}

fn scheduleIdentity(
    catalog_identity: [32]u8,
    entries: []const Entry,
    dependencies: []const Dependency,
    launch_order: []const u32,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/trace-schedule/v1\x00");
    hash.update(&catalog_identity);
    hashInt(&hash, u64, entries.len);
    for (entries) |entry| {
        hashInt(&hash, u32, entry.component_index);
        hashInt(&hash, u32, entry.canonical_ordinal);
        hashBytes(&hash, entry.name);
        hashInt(&hash, u32, entry.instance);
        hashInt(&hash, u8, @intFromEnum(entry.writer));
        hashInt(&hash, u8, @intFromEnum(entry.prepare_api));
        hashInt(&hash, u8, @intFromEnum(entry.execution));
        hashInt(&hash, u32, entry.launch_owner);
        hashOwnership(&hash, entry.buffers);
        hash.update(&entry.catalog_identity);
        hashInt(&hash, u64, entry.dependencies.len);
    }
    hashInt(&hash, u64, dependencies.len);
    for (dependencies) |dependency| {
        hashInt(&hash, u32, dependency.producer_component_index);
        hashInt(&hash, u8, @intFromEnum(dependency.kind));
        hashInt(&hash, u32, dependency.word_base);
        hashInt(&hash, u32, dependency.words_per_instance);
        hashInt(&hash, u32, dependency.instances);
    }
    hashInt(&hash, u64, launch_order.len);
    for (launch_order) |component_index| {
        hashInt(&hash, u32, component_index);
    }
    return hash.finalResult();
}

fn hashOwnership(
    hash: *std.crypto.hash.sha2.Sha256,
    ownership: BufferOwnership,
) void {
    hashInt(hash, u32, ownership.trace_outputs);
    hashInt(hash, u32, ownership.lookup_outputs);
    hashInt(hash, u32, ownership.subword_outputs);
    hashInt(hash, u32, ownership.multiplicity_outputs);
    hashOptional(hash, ownership.native_partial_workspace);
    hashOptional(hash, ownership.native_partial_inputs);
}

fn hashOptional(
    hash: *std.crypto.hash.sha2.Sha256,
    value: ?u32,
) void {
    hashInt(hash, u8, @intFromBool(value != null));
    hashInt(hash, u32, value orelse 0);
}

fn hashBytes(
    hash: *std.crypto.hash.sha2.Sha256,
    bytes: []const u8,
) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    // Keep this typed schedule coupled to the executable APIs it names.
    _ = recorded_witness.prepare;
    _ = fixed_tables.Native.materialize;
    _ = memory.Native.addressBase;
    _ = memory.Native.valueBase;
    _ = native_ec.prepare;
}
