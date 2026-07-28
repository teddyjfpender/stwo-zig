//! Sealed fixed-table and memory writer preparation at CUDA ingress.

const std = @import("std");
const common = @import("stwo_cuda_backend").runtime.stages.common;
const layout = @import("stwo_cuda_backend").runtime.stages.resident_layout;
const fixed_runtime = @import("stwo_cuda_backend").runtime.stages.cairo_base.fixed_tables;
const memory_runtime = @import("stwo_cuda_backend").runtime.stages.cairo_base.memory;
const fixed_plan = @import("../base_writer_plan/fixed_tables.zig");
const memory_plan = @import("../base_writer_plan/memory.zig");
const recorded_binding = @import("../recorded_binding.zig");
const schedule = @import("trace_schedule.zig");

const pointer_words = @sizeOf(usize) / @sizeOf(u32);

pub const DependencyCapability = struct {
    dependency: schedule.Dependency,
    resident: common.Words,
};

pub const FixedSource = struct {
    identity: []const u8,
    resident: common.Words,
};

pub const FixedResident = struct {
    sources: []const FixedSource,
    multiplicity_columns: []const common.Words,
    trace_outputs: []const common.Words,
    lookup_outputs: []const common.Words,
    buffers: fixed_runtime.Buffers,
};

pub const Fixed = struct {
    geometry: fixed_runtime.Geometry,
    buffers: fixed_runtime.Buffers,
    resident: FixedResident,
    catalog_identity: [32]u8,
    binding_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependency_identity: [32]u8,
    dependency_binding_identity: [32]u8,
    capability: ContextCapability,
};

pub const MemorySource = struct {
    resident: common.Words,
    value_offset: u32,
    words_per_value: u32,
};

pub const MemoryAddress = struct {
    geometry: memory_runtime.AddressGeometry,
    buffers: memory_runtime.AddressBuffers,
    source: MemorySource,
    catalog_identity: [32]u8,
    binding_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependency_identity: [32]u8,
    dependency_binding_identity: [32]u8,
    capability: ContextCapability,
};

pub const MemoryValue = struct {
    geometry: memory_runtime.ValueGeometry,
    buffers: memory_runtime.ValueBuffers,
    source_offset: u32,
    words_per_value: u32,
    catalog_identity: [32]u8,
    binding_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependency_identity: [32]u8,
    dependency_binding_identity: [32]u8,
    capability: ContextCapability,
};

pub const ContextCapability = struct {
    owner: usize,
    generation: u64,

    fn init(first: common.Words) !ContextCapability {
        if (first.address == 0 or first.owner == 0 or first.generation == 0)
            return error.TraceWriterBindingMismatch;
        return .{ .owner = first.owner, .generation = first.generation };
    }

    fn include(self: ContextCapability, value: common.Words) !void {
        if (value.address == 0 or value.owner != self.owner or
            value.generation != self.generation)
        {
            return error.TraceWriterBindingMismatch;
        }
    }
};

pub fn prepareFixed(
    allocator: std.mem.Allocator,
    session: anytype,
    plan: fixed_plan.Entry,
    entry: schedule.Entry,
    resident: FixedResident,
    dependencies: []const DependencyCapability,
) !Fixed {
    try common.requireStage(session, .ingress);
    if (!std.mem.eql(
        u8,
        &plan.identity,
        &fixed_plan.recomputeIdentity(plan),
    )) return error.TraceWriterBindingMismatch;
    try validateScheduleEntry(entry, plan.component_index, plan.identity, .fixed);
    const geometry = fixed_runtime.Geometry{
        .source_column_count = plan.source_column_count,
        .multiplicity_column_count = plan.multiplicity_column_count,
        .trace_output_count = plan.trace_output_count,
        .lookup_output_count = plan.lookup_output_count,
        .row_count = plan.row_count,
    };
    try geometry.validate();
    if (resident.sources.len != plan.preprocessed_sources.len or
        resident.multiplicity_columns.len != plan.multiplicity_column_count or
        resident.trace_outputs.len != plan.trace_output_count or
        resident.lookup_outputs.len != plan.lookup_output_count or
        plan.trace_multiplicity_columns.len != plan.trace_output_count or
        plan.lookup_descriptors.len !=
            @as(usize, plan.lookup_output_count) * 4)
    {
        return error.TraceWriterBindingMismatch;
    }
    try validateFixedBufferLengths(geometry, resident.buffers);
    const capability = try ContextCapability.init(
        resident.buffers.multiplicity_pointer_table,
    );
    var reads = std.ArrayList(layout.DeviceRange).empty;
    defer reads.deinit(allocator);
    var writes = std.ArrayList(layout.DeviceRange).empty;
    defer writes.deinit(allocator);
    try appendResident(
        session,
        capability,
        resident.buffers.multiplicity_pointer_table,
        resident.buffers.multiplicity_pointer_table.len,
        &reads,
        allocator,
    );
    inline for (.{
        resident.buffers.trace_multiplicity_columns,
        resident.buffers.trace_output_pointer_table,
        resident.buffers.lookup_descriptors,
        resident.buffers.lookup_output_pointer_table,
    }) |metadata| {
        try appendResident(
            session,
            capability,
            metadata,
            metadata.len,
            &reads,
            allocator,
        );
    }
    if (resident.sources.len == 0) {
        if (resident.buffers.source_pointer_table.len != 0 or
            resident.buffers.source_pointer_table.address != 0)
        {
            return error.TraceWriterBindingMismatch;
        }
    } else {
        try appendResident(
            session,
            capability,
            resident.buffers.source_pointer_table,
            resident.buffers.source_pointer_table.len,
            &reads,
            allocator,
        );
    }
    for (resident.sources, plan.preprocessed_sources) |source, expected| {
        if (!std.mem.eql(u8, source.identity, expected))
            return error.TraceWriterBindingMismatch;
        try appendResident(
            session,
            capability,
            source.resident,
            plan.row_count,
            &reads,
            allocator,
        );
    }
    for (resident.multiplicity_columns) |column| try appendResident(
        session,
        capability,
        column,
        plan.row_count,
        &reads,
        allocator,
    );
    for (resident.trace_outputs) |column| try appendResident(
        session,
        capability,
        column,
        plan.row_count,
        &writes,
        allocator,
    );
    for (resident.lookup_outputs) |column| try appendResident(
        session,
        capability,
        column,
        plan.row_count,
        &writes,
        allocator,
    );
    try layout.requireDisjoint(writes.items, reads.items);
    const dependency_seal = try validateDependencies(
        session,
        entry.dependencies,
        dependencies,
        capability,
    );
    try uploadFixed(allocator, &session.context, plan, resident);
    const binding_identity = fixedBindingIdentity(
        plan.identity,
        entry.buffers,
        dependency_seal.binding_identity,
        resident,
    );
    return .{
        .geometry = geometry,
        .buffers = resident.buffers,
        .resident = resident,
        .catalog_identity = plan.identity,
        .binding_identity = binding_identity,
        .ownership = entry.buffers,
        .dependency_identity = dependency_seal.schedule_identity,
        .dependency_binding_identity = dependency_seal.binding_identity,
        .capability = capability,
    };
}

pub fn prepareMemoryAddress(
    session: anytype,
    plan: memory_plan.Entry,
    entry: schedule.Entry,
    source: MemorySource,
    buffers: memory_runtime.AddressBuffers,
    dependencies: []const DependencyCapability,
) !MemoryAddress {
    try common.requireStage(session, .ingress);
    if (!std.mem.eql(
        u8,
        &plan.identity,
        &memory_plan.recomputeIdentity(plan),
    )) return error.TraceWriterBindingMismatch;
    try validateScheduleEntry(entry, plan.component_index, plan.identity, .address);
    if (plan.kind != .address_to_id or plan.limb_count != 0 or
        plan.output_column_count != memory_runtime.address_column_count or
        source.value_offset != plan.source_value_offset or
        source.words_per_value != plan.source_words_per_value or
        buffers.address_ids.address != source.resident.address or
        buffers.address_ids.len != source.resident.len)
    {
        return error.TraceWriterBindingMismatch;
    }
    const geometry = memory_runtime.AddressGeometry{
        .address_id_words = plan.source_value_count,
        .row_count = plan.row_count,
    };
    try geometry.validate();
    if (buffers.outputs.len != plan.output_column_count)
        return error.TraceWriterBindingMismatch;
    const capability = try validateMemoryAddress(
        session,
        geometry,
        buffers,
    );
    const dependency_seal = try validateDependencies(
        session,
        entry.dependencies,
        dependencies,
        capability,
    );
    return .{
        .geometry = geometry,
        .buffers = buffers,
        .source = source,
        .catalog_identity = plan.identity,
        .binding_identity = memoryAddressBindingIdentity(
            plan.identity,
            entry.buffers,
            dependency_seal.binding_identity,
            source,
            buffers,
        ),
        .ownership = entry.buffers,
        .dependency_identity = dependency_seal.schedule_identity,
        .dependency_binding_identity = dependency_seal.binding_identity,
        .capability = capability,
    };
}

pub fn prepareMemoryValue(
    session: anytype,
    plan: memory_plan.Entry,
    entry: schedule.Entry,
    source_offset: u32,
    buffers: memory_runtime.ValueBuffers,
    dependencies: []const DependencyCapability,
) !MemoryValue {
    try common.requireStage(session, .ingress);
    if (!std.mem.eql(
        u8,
        &plan.identity,
        &memory_plan.recomputeIdentity(plan),
    )) return error.TraceWriterBindingMismatch;
    const kind: ExpectedKind = switch (plan.kind) {
        .id_to_big => .value_big,
        .id_to_small => .value_small,
        else => return error.TraceWriterBindingMismatch,
    };
    try validateScheduleEntry(entry, plan.component_index, plan.identity, kind);
    if (source_offset != plan.source_value_offset or
        buffers.sources.len != plan.limb_count or
        buffers.outputs.len != plan.output_column_count or
        plan.output_column_count != plan.limb_count + 1)
    {
        return error.TraceWriterBindingMismatch;
    }
    const geometry = memory_runtime.ValueGeometry{
        .limb_count = plan.limb_count,
        .source_words = plan.source_value_count,
        .row_count = plan.row_count,
    };
    try geometry.validate();
    const capability = try validateMemoryValue(session, geometry, buffers);
    const dependency_seal = try validateDependencies(
        session,
        entry.dependencies,
        dependencies,
        capability,
    );
    return .{
        .geometry = geometry,
        .buffers = buffers,
        .source_offset = source_offset,
        .words_per_value = plan.source_words_per_value,
        .catalog_identity = plan.identity,
        .binding_identity = memoryValueBindingIdentity(
            plan.identity,
            entry.buffers,
            dependency_seal.binding_identity,
            source_offset,
            plan.source_words_per_value,
            buffers,
        ),
        .ownership = entry.buffers,
        .dependency_identity = dependency_seal.schedule_identity,
        .dependency_binding_identity = dependency_seal.binding_identity,
        .capability = capability,
    };
}

pub fn fixedSealValid(value: Fixed) bool {
    return std.mem.eql(
        u8,
        &value.binding_identity,
        &fixedBindingIdentity(
            value.catalog_identity,
            value.ownership,
            value.dependency_binding_identity,
            value.resident,
        ),
    );
}

pub fn memoryAddressSealValid(value: MemoryAddress) bool {
    return std.mem.eql(
        u8,
        &value.binding_identity,
        &memoryAddressBindingIdentity(
            value.catalog_identity,
            value.ownership,
            value.dependency_binding_identity,
            value.source,
            value.buffers,
        ),
    );
}

pub fn memoryValueSealValid(value: MemoryValue) bool {
    return std.mem.eql(
        u8,
        &value.binding_identity,
        &memoryValueBindingIdentity(
            value.catalog_identity,
            value.ownership,
            value.dependency_binding_identity,
            value.source_offset,
            value.words_per_value,
            value.buffers,
        ),
    );
}

const ExpectedKind = enum { fixed, address, value_big, value_small };

fn validateScheduleEntry(
    entry: schedule.Entry,
    component_index: u32,
    identity: [32]u8,
    kind: ExpectedKind,
) !void {
    const api_matches = switch (kind) {
        .fixed => entry.prepare_api == .fixed_table_materialize,
        .address => entry.prepare_api == .memory_address_base,
        .value_big => entry.prepare_api == .memory_value_base_big,
        .value_small => entry.prepare_api == .memory_value_base_small,
    };
    if (!api_matches or entry.component_index != component_index or
        entry.execution != .standalone or
        entry.launch_owner != component_index or
        !std.mem.eql(u8, &entry.catalog_identity, &identity) or
        !standaloneOwnership(entry.buffers, component_index))
    {
        return error.TraceWriterBindingMismatch;
    }
}

fn standaloneOwnership(
    ownership: schedule.BufferOwnership,
    component_index: u32,
) bool {
    return ownership.trace_outputs == component_index and
        ownership.lookup_outputs == component_index and
        ownership.subword_outputs == component_index and
        ownership.multiplicity_outputs == component_index and
        ownership.native_partial_workspace == null and
        ownership.native_partial_inputs == null;
}

fn validateFixedBufferLengths(
    geometry: fixed_runtime.Geometry,
    buffers: fixed_runtime.Buffers,
) !void {
    if (buffers.source_pointer_table.len !=
        @as(usize, geometry.source_column_count) * pointer_words or
        buffers.multiplicity_pointer_table.len !=
            @as(usize, geometry.multiplicity_column_count) * pointer_words or
        buffers.trace_multiplicity_columns.len !=
            geometry.trace_output_count or
        buffers.trace_output_pointer_table.len !=
            @as(usize, geometry.trace_output_count) * pointer_words or
        buffers.lookup_descriptors.len !=
            @as(usize, geometry.lookup_output_count) * 4 or
        buffers.lookup_output_pointer_table.len !=
            @as(usize, geometry.lookup_output_count) * pointer_words)
    {
        return error.TraceWriterBindingMismatch;
    }
}

fn uploadFixed(
    allocator: std.mem.Allocator,
    uploader: anytype,
    plan: fixed_plan.Entry,
    resident: FixedResident,
) !void {
    const count = resident.sources.len +
        resident.multiplicity_columns.len +
        resident.trace_outputs.len +
        resident.lookup_outputs.len;
    const storage = try allocator.alloc(u32, count * pointer_words);
    defer allocator.free(storage);
    var cursor: usize = 0;
    if (resident.sources.len != 0) {
        const words = storage[cursor..][0 .. resident.sources.len * pointer_words];
        const columns = try allocator.alloc(common.Words, resident.sources.len);
        defer allocator.free(columns);
        for (resident.sources, columns) |source, *column|
            column.* = source.resident;
        try recorded_binding.encodePointerTable(words, columns);
        try uploader.uploadSlice(
            u32,
            resident.buffers.source_pointer_table,
            words,
        );
        cursor += words.len;
    }
    inline for (.{
        .{ resident.multiplicity_columns, resident.buffers.multiplicity_pointer_table },
        .{ resident.trace_outputs, resident.buffers.trace_output_pointer_table },
        .{ resident.lookup_outputs, resident.buffers.lookup_output_pointer_table },
    }) |pair| {
        const words = storage[cursor..][0 .. pair[0].len * pointer_words];
        try recorded_binding.encodePointerTable(words, pair[0]);
        try uploader.uploadSlice(u32, pair[1], words);
        cursor += words.len;
    }
    std.debug.assert(cursor == storage.len);
    try uploader.uploadSlice(
        u32,
        resident.buffers.trace_multiplicity_columns,
        plan.trace_multiplicity_columns,
    );
    try uploader.uploadSlice(
        u32,
        resident.buffers.lookup_descriptors,
        plan.lookup_descriptors,
    );
}

fn validateMemoryAddress(
    session: anytype,
    geometry: memory_runtime.AddressGeometry,
    buffers: memory_runtime.AddressBuffers,
) !ContextCapability {
    const capability = try ContextCapability.init(buffers.address_ids);
    const address = try exactResident(
        session,
        capability,
        buffers.address_ids,
        geometry.address_id_words,
    );
    const multiplicity = try exactResident(
        session,
        capability,
        buffers.multiplicities,
        try geometry.multiplicityWords(),
    );
    var writes: [memory_runtime.address_column_count]layout.DeviceRange =
        undefined;
    for (buffers.outputs, 0..) |output, index| {
        writes[index] = (try exactResident(
            session,
            capability,
            output,
            geometry.row_count,
        )).range;
    }
    try layout.requireDisjoint(
        &writes,
        &.{ address.range, multiplicity.range },
    );
    return capability;
}

fn validateMemoryValue(
    session: anytype,
    geometry: memory_runtime.ValueGeometry,
    buffers: memory_runtime.ValueBuffers,
) !ContextCapability {
    if (buffers.sources.len == 0) return error.TraceWriterBindingMismatch;
    const capability = try ContextCapability.init(buffers.sources[0]);
    var reads: [memory_runtime.big_limb_count + 1]layout.DeviceRange =
        undefined;
    for (buffers.sources, 0..) |source, index| {
        reads[index] = (try exactResident(
            session,
            capability,
            source,
            geometry.source_words,
        )).range;
    }
    reads[geometry.limb_count] = (try exactResident(
        session,
        capability,
        buffers.multiplicities,
        geometry.row_count,
    )).range;
    var writes: [memory_runtime.big_limb_count + 1]layout.DeviceRange =
        undefined;
    for (buffers.outputs, 0..) |output, index| {
        writes[index] = (try exactResident(
            session,
            capability,
            output,
            geometry.row_count,
        )).range;
    }
    try layout.requireDisjoint(
        writes[0 .. geometry.limb_count + 1],
        reads[0 .. geometry.limb_count + 1],
    );
    return capability;
}

const DependencySeal = struct {
    schedule_identity: [32]u8,
    binding_identity: [32]u8,
};

fn validateDependencies(
    session: anytype,
    expected: []const schedule.Dependency,
    supplied: []const DependencyCapability,
    capability: ContextCapability,
) !DependencySeal {
    if (expected.len != supplied.len)
        return error.TraceWriterBindingMismatch;
    const schedule_identity = dependenciesIdentity(expected);
    for (expected, supplied) |wanted, actual| {
        if (!std.meta.eql(wanted, actual.dependency))
            return error.TraceWriterBindingMismatch;
        const minimum: usize = switch (wanted.kind) {
            .producer_words => std.math.add(
                usize,
                wanted.word_base,
                std.math.mul(
                    usize,
                    wanted.words_per_instance,
                    wanted.instances,
                ) catch return error.TraceWriterBindingMismatch,
            ) catch return error.TraceWriterBindingMismatch,
            .capacity => wanted.instances,
            .native_ec_workspace => return error.TraceWriterBindingMismatch,
        };
        _ = try exactResident(
            session,
            capability,
            actual.resident,
            @max(minimum, 1),
        );
    }
    return .{
        .schedule_identity = schedule_identity,
        .binding_identity = try dependencyBindingIdentity(
            expected,
            supplied,
        ),
    };
}

fn appendResident(
    session: anytype,
    capability: ContextCapability,
    value: common.Words,
    expected: usize,
    ranges: *std.ArrayList(layout.DeviceRange),
    allocator: std.mem.Allocator,
) !void {
    try ranges.append(
        allocator,
        (try exactResident(session, capability, value, expected)).range,
    );
}

fn exactResident(
    session: anytype,
    capability: ContextCapability,
    value: common.Words,
    expected: usize,
) !layout.Resident(u32) {
    try capability.include(value);
    if (value.len != expected) return error.TraceWriterBindingMismatch;
    return layout.resident(session, u32, value, expected);
}

pub fn fixedBindingIdentity(
    catalog_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependencies: [32]u8,
    resident: FixedResident,
) [32]u8 {
    var hash = identityHasher(
        "stwo-zig/cairo/cuda/fixed-resident-binding/v1\x00",
        catalog_identity,
        ownership,
        dependencies,
    );
    hashNamedSources(&hash, resident.sources);
    hashSlices(&hash, resident.multiplicity_columns);
    hashSlices(&hash, resident.trace_outputs);
    hashSlices(&hash, resident.lookup_outputs);
    hashFixedBuffers(&hash, resident.buffers);
    return hash.finalResult();
}

pub fn memoryAddressBindingIdentity(
    catalog_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependencies: [32]u8,
    source: MemorySource,
    buffers: memory_runtime.AddressBuffers,
) [32]u8 {
    var hash = identityHasher(
        "stwo-zig/cairo/cuda/memory-address-binding/v1\x00",
        catalog_identity,
        ownership,
        dependencies,
    );
    recorded_binding.hashInt(&hash, u32, source.value_offset);
    recorded_binding.hashInt(&hash, u32, source.words_per_value);
    recorded_binding.hashSlice(&hash, source.resident);
    recorded_binding.hashSlice(&hash, buffers.multiplicities);
    hashSlices(&hash, buffers.outputs);
    return hash.finalResult();
}

pub fn memoryValueBindingIdentity(
    catalog_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependencies: [32]u8,
    source_offset: u32,
    words_per_value: u32,
    buffers: memory_runtime.ValueBuffers,
) [32]u8 {
    var hash = identityHasher(
        "stwo-zig/cairo/cuda/memory-value-binding/v1\x00",
        catalog_identity,
        ownership,
        dependencies,
    );
    recorded_binding.hashInt(&hash, u32, source_offset);
    recorded_binding.hashInt(&hash, u32, words_per_value);
    hashSlices(&hash, buffers.sources);
    recorded_binding.hashSlice(&hash, buffers.multiplicities);
    hashSlices(&hash, buffers.outputs);
    return hash.finalResult();
}

fn identityHasher(
    domain: []const u8,
    catalog_identity: [32]u8,
    ownership: schedule.BufferOwnership,
    dependencies: [32]u8,
) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&catalog_identity);
    hashOwnership(&hash, ownership);
    hash.update(&dependencies);
    return hash;
}

fn hashNamedSources(
    hash: *std.crypto.hash.sha2.Sha256,
    sources: []const FixedSource,
) void {
    recorded_binding.hashInt(hash, u64, sources.len);
    for (sources) |source| {
        recorded_binding.hashBytes(hash, source.identity);
        recorded_binding.hashSlice(hash, source.resident);
    }
}

fn hashSlices(
    hash: *std.crypto.hash.sha2.Sha256,
    slices: []const common.Words,
) void {
    recorded_binding.hashInt(hash, u64, slices.len);
    for (slices) |value| recorded_binding.hashSlice(hash, value);
}

fn hashFixedBuffers(
    hash: *std.crypto.hash.sha2.Sha256,
    buffers: fixed_runtime.Buffers,
) void {
    inline for (.{
        buffers.source_pointer_table,
        buffers.multiplicity_pointer_table,
        buffers.trace_multiplicity_columns,
        buffers.trace_output_pointer_table,
        buffers.lookup_descriptors,
        buffers.lookup_output_pointer_table,
    }) |value| recorded_binding.hashSlice(hash, value);
}

pub fn dependencyIdentity(entry: schedule.Entry) [32]u8 {
    return dependenciesIdentity(entry.dependencies);
}

pub fn dependencyBindingIdentity(
    expected: []const schedule.Dependency,
    supplied: []const DependencyCapability,
) ![32]u8 {
    if (expected.len != supplied.len)
        return error.TraceWriterBindingMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/cairo/cuda/writer-resident-dependencies/v1\x00",
    );
    hash.update(&dependenciesIdentity(expected));
    for (expected, supplied) |wanted, actual| {
        if (!std.meta.eql(wanted, actual.dependency))
            return error.TraceWriterBindingMismatch;
        recorded_binding.hashSlice(&hash, actual.resident);
    }
    return hash.finalResult();
}

fn dependenciesIdentity(
    dependencies: []const schedule.Dependency,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/writer-dependencies/v1\x00");
    recorded_binding.hashInt(&hash, u64, dependencies.len);
    for (dependencies) |dependency| hashDependency(&hash, dependency);
    return hash.finalResult();
}

fn hashDependency(
    hash: *std.crypto.hash.sha2.Sha256,
    dependency: schedule.Dependency,
) void {
    recorded_binding.hashInt(
        hash,
        u32,
        dependency.producer_component_index,
    );
    recorded_binding.hashInt(hash, u8, @intFromEnum(dependency.kind));
    recorded_binding.hashInt(hash, u32, dependency.word_base);
    recorded_binding.hashInt(hash, u32, dependency.words_per_instance);
    recorded_binding.hashInt(hash, u32, dependency.instances);
}

fn hashOwnership(
    hash: *std.crypto.hash.sha2.Sha256,
    ownership: schedule.BufferOwnership,
) void {
    inline for (.{
        ownership.trace_outputs,
        ownership.lookup_outputs,
        ownership.subword_outputs,
        ownership.multiplicity_outputs,
    }) |owner| recorded_binding.hashInt(hash, u32, owner);
    hashOptional(hash, ownership.native_partial_workspace);
    hashOptional(hash, ownership.native_partial_inputs);
}

fn hashOptional(
    hash: *std.crypto.hash.sha2.Sha256,
    value: ?u32,
) void {
    recorded_binding.hashInt(hash, u8, @intFromBool(value != null));
    recorded_binding.hashInt(hash, u32, value orelse 0);
}
