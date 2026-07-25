const std = @import("std");
const proof_plan = @import("../../../frontends/cairo/proof_plan.zig");
const recorded_witness = @import("../recorded_witness.zig");
const native_ec = @import("../native_ec.zig");
const controller = @import("trace_writer_controller.zig");
const schedule_module = @import("trace_schedule.zig");

const TestOps = struct {
    pub fn recorded(
        _: *recorded_witness.PreparedLaunch,
        log: *Log,
    ) !void {
        try log.append(0);
    }
    pub fn fixed(_: controller.FixedBinding, log: *Log) !void {
        try log.append(1);
    }
    pub fn memoryAddress(
        _: controller.MemoryAddressBinding,
        log: *Log,
    ) !void {
        try log.append(2);
    }
    pub fn memoryValue(
        _: controller.MemoryValueBinding,
        log: *Log,
    ) !void {
        try log.append(3);
    }
    pub fn nativeEc(_: *native_ec.Prepared, log: *Log) !void {
        try log.append(4);
    }
    pub fn clearFeeds(_: anytype, _: *Log) !void {}
    pub fn feed(_: anytype, _: *Log) !void {}
    pub fn gather(_: anytype, _: *Log) !void {}
    pub fn compact(_: anytype, _: *Log) !void {}
};

const Log = struct {
    values: [5]u8 = undefined,
    len: usize = 0,

    fn append(self: *Log, value: u8) !void {
        if (self.len >= self.values.len) return error.TooManyLaunches;
        self.values[self.len] = value;
        self.len += 1;
    }
};

test "controller validates ownership and executes dependency order" {
    const ids = [_][32]u8{
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        [_]u8{3} ** 32,
        [_]u8{4} ** 32,
        [_]u8{5} ** 32,
        [_]u8{6} ** 32,
    };
    const native_dependency = [_]schedule_module.Dependency{.{
        .producer_component_index = 4,
        .kind = .native_ec_workspace,
        .word_base = 0,
        .words_per_instance = 0,
        .instances = 1,
    }};
    var entries = [_]schedule_module.Entry{
        entry(0, .recorded_aot, .recorded_witness_prepare, .standalone, 0, ids[0]),
        entry(1, .fixed_table, .fixed_table_materialize, .standalone, 1, ids[1]),
        entry(2, .memory_trace, .memory_address_base, .standalone, 2, ids[2]),
        entry(3, .memory_trace, .memory_value_base_big, .standalone, 3, ids[3]),
        entry(4, .native_backend, .native_ec_prepare, .composite_root, 4, ids[4]),
        entry(5, .native_backend, .native_ec_member, .composite_member, 4, ids[5]),
    };
    entries[4].buffers.native_partial_workspace = 4;
    entries[5].buffers.native_partial_inputs = 4;
    entries[5].dependencies = &native_dependency;
    const launch_order = [_]u32{ 2, 0, 1, 3, 4 };
    var schedule = schedule_module.Schedule{
        .allocator = std.testing.allocator,
        .entries = @constCast(&entries),
        .dependency_storage = @constCast(&native_dependency),
        .launch_order = @constCast(&launch_order),
        .writer_counts = [_]u32{0} **
            std.meta.fields(proof_plan.WriterKind).len,
        .identity = [_]u8{9} ** 32,
    };
    _ = &schedule;
    var recorded = fakeRecorded(ids[0], 0xa0);
    const partial = fakeRecorded(ids[5], 0xa5);
    var native: native_ec.Prepared = undefined;
    native.partial_ec_mul = partial;
    native.catalog_identity = ids[4];
    native.binding_identity = sealIdentity(0xb4);
    const empty = @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).Words{ .address = 0, .len = 0, .owner = 0 };
    const bindings = [_]controller.Binding{
        .{
            .component_index = 0,
            .catalog_identity = ids[0],
            .body = .{ .recorded = &recorded },
        },
        .{
            .component_index = 1,
            .catalog_identity = ids[1],
            .body = .{ .fixed = fakeFixed(entries[1], empty) },
        },
        .{
            .component_index = 2,
            .catalog_identity = ids[2],
            .body = .{
                .memory_address = fakeMemoryAddress(entries[2], empty),
            },
        },
        .{
            .component_index = 3,
            .catalog_identity = ids[3],
            .body = .{
                .memory_value_big = fakeMemoryValue(entries[3], empty),
            },
        },
        .{
            .component_index = 4,
            .catalog_identity = ids[4],
            .body = .{ .native_ec = .{
                .prepared = &native,
                .member_component_index = 5,
                .member_catalog_identity = ids[5],
            } },
        },
    };
    var prepared = try controller.Prepared.init(
        std.testing.allocator,
        schedule,
        &bindings,
    );
    defer prepared.deinit();
    var log = Log{};
    try prepared.executeWith(TestOps, &log);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 2, 0, 1, 3, 4 },
        log.values[0..log.len],
    );

    var drifted = bindings;
    drifted[4].body.native_ec.member_catalog_identity[0] ^= 1;
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            schedule,
            &drifted,
        ),
    );

    var swapped = fakeRecorded(ids[1], 0xcc);
    drifted = bindings;
    drifted[0].body.recorded = &swapped;
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            schedule,
            &drifted,
        ),
    );

    native.partial_ec_mul.catalog_identity = ids[0];
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            schedule,
            &bindings,
        ),
    );
    native.partial_ec_mul = partial;
    native.catalog_identity = ids[1];
    log = .{};
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        prepared.executeWith(TestOps, &log),
    );
    native.catalog_identity = ids[4];

    var fixed_swap = bindings;
    fixed_swap[1].body.fixed.catalog_identity = ids[2];
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            schedule,
            &fixed_swap,
        ),
    );
    var memory_swap = bindings;
    memory_swap[3].body.memory_value_big.catalog_identity = ids[2];
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            schedule,
            &memory_swap,
        ),
    );

    var ownership_entries = entries;
    ownership_entries[1].buffers.trace_outputs = 2;
    var ownership_schedule = schedule;
    ownership_schedule.entries = &ownership_entries;
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            ownership_schedule,
            &bindings,
        ),
    );

    const wrong_dependency = [_]schedule_module.Dependency{.{
        .producer_component_index = 3,
        .kind = .native_ec_workspace,
        .word_base = 0,
        .words_per_instance = 0,
        .instances = 1,
    }};
    var dependency_entries = entries;
    dependency_entries[5].dependencies = &wrong_dependency;
    var dependency_schedule = schedule;
    dependency_schedule.entries = &dependency_entries;
    dependency_schedule.dependency_storage = @constCast(
        &wrong_dependency,
    );
    try std.testing.expectError(
        error.TraceWriterBindingMismatch,
        controller.Prepared.init(
            std.testing.allocator,
            dependency_schedule,
            &bindings,
        ),
    );
}

fn fakeRecorded(
    catalog_identity: [32]u8,
    seal: u8,
) recorded_witness.PreparedLaunch {
    var result: recorded_witness.PreparedLaunch = undefined;
    result.catalog_identity = catalog_identity;
    result.binding_identity = sealIdentity(seal);
    return result;
}

fn sealIdentity(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

fn fakeFixed(
    scheduled: schedule_module.Entry,
    empty: @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
) controller.FixedBinding {
    const buffers = @import(
        "../../../backends/cuda/runtime/stages/cairo_base/fixed_tables.zig",
    ).Buffers{
        .source_pointer_table = empty,
        .multiplicity_pointer_table = empty,
        .trace_multiplicity_columns = empty,
        .trace_output_pointer_table = empty,
        .lookup_descriptors = empty,
        .lookup_output_pointer_table = empty,
    };
    const resident = controller.FixedResident{
        .sources = &.{},
        .multiplicity_columns = &.{},
        .trace_outputs = &.{},
        .lookup_outputs = &.{},
        .buffers = buffers,
    };
    const dependency_identity = controller.dependencyIdentity(scheduled);
    const dependency_binding = controller.dependencyBindingIdentity(
        scheduled.dependencies,
        &.{},
    ) catch unreachable;
    return .{
        .geometry = .{
            .source_column_count = 0,
            .multiplicity_column_count = 1,
            .trace_output_count = 1,
            .lookup_output_count = 1,
            .row_count = 16,
        },
        .buffers = buffers,
        .resident = resident,
        .catalog_identity = scheduled.catalog_identity,
        .binding_identity = controller.fixedBindingIdentity(
            scheduled.catalog_identity,
            scheduled.buffers,
            dependency_binding,
            resident,
        ),
        .ownership = scheduled.buffers,
        .dependency_identity = dependency_identity,
        .dependency_binding_identity = dependency_binding,
        .capability = .{ .owner = 7, .generation = 11 },
    };
}

fn fakeMemoryAddress(
    scheduled: schedule_module.Entry,
    empty: @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
) controller.MemoryAddressBinding {
    const source = controller.MemorySource{
        .resident = empty,
        .value_offset = 1,
        .words_per_value = 1,
    };
    const buffers = @import(
        "../../../backends/cuda/runtime/stages/cairo_base/memory.zig",
    ).AddressBuffers{
        .address_ids = empty,
        .multiplicities = empty,
        .outputs = &.{},
    };
    const dependency_identity = controller.dependencyIdentity(scheduled);
    const dependency_binding = controller.dependencyBindingIdentity(
        scheduled.dependencies,
        &.{},
    ) catch unreachable;
    return .{
        .geometry = .{ .address_id_words = 1, .row_count = 16 },
        .buffers = buffers,
        .source = source,
        .catalog_identity = scheduled.catalog_identity,
        .binding_identity = controller.memoryAddressBindingIdentity(
            scheduled.catalog_identity,
            scheduled.buffers,
            dependency_binding,
            source,
            buffers,
        ),
        .ownership = scheduled.buffers,
        .dependency_identity = dependency_identity,
        .dependency_binding_identity = dependency_binding,
        .capability = .{ .owner = 7, .generation = 11 },
    };
}

fn fakeMemoryValue(
    scheduled: schedule_module.Entry,
    empty: @import(
        "../../../backends/cuda/runtime/stages/common.zig",
    ).Words,
) controller.MemoryValueBinding {
    const buffers = @import(
        "../../../backends/cuda/runtime/stages/cairo_base/memory.zig",
    ).ValueBuffers{
        .sources = &.{},
        .multiplicities = empty,
        .outputs = &.{},
    };
    const dependency_identity = controller.dependencyIdentity(scheduled);
    const dependency_binding = controller.dependencyBindingIdentity(
        scheduled.dependencies,
        &.{},
    ) catch unreachable;
    return .{
        .geometry = .{
            .limb_count = 28,
            .source_words = 1,
            .row_count = 16,
        },
        .buffers = buffers,
        .source_offset = 0,
        .words_per_value = 8,
        .catalog_identity = scheduled.catalog_identity,
        .binding_identity = controller.memoryValueBindingIdentity(
            scheduled.catalog_identity,
            scheduled.buffers,
            dependency_binding,
            0,
            8,
            buffers,
        ),
        .ownership = scheduled.buffers,
        .dependency_identity = dependency_identity,
        .dependency_binding_identity = dependency_binding,
        .capability = .{ .owner = 7, .generation = 11 },
    };
}

fn entry(
    component_index: u32,
    writer: proof_plan.WriterKind,
    api: schedule_module.PrepareApi,
    execution: schedule_module.Execution,
    launch_owner: u32,
    identity: [32]u8,
) schedule_module.Entry {
    return .{
        .component_index = component_index,
        .canonical_ordinal = component_index,
        .name = "test",
        .instance = 0,
        .writer = writer,
        .prepare_api = api,
        .execution = execution,
        .launch_owner = launch_owner,
        .buffers = .{
            .trace_outputs = component_index,
            .lookup_outputs = component_index,
            .subword_outputs = component_index,
            .multiplicity_outputs = component_index,
            .native_partial_workspace = null,
            .native_partial_inputs = null,
        },
        .catalog_identity = identity,
        .dependencies = &.{},
    };
}
