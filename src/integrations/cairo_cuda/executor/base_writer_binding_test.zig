const std = @import("std");
const binding = @import("base_writer_binding.zig");
const fixed_plan = @import("../base_writer_plan/fixed_tables.zig");
const memory_plan = @import("../base_writer_plan/memory.zig");
const memory = @import(
    "../../../backends/cuda/runtime/stages/cairo_base/memory.zig",
);
const schedule = @import("trace_schedule.zig");
const telemetry = @import(
    "../../../backends/cuda/runtime/telemetry.zig",
);
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);

test "fixed ingress derives all tables and its seal detects pointee drift" {
    var source_name = "seq_4".*;
    var source_names = [_][]u8{&source_name};
    const trace_indices = [_]u32{1};
    const descriptors = [_]u32{
        1, 0, 0, 0,
        2, 1, 0, 0,
    };
    var plan = fixed_plan.Entry{
        .component_index = 1,
        .fixed_ordinal = 0,
        .graph_hash = 0x1234,
        .name = "test_fixed",
        .instance = 0,
        .log_size = 4,
        .row_count = 16,
        .source_column_count = 1,
        .multiplicity_column_count = 2,
        .trace_output_count = 1,
        .lookup_output_count = 2,
        .preprocessed_sources = &source_names,
        .trace_multiplicity_columns = &trace_indices,
        .lookup_descriptors = &descriptors,
        .identity = undefined,
    };
    plan.identity = fixed_plan.recomputeIdentity(plan);
    const identity = plan.identity;
    const scheduled = entry(
        1,
        .fixed_table,
        .fixed_table_materialize,
        identity,
    );
    var sources = [_]binding.FixedSource{.{
        .identity = "seq_4",
        .resident = words(0x10_0000, 16),
    }};
    const multiplicities = [_]common.Words{
        words(0x11_0000, 16),
        words(0x12_0000, 16),
    };
    const trace_outputs = [_]common.Words{words(0x13_0000, 16)};
    const lookup_outputs = [_]common.Words{
        words(0x14_0000, 16),
        words(0x15_0000, 16),
    };
    const resident = binding.FixedResident{
        .sources = &sources,
        .multiplicity_columns = &multiplicities,
        .trace_outputs = &trace_outputs,
        .lookup_outputs = &lookup_outputs,
        .buffers = .{
            .source_pointer_table = words(0x20_0000, 2),
            .multiplicity_pointer_table = words(0x21_0000, 4),
            .trace_multiplicity_columns = words(0x22_0000, 1),
            .trace_output_pointer_table = words(0x23_0000, 2),
            .lookup_descriptors = words(0x24_0000, 8),
            .lookup_output_pointer_table = words(0x25_0000, 4),
        },
    };
    var session = TestSession{};
    const prepared = try binding.prepareFixed(
        std.testing.allocator,
        &session,
        plan,
        scheduled,
        resident,
        &.{},
    );
    try std.testing.expectEqual(@as(u64, 6), session.context.uploads);
    try std.testing.expect(binding.fixedSealValid(prepared));
    sources[0].resident.generation += 1;
    try std.testing.expect(!binding.fixedSealValid(prepared));
}

test "memory address and value constructors seal exact source provenance" {
    var session = TestSession{};
    var address_plan = memory_plan.Entry{
        .component_index = 2,
        .name = "memory_address_to_id",
        .instance = 0,
        .kind = .address_to_id,
        .log_size = 4,
        .row_count = 16,
        .source_value_offset = 1,
        .source_value_count = 15,
        .source_words_per_value = 1,
        .limb_count = 0,
        .output_column_count = memory.address_column_count,
        .identity = undefined,
    };
    address_plan.identity = memory_plan.recomputeIdentity(address_plan);
    const address_identity = address_plan.identity;
    var address_outputs: [memory.address_column_count]common.Words = undefined;
    fill(&address_outputs, 0x40_0000, 16);
    const address_buffers = memory.AddressBuffers{
        .address_ids = words(0x30_0000, 15),
        .multiplicities = words(0x31_0000, 256),
        .outputs = &address_outputs,
    };
    var address = try binding.prepareMemoryAddress(
        &session,
        address_plan,
        entry(
            2,
            .memory_trace,
            .memory_address_base,
            address_identity,
        ),
        .{
            .resident = address_buffers.address_ids,
            .value_offset = 1,
            .words_per_value = 1,
        },
        address_buffers,
        &.{},
    );
    try std.testing.expect(binding.memoryAddressSealValid(address));
    address.source.value_offset = 0;
    try std.testing.expect(!binding.memoryAddressSealValid(address));

    var value_plan = memory_plan.Entry{
        .component_index = 3,
        .name = "memory_id_to_big",
        .instance = 0,
        .kind = .id_to_big,
        .log_size = 4,
        .row_count = 16,
        .source_value_offset = 0,
        .source_value_count = 8,
        .source_words_per_value = 8,
        .limb_count = memory.big_limb_count,
        .output_column_count = memory.big_limb_count + 1,
        .identity = undefined,
    };
    value_plan.identity = memory_plan.recomputeIdentity(value_plan);
    const value_identity = value_plan.identity;
    var value_sources: [memory.big_limb_count]common.Words = undefined;
    fill(&value_sources, 0x60_0000, 8);
    var value_outputs: [memory.big_limb_count + 1]common.Words = undefined;
    fill(&value_outputs, 0x80_0000, 16);
    var value = try binding.prepareMemoryValue(
        &session,
        value_plan,
        entry(
            3,
            .memory_trace,
            .memory_value_base_big,
            value_identity,
        ),
        0,
        .{
            .sources = &value_sources,
            .multiplicities = words(0x70_0000, 16),
            .outputs = &value_outputs,
        },
        &.{},
    );
    try std.testing.expect(binding.memoryValueSealValid(value));
    value.words_per_value = 4;
    try std.testing.expect(!binding.memoryValueSealValid(value));
}

const TestSession = struct {
    context: TestContext = .{},
};

const TestContext = struct {
    active_stage: telemetry.Stage = .ingress,
    uploads: u64 = 0,

    pub fn requireStage(self: *TestContext, expected: telemetry.Stage) !void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        value: anytype,
        minimum: usize,
    ) ![*]F {
        if (value.address == 0 or value.len < minimum or
            value.owner != 7 or value.generation != 11 or
            value.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(value.address);
    }

    pub fn uploadSlice(
        self: *TestContext,
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) !void {
        _ = try self.deviceSlicePointer(F, destination, source.len);
        if (destination.len != source.len) return error.SizeOverflow;
        self.uploads += 1;
    }
};

fn entry(
    component_index: u32,
    writer: @import("stwo_cairo_frontend").proof_plan.WriterKind,
    api: schedule.PrepareApi,
    identity: [32]u8,
) schedule.Entry {
    return .{
        .component_index = component_index,
        .canonical_ordinal = component_index,
        .name = "test",
        .instance = 0,
        .writer = writer,
        .prepare_api = api,
        .execution = .standalone,
        .launch_owner = component_index,
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

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

fn fill(output: []common.Words, base: usize, len: usize) void {
    for (output, 0..) |*value, index|
        value.* = words(base + index * 0x1000, len);
}
