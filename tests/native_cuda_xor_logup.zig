const std = @import("std");
const stwo = @import("stwo_under_test");
const exact = stwo.integrations.native_cuda.xor;

test {
    std.testing.refAllDecls(exact);
}

test "exact CUDA XOR is a four-tree resident relation graph" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{ .log_size = 8, .log_step = 2, .offset = 3 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    const bound = try exact.resident_bindings.bind(&provider, &prepared);

    try std.testing.expectEqual(
        @as(usize, 4),
        bound.base.trees.active().len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        (try bound.base.trees.require(.interaction)).column_log_sizes.len,
    );
    const interaction = try bound.base.trees.require(.interaction);
    try std.testing.expectEqual(
        geometry.commitment_rows,
        interaction.coefficients.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, exact.geometry.interaction_columns) *
            geometry.commitment_rows,
        interaction.coefficients.storage.len,
    );
    try std.testing.expectEqual(
        @as(usize, 15),
        bound.constraint_buffers.source_evaluations.storage.len /
            bound.constraint_buffers.source_evaluations.column_stride_words,
    );
    try std.testing.expectEqual(
        @as(usize, 7 * 256),
        bound.relation.source_values.storage.len,
    );
    try std.testing.expect(
        bound.relation.source_values.storage.address !=
            (try bound.base.trees.require(.preprocessed))
                .coefficients.storage.address,
    );
    try std.testing.expectEqual(
        @as(usize, 27),
        prepared.quotient.prepared_terms.len,
    );
    try std.testing.expectEqual(
        exact.geometry.terminal_statement_words,
        bound.base.proof.statement.len,
    );
}

test "exact XOR binds authenticated trace and constraint kernels" {
    const trace = stwo.backends.cuda.runtime.traces.xor_logup;
    const constraint = stwo.backends.cuda.runtime.constraints.xor_logup;
    const trace_kernel = try trace.descriptor(8);
    const constraint_kernel = try constraint.descriptor(8);
    try std.testing.expectEqual(
        stwo.backends.cuda.abi.schema.KernelSchema.native_xor_logup_trace_v1,
        trace_kernel.abi_schema,
    );
    try std.testing.expectEqual(
        stwo.backends.cuda.abi.schema.KernelSchema.native_xor_logup_constraint_v1,
        constraint_kernel.abi_schema,
    );
    try std.testing.expect(trace_kernel.cache_key != 0);
    try std.testing.expect(constraint_kernel.cache_key != 0);
}

test "provisional 2+1 XOR primitive fails closed on exact 7+4 buffers" {
    const common = stwo.backends.cuda.runtime.stages.common;
    const Legacy = stwo.backends.cuda.runtime.stages.trace.OpsFor(struct {
        pub fn stwo_native_xor_trace_on(
            _: [*]u32,
            _: usize,
            _: usize,
            _: [*]u32,
            _: usize,
            _: usize,
            _: u32,
            _: u32,
            _: u32,
            _: u64,
            _: ?*anyopaque,
        ) callconv(.c) c_int {
            @panic("legacy kernel must not be reached");
        }
    });
    var session = LegacySession{};
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Legacy.xor(
            &session,
            matrix(0x1000, 256, 7),
            matrix(0x20_0000, 256, 4),
            256,
            8,
            2,
            3,
        ),
    );
    _ = common;
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !stwo.backends.cuda.runtime.column.DeviceSlice(u32) {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        return .{
            .address = 0x1_0000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 7,
            .generation = 11,
        };
    }
};

const LegacySession = struct {
    context: struct {
        active_stage: stwo.backends.cuda.runtime.telemetry.Stage =
            .trace_generation,
        stream: ?*anyopaque = null,

        pub fn requireStage(
            self: *@This(),
            expected: stwo.backends.cuda.runtime.telemetry.Stage,
        ) !void {
            if (self.active_stage != expected)
                return error.StageOrderViolation;
        }

        pub fn deviceSlicePointer(
            _: *@This(),
            comptime F: type,
            slice: anytype,
            minimum: usize,
        ) ![*]F {
            if (minimum == 0 or slice.len < minimum or
                slice.address == 0 or slice.address % @alignOf(F) != 0)
            {
                return error.InvalidDeviceAddress;
            }
            return @ptrFromInt(slice.address);
        }
    } = .{},

    pub fn recordOrdinaryKernel(
        _: *LegacySession,
        _: stwo.backends.cuda.runtime.telemetry.Stage,
        _: c_int,
    ) !void {}
};

fn matrix(
    address: usize,
    stride: usize,
    columns: usize,
) stwo.backends.cuda.runtime.stages.common.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * columns,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
