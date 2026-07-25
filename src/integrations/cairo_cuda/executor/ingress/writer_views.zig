//! Shared resident views for Cairo base-writer ingress mappers.

const std = @import("std");
const proof_plan = @import(
    "../../../../frontends/cairo/proof_plan.zig",
);
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_bundle = @import(
    "../../../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const witness_bundle = @import(
    "../../../../frontends/cairo/witness/bundle.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const ec_contract = @import(
    "../../../../backends/cuda/runtime/stages/cairo_ec_op_contract.zig",
);
const request_compiler = @import("../../request_compiler.zig");
const controller_bundle = @import("controller_bundle.zig");

pub const Component = struct {
    component_index: u32,
    trace_columns: []const common.Words,
    lookup_words: common.Words,
    sub_words: common.Words,
};

pub const Registry = struct {
    components: []const Component,

    pub fn find(
        self: Registry,
        component_index: u32,
    ) ?Component {
        for (self.components) |component| {
            if (component.component_index == component_index)
                return component;
        }
        return null;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness_bundle.Bundle,
    fixed: fixed_bundle.Bundle,
    controllers: *controller_bundle.Bound,
) !Registry {
    if (proof.components.len != components.components.len)
        return error.InvalidWriterViewInventory;
    var trace_column_count: usize = 0;
    for (request.trace_dispatch.entries) |entry| {
        const matrix = try controllers.main_commit.writerOutput(
            entry.canonical_ordinal,
        );
        if (matrix.column_stride_words == 0 or
            matrix.storage.len % matrix.column_stride_words != 0)
        {
            return error.InvalidWriterViewExtent;
        }
        trace_column_count = try add(
            trace_column_count,
            matrix.storage.len / matrix.column_stride_words,
        );
    }
    const entries = try allocator.alloc(Component, proof.components.len);
    const trace_columns = try allocator.alloc(
        common.Words,
        trace_column_count,
    );
    const lookup_slot = try exactSlot(
        provider,
        request,
        .writer_lookup_inputs,
    );
    const scratch_slot = try exactSlot(
        provider,
        request,
        .writer_scratch,
    );
    var trace_cursor: usize = 0;
    var lookup_cursor: usize = 0;
    var scratch_cursor: usize = 0;
    for (
        request.trace_dispatch.entries,
        entries,
    ) |schedule_entry, *destination| {
        const component_index: usize = schedule_entry.component_index;
        if (component_index >= proof.components.len)
            return error.InvalidWriterViewInventory;
        const planned = proof.components[component_index];
        const component = components.components[component_index];
        const matrix = try controllers.main_commit.writerOutput(
            schedule_entry.canonical_ordinal,
        );
        const column_count =
            matrix.storage.len / matrix.column_stride_words;
        const trace_end = try add(trace_cursor, column_count);
        const columns = trace_columns[trace_cursor..trace_end];
        for (columns, 0..) |*column, local| {
            column.* = try matrix.storage.sub(
                try mul(local, matrix.column_stride_words),
                matrix.column_stride_words,
            );
        }
        trace_cursor = trace_end;

        var lookup_words: usize = 0;
        var sub_words: usize = 0;
        switch (planned.writer) {
            .recorded_aot => {
                const program = (witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering).program;
                lookup_words = try mul(
                    componentRows(component),
                    program.n_lookup_words,
                );
                sub_words = try mul(
                    componentRows(component),
                    program.n_sub_words,
                );
            },
            .native_backend => if (std.mem.eql(
                u8,
                planned.name,
                "ec_op_builtin",
            )) {
                const rows = componentRows(component);
                lookup_words = try mul(
                    rows,
                    ec_contract.lookup_words_per_row,
                );
                sub_words = try mul(
                    try mul(rows, ec_contract.partial_padded_rounds),
                    ec_contract.partial_input_column_count,
                );
            } else {
                const program = (witnesses.find(planned.name) orelse
                    return error.MissingRecordedWitnessLowering).program;
                lookup_words = try mul(
                    componentRows(component),
                    program.n_lookup_words,
                );
                sub_words = try mul(
                    componentRows(component),
                    program.n_sub_words,
                );
            },
            .fixed_table => {
                const entry = fixed.find(planned.name) orelse
                    return error.MissingFixedTableLowering;
                lookup_words = try mul(
                    componentRows(component),
                    entry.lookupCount(),
                );
            },
            .memory_trace => {},
        }
        const lookup = try lookup_slot.sub(
            lookup_cursor,
            lookup_words,
        );
        lookup_cursor = try add(lookup_cursor, lookup_words);
        const sub = try scratch_slot.sub(
            scratch_cursor,
            sub_words,
        );
        scratch_cursor = try add(scratch_cursor, sub_words);
        destination.* = .{
            .component_index = schedule_entry.component_index,
            .trace_columns = columns,
            .lookup_words = lookup,
            .sub_words = sub,
        };
    }
    if (trace_cursor != trace_columns.len or
        lookup_cursor != lookup_slot.len or
        scratch_cursor > scratch_slot.len)
    {
        return error.InvalidWriterViewExtent;
    }
    return .{ .components = entries };
}

fn exactSlot(
    provider: anytype,
    request: *const request_compiler.PreparedRequest,
    kind: @import("../resident_plan.zig").SlotKind,
) !common.Words {
    const descriptor = request.resident.slot(kind, 0) orelse
        return error.MissingWriterViewSlot;
    const storage = try provider.slot(descriptor.id);
    if (storage.len != descriptor.words)
        return error.InvalidWriterViewExtent;
    return storage;
}

fn componentRows(component: composition.Component) usize {
    return @as(usize, 1) << @intCast(component.trace_log_size);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.InvalidWriterViewExtent;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.InvalidWriterViewExtent;
    const rhs = std.math.cast(usize, right) orelse
        return error.InvalidWriterViewExtent;
    return std.math.mul(usize, lhs, rhs) catch
        error.InvalidWriterViewExtent;
}
