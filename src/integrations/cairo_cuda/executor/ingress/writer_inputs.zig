//! Normalized direct witness inputs derived from an authenticated Cairo input.

const std = @import("std");
const adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const direct_inputs = @import("stwo_cairo_frontend").witness.direct_inputs;
const witness = @import("stwo_cairo_frontend").witness.bundle;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const resident_plan = @import("../resident_plan.zig");

pub const Entry = struct {
    component_index: u32,
    first_column: u32,
    column_count: u32,
    first_word: u64,
    row_count: u32,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    column_count: usize,
    word_count: usize,
    maximum_rows: usize,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        proof: *const proof_plan.CairoProofPlan,
        components: composition.Bundle,
        witnesses: witness.Bundle,
        input: *const adapter.ProverInput,
        plan: *const resident_plan.Plan,
    ) !Prepared {
        if (proof.components.len != components.components.len)
            return error.InvalidWriterInputLayout;
        var entry_count: usize = 0;
        var column_count: usize = 0;
        var word_count: usize = 0;
        var maximum_rows: usize = 0;
        for (proof.components, components.components) |planned, component| {
            if (planned.writer != .recorded_aot) continue;
            const program = (witnesses.find(planned.name) orelse
                return error.MissingRecordedWitnessLowering).program;
            if (try direct_inputs.resolve(input, planned.name)) |direct| {
                if (program.n_inputs != direct.columnCount())
                    return error.InvalidWriterInputLayout;
            } else if (planned.producer_edges.len == 0) {
                return error.MissingDirectWriterInput;
            }
            const rows = try pow2(component.trace_log_size);
            if (try direct_inputs.resolve(input, planned.name)) |direct|
                try direct.validateRowCount(rows);
            entry_count += 1;
            column_count = try add(column_count, program.n_inputs);
            word_count = try add(
                word_count,
                try mul(rows, program.n_inputs),
            );
            maximum_rows = @max(maximum_rows, rows);
        }
        const slot = plan.slot(.writer_inputs, 0) orelse
            return error.MissingWriterInputSlot;
        if (slot.words < word_count) {
            return error.InvalidWriterInputLayout;
        }
        const entries = try allocator.alloc(Entry, entry_count);
        errdefer allocator.free(entries);
        var entry_cursor: usize = 0;
        var column_cursor: usize = 0;
        var word_cursor: usize = 0;
        for (
            proof.components,
            components.components,
            0..,
        ) |planned, component, component_index| {
            if (planned.writer != .recorded_aot) continue;
            const program = (witnesses.find(planned.name) orelse
                return error.MissingRecordedWitnessLowering).program;
            const rows = try pow2(component.trace_log_size);
            entries[entry_cursor] = .{
                .component_index = @intCast(component_index),
                .first_column = @intCast(column_cursor),
                .column_count = program.n_inputs,
                .first_word = word_cursor,
                .row_count = @intCast(rows),
            };
            entry_cursor += 1;
            column_cursor += program.n_inputs;
            word_cursor += rows * program.n_inputs;
        }
        std.debug.assert(entry_cursor == entries.len);
        std.debug.assert(column_cursor == column_count);
        std.debug.assert(word_cursor == word_count);
        return .{
            .allocator = allocator,
            .entries = entries,
            .column_count = column_count,
            .word_count = word_count,
            .maximum_rows = maximum_rows,
            .identity = layoutIdentity(plan.identity, entries),
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn uploadAndBind(
        self: Prepared,
        session: anytype,
        provider: anytype,
        plan: *const resident_plan.Plan,
        proof: *const proof_plan.CairoProofPlan,
        input: *const adapter.ProverInput,
    ) !Bound {
        const descriptor = plan.slot(.writer_inputs, 0) orelse
            return error.MissingWriterInputSlot;
        const storage = try provider.slot(descriptor.id);
        if (storage.len < self.word_count)
            return error.InvalidWriterInputLayout;
        const columns = try self.allocator.alloc(
            common.Words,
            self.column_count,
        );
        errdefer self.allocator.free(columns);
        const staging = try self.allocator.alloc(u32, self.maximum_rows);
        defer self.allocator.free(staging);
        for (self.entries) |entry| {
            if (entry.component_index >= proof.components.len)
                return error.InvalidWriterInputLayout;
            const direct = (try direct_inputs.resolve(
                input,
                proof.components[entry.component_index].name,
            )) orelse {
                for (0..entry.column_count) |local| {
                    const first = try add(
                        std.math.cast(usize, entry.first_word) orelse
                            return error.InvalidWriterInputLayout,
                        try mul(local, entry.row_count),
                    );
                    columns[entry.first_column + local] =
                        try storage.sub(first, entry.row_count);
                }
                continue;
            };
            const rows: usize = entry.row_count;
            for (0..entry.column_count) |local| {
                const first = try add(
                    std.math.cast(usize, entry.first_word) orelse
                        return error.InvalidWriterInputLayout,
                    try mul(local, rows),
                );
                const destination = try storage.sub(first, rows);
                try direct.writeColumn(local, staging[0..rows]);
                try session.context.uploadSlice(
                    u32,
                    destination,
                    staging[0..rows],
                );
                columns[entry.first_column + local] = destination;
            }
        }
        return .{
            .allocator = self.allocator,
            .prepared = self,
            .storage = storage,
            .columns = columns,
        };
    }
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    prepared: Prepared,
    storage: common.Words,
    columns: []common.Words,

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn component(
        self: Bound,
        component_index: u32,
    ) ?[]const common.Words {
        for (self.prepared.entries) |entry| {
            if (entry.component_index != component_index) continue;
            return self.columns[entry.first_column..][0..entry.column_count];
        }
        return null;
    }
};

fn layoutIdentity(
    plan_identity: [32]u8,
    entries: []const Entry,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/writer-input-layout/v1\x00");
    hash.update(&plan_identity);
    for (entries) |entry| {
        hashInt(&hash, u32, entry.component_index);
        hashInt(&hash, u32, entry.first_column);
        hashInt(&hash, u32, entry.column_count);
        hashInt(&hash, u64, entry.first_word);
        hashInt(&hash, u32, entry.row_count);
    }
    return hash.finalResult();
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

fn pow2(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.InvalidWriterInputLayout;
    return @as(usize, 1) << @intCast(log_rows);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        error.InvalidWriterInputLayout;
}

fn mul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch
        error.InvalidWriterInputLayout;
}
