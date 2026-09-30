//! Circuit LogUp on the proof-owned CUDA stream. Gate/table kernels produce
//! paired fractions; the shared relation completion does batch inversions,
//! claimed sums and the canonical circle-order scan without host values.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");

const preprocessed = circuit.common.preprocessed;
const component_list = circuit.common.component_list;
const common = cuda.runtime.stages.common;
const fractions = cuda.runtime.stages.circuit_interaction;
const completion = cuda.runtime.stages.relation_completion;
const relation_abi = cuda.abi.stages.relation;

const pointer_words: usize = @sizeOf(usize) / @sizeOf(u32);
pub const interaction_column_count: usize = blk: {
    var total: usize = 0;
    for (fractions.secure_widths) |width| total += 4 * width;
    break :blk total;
};

const pp_ids = .{
    &preprocessed.EQ_COLUMN_IDS,
    &preprocessed.QM31_OPS_COLUMN_IDS,
    &preprocessed.TRIPLE_XOR_COLUMN_IDS,
    &preprocessed.M31_TO_U32_COLUMN_IDS,
    &preprocessed.BLAKE_G_GATE_COLUMN_IDS,
    &.{ "bitwise_xor_8_0", "bitwise_xor_8_1", "bitwise_xor_8_2" },
    &.{},
    &.{ "bitwise_xor_4_0", "bitwise_xor_4_1", "bitwise_xor_4_2" },
    &.{ "bitwise_xor_7_0", "bitwise_xor_7_1", "bitwise_xor_7_2" },
    &.{ "bitwise_xor_9_0", "bitwise_xor_9_1", "bitwise_xor_9_2" },
    &.{"seq_16"},
};

pub const Plan = struct {
    pp_indices: [fractions.component_count][11]u8,
    row_counts: [fractions.component_count]u32,
    geometry: [fractions.component_count]relation_abi.Geometry,
    total_pair_blocks: u32,
    total_inverse_blocks: u32,
    total_row_blocks: u32,

    pub fn init(layout: *const preprocessed.ColumnLayout) !Plan {
        const logs = (try component_list.circuitComponentLogSizes(layout)).toArray();
        var plan = Plan{
            .pp_indices = @splat(@splat(0)),
            .row_counts = undefined,
            .geometry = undefined,
            .total_pair_blocks = 0,
            .total_inverse_blocks = 0,
            .total_row_blocks = 0,
        };
        inline for (pp_ids, 0..) |group, component| {
            const log = logs[component];
            if (log < 4 or log >= 31 or group.len != fractions.pp_widths[component])
                return error.InvalidCircuitInteractionGeometry;
            const rows: u32 = @as(u32, 1) << @intCast(log);
            plan.row_counts[component] = rows;
            inline for (group, 0..) |id, local| {
                var found: ?usize = null;
                for (layout.entries, 0..) |entry, index| {
                    if (std.mem.eql(u8, entry.id, id)) {
                        if (entry.log_size != log) return error.InvalidCircuitInteractionGeometry;
                        found = index;
                        break;
                    }
                }
                plan.pp_indices[component][local] = std.math.cast(u8, found orelse return error.InvalidCircuitInteractionGeometry) orelse return error.InvalidCircuitInteractionGeometry;
            }
            const columns = std.math.cast(u32, fractions.secure_widths[component]) orelse return error.InvalidCircuitInteractionGeometry;
            const row_blocks = ceilDiv(rows, relation_abi.launch_block);
            const pair_blocks = try mul(row_blocks, columns);
            const inverse_blocks = ceilDiv(try mul(rows, columns), relation_abi.inverse_block_values);
            plan.geometry[component] = .{
                .pair_first = plan.total_pair_blocks,
                .pair_blocks = pair_blocks,
                .inverse_first = plan.total_inverse_blocks,
                .inverse_blocks = inverse_blocks,
                .row_first = plan.total_row_blocks,
                .row_blocks = row_blocks,
                .rows = rows,
                .columns = columns,
                .real_rows = rows,
                .source_offset_rows = 0,
                .inverse_rows = @as(u32, 1) << @intCast(31 - log),
            };
            plan.total_pair_blocks = try add(plan.total_pair_blocks, pair_blocks);
            plan.total_inverse_blocks = try add(plan.total_inverse_blocks, inverse_blocks);
            plan.total_row_blocks = try add(plan.total_row_blocks, row_blocks);
        }
        try plan.topology().validate();
        return plan;
    }

    pub fn topology(self: *const Plan) completion.Topology {
        return .{
            .geometry = &self.geometry,
            .max_alpha_powers = 6,
            .total_pair_blocks = self.total_pair_blocks,
            .total_inverse_blocks = self.total_inverse_blocks,
            .total_chain_blocks = self.total_row_blocks,
            .total_row_blocks = self.total_row_blocks,
        };
    }

    pub fn scratchWords(self: *const Plan) !usize {
        return @intCast(try self.topology().scratchWords());
    }
};

pub const Buffers = struct {
    preprocessed_columns: []const common.Words,
    base_columns: []const common.Words,
    interaction_columns: []const common.Words,
    drawn_z_alpha: common.SecureFields,
    alpha_powers: common.SecureFields,
    z: common.SecureFields,
    denominators: []const common.SecureFields,
    claimed_sums: common.SecureFields,
    output_values: common.SecureFields,
    error_flag: common.Words,
    output_pointer_table: common.Words,
    output_tables: common.Words,
    denominator_tables: common.Words,
    claimed_sum_tables: common.Words,
    geometry: completion.Geometries,
    reduction_partials: common.Words,
    scan_block_sums: common.Words,

    pub fn validate(self: Buffers, plan: *const Plan) !void {
        const count = fractions.component_count;
        if (self.preprocessed_columns.len != preprocessed.N_PREPROCESSED_COLUMNS or
            self.base_columns.len != @import("resident_witness.zig").base_column_count or
            self.interaction_columns.len != interaction_column_count or
            self.drawn_z_alpha.len != 2 or self.alpha_powers.len != 6 or self.z.len != 1 or
            self.denominators.len != count or self.claimed_sums.len != count or
            self.error_flag.len != 1 or
            self.output_pointer_table.len != interaction_column_count * pointer_words or
            self.output_tables.len != count * pointer_words or
            self.denominator_tables.len != count * pointer_words or
            self.claimed_sum_tables.len != count * pointer_words or
            self.geometry.len != count or
            self.reduction_partials.len != try plan.scratchWords() or
            self.scan_block_sums.len != try plan.scratchWords())
            return error.InvalidCircuitInteractionBuffers;
        const owner = self.drawn_z_alpha.owner;
        const generation = self.drawn_z_alpha.generation;
        inline for (.{ self.alpha_powers, self.z, self.claimed_sums }) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitInteractionBuffers;
        }
        inline for (.{ self.error_flag, self.output_pointer_table, self.output_tables, self.denominator_tables, self.claimed_sum_tables, self.reduction_partials, self.scan_block_sums }) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitInteractionBuffers;
        }
        if (self.geometry.owner != owner or self.geometry.generation != generation)
            return error.InvalidCircuitInteractionBuffers;
        if (self.output_values.len != 0 and
            (self.output_values.owner != owner or self.output_values.generation != generation))
            return error.InvalidCircuitInteractionBuffers;
        for (self.preprocessed_columns) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitInteractionBuffers;
        }
        for (self.base_columns) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitInteractionBuffers;
        }
        for (self.interaction_columns) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitInteractionBuffers;
        }
        for (self.denominators, plan.row_counts, fractions.secure_widths) |view, rows, columns| {
            if (view.owner != owner or view.generation != generation or
                view.len != @as(usize, rows) * columns)
                return error.InvalidCircuitInteractionBuffers;
        }
    }
};

pub const Bound = struct {
    plan: *const Plan,
    buffers: Buffers,
    primed: bool = false,
    executed: bool = false,

    pub fn init(plan: *const Plan, buffers: Buffers) !Bound {
        try buffers.validate(plan);
        return .{ .plan = plan, .buffers = buffers };
    }

    /// Uploads immutable geometry and the exact device pointer graph at ingress.
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.CircuitInteractionAlreadyPrimed;
        const buffers = self.buffers;
        var coordinate_addresses: [interaction_column_count]usize = undefined;
        for (buffers.interaction_columns, &coordinate_addresses) |column, *address| address.* = column.address;
        const output_pointers = encodePointers(coordinate_addresses.len, &coordinate_addresses);
        try session.context.uploadSlice(u32, buffers.output_pointer_table, &output_pointers);
        var out_tables: [fractions.component_count]usize = undefined;
        var denominator_tables: [fractions.component_count]usize = undefined;
        var claim_tables: [fractions.component_count]usize = undefined;
        var cursor: usize = 0;
        for (0..fractions.component_count) |component| {
            out_tables[component] = buffers.output_pointer_table.address + cursor * pointer_words * @sizeOf(u32);
            denominator_tables[component] = buffers.denominators[component].address;
            claim_tables[component] = (try buffers.claimed_sums.sub(component, 1)).address;
            cursor += 4 * fractions.secure_widths[component];
        }
        if (cursor != interaction_column_count) return error.InvalidCircuitInteractionBuffers;
        const out_table_words = encodePointers(out_tables.len, &out_tables);
        const denominator_words = encodePointers(denominator_tables.len, &denominator_tables);
        const claim_words = encodePointers(claim_tables.len, &claim_tables);
        try session.context.uploadSlice(u32, buffers.output_tables, &out_table_words);
        try session.context.uploadSlice(u32, buffers.denominator_tables, &denominator_words);
        try session.context.uploadSlice(u32, buffers.claimed_sum_tables, &claim_words);
        try session.context.uploadSlice(relation_abi.Geometry, buffers.geometry, &self.plan.geometry);
        self.primed = true;
    }

    pub fn execute(self: *Bound, allocator: std.mem.Allocator, session: anytype) !void {
        if (!self.primed or self.executed) return error.InvalidCircuitInteractionState;
        const buffers = self.buffers;
        try fractions.Native.expandChallenges(session, buffers.drawn_z_alpha, buffers.alpha_powers, buffers.z);
        var base_offset: usize = 0;
        var interaction_offset: usize = 0;
        var output_coordinates: [fractions.component_count][52]common.Words = undefined;
        var instances: [fractions.component_count]completion.InstanceBinding = undefined;
        for (0..fractions.component_count) |component| {
            const rows = self.plan.row_counts[component];
            const base_width = fractions.base_widths[component];
            const interaction_width = 4 * fractions.secure_widths[component];
            var pp: [11]common.Words = undefined;
            for (pp[0..fractions.pp_widths[component]], self.plan.pp_indices[component][0..fractions.pp_widths[component]]) |*out, index|
                out.* = buffers.preprocessed_columns[index];
            const output = buffers.interaction_columns[interaction_offset..][0..interaction_width];
            try fractions.Native.generate(session, .{ .component = @intCast(component), .rows = rows }, .{
                .preprocessed = pp[0..fractions.pp_widths[component]],
                .base_columns = buffers.base_columns[base_offset..][0..base_width],
                .output_columns = output,
                .powers = buffers.alpha_powers,
                .z = buffers.z,
                .denominators = buffers.denominators[component],
                .error_flag = buffers.error_flag,
            });
            @memcpy(output_coordinates[component][0..interaction_width], output);
            instances[component] = .{
                .output_pointer_table = try buffers.output_pointer_table.sub(interaction_offset * pointer_words, interaction_width * pointer_words),
                .output_coordinates = output_coordinates[component][0..interaction_width],
                .denominator_slab = buffers.denominators[component],
                .claimed_sum = try buffers.claimed_sums.sub(component, 1),
            };
            base_offset += base_width;
            interaction_offset += interaction_width;
        }
        const prepared = try completion.prepare(allocator, .{
            .topology = self.plan.topology(),
            .buffers = .{
                .output_tables = buffers.output_tables,
                .denominator_slabs = buffers.denominator_tables,
                .geometry = buffers.geometry,
                .claimed_sums = buffers.claimed_sum_tables,
                .reduction_partials = buffers.reduction_partials,
                .scan_block_sums = buffers.scan_block_sums,
            },
            .instances = &instances,
        });
        defer completion.deinit(allocator, prepared);
        try completion.TraceCommitNative.execute(session, prepared);
        try cuda.runtime.stages.circuit_lookup_sum.Native.check(session, .{
            .claimed_sums = buffers.claimed_sums,
            .output_values = buffers.output_values,
            .alpha_powers = buffers.alpha_powers,
            .z = buffers.z,
            .error_flag = buffers.error_flag,
        });
        self.executed = true;
    }

    pub fn claims(self: Bound) !common.Words {
        if (!self.executed) return error.InvalidCircuitInteractionState;
        return self.buffers.claimed_sums.cast(u32);
    }
};

fn encodePointers(comptime n: usize, addresses: *const [n]usize) [n * pointer_words]u32 {
    var words: [n * pointer_words]u32 = undefined;
    for (addresses, 0..) |address, index| {
        words[index * pointer_words] = @truncate(address);
        words[index * pointer_words + 1] = @truncate(address >> 32);
    }
    return words;
}

fn ceilDiv(value: u32, divisor: u32) u32 {
    return value / divisor + @intFromBool(value % divisor != 0);
}

fn add(a: u32, b: u32) !u32 {
    return std.math.add(u32, a, b) catch error.InvalidCircuitInteractionGeometry;
}

fn mul(a: u32, b: u32) !u32 {
    return std.math.mul(u32, a, b) catch error.InvalidCircuitInteractionGeometry;
}

test "circuit interaction completion plan matches all eleven CPU widths" {
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(@import("stwo_circuit_cpu_integration").air.recorded_sizes);
    const plan = try Plan.init(&layout);
    const base_widths = circuit.witness.trace.traceWidths();
    const interaction_widths = circuit.witness.trace.interactionWidths();
    var total: usize = 0;
    for (fractions.base_widths, base_widths, fractions.secure_widths, interaction_widths) |base_width, base_expected, secure, interaction_expected| {
        try std.testing.expectEqual(base_expected, base_width);
        try std.testing.expectEqual(interaction_expected, 4 * secure);
        total += interaction_expected;
    }
    try std.testing.expectEqual(interaction_column_count, total);
    try plan.topology().validate();
    for (plan.geometry, plan.row_counts) |record, rows| {
        try std.testing.expectEqual(rows, record.rows);
        try std.testing.expectEqual(rows, record.real_rows);
    }
}

test "resident circuit interaction native dispatch compiles" {
    const Dispatch = struct {
        fn run(bound: *Bound, session: *cuda.runtime.NativeSession) !void {
            try bound.execute(std.testing.allocator, session);
        }
    };
    const entry: *const fn (*Bound, *cuda.runtime.NativeSession) anyerror!void = &Dispatch.run;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
