//! Opt-in host/GPU diagnostics for resident Cairo interaction traces.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const circle_poly_mod = @import("stwo_prover_impl").poly.circle.poly;
const circle_eval_mod = @import("stwo_prover_impl").poly.circle.evaluation;
const canonic_circle_mod = @import("stwo_core").poly.circle.canonic;
const relation_bundle_mod = @import("stwo_cairo_frontend").witness.relation_bundle;
const interaction_trace_mod = @import("stwo_cairo_frontend").witness.interaction_trace;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const witness_program_mod = @import("stwo_cairo_frontend").witness.program;
const schedule_bindings = @import("../../schedule_bindings.zig");
const resident_binding = @import("../binding.zig");
const Error = @import("../errors.zig").Error;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const collectComponent = schedule_bindings.collectComponent;
const componentName = schedule_bindings.componentName;
const logicalId = schedule_bindings.logicalId;
const one = schedule_bindings.one;
const oneComponent = schedule_bindings.oneComponent;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;
const wordOffset = resident_binding.wordOffset;

pub fn logInteractionWriterCpuSample(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    component: []const u8,
) !void {
    const entry = witness_bundle.find(component) orelse return Error.MissingBinding;
    const input_bindings = try collectComponent(allocator, schedule, plan, "WitnessInput", component);
    defer allocator.free(input_bindings);
    if (input_bindings.len != entry.program.n_inputs or input_bindings.len == 0)
        return Error.InvalidCardinality;

    const lookup_binding = try oneComponent(schedule, plan, "LookupInputs", component);
    const interaction_bindings = try collectComponent(allocator, schedule, plan, "InteractionTrace", component);
    defer allocator.free(interaction_bindings);
    const row_count = input_bindings[0].size_bytes / @sizeOf(u32);
    if (row_count == 0 or row_count > std.math.maxInt(u32) or
        lookup_binding.size_bytes != row_count * entry.program.n_lookup_words * @sizeOf(u32))
        return Error.InvalidBindingSize;
    for (input_bindings) |binding| if (binding.size_bytes != row_count * @sizeOf(u32))
        return Error.InvalidBindingSize;

    const arena_bytes: [*]align(4) const u8 = @ptrCast(@alignCast(resident_arena.buffer.contents));
    const arena_words = std.mem.bytesAsSlice(u32, arena_bytes[0..resident_arena.buffer.byte_length]);
    const table_pointer_binding = try one(schedule, plan, "ExecutionTablePointers");
    const table_stride_binding = try one(schedule, plan, "ExecutionTableStrides");
    const table_pointer_offset = try wordOffset(table_pointer_binding);
    const table_stride_offset = try wordOffset(table_stride_binding);
    if (table_pointer_binding.size_bytes < 37 * @sizeOf(u32) or
        table_stride_binding.size_bytes < 3 * @sizeOf(u32))
        return Error.InvalidBindingSize;
    const table_pointers = arena_words[table_pointer_offset..][0..37];
    const table_strides = arena_words[table_stride_offset..][0..3];

    const TableReader = struct {
        arena: []const u32,
        pointers: []const u32,
        strides: []const u32,

        pub fn tableLimb(self: @This(), table: u32, row: u32, limb: u32) u32 {
            if (table == 0) {
                if (row >= self.strides[0]) return 0;
                return self.arena[self.pointers[0] + row];
            }
            if (table != 1) return 0;
            const tag = row >> 30;
            const value = row & 0x3fff_ffff;
            if (tag == 1) {
                if (limb >= 28 or value >= self.strides[1]) return 0;
                return self.arena[self.pointers[1 + limb] + value];
            }
            if (limb >= 8 or value >= self.strides[2]) return 0;
            return self.arena[self.pointers[29 + limb] + value];
        }
    };
    const table_reader = TableReader{
        .arena = arena_words,
        .pointers = table_pointers,
        .strides = table_strides,
    };
    const lookup_offset = try wordOffset(lookup_binding);
    for (interaction_bindings, 0..) |binding, trace_ordinal| {
        const lookup_end = lookup_binding.offset_bytes + lookup_binding.size_bytes;
        const interaction_end = binding.offset_bytes + binding.size_bytes;
        if (lookup_binding.offset_bytes < interaction_end and binding.offset_bytes < lookup_end) {
            std.debug.print(
                "interaction_writer_alias component={s} lookup=[{}, {}) trace_ordinal={} trace=[{}, {})\n",
                .{ component, lookup_binding.offset_bytes / 4, lookup_end / 4, trace_ordinal, binding.offset_bytes / 4, interaction_end / 4 },
            );
        }
    }
    const input_offsets = try allocator.alloc(u32, input_bindings.len);
    defer allocator.free(input_offsets);
    for (input_bindings, input_offsets) |binding, *offset| offset.* = try wordOffset(binding);
    const row_count_usize: usize = @intCast(row_count);
    const sample_rows = [_]usize{ 0, @min(1, row_count_usize - 1), row_count_usize / 2, row_count_usize - 1 };
    const inputs = try allocator.alloc(u32, input_bindings.len);
    defer allocator.free(inputs);
    for (sample_rows) |row| {
        for (input_offsets, inputs) |offset, *value| value.* = arena_words[offset + row];
        var expected = try witness_program_mod.interpretCore(allocator, entry.program, inputs, table_reader);
        defer expected.deinit(allocator);
        var mismatch_count: usize = 0;
        var first_word: usize = 0;
        var first_expected: u32 = 0;
        var first_actual: u32 = 0;
        for (expected.lookup_words, 0..) |expected_word, word| {
            const actual_word = arena_words[lookup_offset + word * row_count_usize + row];
            if (actual_word == expected_word) continue;
            if (mismatch_count == 0) {
                first_word = word;
                first_expected = expected_word;
                first_actual = actual_word;
            }
            mismatch_count += 1;
        }
        std.debug.print(
            "interaction_writer_diff component={s} row={} mismatches={} first_word={} cpu={} metal={}\n",
            .{ component, row, mismatch_count, first_word, first_expected, first_actual },
        );
    }
    try logLookupRelationCpuClaim(
        allocator,
        resident_arena,
        schedule,
        plan,
        component,
        lookup_binding,
        @intCast(row_count),
        null,
    );
}

pub fn logLookupRelationCpuClaim(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
    source: arena_plan.Binding,
    rows: u32,
    output_bindings: ?[]const arena_plan.Binding,
) !void {
    var bundle = try relation_bundle_mod.Bundle.readFile(allocator, "vectors/cairo/cairo_relation_templates.bin");
    defer bundle.deinit();
    const relation_component = bundle.find(component) orelse return Error.MissingBinding;
    if (relation_component.traces.len != 1 or relation_component.traces[0].layout != .lookup_words)
        return Error.InvalidCardinality;
    const trace = relation_component.traces[0];
    const column_count = trace.descriptors.len / 16;
    const cumulative_sums = try allocator.alloc(QM31, column_count);
    defer allocator.free(cumulative_sums);
    const last_column_values = if (output_bindings != null)
        try allocator.alloc(QM31, rows)
    else
        null;
    defer if (last_column_values) |values| allocator.free(values);
    if (output_bindings) |outputs| {
        if (outputs.len != column_count * 4) return Error.InvalidCardinality;
        for (outputs) |binding| if (binding.size_bytes != @as(u64, rows) * 4)
            return Error.InvalidBindingSize;
    }

    const arena_bytes: [*]align(4) const u8 = @ptrCast(@alignCast(resident_arena.buffer.contents));
    const arena_words = std.mem.bytesAsSlice(u32, arena_bytes[0..resident_arena.buffer.byte_length]);
    const source_offset = try wordOffset(source);
    const alpha_binding = try one(schedule, plan, "RelationAlphaPowers");
    const z_binding = try one(schedule, plan, "RelationZ");
    const alpha_offset = try wordOffset(alpha_binding);
    const z_offset = try wordOffset(z_binding);
    if (alpha_binding.size_bytes % 16 != 0 or z_binding.size_bytes < 16 or source.size_bytes % 4 != 0)
        return Error.InvalidBindingSize;
    const alpha_count: usize = @intCast(alpha_binding.size_bytes / 16);
    const alpha_powers = try allocator.alloc(QM31, alpha_count);
    defer allocator.free(alpha_powers);
    for (alpha_powers, 0..) |*alpha, index| {
        const offset = alpha_offset + index * 4;
        alpha.* = QM31.fromU32Unchecked(
            arena_words[offset],
            arena_words[offset + 1],
            arena_words[offset + 2],
            arena_words[offset + 3],
        );
    }
    const z = QM31.fromU32Unchecked(
        arena_words[z_offset],
        arena_words[z_offset + 1],
        arena_words[z_offset + 2],
        arena_words[z_offset + 3],
    );
    const source_word_count: usize = @intCast(source.size_bytes / 4);
    const source_columns = try interaction_trace_mod.LookupColumns.init(
        arena_words[source_offset..][0..source_word_count],
        rows,
    );
    var reference = try interaction_trace_mod.Reference.init(
        allocator,
        trace.descriptors,
        try interaction_trace_mod.SourceView.lookupWords(source_columns, rows),
        z,
        alpha_powers,
    );
    defer reference.deinit();
    var total = QM31.zero();
    var raw_mismatch_count: usize = 0;
    var first_raw_mismatch: [4]usize = .{ 0, 0, 0, 0 };
    var first_raw_expected: u32 = 0;
    var first_raw_actual: u32 = 0;
    var timer = try std.time.Timer.start();
    for (0..rows) |row_usize| {
        const row: u32 = @intCast(row_usize);
        const row_total = try reference.evaluateRow(row, cumulative_sums);
        for (cumulative_sums, 0..) |sum, relation_column| {
            if (output_bindings) |outputs| if (relation_column + 1 < column_count) {
                const coordinates = sum.toM31Array();
                for (0..4) |coordinate| {
                    const output_offset = try wordOffset(outputs[relation_column * 4 + coordinate]);
                    const actual = arena_words[output_offset + row];
                    if (actual == coordinates[coordinate].v) continue;
                    if (raw_mismatch_count == 0) {
                        first_raw_mismatch = .{ row, relation_column, coordinate, 0 };
                        first_raw_expected = coordinates[coordinate].v;
                        first_raw_actual = actual;
                    }
                    raw_mismatch_count += 1;
                }
            };
        }
        if (last_column_values) |values| values[row] = row_total;
        total = total.add(row_total);
    }
    const coordinates = total.toM31Array();
    std.debug.print(
        "interaction_relation_cpu component={s} rows={} elapsed_ms={d:.3} value={},{},{},{}\n",
        .{ component, rows, @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms, coordinates[0].v, coordinates[1].v, coordinates[2].v, coordinates[3].v },
    );
    if (output_bindings) |outputs| {
        _ = try interaction_trace_mod.scanLastColumnInPlace(last_column_values.?, total);
        var scan_mismatch_count: usize = 0;
        var first_scan_mismatch: [4]usize = .{ 0, 0, 0, 0 };
        var first_scan_expected: u32 = 0;
        var first_scan_actual: u32 = 0;
        for (0..rows) |scan_index| {
            const row = try interaction_trace_mod.circleScanRow(rows, scan_index);
            const expected = last_column_values.?[row].toM31Array();
            for (0..4) |coordinate| {
                const output_offset = try wordOffset(outputs[(column_count - 1) * 4 + coordinate]);
                const actual = arena_words[output_offset + row];
                if (actual == expected[coordinate].v) continue;
                if (scan_mismatch_count == 0) {
                    first_scan_mismatch = .{ scan_index, row, coordinate, 0 };
                    first_scan_expected = expected[coordinate].v;
                    first_scan_actual = actual;
                }
                scan_mismatch_count += 1;
            }
        }
        std.debug.print(
            "interaction_relation_trace_diff component={s} raw_mismatches={} raw_first_row={} raw_first_column={} raw_first_coordinate={} raw_cpu={} raw_metal={} scan_mismatches={} scan_first_index={} scan_first_row={} scan_first_coordinate={} scan_cpu={} scan_metal={}\n",
            .{
                component,
                raw_mismatch_count,
                first_raw_mismatch[0],
                first_raw_mismatch[1],
                first_raw_mismatch[2],
                first_raw_expected,
                first_raw_actual,
                scan_mismatch_count,
                first_scan_mismatch[0],
                first_scan_mismatch[1],
                first_scan_mismatch[2],
                first_scan_expected,
                first_scan_actual,
            },
        );
    }
}

pub fn logComponentInteractionDigests(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
) !void {
    _ = allocator;
    var local_index: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), "InteractionTrace") or
            !std.mem.eql(u8, try componentName(entry), component)) continue;
        const output = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
        const bytes = try resident_arena.bytes(output);
        if (bytes.len < 4 or bytes.len % 4 != 0 or !std.math.isPowerOfTwo(bytes.len / 4))
            return Error.InvalidBindingSize;
        var digest: u64 = 0xcbf29ce484222325;
        for (bytes) |byte| {
            digest ^= byte;
            digest *%= 0x100000001b3;
        }
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        std.debug.print(
            "interaction_eval_digest component={s} local_index={} logical_id={} log_size={} first={} last={} fnv64={x:0>16}\n",
            .{ component, local_index, output.logical_id, std.math.log2_int(usize, words.len), words[0], words[words.len - 1], digest },
        );
        local_index += 1;
    }
    if (local_index == 0) return Error.MissingBinding;
}

pub fn logInteractionCoefficientDigests(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    stage: []const u8,
) !void {
    var count: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), "InteractionCoefficients")) continue;
        const binding = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
        const bytes = try resident_arena.bytes(binding);
        if (bytes.len < 4 or bytes.len % 4 != 0 or !std.math.isPowerOfTwo(bytes.len / 4))
            return Error.InvalidBindingSize;
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        var raw_digest: u64 = 0xcbf29ce484222325;
        var canonical_digest: u64 = 0xcbf29ce484222325;
        for (words) |word| {
            for (0..4) |byte_index| {
                raw_digest ^= @as(u8, @truncate(word >> @intCast(byte_index * 8)));
                raw_digest *%= 0x100000001b3;
            }
            const canonical = word % 0x7fffffff;
            for (0..4) |byte_index| {
                canonical_digest ^= @as(u8, @truncate(canonical >> @intCast(byte_index * 8)));
                canonical_digest *%= 0x100000001b3;
            }
        }
        std.debug.print(
            "interaction_coeff_digest stage={s} component={s} ordinal={} logical_id={} log_size={} first={} last={} canonical_first={} canonical_last={} raw_fnv64={x:0>16} fnv64={x:0>16}\n",
            .{
                stage,
                try componentName(entry),
                try ordinal(entry),
                binding.logical_id,
                std.math.log2_int(usize, words.len),
                words[0],
                words[words.len - 1],
                words[0] % 0x7fffffff,
                words[words.len - 1] % 0x7fffffff,
                raw_digest,
                canonical_digest,
            },
        );
        count += 1;
    }
    if (count == 0) return Error.MissingBinding;
}

pub fn logLogicalBindingDigest(
    resident_arena: *arena_plan.ResidentArena,
    plan: arena_plan.Plan,
    logical_id: u32,
    stage: []const u8,
) !void {
    const binding = plan.binding(logical_id) catch return Error.MissingBinding;
    const bytes = try resident_arena.bytes(binding);
    if (bytes.len < 4 or bytes.len % 4 != 0) return Error.InvalidBindingSize;
    var digest: u64 = 0xcbf29ce484222325;
    for (bytes) |byte| {
        digest ^= byte;
        digest *%= 0x100000001b3;
    }
    const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
    std.debug.print(
        "logical_binding_digest stage={s} logical_id={} words={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
        .{ stage, logical_id, words.len, words[0], words[words.len - 1], digest },
    );
}

pub fn logCpuColumnLdeDigest(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    plan: arena_plan.Plan,
    logical_id: u32,
    log_size: u32,
) !void {
    const binding = plan.binding(logical_id) catch return Error.MissingBinding;
    const bytes = try resident_arena.bytes(binding);
    if (bytes.len != (@as(usize, 1) << @intCast(log_size)) * 4) return Error.InvalidBindingSize;
    const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
    const values = try allocator.alloc(M31, words.len);
    defer allocator.free(values);
    for (words, values) |word, *value| value.* = M31.fromCanonical(word % 0x7fffffff);

    const domain = canonic_circle_mod.CanonicCoset.new(log_size).circleDomain();
    const evaluation = try circle_eval_mod.CircleEvaluation.init(domain, values);
    var coefficients = try circle_poly_mod.interpolateFromEvaluation(allocator, evaluation);
    defer coefficients.deinit(allocator);
    {
        const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-cpu-coeff.u32le", .{});
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(coefficients.coefficients()));
    }
    const lde_domain = canonic_circle_mod.CanonicCoset.new(log_size + 1).circleDomain();
    const lde = try coefficients.evaluate(allocator, lde_domain);
    defer allocator.free(@constCast(lde.values));
    {
        const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-cpu-lde.u32le", .{});
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(lde.values));
    }
    var digest: u64 = 0xcbf29ce484222325;
    for (lde.values) |value| {
        for (0..4) |byte_index| {
            digest ^= @as(u8, @truncate(value.v >> @intCast(byte_index * 8)));
            digest *%= 0x100000001b3;
        }
    }
    std.debug.print(
        "cpu_column_lde_digest source_id={} log_size={} lde_log_size={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
        .{ logical_id, log_size, log_size + 1, lde.values[0].v, lde.values[lde.values.len - 1].v, digest },
    );
}
