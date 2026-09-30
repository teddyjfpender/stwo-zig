//! Explicit development terminal reads. This path always rejects publication
//! and never emits a benchmark receipt or a verified proof.
const std = @import("std");

pub fn runIfRequested(allocator: std.mem.Allocator, transaction: anytype, diagnostic: anytype, writers: anytype) !void {
    const path = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_SOURCE_DIAGNOSTIC") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidDiagnosticPath;
    var directory = try std.fs.openDirAbsolute(path, .{});
    defer directory.close();
    const session = transaction.proofSession();
    try session.beginStage(.proof_assembly);
    const Record = struct { component: []const u8, instance: u32, rows: u32, layout: []const u8, columns: usize, file: []const u8 };
    var records = std.ArrayList(Record).empty;
    defer records.deinit(allocator);
    defer for (records.items) |record| allocator.free(record.file);
    for (diagnostic.request.relation_plan.instances, writers.relation_sources.sources, 0..) |instance, source, index| {
        if (!std.mem.startsWith(u8, instance.component, "memory_") and
            !std.mem.startsWith(u8, instance.component, "blake_") and
            !std.mem.eql(u8, instance.component, "range_check_11")) continue;
        const columns = if (source.lookup_words != null) instance.lookup_word_columns else source.base_columns.len;
        const words = try std.math.mul(usize, columns, instance.geometry.rows);
        if (words > 32 * 1024 * 1024) return error.DiagnosticExtentTooLarge;
        const values = try allocator.alloc(u32, words);
        defer allocator.free(values);
        if (source.lookup_words) |lookup| {
            try session.context.readProofSlice(u32, values, lookup);
        } else for (source.base_columns, 0..) |column, ordinal| {
            try session.context.readProofSlice(u32, values[ordinal * instance.geometry.rows ..][0..instance.geometry.rows], column);
        }
        // This diagnostic stage is still open; its timing end event has not
        // been recorded yet, so do not collect completed-stage timings here.
        try session.context.sync();
        const name = try std.fmt.allocPrint(allocator, "source-{}.bin", .{index});
        errdefer allocator.free(name);
        const file = try directory.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(values));
        try file.sync();
        try records.append(allocator, .{ .component = instance.component, .instance = instance.component_instance, .rows = instance.geometry.rows, .layout = @tagName(instance.layout), .columns = columns, .file = name });
    }
    if (diagnostic.request.resident.slot(.writer_scratch, 1)) |slot| {
        const source = try transaction.slot(slot.id);
        const debug_values = try allocator.alloc(u32, source.len);
        defer allocator.free(debug_values);
        try session.context.readProofSlice(u32, debug_values, source);
        try session.context.sync();
        const file = try directory.createFile("eval-debug.bin", .{ .exclusive = true });
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(debug_values));
        try file.sync();
        for (diagnostic.composition.components, 0..) |component, index| {
            const meta = try std.json.Stringify.valueAlloc(allocator, .{ .diagnostic_rows = 8, .sample_offsets = [_]i32{ -1, 0, 1 }, .label = component.label, .trace_log_size = component.trace_log_size, .evaluation_log_size = component.evaluation_log_size, .random_coefficient_offset = component.random_coefficient_offset, .trace_spans = component.trace_spans, .preprocessed_indices = component.preprocessed_indices, .denominator_inverses = component.denominator_inverses, .ext_parameter_count = component.ext_sources.len, .part_count = component.parts.len, .total_constraints = diagnostic.composition.total_constraints, .full_proof_verified = false, .accepted_benchmark = false }, .{});
            defer allocator.free(meta);
            const name = try std.fmt.allocPrint(allocator, "eval-component-{}.json", .{index});
            defer allocator.free(name);
            const output = try directory.createFile(name, .{ .exclusive = true });
            defer output.close();
            try output.writeAll(meta);
            for (component.parts, 0..) |part, ordinal| {
                const program = part.program;
                const payload = try std.json.Stringify.valueAlloc(allocator, .{ .rc_base = part.rc_base, .header = program.header, .base_consts = program.base_consts, .ext_consts = program.ext_consts, .base_insts = program.base_insts, .ext_insts = program.ext_insts, .constraint_roots = program.constraint_roots }, .{});
                defer allocator.free(payload);
                const part_name = try std.fmt.allocPrint(allocator, "eval-part-{}-{}.json", .{ index, ordinal });
                defer allocator.free(part_name);
                const part_file = try directory.createFile(part_name, .{ .exclusive = true });
                defer part_file.close();
                try part_file.writeAll(payload);
            }
        }
    }

    // Preserve exact device coefficients only in the explicitly rejected path.
    // The normal proof arena retains its original lifetimes and memory plan.
    for (diagnostic.request.proof_program.commitments, 0..) |tree, ordinal| {
        if (tree.role == .preprocessed) continue;
        const kind: @import("stwo_cairo_cuda").executor.resident_plan.SlotKind = if (tree.role == .composition) .constraint_composition_output else .trace_coefficients;
        const slot = diagnostic.request.resident.slot(kind, @intCast(ordinal)) orelse return error.InvalidDiagnosticCoefficientSlot;
        const coefficients = try transaction.slot(slot.id);
        if (coefficients.len > 128 * 1024 * 1024) return error.DiagnosticExtentTooLarge;
        const coefficient_values = try allocator.alloc(u32, coefficients.len);
        defer allocator.free(coefficient_values);
        try session.context.readProofSlice(u32, coefficient_values, coefficients);
        try session.context.sync();
        const name = try std.fmt.allocPrint(allocator, "coefficients-tree-{}.bin", .{ordinal});
        defer allocator.free(name);
        const file = try directory.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(coefficient_values));
        try file.sync();
    }
    const SlotKind = @import("stwo_cairo_cuda").executor.resident_plan.SlotKind;
    for ([_]SlotKind{ .oods_parameter, .oods_fold_counts, .oods_sample_points, .oods_evaluation_points, .oods_folding_factors, .oods_reduce_a, .oods_reduce_b, .quotient_challenge, .quotient_result_coordinates, .fri_last_coefficients }) |kind| {
        const slot = diagnostic.request.resident.slot(kind, 0) orelse return error.InvalidDiagnosticSlot;
        const source = try transaction.slot(slot.id);
        const data = try allocator.alloc(u32, source.len);
        defer allocator.free(data);
        try session.context.readProofSlice(u32, data, source);
        try session.context.sync();
        const name = try std.fmt.allocPrint(allocator, "{s}.bin", .{@tagName(kind)});
        defer allocator.free(name);
        const file = try directory.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(std.mem.sliceAsBytes(data));
        try file.sync();
    }
    const terminal = diagnostic.request.resident.slot(.terminal_bundle, 0) orelse return error.InvalidTerminalBinding;
    const source = try transaction.slot(terminal.id);
    const values = try allocator.alloc(u32, source.len);
    defer allocator.free(values);
    try session.context.readProofSlice(u32, values, source);
    try session.context.sync();
    const transport = try directory.createFile("terminal.bin", .{ .exclusive = true });
    defer transport.close();
    try transport.writeAll(std.mem.sliceAsBytes(values));
    try transport.sync();
    const metadata = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "stwo-cairo-cuda-source-diagnostic-v1",
        .full_proof_verified = false,
        .accepted_benchmark = false,
        .sources = records.items,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(metadata);
    const report = try directory.createFile("sources.json", .{ .exclusive = true });
    defer report.close();
    try report.writeAll(metadata);
    try report.sync();
    return error.CairoCudaDiagnosticOnly;
}
