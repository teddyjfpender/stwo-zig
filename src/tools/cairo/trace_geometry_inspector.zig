//! Inspect the exact CUDA trace-column geometry without opening a GPU runtime.
const std = @import("std");
const stwo = @import("stwo");

const source = stwo.integrations.cairo_cuda.canonical_source;
const CompileOptions = stwo.backends.cuda.runtime.execution_plan.CompileOptions;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) {
        std.debug.print("usage: cairo-trace-geometry <adapted-input.cpi>...\n", .{});
        return error.InvalidArgument;
    }
    var assets = try source.Assets.load(allocator, .{ .input = args[1] });
    defer assets.deinit();
    const target: CompileOptions = .{
        .sm = 90,
        .device_uuid = [_]u8{1} ** 16,
        .driver_version = 580,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .runtime_build_identity = [_]u8{1} ** 32,
        .host_toolchain_identity = [_]u8{1} ** 32,
        .kernel_pack_identity = [_]u8{1} ** 32,
        .lane_streams = 0,
        .enable_graphs = true,
    };
    for (args[1..]) |path| {
        var prepared = try source.prepareWithAssets(allocator, .{ .input = path }, target, &assets);
        defer prepared.deinit();
        for (prepared.claim.components, prepared.geometry.extents) |component, extent| {
            if (!std.mem.eql(u8, component.name, "pedersen_builtin") and
                !std.mem.eql(u8, component.name, "pedersen_aggregator_window_bits_18") and
                !std.mem.eql(u8, component.name, "partial_ec_mul_window_bits_18")) continue;
            std.debug.print("extent pie={s} label={s} active_rows={} padded_rows={} distinct_rows={?}\n", .{
                std.fs.path.stem(path), component.name, extent.active_rows, extent.padded_rows, extent.distinct_rows,
            });
        }
        const program = prepared.request.proof_program;
        for (program.commitments) |tree| {
            const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
            var words: u64 = 0;
            var max_log: u32 = 0;
            for (columns) |column| {
                if (column.log_rows >= 63) return error.InvalidTraceLog;
                words = try std.math.add(u64, words, @as(u64, 1) << @intCast(column.log_rows));
                max_log = @max(max_log, column.log_rows);
            }
            std.debug.print("tree pie={s} role={s} columns={} words={} max_log={} evaluation_log={} excess_u32={}\n", .{
                std.fs.path.stem(path),   @tagName(tree.role),                                                             columns.len, words, max_log,
                tree.evaluation_log_rows, if (words > std.math.maxInt(u32)) words - std.math.maxInt(u32) else @as(u64, 0),
            });
            var cursor: usize = 0;
            while (cursor < columns.len) {
                const component = columns[cursor].component;
                const log_rows = columns[cursor].log_rows;
                var end = cursor + 1;
                while (end < columns.len and columns[end].component == component and columns[end].log_rows == log_rows) : (end += 1) {}
                const count = end - cursor;
                const component_words = try std.math.mul(u64, @intCast(count), @as(u64, 1) << @intCast(log_rows));
                const label = if (component < prepared.composition.components.len)
                    prepared.composition.components[component].label
                else
                    @tagName(tree.role);
                std.debug.print("component pie={s} role={s} index={} label={s} columns={} log_rows={} words={}\n", .{
                    std.fs.path.stem(path), @tagName(tree.role), component, label, count, log_rows, component_words,
                });
                cursor = end;
            }
        }
    }
}
