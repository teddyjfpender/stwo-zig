//! Inspect the exact CUDA trace-column geometry without opening a GPU runtime.
const std = @import("std");
const stwo = @import("stwo");

const source = stwo.integrations.cairo_cuda.canonical_source;
const trace_commit = stwo.integrations.cairo_cuda.executor.trace_commit;
const CompileOptions = stwo.backends.cuda.runtime.execution_plan.CompileOptions;
const Stage = stwo.backends.cuda.runtime.telemetry.Stage;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const breakdown = args.len > 1 and std.mem.eql(u8, args[1], "--memory-breakdown");
    const first_path: usize = if (breakdown) 2 else 1;
    if (args.len <= first_path) {
        std.debug.print("usage: cairo-trace-geometry [--memory-breakdown] <adapted-input.cpi>...\n", .{});
        return error.InvalidArgument;
    }
    var assets = try source.Assets.load(allocator, .{ .input = args[first_path] });
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
    for (args[first_path..]) |path| {
        var prepared = try source.prepareWithAssets(allocator, .{ .input = path }, target, &assets);
        defer prepared.deinit();
        const summary = prepared.request.resident.summary;
        std.debug.print("resident pie={s} logical_bytes={} peak_live_bytes={} allocated_bytes={} coefficient_cells={} evaluation_cells={}\n", .{
            std.fs.path.stem(path),           summary.logicalBytes(),    summary.peak_live_words * 4,
            summary.allocatedResidentBytes(), summary.coefficient_cells, summary.evaluation_cells,
        });
        if (breakdown) {
            const pie = std.fs.path.stem(path);
            for (std.enums.values(Stage)) |stage| {
                for (0..2) |phase| {
                    const point = stage.index() * 2 + phase;
                    var live_words: u64 = 0;
                    for (prepared.request.resident.slots) |slot| {
                        if (slot.live_from.index() * 2 + slot.live_from_phase <= point and
                            slot.live_through.index() * 2 + slot.live_through_phase >= point)
                            live_words += slot.words;
                    }
                    std.debug.print("stage pie={s} stage={s} phase={} live_bytes={}\n", .{ pie, @tagName(stage), phase, live_words * 4 });
                }
            }
            for (prepared.request.resident.slots) |slot| {
                std.debug.print("slot pie={s} kind={s} ordinal={} bytes={} from={s}/{} through={s}/{} storage={s}\n", .{
                    pie,                      @tagName(slot.kind),  slot.ordinal,                slot.words * 4,
                    @tagName(slot.live_from), slot.live_from_phase, @tagName(slot.live_through), slot.live_through_phase,
                    @tagName(slot.storage),
                });
            }
            for (prepared.request.proof.components, prepared.composition.components) |planned, component| {
                const witness = prepared.witnesses.find(planned.name) orelse continue;
                const rows: u64 = @as(u64, 1) << @intCast(component.trace_log_size);
                const lookup_bytes = rows * witness.program.n_lookup_words * 4;
                if (lookup_bytes == 0) continue;
                std.debug.print("lookup pie={s} component={s} instance={} rows={} words_per_row={} bytes={}\n", .{
                    pie, planned.name, planned.instance, rows, witness.program.n_lookup_words, lookup_bytes,
                });
            }
        }
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
            var commitment = if (tree.role == .main)
                try trace_commit.Prepared.initMain(
                    allocator,
                    program,
                    prepared.request.resident,
                    prepared.request.trace_dispatch,
                )
            else
                try trace_commit.Prepared.initProduced(
                    allocator,
                    program,
                    prepared.request.resident,
                    tree.role,
                );
            defer commitment.deinit();
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
