//! Inspect the exact CUDA trace-column geometry without opening a GPU runtime.
const std = @import("std");
const stwo = @import("stwo");

const source = stwo.integrations.cairo_cuda.canonical_source;
const trace_commit = stwo.integrations.cairo_cuda.executor.trace_commit;
const controller_bundle = stwo.integrations.cairo_cuda.executor.ingress.controller_bundle;
const CompileOptions = stwo.backends.cuda.runtime.execution_plan.CompileOptions;
const Stage = stwo.backends.cuda.runtime.telemetry.Stage;
const Variant = stwo.frontends.cairo.preprocessed.trace.Variant;
const Lane = stwo.frontends.cairo.proving.leaf_lane.Lane;
const wire = @import("stwo_circuit_recursion_wire");
const report = @import("trace_geometry_report.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var breakdown = false;
    var jsonl = false;
    var registry_path: ?[]const u8 = null;
    var artifact_dir: ?[]const u8 = null;
    var inputs: std.ArrayList([]const u8) = .empty;
    defer inputs.deinit(allocator);
    var cursor: usize = 1;
    while (cursor < args.len) : (cursor += 1) {
        const arg = args[cursor];
        if (std.mem.eql(u8, arg, "--memory-breakdown")) {
            breakdown = true;
        } else if (std.mem.eql(u8, arg, "--jsonl")) {
            jsonl = true;
        } else if (std.mem.eql(u8, arg, "--circuit-registry")) {
            cursor += 1;
            if (cursor >= args.len or registry_path != null) return error.InvalidArgument;
            registry_path = args[cursor];
        } else if (std.mem.eql(u8, arg, "--artifact-dir")) {
            cursor += 1;
            if (cursor >= args.len or artifact_dir != null) return error.InvalidArgument;
            artifact_dir = args[cursor];
        } else if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print("usage: cairo-trace-geometry [--circuit-registry registry.json] [--artifact-dir vectors/cairo] [--jsonl | --memory-breakdown] <adapted-input.cpi>...\n", .{});
            return;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.InvalidArgument;
        } else {
            try inputs.append(allocator, arg);
        }
    }
    if (inputs.items.len == 0 or (jsonl and breakdown)) return error.InvalidArgument;
    var leaf_lane: ?Lane = null;
    var registry_sha: ?[32]u8 = null;
    if (registry_path) |path| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
        defer allocator.free(bytes);
        var registry = try wire.registry.parseRegistry(allocator, bytes);
        defer registry.deinit();
        leaf_lane = try Lane.fromParameters(registry.registry.cairo_prover_params);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        registry_sha = digest;
    }
    const forced_variant = std.posix.getenv("STWO_CAIRO_CUDA_PREPROCESSED_VARIANT");
    const variant = if (forced_variant) |name|
        std.meta.stringToEnum(Variant, name) orelse return error.InvalidPreprocessedVariant
    else
        Variant.canonical_small;
    if (leaf_lane) |lane| {
        if (forced_variant != null and variant != @as(Variant, @enumFromInt(@intFromEnum(lane.variant))))
            return error.RegistryVariantMismatch;
    }
    const asset_root = artifact_dir orelse if (std.posix.getenv("STWO_CAIRO_CUDA_ARTIFACT_DIR")) |value|
        value
    else
        "vectors/cairo";
    const library = try std.fs.path.join(allocator, &.{ asset_root, "official/air_template_library_v1.json" });
    defer allocator.free(library);
    const witnesses = try std.fs.path.join(allocator, &.{ asset_root, "official/witness_programs_v1.bin" });
    defer allocator.free(witnesses);
    const topology = try std.fs.path.join(allocator, &.{ asset_root, "official/witness_feed_topology_v1.json" });
    defer allocator.free(topology);
    const fixed = try std.fs.path.join(allocator, &.{ asset_root, "cairo_fixed_tables.bin" });
    defer allocator.free(fixed);
    const relations = try std.fs.path.join(allocator, &.{ asset_root, "cairo_relation_templates.bin" });
    defer allocator.free(relations);
    const paths = source.Paths{
        .input = inputs.items[0],
        .leaf_lane = leaf_lane,
        .variant = variant,
        .automatic_variant = forced_variant == null and leaf_lane == null,
        .library = library,
        .witnesses = witnesses,
        .topology = topology,
        .fixed = fixed,
        .relations = relations,
    };
    var assets = try source.Assets.load(allocator, paths);
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
    for (inputs.items) |path| {
        var candidate_paths = paths;
        candidate_paths.input = path;
        var prepared = try source.prepareWithAssets(allocator, candidate_paths, target, &assets);
        defer prepared.deinit();
        var controllers = try controller_bundle.Prepared.init(
            allocator,
            &prepared.request,
            prepared.protocol,
            prepared.composition,
            prepared.preprocessed_logs,
        );
        defer controllers.deinit();
        const summary = prepared.request.resident.summary;
        if (jsonl) {
            try report.writeJsonReport(allocator, path, &assets, &prepared, &controllers, registry_sha);
            continue;
        }
        std.debug.print("resident pie={s} logical_bytes={} peak_live_bytes={} allocated_bytes={} request_arena_bytes={} coefficient_cells={} evaluation_cells={}\n", .{
            std.fs.path.stem(path),                              summary.logicalBytes(),           summary.peak_live_words * 4,
            controllers.resident.combined_arena.total_words * 4, summary.allocatedResidentBytes(), summary.coefficient_cells,
            summary.evaluation_cells,
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
                const placement = try controllers.resident.combined_arena.placement(slot.id);
                std.debug.print("slot pie={s} kind={s} ordinal={} bytes={} offset_bytes={} from={s}/{} through={s}/{} storage={s}\n", .{
                    pie,                      @tagName(slot.kind),  slot.ordinal,                slot.words * 4,
                    placement.offset_words * 4, @tagName(slot.live_from), slot.live_from_phase, @tagName(slot.live_through), slot.live_through_phase,
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
            for (prepared.request.proof.components, prepared.composition.components) |planned, component| {
                const witness = prepared.witnesses.find(planned.name) orelse continue;
                const rows: u64 = @as(u64, 1) << @intCast(component.trace_log_size);
                const scratch_bytes = rows * witness.program.n_sub_words * 4;
                if (scratch_bytes == 0) continue;
                std.debug.print("subscratch pie={s} component={s} instance={} rows={} words_per_row={} bytes={} producer_edges={}\n", .{
                    pie, planned.name, planned.instance, rows, witness.program.n_sub_words, scratch_bytes, planned.producer_edges.len,
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
            var component_cursor: usize = 0;
            while (component_cursor < columns.len) {
                const component = columns[component_cursor].component;
                const log_rows = columns[component_cursor].log_rows;
                var end = component_cursor + 1;
                while (end < columns.len and columns[end].component == component and columns[end].log_rows == log_rows) : (end += 1) {}
                const count = end - component_cursor;
                const component_words = try std.math.mul(u64, @intCast(count), @as(u64, 1) << @intCast(log_rows));
                const label = if (component < prepared.composition.components.len)
                    prepared.composition.components[component].label
                else
                    @tagName(tree.role);
                std.debug.print("component pie={s} role={s} index={} label={s} columns={} log_rows={} words={}\n", .{
                    std.fs.path.stem(path), @tagName(tree.role), component, label, count, log_rows, component_words,
                });
                component_cursor = end;
            }
        }
    }
}
