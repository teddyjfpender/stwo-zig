//! Canonical CPU block-v5 production and fresh complete detached reception.
//! Usage: ELF INPUT ORACLE MAX_SEGMENT_CYCLES JOB_ID_HEX OUTPUT_DIR [--recursive-completion].
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Stack = @import("prover/block_v5_cpu_canonical_stack_v1.zig");
const Driver = Stack.Driver;
const Runner = @import("prover/block_v4_cpu_runner_source.zig");
const Parent = @import("recursion/blake3_execution_parent_protocol.zig");
const Schedule = @import("runner/balanced_schedule.zig").Schedule;
const GiB: usize = 1024 * 1024 * 1024;

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 7 and args.len != 8) return error.ExpectedElfInputOracleCyclesJobIdOutputDirectory;
    const recursive_completion = args.len == 8;
    if (recursive_completion and !std.mem.eql(u8, args[7], "--recursive-completion")) return error.InvalidCpuRecursiveCompletionOption;
    const maximum = try std.fmt.parseInt(u32, args[4], 10);
    if (maximum == 0 or maximum > 1 << 22) return error.InvalidV5CpuSegmentBudget;
    const job_id = try @import("prover/block_v4_cpu_trusted_manifest_v1.zig").parseSha256Hex(args[5]);
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 40 * GiB);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try read(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try read(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try read(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    const profile = Parent.Profile.csp_q70_pow26;
    const config = profile.config();
    var timer = try std.time.Timer.start();
    std.debug.print("BLOCK_V5_PREFLIGHT started=true segment_cycle_budget={d}\n", .{maximum});
    var planned = try @import("prover/block_v4_cpu_host_preflight_v1.zig").run(a, elf, input, oracle, maximum);
    const schedule = try Schedule.initExactWithTerminalSuffix(planned.last.cycle, maximum, planned.required_terminal_cycles);
    planned.schedule = schedule;
    const job = try @import("recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = Runner.Pins{ .execution_recipe = @import("prover/block_v5_execution_recipe_v1.zig").canonical, .elf_sha256 = Runner.sha256(elf), .input_sha256 = Runner.sha256(input), .oracle_sha256 = Runner.sha256(oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try Runner.Source.initFromPlan(a, elf, input, oracle, maximum, config, pins, planned);
    defer source.deinit();
    const preflight_ns = timer.lap();
    std.debug.print("BLOCK_V5_PREFLIGHT complete=true guest_cycles={d} segments={d} preflight_ms={d}\n", .{ planned.last.cycle, schedule.segments, preflight_ns / std.time.ns_per_ms });
    // Create-only directory prevents mixing files from different public jobs.
    try std.fs.cwd().makeDir(args[6]);
    var dir = try std.fs.cwd().openDir(args[6], .{});
    defer dir.close();
    var options = if (recursive_completion) try Stack.ProductOptions.optionsWithRecursiveCompletion(profile, 1024, 4) else Stack.ProductOptions.options(profile, 1024, 4);
    // The nested cache still allocates through the aggregate 40 GiB budget.
    // Larger opcode rosters need more recursive capacity than tiny fixtures.
    options.cache.aggregate_host_byte_limit = 16 * GiB;
    options.cache.worker_options.host_byte_limit = 16 * GiB;
    const result = try Driver.run(a, dir, &source, .{ .runner_pins = pins, .job_id = job_id, .expected_final_rw_root = planned.last.machine.rw_memory.bytes }, options);
    const pipeline_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{
        .format_version = Stack.REPORT_VERSION,
        .architecture = Stack.ARCHITECTURE,
        .recursive_completion_selected = recursive_completion,
        .recursive_completion = result.recursive_completion,
        .recursive_completion_scope = "requester/PAGE/RAM/public/final stage times include setup, proving, staging and fresh verification; original complete detached bundle verification remains mandatory",
        .recursive_completion_isolated_stark_timing = false,
        .recursive_completion_block_authority = false,
        .native_capacity_protocol_version = Stack.NativeProtocol.VERSION,
        .native_projection_protocol_version = Stack.FusedProtocol.VERSION,
        .optimization_mode = @tagName(@import("builtin").mode),
        .caller_protocol_version = @import("prover/block_v5_precompile_protocol_v1.zig").VERSION,
        .word_memory_protocol_version = @import("prover/block_v5_word_memory_protocol_v1.zig").VERSION,
        .register_custody_mode = options.collection.ordinary.memory.register_custody_mode,
        .native_main_cell_limit = options.collection.physical.native.max_main_cells,
        .fixed_basis_retained_byte_limit = options.collection.fixed_basis.?.max_retained_bytes,
        .fixed_basis_limit_scope = "one bounded immutable capacity basis; oversized geometry uses cold commitment; aggregate allocator remains authoritative",
        .caller_circuit_profile = @tagName(@import("prover/block_v5_precompile_protocol_v1.zig").circuit_profile),
        .complete_block_verified = true,
        .profile = @tagName(profile),
        .queries = config.fri_config.n_queries,
        .pow_bits = config.pow_bits,
        .guest_cycles = planned.last.cycle,
        .segments = schedule.segments,
        .segment_cycle_budget = maximum,
        .recursive_cache_limit_bytes = options.cache.aggregate_host_byte_limit,
        .memory_events = result.verified.memory_events,
        .memory_events_scope = "sorted writable-memory custody; register chains proved within execution windows",
        .sorter = result.sorter,
        .witness_file_bytes = result.witness_file_bytes,
        .execution_witness_passes = @as(u32, 1),
        .witness_proving_source = "staged canonical columns with independent physical-root recommit",
        .lookup_groups = result.verified.lookup_groups,
        .preflight_ns = preflight_ns,
        .pipeline_ns = pipeline_ns,
        .collection_ns = result.collection_ns,
        .proving_ns = result.proving_ns,
        .forest_ns = result.forest_ns,
        .forest_ns_scope = "remaining forest wait and manifest staging after overlapped base proving",
        .verification_ns = result.verification_ns,
        .proof_generation_ns = result.collection_ns + result.proving_ns + result.forest_ns,
        .peak_rss_bytes = try @import("prover/block_v4_cpu_cli_rss_v1.zig").peakBytes(),
        .peak_rss_scope = "entire standalone prover process including preflight; compilation excluded",
        .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
        .recursive_stage_peak_bytes = result.recursive_stage_peak_bytes,
        .driver_aggregate_heap_peak_bytes = result.aggregate_heap_peak_bytes,
        .parallel_family_peak = result.parallel_family_peak,
        .family_reservation_peak_bytes = result.family_reservation_peak_bytes,
        .independent_family_wall_ns = result.family_proving_ns,
        .independent_family_wall_ns_scope = "overlapping family jobs including witness recommit; do not sum as end-to-end proving time",
        .recursive_leaf_queue_capacity = options.recursive_leaf_queue.capacity,
        .recursive_leaf_queue = result.recursive_leaf_queue,
        .recursive_leaf_queue_scope = "queue-owned verified captures only; foreground capture allocations excluded; no retained native proof, replay or PCS",
        .supplemental_recursive_workers_selected = options.recursive_families != null,
        .supplemental_recursive_workers = result.supplemental_recursive_workers,
        .supplemental_recursive_workers_scope = "joined original setup-cache hit/miss and request-lane counters by family; allocator peaks are scoped, exclude RSS and must not be summed as concurrent memory",
        .proof_files = result.proof_files,
        .proof_file_bytes = result.proof_file_bytes,
        .proof_file_scope = "base STARK and selected PAGE/completion proof artifacts; original native forest artifacts separately inventoried by measurement harness",
        .elf_sha256 = std.fmt.bytesToHex(pins.elf_sha256, .lower),
        .input_sha256 = std.fmt.bytesToHex(pins.input_sha256, .lower),
        .oracle_sha256 = std.fmt.bytesToHex(pins.oracle_sha256, .lower),
        .job_id = std.fmt.bytesToHex(job_id, .lower),
        .source_image_digest = std.fmt.bytesToHex(result.verified.span.source_image_digest, .lower),
        .program_root = std.fmt.bytesToHex(pins.program_root.bytes, .lower),
        .initial_rw_root = std.fmt.bytesToHex(pins.initial_rw_root.bytes, .lower),
        .final_rw_root = std.fmt.bytesToHex(result.verified.final_rw_root, .lower),
        .receiver_policy_sha256 = std.fmt.bytesToHex(result.receiver_policy_sha256, .lower),
        .bundle_manifest_sha256 = std.fmt.bytesToHex(result.bundle_manifest_sha256, .lower),
        .forest_manifest_sha256 = std.fmt.bytesToHex(result.forest_manifest_sha256, .lower),
        .verification = result.verified,
        .measurement_scope = "separate process; optimization_mode recorded; compilation excluded; preflight separately recorded; proof generation includes source collection, sort, roots, all base proofs and recursion",
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    var file = try dir.createFile("block-v5-cpu-report.json", .{ .exclusive = true });
    defer file.close();
    try file.writeAll(report);
    try file.writeAll("\n");
    try file.sync();
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
fn read(a: std.mem.Allocator, path: []const u8, cap: usize) ![]u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(a, cap);
}
