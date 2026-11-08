const std = @import("std");
const stwo = @import("stwo");
const metal = stwo.backends.metal.runtime;
const metal_telemetry = stwo.backends.metal.telemetry;
const codegen = stwo.integrations.cairo_metal.eval_codegen;
const composition = stwo.frontends.cairo.witness.composition_bundle;
const composition_prewarm = stwo.integrations.cairo_metal.composition_prewarm;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const verify_warm = args.len == 4 and std.mem.eql(u8, args[3], "--verify-warm");
    const path = if (args.len == 1)
        "vectors/cairo/sn_pie_2_composition.bin"
    else if (args.len <= 3 or verify_warm)
        args[1]
    else
        return error.InvalidArguments;
    var bundle = try composition.Bundle.readFile(allocator, path);
    defer bundle.deinit();
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    if (args.len == 3 or verify_warm) {
        const evidence = try composition_prewarm.prewarm(.{
            .allocator = allocator,
            .runtime = &runtime,
            .bundle = &bundle,
            .metallib_path = args[2],
            // Offline codegen tooling: this operates on libraries it or CI has
            // just compiled, which cannot be in a checked-in manifest. The
            // digest is still measured and lands in this tool's result.
            .policy = .report_only,
        });
        return writeResult(.{
            .components = bundle.components.len,
            .programs = evidence.resolved_plan_count,
            .constraints = bundle.total_constraints,
            .instructions = instructionCount(bundle),
            .source_bytes = 0,
            .largest_source_bytes = 0,
            .codegen_ms = 0,
            .metal_compile_ms = nanosecondsToMilliseconds(evidence.plan_preparation_ns),
            .all_programs_compiled = evidence.resolved_plan_count == evidence.expected_plan_count,
            .pipeline_cache_delta = evidence.cache_delta,
            .warm_verification = if (verify_warm) warm: {
                const second = try composition_prewarm.prewarm(.{
                    .allocator = allocator,
                    .runtime = &runtime,
                    .bundle = &bundle,
                    .metallib_path = args[2],
                    .policy = .report_only,
                });
                try composition_prewarm.validateSecondPass(second);
                break :warm .{
                    .passed = true,
                    .pipeline_cache_delta = second.cache_delta,
                };
            } else null,
        });
    }

    const cache_before = runtime.pipelineCacheStats();
    var timer = try std.time.Timer.start();
    var codegen_ns: u64 = 0;
    var compile_ns: u64 = 0;
    var source_bytes: u64 = 0;
    var program_count: u32 = 0;
    var instruction_count: u64 = 0;
    var largest_source: usize = 0;
    for (bundle.components) |component| for (component.parts) |part| {
        const name = try codegen.kernelName(allocator, part.semantic_hash);
        defer allocator.free(name);
        instruction_count += part.program.base_insts.len + part.program.ext_insts.len;
        const layout: metal.EvalLayout = .{
            .trace_offsets = 0,
            .interaction_offsets = 0,
            .base_params = 0,
            .ext_params = 0,
            .random_coeffs = 0,
            .denom_inv = 0,
            .coordinates = .{ 0, 0, 0, 0 },
            .row_count = @as(u32, 1) << @intCast(component.evaluation_log_size),
            .trace_log_size = component.trace_log_size,
            .domain_log_size = part.program.header.domain_log_size,
            .rc_base = part.rc_base,
        };
        timer.reset();
        const source = try codegen.generate(allocator, part.program);
        codegen_ns += timer.read();
        defer allocator.free(source);
        source_bytes += source.len;
        largest_source = @max(largest_source, source.len);
        timer.reset();
        var plan = try runtime.prepareEval(source, name, layout);
        compile_ns += timer.read();
        plan.deinit();
        program_count += 1;
    };
    try writeResult(.{
        .components = bundle.components.len,
        .programs = program_count,
        .constraints = bundle.total_constraints,
        .instructions = instruction_count,
        .source_bytes = source_bytes,
        .largest_source_bytes = largest_source,
        .codegen_ms = nanosecondsToMilliseconds(codegen_ns),
        .metal_compile_ms = nanosecondsToMilliseconds(compile_ns),
        .all_programs_compiled = true,
        .pipeline_cache_delta = metal_telemetry.PipelineCacheDelta.between(
            runtime.pipelineCacheStats(),
            cache_before,
        ),
        .warm_verification = null,
    });
}

const Result = struct {
    components: usize,
    programs: u64,
    constraints: u64,
    instructions: u64,
    source_bytes: u64,
    largest_source_bytes: usize,
    codegen_ms: f64,
    metal_compile_ms: f64,
    all_programs_compiled: bool,
    pipeline_cache_delta: metal_telemetry.PipelineCacheDelta,
    warm_verification: ?WarmVerification,
};

const WarmVerification = struct {
    passed: bool,
    pipeline_cache_delta: metal_telemetry.PipelineCacheDelta,
};

fn instructionCount(bundle: composition.Bundle) u64 {
    var count: u64 = 0;
    for (bundle.components) |component| for (component.parts) |part| {
        count += part.program.base_insts.len + part.program.ext_insts.len;
    };
    return count;
}

fn nanosecondsToMilliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn writeResult(result: Result) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}
