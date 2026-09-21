const std = @import("std");
const stwo = @import("stwo");

const metal = stwo.backends.metal.runtime;
const m31 = stwo.core.fields.m31;
const canonic = stwo.core.poly.circle.canonic;
const twiddles = stwo.prover.poly.twiddles;

const M31 = m31.M31;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var column_count: usize = 64;
    var base_log_size: u32 = 18;
    var repetitions: usize = 11;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--columns") and index + 1 < args.len) {
            index += 1;
            column_count = try std.fmt.parseInt(usize, args[index], 10);
        } else if (std.mem.eql(u8, args[index], "--log-size") and index + 1 < args.len) {
            index += 1;
            base_log_size = try std.fmt.parseInt(u32, args[index], 10);
        } else if (std.mem.eql(u8, args[index], "--repetitions") and index + 1 < args.len) {
            index += 1;
            repetitions = try std.fmt.parseInt(usize, args[index], 10);
        } else return error.InvalidArgument;
    }
    if (column_count == 0 or base_log_size < 3 or base_log_size >= 29 or repetitions == 0)
        return error.InvalidArgument;

    const extended_log_size = base_log_size + 1;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const base_domain = canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);

    const seed = try allocator.alloc(M31, column_count * base_len);
    defer allocator.free(seed);
    const base_backing = try allocator.alloc(M31, seed.len);
    defer allocator.free(base_backing);
    const transform_backing = try allocator.alloc(M31, column_count * extended_len);
    defer allocator.free(transform_backing);
    for (seed, 0..) |*value, item| {
        value.* = M31.fromCanonical(@intCast((item * 8191 + 43) % m31.Modulus));
    }
    const sources = try allocator.alloc([]const M31, column_count);
    defer allocator.free(sources);
    const bases = try allocator.alloc([]M31, column_count);
    defer allocator.free(bases);
    const extended = try allocator.alloc([]M31, column_count);
    defer allocator.free(extended);
    for (0..column_count) |column| {
        bases[column] = base_backing[column * base_len ..][0..base_len];
        sources[column] = bases[column];
        extended[column] = transform_backing[column * extended_len ..][0..extended_len];
    }

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const samples = try allocator.alloc(f64, repetitions);
    defer allocator.free(samples);
    for (samples) |*sample| {
        @memcpy(base_backing, seed);
        const result = try runtime.transformCircleLdeInto(
            allocator,
            sources,
            bases,
            extended,
            transform_backing,
            0,
            extended_len,
            base_tree.itwiddles,
            extended_tree.twiddles,
            base_log_size,
            extended_log_size,
        );
        sample.* = result.gpu_milliseconds;
    }
    std.mem.sort(f64, samples, {}, std.sort.asc(f64));
    std.debug.print(
        "columns={} base_log={} median_gpu_ms={d:.6} min_gpu_ms={d:.6} checksum={}\n",
        .{
            column_count,
            base_log_size,
            samples[samples.len / 2],
            samples[0],
            extended[0][extended_len - 1].toU32(),
        },
    );
}
