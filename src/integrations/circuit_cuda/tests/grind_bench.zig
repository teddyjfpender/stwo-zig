//! `circuit-cuda-grind-bench` (GPU host): the circuit grinds on the CPU
//! (the channel's own grind on every core) and on the CUDA device, both
//! channels, at the production widths. Each run grinds fresh transcripts;
//! the CPU and device runs are interleaved and every device nonce is checked
//! against the CPU's. Reports the median and the spread.
//!
//! Usage: circuit-cuda-grind-bench [repetitions] (default 7).

const std = @import("std");
const core = @import("stwo_core");
const circuit_cuda = @import("stwo_circuit_cuda_integration");

const device_grind = circuit_cuda.device_grind;
const Blake2sChannel = core.channel.blake2s.Blake2sChannel;
const Blake2sM31Channel = core.channel.blake2s.Blake2sM31Channel;

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    const repetitions: usize = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 7;

    try device_grind.requireDevice();
    // Warm the context (first CUDA call creates it).
    _ = try device_grind.grind(.m31, [_]u8{0} ** 32, 8);

    const cpu_workers = try std.Thread.getCpuCount();
    std.debug.print("channel bits  cpu median (min..max) ms   cuda median (min..max) ms   speedup\n", .{});
    inline for (.{ .{ Blake2sM31Channel, device_grind.Output.m31, "m31" }, .{ Blake2sChannel, device_grind.Output.plain, "plain" } }) |case| {
        for ([_]u32{ 20, 26 }) |bits| {
            const cpu = try gpa.alloc(f64, repetitions);
            defer gpa.free(cpu);
            const cuda = try gpa.alloc(f64, repetitions);
            defer gpa.free(cuda);
            for (0..repetitions) |rep| {
                var channel = case[0]{};
                channel.mixU64(0xc0da_0000 + rep * 31 + bits);
                var timer = try std.time.Timer.start();
                const expected = channel.grindWithWorkerCount(bits, cpu_workers);
                cpu[rep] = @as(f64, @floatFromInt(timer.lap())) / std.time.ns_per_ms;
                const nonce = try device_grind.grind(case[1], channel.computePowPrefix(bits), bits);
                cuda[rep] = @as(f64, @floatFromInt(timer.lap())) / std.time.ns_per_ms;
                if (nonce != expected) {
                    std.debug.print("MISMATCH {s} {d} bits: cuda 0x{x}, cpu 0x{x}\n", .{ case[2], bits, nonce, expected });
                    return error.NonceMismatch;
                }
            }
            std.mem.sort(f64, cpu, {}, std.sort.asc(f64));
            std.mem.sort(f64, cuda, {}, std.sort.asc(f64));
            const cpu_median = cpu[repetitions / 2];
            const cuda_median = cuda[repetitions / 2];
            std.debug.print("{s:<7} {d:>4}  {d:>10.2} ({d:.2}..{d:.2})   {d:>10.2} ({d:.2}..{d:.2})   {d:.1}x\n", .{
                case[2],                  bits,
                cpu_median,               cpu[0],
                cpu[repetitions - 1],     cuda_median,
                cuda[0],                  cuda[repetitions - 1],
                cpu_median / cuda_median,
            });
        }
    }
}
