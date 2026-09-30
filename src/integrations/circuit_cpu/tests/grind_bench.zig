//! Proof-of-work grind throughput on the two circuit channels (design §9.1:
//! "M7 reports grind time separately").
//!
//! Every circuit proof grinds twice in Rust `SimdBackend` order
//! (`core.channel.blake2s.pow_order`): the 20-bit interaction grind and the
//! FRI grind at the FRI config's PoW bits (26 in canonical_small and
//! production). Leaves and internal folds grind on `Blake2sM31Channel`, the
//! root on `Blake2sChannel`. This times, per channel and difficulty, the
//! entry points the circuit prover calls (`channel.grind` and the prover's
//! `proof_of_work.grindForBackend(CpuBackend, ..)`) on a proof-scoped pool,
//! over `mix_u64(seed)` transcripts, and checks that both return the same
//! nonce (the canonical one). Not a test: `zig build bench-grind`.
//!
//! Arguments: `[seeds] [bits...]`, default `6 20 26`.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const pow = prover.pcs.proof_of_work;

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    const n_seeds: u64 = if (args.len > 1) try std.fmt.parseInt(u64, args[1], 10) else 6;
    var bits_list: std.ArrayList(u32) = .empty;
    defer bits_list.deinit(gpa);
    for (args[@min(args.len, 2)..]) |arg| try bits_list.append(gpa, try std.fmt.parseInt(u32, arg, 10));
    if (bits_list.items.len == 0) try bits_list.appendSlice(gpa, &.{ 20, 26 });

    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    std.debug.print("pool workers {d}, seeds {d}\n", .{ pool.workerCount(), n_seeds });

    inline for (.{ .{ "m31", core.channel.blake2s.Blake2sM31Channel }, .{ "plain", core.channel.blake2s.Blake2sChannel } }) |pair| {
        for (bits_list.items) |bits| try run(pair[0], pair[1], bits, n_seeds);
    }
}

fn run(comptime label: []const u8, comptime Channel: type, bits: u32, n_seeds: u64) !void {
    var channel_ns: u64 = 0;
    var prover_ns: u64 = 0;
    var channel_max: u64 = 0;
    var prover_max: u64 = 0;
    var hi_positive: usize = 0;
    var searched: u64 = 0;
    var seed: u64 = 0;
    while (seed < n_seeds) : (seed += 1) {
        var channel = Channel{};
        channel.mixU64(seed);
        // Alternate which entry point goes first so neither always runs warm.
        var nonces: [2]u64 = undefined;
        var times: [2]u64 = undefined;
        for (0..2) |slot| {
            const which = (slot + seed) % 2;
            var timer = try std.time.Timer.start();
            nonces[which] = if (which == 0) channel.grind(bits) else try pow.grindForBackend(CpuBackend, &channel, bits);
            times[which] = timer.read();
        }
        if (nonces[0] != nonces[1]) {
            std.debug.print("{s} {d} bits seed {d}: channel.grind {d} != prover grind {d}\n", .{ label, bits, seed, nonces[0], nonces[1] });
            return error.NonceMismatch;
        }
        if (!channel.verifyPowNonce(bits, nonces[0])) return error.InvalidNonce;
        if (nonces[0] >> 32 != 0) hi_positive += 1;
        searched += core.channel.blake2s.pow_order.indexFromNonce(nonces[0]).? + 1;
        channel_ns += times[0];
        prover_ns += times[1];
        channel_max = @max(channel_max, times[0]);
        prover_max = @max(prover_max, times[1]);
    }
    std.debug.print(
        "{s:<5} {d:>2} bits: channel.grind mean {d:>7.1} ms (max {d:>7.1}, {d:>6.0} Mnonce/s), prover grind mean {d:>7.1} ms (max {d:>7.1}, {d:>6.0} Mnonce/s); {d}/{d} nonces with hi > 0, mean index {d}\n",
        .{
            label,                      bits,
            ms(channel_ns / n_seeds),   ms(channel_max),
            rate(searched, channel_ns), ms(prover_ns / n_seeds),
            ms(prover_max),             rate(searched, prover_ns),
            hi_positive,                n_seeds,
            searched / n_seeds,
        },
    );
}

/// Canonical search indices covered per microsecond (millions per second).
fn rate(indices: u64, ns: u64) f64 {
    return @as(f64, @floatFromInt(indices)) * 1000.0 / @as(f64, @floatFromInt(@max(ns, 1)));
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}
