//! Scoped mainnet public-image benchmark. It derives the initial RW root,
//! register image, and layout from a fresh ELF/input session, independently
//! of the public roster files. It does not verify block execution or proofs.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const runner = @import("runner/mod.zig");
const snapshot = @import("recursion/air/blake3_memory_snapshot.zig");
const fallback = @import("prover/block_memory_public_rw_fallback_v2.zig");
const seal_mod = @import("prover/block_memory_source_seal_v2.zig");
const manifest = @import("prover/block_commitment_manifest.zig");

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 5) return error.ExpectedElfInputNonzeroImageFirstTouchRoster;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    var image = try std.fs.cwd().openFile(args[3], .{});
    defer image.close();
    var touches = try std.fs.cwd().openFile(args[4], .{});
    defer touches.close();

    var session_timer = try std.time.Timer.start();
    var session = try runner.EthereumShaExecutionSession.init(a, elf, .{
        .input = input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var first = try session.startSegment(1);
    defer first.deinit();
    var independent = try snapshot.fromSnapshot(a, &first.base.rw_memory, .entry, .continuation);
    defer independent.deinit();
    const session_ns = session_timer.read();

    const image_len = try image.getEndPos();
    const touch_len = try touches.getEndPos();
    if (image_len % fallback.IMAGE_RECORD_BYTES != 0 or touch_len % fallback.TOUCH_RECORD_BYTES != 0)
        return error.InvalidPublicInitialRosterLength;
    const pin = fallback.Pin{
        .initial_rw_root = independent.root,
        .layout = first.base.rw_memory.layout,
        .image_count = image_len / fallback.IMAGE_RECORD_BYTES,
        .first_touch_count = touch_len / fallback.TOUCH_RECORD_BYTES,
    };
    const files = fallback.Files{ .nonzero_image = image, .first_touches = touches };
    const roster_digest = try fallback.digestRoster(pin, files);
    // Benchmark-only challenge context. Production uses independently pinned
    // first-round/shard digests from its complete SourceSeal statement.
    const base = manifest.Sealed{ .digest = @splat(0x42), .instance_count = 218 };
    const sealed = try seal_mod.SourceSeal.initBound(base, 4294967279, roster_digest, 218, 340, @splat(0x43), @splat(0x44));
    var verify_timer = try std.time.Timer.start();
    const verified = try fallback.verifyMainnetDirectBound(a, pin, files, sealed, first.base.entry_cpu.regs);
    const verify_ns = verify_timer.read();
    const root_hex = std.fmt.bytesToHex(independent.root.bytes, .lower);
    const digest_hex = std.fmt.bytesToHex(roster_digest, .lower);
    const rw_claim = verified.initial_sum.toM31Array();
    const register_claim = verified.register_sum.toM31Array();
    const report = try std.json.Stringify.valueAlloc(backing, .{
        .scope = "public RW/register first-touch fallback; no STARK or complete-block authority",
        .session_ns = session_ns,
        .verify_ns = verify_ns,
        .peak_tracked_bytes = budget.snapshot().peak_live_bytes,
        .initial_rw_root = root_hex,
        .sealed_roster_digest = digest_hex,
        .image_words = pin.image_count,
        .first_touches = verified.total_first_touches,
        .rw_first_touches = verified.rw_first_touches,
        .rw_zero_first_touches = verified.rw_zero_first_touches,
        .register_first_touches = verified.register_first_touches,
        .rw_claim = .{ rw_claim[0].toU32(), rw_claim[1].toU32(), rw_claim[2].toU32(), rw_claim[3].toU32() },
        .register_claim = .{ register_claim[0].toU32(), register_claim[1].toU32(), register_claim[2].toU32(), register_claim[3].toU32() },
    }, .{ .whitespace = .indent_2 });
    defer backing.free(report);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buffer);
    try stdout.interface.writeAll(report);
    try stdout.interface.writeByte('\n');
    try stdout.interface.flush();
}
