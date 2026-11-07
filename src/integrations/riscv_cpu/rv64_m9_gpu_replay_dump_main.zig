//! `rv64-m9-gpu-replay-dump CONFIG OUT_DIR CHUNK REF_SEGMENT [MAX_SEGMENTS]`
//!
//! M9 GPU capture replay prototype, CPU half (diagnostic only; no proof, no acceptance).
//! 1. Plain fast first pass over the whole block (production loop: `Engine.run` plus a
//!    reference `Session.step` for every instruction the engine stops before), timed.
//! 2. Seeded first pass (`rv64_m9_gpu_replay.runSeeded`): the same loop that also records
//!    per-chunk seeds, the memory-before tape and host steps; timed; checkpoints taken.
//! 3. CPU recorder reference per segment: `Walk.createSegment` from the checkpoint and
//!    `nextTaking` (the production traced walk). Checks memory tape and host steps byte for
//!    byte, and writes the SHA-256 of the reference compact steps for the GPU harness.
//! Files in OUT_DIR: rom.bin, meta.txt, seg<k>.{seeds,mem,slow}, seg<REF>.ref (all steps).
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const Request = @import("rv64_ethereum_request.zig");
const Walk = @import("rv64_ethereum_native_prepare.zig").Walk;
const Native = @import("rv64_ethereum_batch.zig");
const R = @import("rv64_m9_gpu_replay.zig");

const Pass = struct { exec_ns: u64 = 0, total_ns: u64 = 0, retired: u64 = 0, fast: u64 = 0, host_steps: u64 = 0, segments: u32 = 0 };

fn writeFile(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var f = try dir.createFile(name, .{});
    defer f.close();
    try f.writeAll(bytes);
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    // `rv64-m9-gpu-replay-dump --op-corpus OUT_DIR`: synthetic per-opcode corpus (see the file).
    if (args.len == 3 and std.mem.eql(u8, args[1], "--op-corpus")) return @import("rv64_m9_gpu_replay_opcorpus.zig").run(a, args[2]);
    if (args.len < 5) return error.Usage;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Request.Config, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const config = parsed.value;
    try @import("word16_global_execution/services/gkr_local/service_scope.zig").profile(config.execution_profile);
    try std.fs.cwd().makePath(args[2]);
    var out = try std.fs.cwd().openDir(args[2], .{});
    defer out.close();
    const chunk = try std.fmt.parseUnsigned(u32, args[3], 10);
    const ref_segment = try std.fmt.parseInt(i64, args[4], 10);
    const max_segments: u32 = if (args.len > 5) try std.fmt.parseUnsigned(u32, args[5], 10) else std.math.maxInt(u32);
    var timer = try std.time.Timer.start();
    const prefault = if (std.posix.getenv("STWO_RV64_M9_PREFAULT")) |v| std.mem.eql(u8, v, "1") else false;

    // ---- 1. plain first pass (production loop, checkpoints included) ----
    var plain: Pass = .{};
    // Host-step time by kind: 0 ordinary trap/absent page, 1.. Event tags, then curve ops.
    const HOST_KINDS = 1 + @typeInfo(rv.ethereum_services.Event).@"union".fields.len;
    var host_ns = [_]u64{0} ** (HOST_KINDS + rv.ethereum_services.curves.COUNT);
    var host_n = [_]u64{0} ** (HOST_KINDS + rv.ethereum_services.curves.COUNT);
    const skip_ref = if (std.posix.getenv("STWO_RV64_M9_SKIP_REF")) |v| std.mem.eql(u8, v, "1") else false;
    {
        var w = try Walk.create(a, config);
        defer w.destroy();
        var e = try rv.fast_execution.Engine.init(a, w.memory, .{ .stop_pcs = &.{config.terminal_pc}, .isa = w.session.keccak.base.decoder.isa });
        defer e.deinit();
        e.attach();
        var recorder = try rv.checkpoint.Recorder.init(a, &e);
        defer recorder.deinit();
        const cpu = &w.session.keccak.base.cpu;
        const t0 = timer.read();
        var done = false;
        while (!done and plain.segments < max_segments) : (plain.segments += 1) {
            var cp = try recorder.take(&w.session);
            recorder.release(&cp);
            const s0 = timer.read();
            const limit = cpu.retired +| config.batch_steps;
            var event: rv.ethereum_services.Event = undefined;
            while (true) {
                _ = e.run(cpu, @min(limit, config.max_steps));
                if (cpu.pc == config.terminal_pc) break;
                if (cpu.retired == limit) break;
                const h0 = timer.read();
                const row = try w.session.step(&event);
                const dt = timer.read() - h0;
                const kind: usize = if (row != null) 0 else switch (event) {
                    .curve => |call| HOST_KINDS + rv.ethereum_services.curves.index(call.op),
                    else => 1 + @intFromEnum(std.meta.activeTag(event)),
                };
                host_ns[kind] += dt;
                host_n[kind] += 1;
                plain.host_steps += 1;
                if (cpu.pc == config.terminal_pc or cpu.retired == limit) break;
            }
            plain.exec_ns += timer.read() - s0;
            if (cpu.pc == config.terminal_pc) done = true;
        }
        plain.total_ns = timer.read() - t0;
        plain.retired = cpu.retired;
        plain.fast = e.fast_retired;
        e.detach();
    }

    // ---- 2. seeded first pass ----
    var seeded: Pass = .{};
    var w = try Walk.create(a, config);
    defer w.destroy();
    var e = try rv.fast_execution.Engine.init(a, w.memory, .{ .stop_pcs = &.{config.terminal_pc}, .isa = w.session.keccak.base.decoder.isa });
    defer e.deinit();
    var program = try rv.fast_execution.Engine.cloneProgram(a, &e);
    defer program.deinit();
    program.restrict(@as(*const @TypeOf(w.request.authority), &w.request.authority), Native.admitsFast);
    w.fast_program = &program;
    defer w.fast_program = null;
    e.attach();
    var recorder = try rv.checkpoint.Recorder.init(a, &e);
    defer recorder.deinit();
    var checkpoints = std.ArrayList(rv.checkpoint.Checkpoint).empty;
    defer {
        for (checkpoints.items) |*cp| recorder.release(cp);
        checkpoints.deinit(a);
    }
    var tapes = std.ArrayList(R.SegmentTape).empty;
    defer {
        for (tapes.items) |*t| t.deinit();
        tapes.deinit(a);
    }
    var ends = std.ArrayList(u64).empty;
    defer ends.deinit(a);
    {
        const cpu = &w.session.keccak.base.cpu;
        const t0 = timer.read();
        var done = false;
        while (!done and seeded.segments < max_segments) : (seeded.segments += 1) {
            try checkpoints.append(a, try recorder.take(&w.session));
            try tapes.append(a, R.SegmentTape.init(a, chunk));
            const t = &tapes.items[tapes.items.len - 1];
            const limit = cpu.retired +| config.batch_steps;
            try t.begin(&e, cpu, limit - cpu.retired);
            // STWO_RV64_M9_PREFAULT=1: touch the reserved tape first (production would recycle
            // already-faulted per-segment buffers), so the timing isolates the recording work.
            if (prefault) {
                @memset(t.memory.allocatedSlice()[t.memory.items.len..], 0);
                @memset(std.mem.sliceAsBytes(t.seeds.allocatedSlice()[t.seeds.items.len..]), 0);
            }
            const s0 = timer.read();
            var event: rv.ethereum_services.Event = undefined;
            while (true) {
                _ = R.runSeeded(&e, cpu, @min(limit, config.max_steps), t);
                if (cpu.pc == config.terminal_pc) break;
                if (cpu.retired == limit) break;
                const row = try w.session.step(&event);
                try t.hostStep(row orelse event.retirement(), cpu);
                seeded.host_steps += 1;
                if (cpu.pc == config.terminal_pc or cpu.retired == limit) break;
            }
            seeded.exec_ns += timer.read() - s0;
            t.finish(cpu.retired, cpu.pc);
            try t.verifyPartition(cpu.retired);
            try ends.append(a, cpu.retired);
            if (cpu.pc == config.terminal_pc) done = true;
        }
        seeded.total_ns = timer.read() - t0;
        seeded.retired = cpu.retired;
        seeded.fast = e.fast_retired;
        e.detach();
    }
    if (plain.retired != seeded.retired) return error.M9PlainSeededRetiredMismatch;

    // ---- ROM ----
    const rom = try R.exportRom(a, &e);
    defer a.free(rom);
    try writeFile(out, "rom.bin", std.mem.sliceAsBytes(rom));

    // ---- 3. CPU recorder reference, per segment ----
    var meta = std.ArrayList(u8).empty;
    defer meta.deinit(a);
    try meta.print(a, "code_lo {d}\nslots {d}\nchunk {d}\nsegments {d}\n", .{ e.code_lo, rom.len, chunk, tapes.items.len });
    var hist = [_]u64{0} ** (R.OP_NAMES.len + 1);
    var ref_ns_total: u64 = 0;
    var ref_fast_ns: u64 = 0;
    var ref_traced_ns: u64 = 0;
    var ref_finish_ns: u64 = 0;
    var ref_steps_total: u64 = 0;
    var mismatches: u64 = 0;
    var seeds_total: u64 = 0;
    var words_total: u64 = 0;
    for (tapes.items, checkpoints.items, 0..) |*t, *cp, k| {
        if (skip_ref) break;
        const index: u32 = @intCast(k);
        var seg = try Walk.createSegment(a, w, cp, index);
        defer seg.destroy();
        const r0 = timer.read();
        var taken = (try seg.nextTaking()) orelse return error.M9NoReferenceBatch;
        defer taken.deinit();
        ref_ns_total += timer.read() - r0;
        ref_fast_ns += seg.fast_ns;
        ref_traced_ns += seg.traced_ns;
        ref_finish_ns += seg.finish_ns;
        const steps = taken.tape.steps();
        ref_steps_total += steps.len;
        const n = ends.items[k] - t.start;
        if (steps.len != n) return error.M9ReferenceLengthMismatch;
        // memory-before tape and host steps, byte for byte
        if (!std.mem.eql(u64, taken.tape.memory_before.items, t.memory.items)) {
            std.debug.print("M9 segment {d}: memory tape mismatch (ref {d} words, seeded {d})\n", .{ k, taken.tape.memory_before.items.len, t.memory.items.len });
            mismatches += 1;
        }
        for (t.slow.items) |s| {
            if (!std.mem.eql(u8, std.mem.asBytes(&steps[s.pos]), std.mem.asBytes(&s.step))) {
                mismatches += 1;
                if (mismatches < 8) std.debug.print("M9 segment {d}: host step mismatch at {d}\n", .{ k, s.pos });
            }
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(steps), &digest, .{});
        // opcode census along the pc chain (host steps counted last)
        {
            var pc = taken.tape.initial_pc;
            var slow_i: usize = 0;
            for (steps, 0..) |step, pos| {
                if (slow_i < t.slow.items.len and t.slow.items[slow_i].pos == pos) {
                    hist[R.OP_NAMES.len] += 1;
                    slow_i += 1;
                } else hist[rom[@intCast((pc - e.code_lo) / 4)].op] += 1;
                pc = step.next_pc;
            }
        }
        var name_buf: [64]u8 = undefined;
        try writeFile(out, try std.fmt.bufPrint(&name_buf, "seg{d}.seeds", .{k}), std.mem.sliceAsBytes(t.seeds.items));
        try writeFile(out, try std.fmt.bufPrint(&name_buf, "seg{d}.mem", .{k}), std.mem.sliceAsBytes(t.memory.items));
        try writeFile(out, try std.fmt.bufPrint(&name_buf, "seg{d}.slow", .{k}), std.mem.sliceAsBytes(t.slow.items));
        if (ref_segment == @as(i64, @intCast(k))) try writeFile(out, try std.fmt.bufPrint(&name_buf, "seg{d}.ref", .{k}), std.mem.sliceAsBytes(steps));
        try meta.print(a, "seg {d} {d} {d} {d} {d} {s} {d}\n", .{ k, steps.len, t.seeds.items.len, t.memory.items.len, t.slow.items.len, &std.fmt.bytesToHex(digest, .lower), t.end_slot });
        seeds_total += t.seeds.items.len;
        words_total += t.memory.items.len;
    }
    try writeFile(out, "meta.txt", meta.items);

    var stdout_buf: [1 << 16]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    const o = &stdout.interface;
    const mips = struct {
        fn f(steps: u64, ns: u64) f64 {
            return if (ns == 0) 0 else @as(f64, @floatFromInt(steps)) * 1e3 / @as(f64, @floatFromInt(ns));
        }
    }.f;
    try o.print("{{\n \"scope\": \"M9 GPU replay prototype, CPU half (diagnostic only)\",\n \"prefault\": {},\n \"chunk\": {d},\n \"segments\": {d},\n \"retired\": {d},\n", .{ prefault, chunk, tapes.items.len, seeded.retired });
    try o.print(" \"plain\": {{\"exec_ns\": {d}, \"total_ns\": {d}, \"fast\": {d}, \"host_steps\": {d}, \"mips\": {d:.1}}},\n", .{ plain.exec_ns, plain.total_ns, plain.fast, plain.host_steps, mips(plain.retired, plain.exec_ns) });
    try o.print(" \"seeded\": {{\"exec_ns\": {d}, \"total_ns\": {d}, \"fast\": {d}, \"host_steps\": {d}, \"mips\": {d:.1}, \"seeds\": {d}, \"memory_words\": {d}, \"bytes_per_step\": {d:.3}}},\n", .{ seeded.exec_ns, seeded.total_ns, seeded.fast, seeded.host_steps, mips(seeded.retired, seeded.exec_ns), seeds_total, words_total, @as(f64, @floatFromInt(seeds_total * @sizeOf(R.Seed) + words_total * 8 + seeded.host_steps * @sizeOf(R.SlowStep))) / @as(f64, @floatFromInt(seeded.retired)) });
    try o.print(" \"cpu_recorder\": {{\"steps\": {d}, \"next_taking_ns\": {d}, \"traced_ns\": {d}, \"fast_ns\": {d}, \"finish_ns\": {d}, \"ns_per_step\": {d:.2}}},\n", .{ ref_steps_total, ref_ns_total, ref_traced_ns, ref_fast_ns, ref_finish_ns, @as(f64, @floatFromInt(ref_ns_total)) / @as(f64, @floatFromInt(@max(ref_steps_total, 1))) });
    try o.print(" \"host_steps_by_kind\": {{", .{});
    {
        var sep = false;
        for (host_ns, host_n, 0..) |ns, count, kind| {
            if (count == 0) continue;
            const name: []const u8 = if (kind == 0) "ordinary" else if (kind < HOST_KINDS) eventName(kind - 1) else curveName(kind - HOST_KINDS);
            try o.print("{s}\"{s}\": {{\"n\": {d}, \"ns\": {d}}}", .{ if (sep) ", " else "", name, count, ns });
            sep = true;
        }
    }
    try o.print("}},\n \"reference_skipped\": {},\n", .{skip_ref});
    try o.print(" \"cpu_parity_mismatches\": {d},\n \"op_census\": {{", .{mismatches});
    var first = true;
    for (hist, 0..) |count, op| {
        if (count == 0) continue;
        try o.print("{s}\"{s}\": {d}", .{ if (first) "" else ", ", if (op < R.OP_NAMES.len) R.OP_NAMES[op] else "host", count });
        first = false;
    }
    try o.print("}}\n}}\n", .{});
    try o.flush();
    if (mismatches != 0) return error.M9CpuParityMismatch;
}

fn curveName(i: usize) []const u8 {
    inline for (@typeInfo(rv.ethereum_services.curves.Op).@"enum".fields) |f| {
        if (rv.ethereum_services.curves.index(@enumFromInt(f.value)) == i) return "curve." ++ f.name;
    }
    return "curve.?";
}

fn eventName(i: usize) []const u8 {
    inline for (@typeInfo(rv.ethereum_services.Event).@"union".fields, 0..) |f, k| {
        if (k == i) return f.name;
    }
    return "event.?";
}
