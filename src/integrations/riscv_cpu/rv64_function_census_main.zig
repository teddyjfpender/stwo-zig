//! Bounded, read-only exact fact census. Not a VM, witness builder or proof verifier.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const Ops = @import("stwo_riscv_frontend").rv64_air.word16_v1.operations;
const Request = @import("rv64_ethereum_request.zig");
const Owner = @import("rv64_ethereum_worker_expected.zig").Owner;
const H = @import("rv64_work_packet_header.zig");
const IO = @import("rv64_work_packet_io.zig");
const Public = @import("rv64_work_packet_public.zig");
const Admission = @import("rv64_work_packet_admission.zig");
const Budget = @import("rv64_work_packet_budget.zig");
const Key = struct { a: u64, b: u64, c: u64, id: u32 };
const Record = struct { key: Key, count: u32 };
const MAX_KEYS: u32 = (1 << 22) - 1;
fn less(_: void, a: Record, b: Record) bool {
    if (a.key.id != b.key.id) return a.key.id < b.key.id;
    if (a.key.a != b.key.a) return a.key.a < b.key.a;
    if (a.key.b != b.key.b) return a.key.b < b.key.b;
    return a.key.c < b.key.c;
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5) return error.ExpectedConfigOutputDirectoryStartCount;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer parsed.deinit();
    const config = parsed.value;
    try Request.validateBudget(config);
    var owner = try Owner.init(a, config);
    defer owner.deinit();
    const expected = H.Expected{ .identity = try H.identityFor(config, &owner.authority, &owner.policy), .authority = &owner.authority, .policy = &owner.policy, .state_policy = config.state_policy };
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    const start = try std.fmt.parseInt(u32, args[3], 10);
    const count = try std.fmt.parseInt(u32, args[4], 10);
    if (start > 25 or count > 25 - start) return error.CensusBatchBound;
    for (start..start + count) |index| {
        var timer = try std.time.Timer.start();
        const name = try std.fmt.allocPrint(a, "{s}/jobs/job-{d:0>6}.work", .{ config.output_directory, index });
        defer a.free(name);
        var file = try std.fs.cwd().openFile(name, .{});
        defer file.close();
        var header_raw: [H.BYTES]u8 = undefined;
        try IO.exact(file, &header_raw);
        const h = try H.decode(&header_raw, try file.getEndPos(), expected, .{ .steps = config.batch_steps });
        if (h.metadata.index != index) return error.InvalidCensusIndex;
        if (!std.mem.eql(u8, &h.content_digest, &try IO.digest(file, try h.totalBytes()))) return error.WorkPacketDigestMismatch;
        try file.seekTo(H.BYTES);
        var public_raw: [Public.BYTES]u8 = undefined;
        try IO.exact(file, &public_raw);
        const public = try Public.decode(&public_raw, &owner.authority);
        if (public.state_policy != config.state_policy) return error.WorkPacketAuthorityMismatch;
        try Budget.check(file, h, public.statement.steps, .{ .steps = config.batch_steps });
        const opcodes = try Admission.check(file, h, public, &owner.authority);
        const validation_ns = timer.read();
        var map: std.AutoHashMapUnmanaged(Key, u32) = .empty;
        defer map.deinit(a);
        // Allocate once: exact maximum is public steps <= 2^22-1; no growth
        // controlled by tuple values and no whole-execution hash map.
        try map.ensureTotalCapacity(a, public.statement.steps);
        const map_bytes = map.capacity() * (@sizeOf(Key) + @sizeOf(u32) + 1);
        const tape_start = H.BYTES + try h.bodyBytes() + h.graph_bytes;
        try file.seekTo(tape_start + rv.compact_tape_wire.HEADER_BYTES);
        var reader = IO.Reader{ .file = file, .remaining = @as(usize, public.statement.steps) * 48 };
        var pc = public.statement.initial_pc;
        var families: [3]u64 = @splat(0);
        var branch_count: u64 = 0;
        var seen: Admission.OpcodeCounts = @splat(0);
        for (0..public.statement.steps) |_| {
            var step: [48]u8 = undefined;
            try reader.bytes(&step);
            const slot = try owner.authority.program.lookup(pc);
            const ins = owner.authority.program.decoded[slot].instruction;
            seen[@intFromEnum(ins.opcode)] += 1;
            const flags = std.mem.readInt(u32, step[44..48], .little);
            if (flags > 1) return error.InvalidCensusFlags;
            if (Ops.classify(ins.opcode)) |op| {
                families[@intFromEnum(op.family) - 1] += 1;
                branch_count += @intFromBool(op.branch_predicate);
                const key = Key{ .id = op.busId(), .a = std.mem.readInt(u64, step[8..16], .little), .b = if (op.use_immediate) @bitCast(ins.imm) else std.mem.readInt(u64, step[16..24], .little), .c = if (op.branch_predicate) flags else std.mem.readInt(u64, step[32..40], .little) };
                const entry = map.getOrPutAssumeCapacity(key);
                if (!entry.found_existing) entry.value_ptr.* = 0;
                entry.value_ptr.* = try std.math.add(u32, entry.value_ptr.*, 1);
            }
            pc = std.mem.readInt(u64, step[0..8], .little);
        }
        try reader.finish();
        if (pc != public.statement.final_pc or !std.mem.eql(u64, &seen, &opcodes) or map.count() > MAX_KEYS) return error.CensusMismatch;
        const scan_ns = timer.read() - validation_ns;
        const records = try a.alloc(Record, map.count());
        defer a.free(records);
        var it = map.iterator();
        var ri: usize = 0;
        while (it.next()) |entry| : (ri += 1) records[ri] = .{ .key = entry.key_ptr.*, .count = entry.value_ptr.* };
        const unique = map.count();
        map.deinit(a);
        map = .empty;
        std.mem.sort(Record, records, {}, less);
        const run_name = try std.fmt.allocPrint(a, "job-{d:0>6}.run", .{index});
        defer a.free(run_name);
        var run = try dir.createFile(run_name, .{});
        defer run.close();
        var buffer: [65536]u8 = undefined;
        var at: usize = 0;
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        for (records) |r| {
            const row = buffer[at..][0..32];
            std.mem.writeInt(u64, row[0..8], r.key.a, .little);
            std.mem.writeInt(u64, row[8..16], r.key.b, .little);
            std.mem.writeInt(u64, row[16..24], r.key.c, .little);
            std.mem.writeInt(u32, row[24..28], r.key.id, .little);
            std.mem.writeInt(u32, row[28..32], r.count, .little);
            at += 32;
            if (at == buffer.len) {
                sha.update(buffer[0..at]);
                try run.writeAll(buffer[0..at]);
                at = 0;
            }
        }
        sha.update(buffer[0..at]);
        try run.writeAll(buffer[0..at]);
        var digest: [32]u8 = undefined;
        sha.final(&digest);
        const json = try std.json.Stringify.valueAlloc(a, .{ .index = index, .steps = public.statement.steps, .opcode_counts = opcodes, .families = families, .branch_queries = branch_count, .unique = unique, .packet_digest = std.fmt.bytesToHex(h.content_digest, .lower), .run_sha256 = std.fmt.bytesToHex(digest, .lower), .validation_ns = validation_ns, .scan_ns = scan_ns, .total_ns = timer.read(), .map_capacity_limit = MAX_KEYS, .map_allocation_estimate_bytes = map_bytes, .record_allocation_bytes = records.len * @sizeOf(Record), .scope = "validated packet advice; no VM, no graph decode, no physical proof verification" }, .{ .whitespace = .indent_2 });
        defer a.free(json);
        const json_name = try std.fmt.allocPrint(a, "job-{d:0>6}.json", .{index});
        defer a.free(json_name);
        try dir.writeFile(.{ .sub_path = json_name, .data = json });
        std.debug.print("job {d}: {d} steps, {d} distinct function facts, {d} ms\n", .{ index, public.statement.steps, unique, timer.read() / std.time.ns_per_ms });
    }
}
