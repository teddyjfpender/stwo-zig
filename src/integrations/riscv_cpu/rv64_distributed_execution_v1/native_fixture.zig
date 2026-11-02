//! Six real native retirements, observed ONCE. The VM/Memory die before proving.
//! Expected terminal values are independently specified by the public test.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const W = frontend.rv64_air.word16_cpu;
const Public = @import("public.zig");
const Wire = @import("../rv64_distributed_v1/wire.zig");
const a_word: u64 = 0xffff000180007fff;
const b_word: u64 = 0x7fffffff8000ffff;
fn instruction(funct3: u32, rd: u32, rs1: u32, rs2: u32) u32 {
    return 0x33 | (rd << 7) | (funct3 << 12) | (rs1 << 15) | (rs2 << 20);
}
pub const WORDS = [_]u32{
    instruction(7, 3, 1, 2), instruction(6, 1, 3, 1), instruction(4, 0, 1, 2),
    instruction(4, 2, 1, 3), instruction(7, 4, 2, 1), instruction(6, 5, 4, 3),
};
pub const BASE = 4096;
fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
pub fn expected(program: *const W.rom.Setup) !Public.Expected {
    var initial: [32]u64 = @splat(0);
    initial[1] = a_word;
    initial[2] = b_word;
    var final = initial;
    final[3] = a_word & b_word;
    final[2] = a_word ^ final[3];
    final[4] = final[2];
    final[5] = a_word;
    var result = Public.Expected{
        .request_id = (1 << 60) + 23,
        .request_digest = hash("six-real-retirements-binary-only-request-v1"),
        .instance = hash("six-real-retirements-binary-only-instance-v1"),
        .relation_epoch = (1 << 53) + 9,
        .program_identity = program.identity,
        .worker_jobs = @splat(@splat(0)),
        .cpu_logs = .{ 5, 5 },
        .total_steps = 6,
        .initial_pc = BASE,
        .final_pc = BASE + 24,
        .initial_registers = initial,
        .final_registers = final,
    };
    // These are expected work descriptor IDs, NOT a claim of hashing private
    // witness contents. Physical PCS roots bind the actual tuples/weights.
    for (&result.worker_jobs, 0..) |*job, ordinal| {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("expected-register-only-work-descriptor-v1");
        h.update(&Wire.contextBytes(result.context()));
        h.update(&.{@intCast(ordinal)});
        for (knownShards()) |shard| h.update(&(try Public.shardDigest(shard)));
        job.* = h.finalResult();
    }
    return result;
}
/// Independently expected test plan; the fresh receiver needs no VM replay
/// and derives its work IDs from this known plan rather than proof metadata.
pub fn knownShards() Public.Boundaries {
    var initial: [32]u64 = @splat(0);
    initial[1] = a_word;
    initial[2] = b_word;
    var middle = initial;
    middle[3] = a_word & b_word;
    var final = middle;
    final[2] = a_word ^ middle[3];
    final[4] = final[2];
    final[5] = a_word;
    var clocks0: [32]u32 = @splat(0);
    clocks0[1] = 9;
    clocks0[2] = 10;
    clocks0[3] = 5;
    var clocks1: [32]u32 = @splat(0);
    clocks1[1] = 6;
    clocks1[2] = 5;
    clocks1[3] = 10;
    clocks1[4] = 9;
    clocks1[5] = 11;
    return .{
        .{ .first_step = 0, .cpu_log = 5, .public = .{ .steps = 3, .initial_pc = BASE, .final_pc = BASE + 12, .initial_registers = initial, .final_registers = middle, .register_clocks = clocks0 } },
        .{ .first_step = 3, .cpu_log = 5, .public = .{ .steps = 3, .initial_pc = BASE + 12, .final_pc = BASE + 24, .initial_registers = middle, .final_registers = final, .register_clocks = clocks1 } },
    };
}
pub const Fixture = struct {
    records: [2][3]rv.machine.Retirement,
    shards: Public.Boundaries,
    pub fn init(a: std.mem.Allocator) !Fixture {
        var memory = rv.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = BASE, .size = 24, .permissions = .{ .read = true, .execute = true } });
        for (WORDS, 0..) |raw, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, raw, .little);
            try memory.initialize(BASE + 4 * i, &bytes);
        }
        var cpu = rv.machine.Cpu.init(BASE, 0);
        cpu.regs[1] = a_word;
        cpu.regs[2] = b_word;
        var result: Fixture = undefined;
        for (0..2) |shard| {
            const before = cpu.regs;
            const initial_pc = cpu.pc;
            var clocks: [32]u32 = @splat(0);
            for (0..3) |row| {
                var record = try cpu.step(&memory);
                // Retirement clock advice is explicitly rebased; architecture
                // keeps PC and register values. No instruction is re-executed.
                record.clock -= @intCast(3 * shard);
                result.records[shard][row] = record;
                for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| {
                    if (id != 0) clocks[id] = @intCast(4 * row + slot + 1);
                }
            }
            result.shards[shard] = .{ .first_step = 3 * shard, .cpu_log = 5, .public = .{
                .steps = 3,
                .initial_pc = initial_pc,
                .final_pc = cpu.pc,
                .initial_registers = before,
                .final_registers = cpu.regs,
                .register_clocks = clocks,
            } };
        }
        if (!std.meta.eql(result.shards, knownShards())) return error.InvalidNativeBinaryFixture;
        return result;
    }
};
