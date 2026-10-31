//! Shared native mixed-service execution fixture; no proving orchestration.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const Service = @import("../rv64_keccak_cpu.zig");
const SecpCtx = @import("../delegations/secp256k1/context.zig");
const Cell = @import("../rv64_full_statement.zig").Cell;
pub const pc: u64 = 0x100003000;
pub const pointer: u64 = 0xf123456780003fe0;
pub const program = [_]u32{ 0x00043f83, 0x00843503, 0x01043883, 0x00000073, 0x01843503, 0x02043883, 0x00000073, 0x02843883, 0x00000073, 0x022086b3, 0x0220c1bb, 0x00053583 };
fn wordsFor(format: rv.execution_profile.SecpPacketFormat) [24]u64 {
    // Both inputs are the secp256k1 generator in projective coordinates.
    const coordinates = [_]u256{ 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 1 };
    var result: [24]u64 = @splat(0);
    for (coordinates, 0..) |coordinate, k| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, coordinate, if (format == .big_endian_bytes_v1) .big else .little);
        for (0..4) |word| result[k * 4 + word] = std.mem.readInt(u64, bytes[word * 8 ..][0..8], .little);
    }
    @memcpy(result[12..24], result[0..12]);
    return result;
}
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    memory: rv.memory.Memory,
    initial_words: [64]u64,
    records: [program.len]rv.machine.Retirement,
    kcalls: [1]rv.services.Call,
    scalls: [2]rv.ethereum_services.SecpCall,
    cell_storage: [64]Cell,
    clock_storage: [64]u32,
    captured: []rv.boundary_capture.Cell,
    public: Service.Public,
    pub fn create(a: std.mem.Allocator, profile: rv.execution_profile.Profile) !*Fixture {
        const self = try a.create(Fixture);
        errdefer a.destroy(self);
        self.allocator = a;
        const format: rv.execution_profile.SecpPacketFormat = if (profile == .ethereum_services_v1) .big_endian_bytes_v1 else .little_endian_words_v2;
        const tags = [_]u64{ rv.execution_profile.KECCAK_TAG, if (profile == .ethereum_services_v1) rv.execution_profile.SECP_ADD_TAG else rv.execution_profile.SECP_ADD_WORD_TAG, if (profile == .ethereum_services_v1) rv.execution_profile.SECP_DOUBLE_TAG else rv.execution_profile.SECP_DOUBLE_WORD_TAG };
        // K uses a separate25word buffer; ADD/DOUBLE alias the same first point.
        // Tags/pointers enter via LD, so the CPU authenticates their memory inputs.
        self.memory = rv.memory.Memory.init(a, .{});
        errdefer self.memory.deinit();
        const memory = &self.memory;
        try memory.map(.{ .start = pc, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = pointer, .size = 512, .permissions = .{ .read = true, .write = true } });
        for (program, 0..) |raw, i| {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, raw, .little);
            try memory.initialize(pc + 4 * i, &b);
        }
        const initial_words = wordsFor(format);
        var initial: [64]u64 = @splat(0);
        @memcpy(initial[0..24], &initial_words);
        // B0..23secppacket; B24..48Kbuffer; B49..54immutablearguments.
        initial[49] = 17;
        initial[50] = pointer + 24 * 8;
        initial[51] = tags[0];
        initial[52] = pointer;
        initial[53] = tags[1];
        initial[54] = tags[2];
        self.initial_words = initial;
        for (initial, 0..) |word, i| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, word, .little);
            try memory.initialize(pointer + 8 * i, &b);
        }
        var cpu = rv.machine.Cpu.init(pc, 0);
        cpu.regs[1] = 0x9234567880000001;
        cpu.regs[2] = 0xfffffffffffffff4;
        cpu.regs[8] = pointer + 49 * 8;
        const initial_registers = cpu.regs;
        var session = try rv.ethereum_services.Session.initWithProfile(a, cpu, memory, .{}, profile);
        defer session.deinit();
        const records = &self.records;
        const kcalls = &self.kcalls;
        const scalls = &self.scalls;
        var capture = try rv.boundary_capture.Capture.init(a, 0, program.len, 64);
        defer capture.deinit();
        var ki: usize = 0;
        var si: usize = 0;
        var reg_clocks: [32]u32 = @splat(0);
        var mem_clocks: [64]u32 = @splat(0);
        for (records, 0..) |*record, i| {
            var event: rv.ethereum_services.Event = undefined;
            record.* = (try session.step(&event)) orelse blk: {
                switch (event) {
                    .keccak => |call| {
                        kcalls[ki] = call;
                        ki += 1;
                        for (0..25) |lane| mem_clocks[@intCast((call.pointer - pointer) / 8 + lane)] = @intCast(4 * call.clock);
                    },
                    .secp => |call| {
                        scalls[si] = call;
                        si += 1;
                        for (0..call.wordCount()) |lane| mem_clocks[@intCast((call.pointer - pointer) / 8 + lane)] = @intCast(4 * call.clock);
                    },
                }
                break :blk event.retirement();
            };
            if (record.opcode == .ECALL) try capture.appendEvent(event, memory) else try capture.append(record.*, memory);
            const decoded = try rv.execution_profile.decode(profile, record.instruction);
            const effects = rv.execution_profile.effects(profile, record.opcode);
            if (effects.reads_rs1 and decoded.rs1 != 0) reg_clocks[decoded.rs1] = @intCast(4 * i + 1);
            if (effects.reads_rs2 and decoded.rs2 != 0) reg_clocks[decoded.rs2] = @intCast(4 * i + 2);
            if (effects.writes_rd and decoded.rd != 0) reg_clocks[decoded.rd] = @intCast(4 * i + 3);
            if (record.memory) |mem_event| mem_clocks[@intCast((mem_event.address.toInt() - pointer) / 8)] = @intCast(4 * i + 4);
        }
        try std.testing.expectEqual(@as(usize, 1), ki);
        try std.testing.expectEqual(@as(usize, 2), si);
        const cell_storage = &self.cell_storage;
        const clock_storage = &self.clock_storage;
        var count: usize = 0;
        for (mem_clocks, 0..) |clock, i| if (clock != 0) {
            cell_storage[count] = .{ .address = pointer + 8 * i, .initial = initial[i], .final = try memory.load(pointer + 8 * i, 8), .readable = true, .writable = true };
            clock_storage[count] = clock;
            count += 1;
        };
        const cells = cell_storage[0..count];
        const clocks = clock_storage[0..count];
        self.public = Service.Public{ .execution_profile = profile, .arithmetic_policy = .division_multiplication_services_v3, .multiplication_requests = 1, .state_policy = .cyclic_v2, .keccak_calls = 1, .division_requests = 1, .secp = .{ .add = .{ .roster = .present, .calls = 1, .geometry = try SecpCtx.Source.Geometry.minimal(.add, 1) }, .double = .{ .roster = .present, .calls = 1, .geometry = try SecpCtx.Source.Geometry.minimal(.double, 1) } }, .statement = .{ .program = .{ .base = pc, .words = &program }, .steps = program.len, .initial_pc = pc, .final_pc = session.keccak.base.cpu.pc, .initial_registers = initial_registers, .final_registers = session.keccak.base.cpu.regs, .cells = cells, .memory_clocks = clocks, .register_clocks = reg_clocks, .opcodes = try air.program.opcode_policy.derive(.{ .base = pc, .words = &program }, profile) } };
        self.captured = try capture.sorted(a);
        return self;
    }
    pub fn deinit(self: *Fixture) void {
        const a = self.allocator;
        a.free(self.captured);
        self.memory.deinit();
        a.destroy(self);
    }
};
