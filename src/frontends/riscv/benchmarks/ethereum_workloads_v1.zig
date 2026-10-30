//! Deterministic bounded Ethereum-profile workloads for complete execution
//! profiling. These synthetic programs expose the workload mix explicitly;
//! their results are never labeled as Ethereum block proofs.
const std = @import("std");
const Elf = @import("../runner/guest_precompile/test_elf.zig");
const Custom = @import("../isa/custom0.zig");
pub const Kind = enum { keccak_heavy, memory_heavy, mixed_ethereum };
pub const instruction_count = 40;
pub const data_size = 384;
pub const Image = @TypeOf(Elf.buildReleaseProgram(instruction_count, @as(*const [instruction_count]u32, undefined), data_size, .rv32im_zkvm_ethereum_sha_v1));
pub const Owned = struct {
    elf: Image,
    cycles: u64,
    output: [43]u8,
    kind: Kind,
    iterations: u32,
    keccak_calls: u32,
    recovery_calls: u32,
    native_ram_words: u32,
    native_rounds_per_call: u32,
};
fn immediate(opcode: u7, funct3: u3, rd: u5, rs: u5, value: i32) u32 {
    return (@as(u32, @bitCast(value)) & 4095) << 20 | @as(u32, rs) << 15 | @as(u32, funct3) << 12 | @as(u32, rd) << 7 | opcode;
}
fn store(rs: u5, base: u5, offset: u12) u32 {
    return @as(u32, offset >> 5) << 25 | @as(u32, rs) << 20 | @as(u32, base) << 15 | 2 << 12 | @as(u32, offset & 31) << 7 | 0x23;
}
fn branch(rs: u5, offset: i32) u32 {
    const bits: u32 = @bitCast(offset);
    return ((bits >> 12) & 1) << 31 | ((bits >> 5) & 63) << 25 | @as(u32, rs) << 15 | 1 << 12 | ((bits >> 1) & 15) << 8 | ((bits >> 11) & 1) << 7 | 0x63;
}
pub fn make(kind: Kind, iterations: u32) !Owned {
    if (iterations == 0 or iterations > 32768 or (kind != .memory_heavy and iterations > 1024)) return error.WorkloadIterationLimit;
    var code: [instruction_count]u32 = @splat(0x13);
    var at: usize = 0;
    const Emit = struct {
        fn put(c: *[instruction_count]u32, i: *usize, op: u32) void {
            c[i.*] = op;
            i.* += 1;
        }
    };
    Emit.put(&code, &at, 0x001002b7); // x5 = recovery record.
    Emit.put(&code, &at, immediate(0x13, 0, 5, 5, 256));
    Emit.put(&code, &at, immediate(0x13, 0, 6, 5, 168)); // Adjacent Keccak state.
    if (kind == .mixed_ethereum) Emit.put(&code, &at, Custom.encodeSecp256k1Recover(5));
    Emit.put(&code, &at, 0x00200537); // x10 = first-touch stack region 0x200000.
    Emit.put(&code, &at, immediate(0x13, 0, 9, 0, 0)); // Checksum.
    Emit.put(&code, &at, ((iterations + 2048) & 0xfffff000) | 7 << 7 | 0x37);
    const low: i32 = @as(i32, @intCast(iterations)) - @as(i32, @intCast((iterations + 2048) & 0xfffff000));
    Emit.put(&code, &at, immediate(0x13, 0, 7, 7, low));
    const loop_start = at;
    if (kind != .memory_heavy) Emit.put(&code, &at, Custom.encodeKeccakf(6));
    const native_rounds: u32 = if (kind == .mixed_ethereum) 512 else 1;
    if (kind == .mixed_ethereum) Emit.put(&code, &at, immediate(0x13, 0, 12, 0, @intCast(native_rounds)));
    const native_loop_start = at;
    if (kind != .keccak_heavy) {
        Emit.put(&code, &at, store(7, 10, 0));
        Emit.put(&code, &at, immediate(0x03, 2, 8, 10, 0));
        Emit.put(&code, &at, @as(u32, 8) << 20 | 9 << 15 | 9 << 7 | 0x33); // add checksum,x8
        Emit.put(&code, &at, @as(u32, 7) << 20 | 8 << 15 | 4 << 12 | 11 << 7 | 0x33); // xor
        Emit.put(&code, &at, immediate(0x13, 7, 11, 11, 255));
        Emit.put(&code, &at, immediate(0x13, 0, 10, 10, 4));
    }
    if (kind == .mixed_ethereum) {
        Emit.put(&code, &at, immediate(0x13, 0, 12, 12, -1));
        Emit.put(&code, &at, branch(12, -4 * @as(i32, @intCast(at - native_loop_start))));
    }
    Emit.put(&code, &at, immediate(0x13, 0, 7, 7, -1));
    Emit.put(&code, &at, branch(7, -4 * @as(i32, @intCast(at - loop_start))));
    const loop_length = at - loop_start + (native_rounds - 1) * 8;
    Emit.put(&code, &at, 0x00100137);
    Emit.put(&code, &at, immediate(0x13, 0, 3, 0, 1));
    Emit.put(&code, &at, immediate(0x13, 0, 4, 0, 43));
    Emit.put(&code, &at, store(9, 2, 8));
    Emit.put(&code, &at, store(4, 2, 4));
    Emit.put(&code, &at, store(3, 2, 40));
    Emit.put(&code, &at, store(3, 2, 0));
    Emit.put(&code, &at, 0x0000006f);
    var image = Elf.buildReleaseProgram(instruction_count, &code, data_size, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, image[264..268], .little);
    for ([6]usize{ 2, 3, 5, 6, 7, 8 }, [6]u32{ 0x100100, data_size, 0x200000, 0x600000, 0x100300, 0x100310 }) |index, value|
        std.mem.writeInt(u32, image[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    if (kind == .mixed_ethereum) {
        const valid = Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
        const record_size = @import("../isa/ethereum_signer_recovery.zig").record_size;
        @memcpy(image[640 + instruction_count * 4 ..][0..record_size], valid[640 + 8 * 4 ..][0..record_size]);
    }
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const checksum = if (kind == .keccak_heavy) 0 else native_rounds * iterations * (iterations + 1) / 2;
    std.mem.writeInt(u32, output[0..4], checksum, .little);
    return .{ .elf = image, .cycles = loop_start + @as(u64, iterations) * loop_length + 7, .output = output, .kind = kind, .iterations = iterations, .keccak_calls = if (kind == .memory_heavy) 0 else iterations, .recovery_calls = @intFromBool(kind == .mixed_ethereum), .native_rounds_per_call = if (kind == .keccak_heavy) 0 else native_rounds, .native_ram_words = if (kind == .keccak_heavy) 0 else native_rounds * iterations };
}
