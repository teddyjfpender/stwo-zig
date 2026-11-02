//! Optional real-ELF admitted-policy diagnostic, never an observed-path key.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
test "immutable executable ELF service opcode geometry diagnostic" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_RV64_SERVICE_GEOMETRY_ELF") catch return;
    defer a.free(path);
    const output = try std.process.getEnvVarOwned(a, "STWO_RV64_SERVICE_GEOMETRY_OUTPUT");
    defer a.free(output);
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 64 * 1024 * 1024);
    defer a.free(bytes);
    _ = try rv.elf.inspect(bytes, .{});
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(a);
    const table = std.mem.readInt(u64, bytes[32..40], .little);
    const count = std.mem.readInt(u16, bytes[56..58], .little);
    for (0..count) |i| {
        const at: usize = @intCast(table + 56 * i);
        if (std.mem.readInt(u32, bytes[at..][0..4], .little) != 1 or std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little) & 1 == 0) continue;
        const file: usize = @intCast(std.mem.readInt(u64, bytes[at + 8 ..][0..8], .little));
        const filesz: usize = @intCast(std.mem.readInt(u64, bytes[at + 32 ..][0..8], .little));
        const memsz: usize = @intCast(std.mem.readInt(u64, bytes[at + 40 ..][0..8], .little));
        if (memsz % 4 != 0) return error.InvalidExecutableWordGeometry;
        for (0..memsz / 4) |j| {
            var raw: [4]u8 = @splat(0);
            for (&raw, 0..) |*b, k| if (4 * j + k < filesz) {
                b.* = bytes[file + 4 * j + k];
            };
            try words.append(a, std.mem.readInt(u32, &raw, .little));
        }
    }
    const allowed = try air.program.opcode_policy.derive(.{ .base = 0, .words = words.items }, .keccak_service_v1);
    var opcodes: [65]rv.decode.Opcode = undefined;
    var n: usize = 0;
    for (allowed, 0..) |yes, op| if (yes) {
        opcodes[n] = @enumFromInt(op);
        n += 1;
    };
    const plan = try air.encoding.Plan.fromOpcodesWithProfiles(opcodes[0..n], .division_service_v2, .keccak_service_v1);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const interaction = air.layout.INTERACTION + 8 + air.range.cpu.interactionCount(&plan) + air.range.table_cpu.interactionCount(&plan, .byte_and) + air.range.table_cpu.interactionCount(&plan, .byte_shift) + 8 + 8;
    const mul_plan = air.arithmetic.division.cpu.planWithMultiplication(opcodes[0..n], .keccak_service_v1);
    const mul_interaction = air.layout.INTERACTION + 8 + air.range.cpu.interactionCount(&mul_plan) + air.range.table_cpu.interactionCount(&mul_plan, .byte_and) + air.range.table_cpu.interactionCount(&mul_plan, .byte_shift) + 8 + 8 + 8;
    std.debug.print("immutable ELF MUL model oldCPUmain={d} new={d} oldInter={d} newInterIncludingMulBus={d} oldBYTE={d} newBYTE={d} providerMain={d}/inter={d}/BYTE={d}\n", .{ plan.main_count + air.full.frame.width(.keccak_service_v1), mul_plan.main_count + air.full.frame.width(.keccak_service_v1), interaction, mul_interaction, plan.range_count, mul_plan.range_count, air.arithmetic.multiplication.layout.MAIN, air.arithmetic.multiplication.layout.INTERACTION, air.arithmetic.multiplication.layout.BYTE_QUERIES });
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-immutable-rom-cpu-geometry-v1", .opcodes_from_immutable_rom = true, .execution_profile = "keccak_service_v1", .arithmetic_policy = "division_service_v2", .elf_sha256 = hex[0..], .executable_words = words.items.len, .admitted_opcodes = allowed, .admitted_opcode_count = n, .fixed_columns = 3, .main_columns = plan.main_count + air.full.frame.width(.keccak_service_v1), .interaction_columns = interaction, .range_queries_per_row = plan.range_count, .multiplication_service_model = .{ .arithmetic_policy = "division_multiplication_services_v3", .proven = false, .main_columns = mul_plan.main_count + air.full.frame.width(.keccak_service_v1), .interaction_columns_including_cpu_mul_bus8 = mul_interaction, .range_queries_per_row = mul_plan.range_count, .provider_main = air.arithmetic.multiplication.layout.MAIN, .provider_interaction = air.arithmetic.multiplication.layout.INTERACTION, .provider_byte_queries_per_padded_row = air.arithmetic.multiplication.layout.BYTE_QUERIES } }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.cwd().writeFile(.{ .sub_path = output, .data = json });
}
