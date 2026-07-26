//! Canonical RVFI-shaped retirement trace for formal-model differentials.
//!
//! Format:
//! ```json
//! {
//!   "schema": "stwo-riscv-retirement-trace-v1",
//!   "profile": "rv32im-zkvm-v1",
//!   "initial_pc": 65536,
//!   "retirements": [{
//!     "order": 0, "pc": 65536, "instruction": 1048723,
//!     "rd": 1, "rd_value": 1, "next_pc": 65540,
//!     "memory": {
//!       "address": 0, "read_mask": 0, "read_value": 0,
//!       "write_mask": 0, "write_value": 0
//!     }
//!   }],
//!   "final_pc": 65544,
//!   "final_regs": [0, 42, ...],
//!   "total_steps": 5
//! }
//! ```

const std = @import("std");
const decode = @import("../isa/decode.zig");
const profile = @import("../isa/profile.zig");
const trace_mod = @import("trace.zig");
const cpu_mod = @import("cpu.zig");

pub const SCHEMA = "stwo-riscv-retirement-trace-v1";

/// Write every successful RV32IM retirement in the fields shared with RVFI.
/// ECALL/EBREAK host events may exist in a diagnostic execution trace, but
/// they are outside the proof profile and are intentionally omitted here.
pub fn writeTraceJson(
    writer: anytype,
    exec_trace: *const trace_mod.Trace,
    final_cpu: cpu_mod.Cpu,
) !void {
    try writer.print(
        "{{\"schema\":\"{s}\",\"profile\":\"{s}\",\"initial_pc\":{d},\"retirements\":[",
        .{ SCHEMA, profile.name, exec_trace.initial_pc },
    );
    var order: usize = 0;
    for (exec_trace.rows.items) |row| {
        _ = decode.proofOpcode(row.opcode) catch continue;
        if (order != 0) try writer.writeByte(',');
        const usage = decode.operandUsage(row.opcode);
        const rd: u5 = if (usage.writes_rd) row.rd else 0;
        const rd_value = if (usage.writes_rd and row.rd != 0) row.rd_val else 0;
        const width = decode.memoryWidthBytes(row.opcode) orelse 0;
        const mask: u8 = if (width == 0)
            0
        else
            (@as(u8, 1) << @intCast(width)) - 1;
        const value_mask = memoryValueMask(width);
        try writer.print(
            "{{\"order\":{d},\"pc\":{d},\"instruction\":{d}," ++
                "\"rd\":{d},\"rd_value\":{d},\"next_pc\":{d}," ++
                "\"memory\":{{\"address\":{d},\"read_mask\":{d}," ++
                "\"read_value\":{d},\"write_mask\":{d},\"write_value\":{d}}}}}",
            .{
                order,
                row.pc,
                row.inst_word,
                rd,
                rd_value,
                row.next_pc,
                if (width == 0) 0 else row.mem_addr,
                if (row.is_load) mask else 0,
                if (row.is_load) row.mem_val & value_mask else 0,
                if (row.is_store) mask else 0,
                if (row.is_store) row.mem_val & value_mask else 0,
            },
        );
        order += 1;
    }
    try writer.writeAll("],");
    try writer.print("\"final_pc\":{d},\"final_regs\":[", .{final_cpu.pc});
    for (0..32) |i| {
        if (i > 0) try writer.writeAll(",");
        try writer.print("{d}", .{final_cpu.readReg(@intCast(i))});
    }
    try writer.writeAll("],");
    try writer.print("\"total_steps\":{d}}}", .{order});
}

fn memoryValueMask(width: u3) u32 {
    return switch (width) {
        0 => 0,
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        else => unreachable,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const runner = @import("mod.zig");

/// Build a minimal in-memory ELF with the given instructions at vaddr 0x10000.
fn buildTestElf(comptime n_insts: usize, instructions: [n_insts]u32) [84 + n_insts * 4]u8 {
    const code_size = n_insts * 4;
    var elf_buf: [84 + code_size]u8 = [_]u8{0} ** (84 + code_size);

    // ELF header
    elf_buf[0] = 0x7F;
    elf_buf[1] = 'E';
    elf_buf[2] = 'L';
    elf_buf[3] = 'F';
    elf_buf[4] = 1; // ELFCLASS32
    elf_buf[5] = 1; // ELFDATA2LSB
    elf_buf[6] = 1; // EI_VERSION
    elf_buf[16] = 2; // e_type = ET_EXEC
    elf_buf[18] = 0xF3; // e_machine = EM_RISCV
    elf_buf[20] = 1; // e_version
    // e_entry = 0x10000
    elf_buf[24] = 0x00;
    elf_buf[25] = 0x00;
    elf_buf[26] = 0x01;
    elf_buf[27] = 0x00;
    // e_phoff = 52
    elf_buf[28] = 52;
    // e_ehsize = 52
    elf_buf[40] = 52;
    // e_phentsize = 32
    elf_buf[42] = 32;
    // e_phnum = 1
    elf_buf[44] = 1;

    // Program header at offset 52
    elf_buf[52] = 1; // p_type = PT_LOAD
    elf_buf[56] = 84; // p_offset = 84
    // p_vaddr = 0x10000
    elf_buf[60] = 0x00;
    elf_buf[61] = 0x00;
    elf_buf[62] = 0x01;
    elf_buf[63] = 0x00;
    // p_filesz
    elf_buf[68] = code_size;
    // p_memsz
    elf_buf[72] = code_size;

    // Instructions at offset 84
    for (instructions, 0..) |inst_word, i| {
        const offset = 84 + i * 4;
        elf_buf[offset] = @truncate(inst_word);
        elf_buf[offset + 1] = @truncate(inst_word >> 8);
        elf_buf[offset + 2] = @truncate(inst_word >> 16);
        elf_buf[offset + 3] = @truncate(inst_word >> 24);
    }

    return elf_buf;
}

test "trace_dump: writeTraceJson produces well-formed JSON" {
    const alloc = std.testing.allocator;

    // ADDI x1, x0, 42  then  ECALL
    const elf = buildTestElf(2, .{
        0x02A00093, // ADDI x1, x0, 42
        0x00000073, // ECALL
    });

    var result = try runner.run(alloc, &elf, 1000);
    defer result.deinit();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);

    try writeTraceJson(buf.writer(alloc), &result.execution_trace, result.cpu_final);

    // Parse the JSON to verify it is well-formed.
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    try std.testing.expectEqualStrings(
        SCHEMA,
        root.get("schema").?.string,
    );
    try std.testing.expectEqualStrings(
        profile.name,
        root.get("profile").?.string,
    );

    // ECALL is an environment event, not a successful proof retirement.
    const total_steps = root.get("total_steps").?.integer;
    try std.testing.expectEqual(@as(i64, 1), total_steps);

    // Verify final_pc is present and numeric
    const final_pc = root.get("final_pc").?.integer;
    try std.testing.expect(final_pc > 0);

    // Verify final_regs has 32 entries
    const final_regs = root.get("final_regs").?.array;
    try std.testing.expectEqual(@as(usize, 32), final_regs.items.len);

    // x1 should be 42
    try std.testing.expectEqual(@as(i64, 42), final_regs.items[1].integer);

    // x0 is always 0
    try std.testing.expectEqual(@as(i64, 0), final_regs.items[0].integer);

    const retirements = root.get("retirements").?.array;
    try std.testing.expectEqual(@as(usize, 1), retirements.items.len);
    const first = retirements.items[0].object;
    try std.testing.expectEqual(@as(i64, 0x10000), first.get("pc").?.integer);
    try std.testing.expectEqual(@as(i64, 0x02A00093), first.get("instruction").?.integer);
    try std.testing.expectEqual(@as(i64, 1), first.get("rd").?.integer);
    try std.testing.expectEqual(@as(i64, 42), first.get("rd_value").?.integer);
    try std.testing.expectEqual(@as(i64, 0x10004), first.get("next_pc").?.integer);
}

test "trace_dump: multi-instruction trace with register side-effects" {
    const alloc = std.testing.allocator;

    // x1 = 10, x2 = 20, x3 = x1 + x2 = 30, ECALL
    const elf = buildTestElf(4, .{
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2
        0x00000073, // ECALL
    });

    var result = try runner.run(alloc, &elf, 1000);
    defer result.deinit();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);

    try writeTraceJson(buf.writer(alloc), &result.execution_trace, result.cpu_final);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const final_regs = root.get("final_regs").?.array;

    // x1=10, x2=20, x3=30
    try std.testing.expectEqual(@as(i64, 10), final_regs.items[1].integer);
    try std.testing.expectEqual(@as(i64, 20), final_regs.items[2].integer);
    try std.testing.expectEqual(@as(i64, 30), final_regs.items[3].integer);

    const total_steps = root.get("total_steps").?.integer;
    try std.testing.expectEqual(@as(i64, 3), total_steps);
}

test "trace_dump: load and store effects use RVFI byte masks and unshifted values" {
    const alloc = std.testing.allocator;
    const elf = buildTestElf(4, .{
        0x07F00093, // ADDI x1, x0, 0x7f
        0x00110023, // SB x1, 0(x2)
        0x00010183, // LB x3, 0(x2)
        0x00000073, // ECALL
    });
    var result = try runner.run(alloc, &elf, 1000);
    defer result.deinit();
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);
    try writeTraceJson(buf.writer(alloc), &result.execution_trace, result.cpu_final);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const rows = parsed.value.object.get("retirements").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), rows.len);
    const store = rows[1].object.get("memory").?.object;
    try std.testing.expectEqual(@as(i64, 1), store.get("write_mask").?.integer);
    try std.testing.expectEqual(@as(i64, 0x7f), store.get("write_value").?.integer);
    const load = rows[2].object.get("memory").?.object;
    try std.testing.expectEqual(@as(i64, 1), load.get("read_mask").?.integer);
    try std.testing.expectEqual(@as(i64, 0x7f), load.get("read_value").?.integer);
}
