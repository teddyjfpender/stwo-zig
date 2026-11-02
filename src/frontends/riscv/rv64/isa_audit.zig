//! Static ISA audit of RV64 ELF files (executables or relocatable objects).
//! Every 4-byte word of every SHF_EXECINSTR section is decoded with the SAME
//! decoders the executor and ROM builder use (`decode.decodeFor`) and with the
//! candidate Zbb/Zba decoder, and classified:
//!   rv64im        - admitted by every profile;
//!   zbb_binary    - admitted only by `decode.Isa.rv64im_zbb_binary`;
//!   other_bitmanip- a Zbb/Zba encoding OUTSIDE the admitted subset (must be 0);
//!   unimp         - the canonical `unimp` word 0xc0001073 (`__builtin_trap`)
//!                   or the all-zero word (linker alignment padding); both are
//!                   illegal under every profile, so they can only trap;
//!   undecodable   - anything else (data/padding in text, other extensions).
//! Usage: rv64-isa-audit [--require-subset] FILE...  ; prints one JSON object
//! per file. With --require-subset, exits 1 if any file has other_bitmanip > 0
//! or undecodable > 0.
const std = @import("std");
const isa = @import("decode.zig");
const cisa = @import("candidate_isa.zig");

pub const Class = enum { rv64im, zbb_binary, other_bitmanip, unimp, undecodable };
pub const UNIMP: u32 = 0xc0001073;
pub fn classify(word: u32) Class {
    if (isa.Instruction.decode(word)) |_| return .rv64im else |_| {}
    if (isa.decodeZbbBinary(word) != null) return .zbb_binary;
    if (cisa.decode(word) != null) return .other_bitmanip;
    if (word == UNIMP or word == 0) return .unimp;
    return .undecodable;
}

pub const Report = struct {
    rv64im: u64 = 0,
    zbb_binary: u64 = 0,
    other_bitmanip: u64 = 0,
    unimp: u64 = 0,
    undecodable: u64 = 0,
    zbb_ops: [7]u64 = @splat(0),
    other_ops: [@typeInfo(cisa.Op).@"enum".fields.len]u64 = @splat(0),
    first_other: ?u64 = null,
    first_undecodable: ?u64 = null,
    pub fn add(self: *Report, word: u32, offset: u64) void {
        switch (classify(word)) {
            .rv64im => self.rv64im += 1,
            .zbb_binary => {
                self.zbb_binary += 1;
                const op = isa.decodeZbbBinary(word).?.opcode;
                self.zbb_ops[@intFromEnum(op) - isa.BASE_OPCODE_COUNT] += 1;
            },
            .other_bitmanip => {
                self.other_bitmanip += 1;
                self.other_ops[@intFromEnum(cisa.decode(word).?.op)] += 1;
                if (self.first_other == null) self.first_other = offset;
            },
            .unimp => self.unimp += 1,
            .undecodable => {
                self.undecodable += 1;
                if (self.first_undecodable == null) self.first_undecodable = offset;
            },
        }
    }
};

pub fn auditBytes(bytes: []const u8) !Report {
    if (bytes.len < @sizeOf(std.elf.Elf64_Ehdr)) return error.NotElf64;
    const header: *align(1) const std.elf.Elf64_Ehdr = @ptrCast(bytes.ptr);
    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF") or header.e_ident[std.elf.EI_CLASS] != std.elf.ELFCLASS64 or header.e_machine != .RISCV) return error.NotRiscv64Elf;
    var report = Report{};
    const shoff: usize = @intCast(header.e_shoff);
    for (0..header.e_shnum) |i| {
        const at = shoff + i * @sizeOf(std.elf.Elf64_Shdr);
        if (at + @sizeOf(std.elf.Elf64_Shdr) > bytes.len) return error.TruncatedElf;
        const sh: *align(1) const std.elf.Elf64_Shdr = @ptrCast(bytes[at..].ptr);
        if (sh.sh_type != std.elf.SHT_PROGBITS or sh.sh_flags & std.elf.SHF_EXECINSTR == 0) continue;
        const start: usize = @intCast(sh.sh_offset);
        const size: usize = @intCast(sh.sh_size);
        if (start + size > bytes.len) return error.TruncatedElf;
        // IALIGN=32 and no C extension: instructions are 4-byte aligned words.
        if (size % 4 != 0) return error.UnalignedTextSection;
        var off: usize = 0;
        while (off < size) : (off += 4) report.add(std.mem.readInt(u32, bytes[start + off ..][0..4], .little), sh.sh_addr + off);
    }
    return report;
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    var require = false;
    var failed = false;
    var out_buffer: [4096]u8 = undefined;
    var out = std.fs.File.stdout().writer(&out_buffer);
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--require-subset")) {
            require = true;
            continue;
        }
        const bytes = try std.fs.cwd().readFileAlloc(a, arg, 1 << 30);
        defer a.free(bytes);
        const r = try auditBytes(bytes);
        if (r.other_bitmanip != 0 or r.undecodable != 0) failed = true;
        try out.interface.print("{{\"file\":\"{s}\",\"rv64im\":{d},\"zbb_binary\":{d},\"other_bitmanip\":{d},\"unimp\":{d},\"undecodable\":{d},\"zbb_ops\":{{", .{ arg, r.rv64im, r.zbb_binary, r.other_bitmanip, r.unimp, r.undecodable });
        const names = [_][]const u8{ "andn", "orn", "xnor", "rev8", "sext.b", "sext.h", "zext.h" };
        for (names, r.zbb_ops, 0..) |n, c, i| try out.interface.print("{s}\"{s}\":{d}", .{ if (i == 0) "" else ",", n, c });
        try out.interface.writeAll("},\"other_ops\":{");
        var first = true;
        inline for (@typeInfo(cisa.Op).@"enum".fields, 0..) |f, i| if (r.other_ops[i] != 0) {
            try out.interface.print("{s}\"{s}\":{d}", .{ if (first) "" else ",", f.name, r.other_ops[i] });
            first = false;
        };
        try out.interface.writeAll("}");
        if (r.first_other) |o| try out.interface.print(",\"first_other_at\":{d}", .{o});
        if (r.first_undecodable) |o| try out.interface.print(",\"first_undecodable_at\":{d}", .{o});
        try out.interface.writeAll("}\n");
    }
    try out.interface.flush();
    if (require and failed) std.process.exit(1);
}

test "classes are disjoint and pinned" {
    try std.testing.expectEqual(Class.rv64im, classify(0x00c5f533)); // and
    try std.testing.expectEqual(Class.zbb_binary, classify(0x40c5f533)); // andn
    try std.testing.expectEqual(Class.zbb_binary, classify(0x6b85d513)); // rev8
    try std.testing.expectEqual(Class.zbb_binary, classify(0x0805c53b)); // zext.h
    try std.testing.expectEqual(Class.other_bitmanip, classify(0x60059513)); // clz
    try std.testing.expectEqual(Class.other_bitmanip, classify(0x0ac5f533)); // maxu
    try std.testing.expectEqual(Class.other_bitmanip, classify(0x63f5d513)); // rori
    try std.testing.expectEqual(Class.undecodable, classify(0x08c5c53b)); // packw a0,a1,a2 (Zbkb)
    try std.testing.expectEqual(Class.undecodable, classify(0x6985d513)); // rev8 RV32 encoding
    try std.testing.expectEqual(Class.unimp, classify(UNIMP));
    try std.testing.expectEqual(Class.unimp, classify(0));
    try std.testing.expectError(error.IllegalInstruction, isa.decodeFor(.rv64im_zbb_binary, 0));
    try std.testing.expectError(error.IllegalInstruction, isa.decodeFor(.rv64im_zbb_binary, UNIMP));
}
