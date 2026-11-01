//! Execution-only CANDIDATE instructions for profile
//! `ethereum_services_v3_candidate_isa`: a Zbb subset and the Zba extension of
//! the RISC-V Bit-Manipulation ISA-extensions spec (v1.0.0), RV64 encodings.
//!
//! The admitted decoder (decode.zig), execution_profile.zig, compact tape and
//! everything the prover reads are untouched. Every encoding here is illegal in
//! the admitted RV64IM decoder; the execution tool tries this decoder only after
//! the admitted step reported `IllegalInstruction` (no architectural change
//! happened), executes the instruction here and retires exactly one instruction.
//! Results that use it are evidence for an ISA proposal, never promotable.
//! Rules: autoresearch/guest_efficiency/CONTEXT.md ("Candidate instructions").
const std = @import("std");
const machine = @import("machine.zig");

pub const Op = enum {
    // Zbb
    andn, orn, xnor,
    clz, clzw, ctz, ctzw, cpop, cpopw,
    max, maxu, min, minu,
    sext_b, sext_h, zext_h,
    rol, rolw, ror, rori, roriw, rorw,
    orc_b, rev8,
    // Zba
    sh1add, sh2add, sh3add,
    add_uw, sh1add_uw, sh2add_uw, sh3add_uw, slli_uw,
};

/// Serialized as `candidate_isa_counts: {name: retired}`.
pub const Counts = blk: {
    const ops = @typeInfo(Op).@"enum".fields;
    var fields: [ops.len]std.builtin.Type.StructField = undefined;
    for (ops, 0..) |op, i| fields[i] = .{ .name = op.name, .type = u64, .default_value_ptr = &@as(u64, 0), .is_comptime = false, .alignment = @alignOf(u64) };
    break :blk @Type(.{ .@"struct" = .{ .layout = .auto, .fields = &fields, .decls = &.{}, .is_tuple = false } });
};

pub fn bump(counts: *Counts, op: Op) void {
    switch (op) {
        inline else => |o| @field(counts, @tagName(o)) += 1,
    }
}

pub const Decoded = struct { op: Op, rd: u5, rs1: u5, rs2: u5, shamt: u6 = 0 };

const OP: u7 = 0b0110011;
const OP_32: u7 = 0b0111011;
const OP_IMM: u7 = 0b0010011;
const OP_IMM_32: u7 = 0b0011011;

/// Decodes only the candidate subset; null for everything else (including all
/// admitted RV64IM encodings).
pub fn decode(word: u32) ?Decoded {
    const opcode: u7 = @truncate(word);
    const rd: u5 = @truncate(word >> 7);
    const f3: u3 = @truncate(word >> 12);
    const rs1: u5 = @truncate(word >> 15);
    const rs2: u5 = @truncate(word >> 20);
    const f7: u7 = @truncate(word >> 25);
    const imm12: u12 = @truncate(word >> 20);
    const d = struct {
        fn r(op: Op, w: u32) Decoded {
            return .{ .op = op, .rd = @truncate(w >> 7), .rs1 = @truncate(w >> 15), .rs2 = @truncate(w >> 20) };
        }
    };
    switch (opcode) {
        OP => {
            const op: Op = switch (f7) {
                0b0100000 => switch (f3) {
                    0b111 => .andn,
                    0b110 => .orn,
                    0b100 => .xnor,
                    else => return null,
                },
                0b0000101 => switch (f3) {
                    0b110 => .max,
                    0b111 => .maxu,
                    0b100 => .min,
                    0b101 => .minu,
                    else => return null,
                },
                0b0110000 => switch (f3) {
                    0b001 => .rol,
                    0b101 => .ror,
                    else => return null,
                },
                0b0010000 => switch (f3) {
                    0b010 => .sh1add,
                    0b100 => .sh2add,
                    0b110 => .sh3add,
                    else => return null,
                },
                else => return null,
            };
            return d.r(op, word);
        },
        OP_32 => {
            const op: Op = switch (f7) {
                0b0000100 => switch (f3) {
                    0b000 => .add_uw,
                    // zext.h (RV64) is the rs2 = 0 case of the packw encoding.
                    0b100 => if (rs2 == 0) .zext_h else return null,
                    else => return null,
                },
                0b0010000 => switch (f3) {
                    0b010 => .sh1add_uw,
                    0b100 => .sh2add_uw,
                    0b110 => .sh3add_uw,
                    else => return null,
                },
                0b0110000 => switch (f3) {
                    0b001 => .rolw,
                    0b101 => .rorw,
                    else => return null,
                },
                else => return null,
            };
            return d.r(op, word);
        },
        OP_IMM => switch (f3) {
            0b001 => {
                const op: Op = switch (imm12) {
                    0x600 => .clz,
                    0x601 => .ctz,
                    0x602 => .cpop,
                    0x604 => .sext_b,
                    0x605 => .sext_h,
                    else => return null,
                };
                return .{ .op = op, .rd = rd, .rs1 = rs1, .rs2 = 0 };
            },
            0b101 => {
                if (imm12 == 0x287) return .{ .op = .orc_b, .rd = rd, .rs1 = rs1, .rs2 = 0 };
                if (imm12 == 0x6b8) return .{ .op = .rev8, .rd = rd, .rs1 = rs1, .rs2 = 0 };
                if (word >> 26 == 0b011000) return .{ .op = .rori, .rd = rd, .rs1 = rs1, .rs2 = 0, .shamt = @truncate(word >> 20) };
                return null;
            },
            else => return null,
        },
        OP_IMM_32 => switch (f3) {
            0b001 => {
                if (word >> 26 == 0b000010) return .{ .op = .slli_uw, .rd = rd, .rs1 = rs1, .rs2 = 0, .shamt = @truncate(word >> 20) };
                const op: Op = switch (imm12) {
                    0x600 => .clzw,
                    0x601 => .ctzw,
                    0x602 => .cpopw,
                    else => return null,
                };
                return .{ .op = op, .rd = rd, .rs1 = rs1, .rs2 = 0 };
            },
            0b101 => {
                if (f7 == 0b0110000) return .{ .op = .roriw, .rd = rd, .rs1 = rs1, .rs2 = 0, .shamt = @truncate(word >> 20 & 31) };
                return null;
            },
            else => return null,
        },
        else => return null,
    }
}

fn sext32(x: u32) u64 {
    return @bitCast(@as(i64, @as(i32, @bitCast(x))));
}

/// Pure semantics: `a` = x[rs1], `b` = x[rs2] (unused for unary/immediate forms).
pub fn execute(inst: Decoded, a: u64, b: u64) u64 {
    const aw: u32 = @truncate(a);
    const sa: i64 = @bitCast(a);
    const sb: i64 = @bitCast(b);
    const zw: u64 = aw;
    return switch (inst.op) {
        .andn => a & ~b,
        .orn => a | ~b,
        .xnor => ~(a ^ b),
        .clz => @clz(a),
        .clzw => @clz(aw),
        .ctz => @ctz(a),
        .ctzw => @ctz(aw),
        .cpop => @popCount(a),
        .cpopw => @popCount(aw),
        .max => if (sa < sb) b else a,
        .maxu => @max(a, b),
        .min => if (sa < sb) a else b,
        .minu => @min(a, b),
        .sext_b => @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(a)))))),
        .sext_h => @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(a)))))),
        .zext_h => a & 0xffff,
        .rol => std.math.rotl(u64, a, @as(u6, @truncate(b))),
        .ror => std.math.rotr(u64, a, @as(u6, @truncate(b))),
        .rori => std.math.rotr(u64, a, inst.shamt),
        .rolw => sext32(std.math.rotl(u32, aw, @as(u5, @truncate(b)))),
        .rorw => sext32(std.math.rotr(u32, aw, @as(u5, @truncate(b)))),
        .roriw => sext32(std.math.rotr(u32, aw, @as(u5, @truncate(inst.shamt)))),
        .orc_b => blk: {
            var r: u64 = 0;
            inline for (0..8) |i| {
                if ((a >> (8 * i)) & 0xff != 0) r |= @as(u64, 0xff) << (8 * i);
            }
            break :blk r;
        },
        .rev8 => @byteSwap(a),
        .sh1add => b +% (a << 1),
        .sh2add => b +% (a << 2),
        .sh3add => b +% (a << 3),
        .add_uw => b +% zw,
        .sh1add_uw => b +% (zw << 1),
        .sh2add_uw => b +% (zw << 2),
        .sh3add_uw => b +% (zw << 3),
        .slli_uw => zw << inst.shamt,
    };
}

/// Executes the candidate instruction `word` at `cpu.pc` and retires it, or
/// returns null (CPU unchanged) when `word` is not a candidate encoding.
pub fn step(cpu: *machine.Cpu, word: u32, counts: *Counts) ?Op {
    const inst = decode(word) orelse return null;
    const result = execute(inst, cpu.read(inst.rs1), cpu.read(inst.rs2));
    if (inst.rd != 0) cpu.regs[inst.rd] = result;
    cpu.pc +%= 4;
    cpu.retired += 1;
    bump(counts, inst.op);
    return inst.op;
}
