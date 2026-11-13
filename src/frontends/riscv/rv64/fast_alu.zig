//! Bit-exact fast-path RV64 ALU dispatch over the engine-owned opcode enum.

pub fn For(comptime owner_context: anytype) type {
    const Op = owner_context.Op;
    const machine = owner_context.machine;
    const std = owner_context.std;
    return struct {
        pub inline fn alu(comptime op: Op, a: u64, b: u64, imm: u64) u64 {
            const sa: i64 = @bitCast(a);
            const sb: i64 = @bitCast(b);
            const aw: u32 = @truncate(a);
            const bw: u32 = @truncate(b);
            const sext32 = machine.sext32;
            return switch (op) {
                .add => a +% b,
                .sub => a -% b,
                .addi => a +% imm,
                .slt => @intFromBool(sa < sb),
                .sltu => @intFromBool(a < b),
                .slti => @intFromBool(sa < @as(i64, @bitCast(imm))),
                .sltiu => @intFromBool(a < imm),
                .@"and" => a & b,
                .@"or" => a | b,
                .xor => a ^ b,
                .andi => a & imm,
                .ori => a | imm,
                .xori => a ^ imm,
                .sll => a << @as(u6, @truncate(b)),
                .srl => a >> @as(u6, @truncate(b)),
                .sra => @bitCast(sa >> @as(u6, @truncate(b))),
                .slli => a << @as(u6, @truncate(imm)),
                .srli => a >> @as(u6, @truncate(imm)),
                .srai => @bitCast(sa >> @as(u6, @truncate(imm))),
                .addw => sext32(aw +% bw),
                .subw => sext32(aw -% bw),
                .addiw => sext32(aw +% @as(u32, @truncate(imm))),
                .sllw => sext32(aw << @as(u5, @truncate(b))),
                .srlw => sext32(aw >> @as(u5, @truncate(b))),
                .sraw => sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(b)))),
                .slliw => sext32(aw << @as(u5, @truncate(imm))),
                .srliw => sext32(aw >> @as(u5, @truncate(imm))),
                .sraiw => sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(imm)))),
                .mul => a *% b,
                .mulhu => @intCast((@as(u128, a) * b) >> 64),
                .mulh => @truncate(@as(u128, @bitCast(@as(i128, sa) * sb)) >> 64),
                .mulhsu => @truncate(@as(u128, @bitCast(@as(i128, sa) * @as(i128, b))) >> 64),
                .mulw => sext32(aw *% bw),
                .div => machine.divSigned64(sa, sb, false),
                .rem => machine.divSigned64(sa, sb, true),
                .divu => if (b == 0) std.math.maxInt(u64) else a / b,
                .remu => if (b == 0) a else a % b,
                .divw => sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), false)),
                .remw => sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), true)),
                .divuw => sext32(if (bw == 0) std.math.maxInt(u32) else aw / bw),
                .remuw => sext32(if (bw == 0) aw else aw % bw),
                .andn => a & ~b,
                .orn => a | ~b,
                .xnor => ~(a ^ b),
                .rev8 => @byteSwap(a),
                .sext_b => @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(a)))))),
                .sext_h => @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(a)))))),
                .zext_h => a & 0xffff,
                else => @compileError("not an ALU op"),
            };
        }
    };
}
