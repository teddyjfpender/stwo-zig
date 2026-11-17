//! Traced retirement and boundary capture borrowing the existing fast engine state.

pub fn For(comptime owner_context: anytype) type {
    const std = owner_context.std;
    const machine = owner_context.machine;
    const mem = owner_context.mem;
    const compact_tape = owner_context.compact_tape;
    const PAGE_SHIFT = owner_context.PAGE_SHIFT;
    const SINK = owner_context.SINK;
    const Op = owner_context.Op;
    const Exit = owner_context.Exit;
    const UNKNOWN_MASK = owner_context.UNKNOWN_MASK;
    const Trace = owner_context.Trace;
    const Engine = owner_context.Engine;
    const alu = owner_context.alu;
    const slotOf = owner_context.slotOf;
    const fill = owner_context.fill;
    const captureMask = owner_context.captureMask;
    return struct {
        pub fn runTraced(self: *Engine, cpu: *machine.Cpu, limit: u64, trace: *Trace) Exit {
            if (cpu.retired >= limit) return .limit;
            var i: usize = slotOf(self, cpu.pc) orelse return .slow;
            std.debug.assert(self.cmask.len == self.rights.len);
            var r: [33]u64 = undefined;
            @memcpy(r[0..32], &cpu.regs);
            r[0] = 0;
            r[SINK] = 0;
            const slots = self.slots.ptr;
            const blen = self.blen.ptr;
            const rd_tab = self.rd_tab;
            const wr_tab = self.wr_tab;
            const cmask = self.cmask;
            const code_lo = self.code_lo;
            const steps = trace.steps.ptr;
            const before = trace.memory_before;
            const cap = trace.capture;
            const start = trace.len;
            std.debug.assert(limit - cpu.retired <= trace.steps.len - start);
            const end_pos: usize = start + @as(usize, @intCast(limit - cpu.retired));
            std.debug.assert(before.capacity - before.items.len >= end_pos - start);
            var pos = start;
            var clocks = trace.clocks;
            const saved_zero = clocks[0];
            var divisions: u32 = 0;
            var multiplications: u32 = 0;
            sw: switch (Op.enter) {
                .enter => {
                    const n = blen[i];
                    if (n == 0 or n > end_pos - pos) break :sw;
                    continue :sw slots[i].op;
                },
                .slow => break :sw,
                .nop => {
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                    pos += 1;
                    i += 1;
                    continue :sw slots[i].op;
                },
                .li => {
                    const s = slots[i];
                    const tick: u32 = @intCast(4 * pos);
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = 0, .rhs = 0, .previous_rd = r[s.rd], .result = s.imm, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                    clocks[s.rd] = tick + 3;
                    r[s.rd] = s.imm;
                    r[SINK] = 0;
                    pos += 1;
                    i += 1;
                    continue :sw slots[i].op;
                },
                inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw, .andn, .orn, .xnor, .rev8, .sext_b, .sext_h, .zext_h => |op| {
                    const s = slots[i];
                    const x = r[s.rs1];
                    const y = r[s.rs2];
                    const v = alu(op, x, y, s.imm);
                    const tick: u32 = @intCast(4 * pos);
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = y, .previous_rd = r[s.rd], .result = v, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                    clocks[s.rs1] = tick + 1;
                    clocks[s.rs2] = tick + 2;
                    clocks[s.rd] = tick + 3;
                    switch (op) {
                        .div, .divu, .rem, .remu, .divw, .divuw, .remw, .remuw => divisions += 1,
                        .mul, .mulh, .mulhsu, .mulhu, .mulw => multiplications += 1,
                        else => {},
                    }
                    r[s.rd] = v;
                    r[SINK] = 0;
                    pos += 1;
                    i += 1;
                    continue :sw slots[i].op;
                },
                inline .lb, .lh, .lw, .ld, .lbu, .lhu, .lwu => |op| {
                    const s = slots[i];
                    const T = switch (op) {
                        .lb, .lbu => u8,
                        .lh, .lhu => u16,
                        .lw, .lwu => u32,
                        .ld => u64,
                        else => unreachable,
                    };
                    const x = r[s.rs1];
                    const address = x +% s.imm;
                    if (address & (@sizeOf(T) - 1) != 0) break :sw;
                    const index = address >> PAGE_SHIFT;
                    const base = (if (index < rd_tab.len) rd_tab[@intCast(index)] else null) orelse fill(self, index, false) orelse break :sw;
                    const m = if (cmask[@intCast(index)] != UNKNOWN_MASK) cmask[@intCast(index)] else captureMask(self, index);
                    if (m == 0) break :sw;
                    const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
                    const word = std.mem.readInt(u64, base[offset & ~@as(usize, 7) ..][0..8], .little);
                    const tick: u32 = @intCast(4 * pos);
                    if (!cap.fastWord(address & ~@as(u64, 7), word, word, @intCast(m), tick + 4)) break :sw;
                    const raw: T = @truncate(word >> @intCast((offset & 7) * 8));
                    const v: u64 = switch (op) {
                        .lb => @bitCast(@as(i64, @as(i8, @bitCast(raw)))),
                        .lh => @bitCast(@as(i64, @as(i16, @bitCast(raw)))),
                        .lw => @bitCast(@as(i64, @as(i32, @bitCast(raw)))),
                        else => raw,
                    };
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = 0, .previous_rd = r[s.rd], .result = v, .memory_index = @intCast(before.items.len), .flags = 0 };
                    before.appendAssumeCapacity(word);
                    clocks[s.rs1] = tick + 1;
                    clocks[s.rd] = tick + 3;
                    r[s.rd] = v;
                    r[SINK] = 0;
                    pos += 1;
                    i += 1;
                    continue :sw slots[i].op;
                },
                inline .sb, .sh, .sw, .sd => |op| {
                    const s = slots[i];
                    const T = switch (op) {
                        .sb => u8,
                        .sh => u16,
                        .sw => u32,
                        .sd => u64,
                        else => unreachable,
                    };
                    const x = r[s.rs1];
                    const y = r[s.rs2];
                    const address = x +% s.imm;
                    if (address & (@sizeOf(T) - 1) != 0) break :sw;
                    const index = address >> PAGE_SHIFT;
                    const base = (if (index < wr_tab.len) wr_tab[@intCast(index)] else null) orelse fill(self, index, true) orelse break :sw;
                    const m = if (cmask[@intCast(index)] != UNKNOWN_MASK) cmask[@intCast(index)] else captureMask(self, index);
                    if (m != 3) break :sw;
                    const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
                    const bytes = base[offset & ~@as(usize, 7) ..][0..8];
                    const word = std.mem.readInt(u64, bytes, .little);
                    const shift: u6 = @intCast((offset & 7) * 8);
                    const width_mask: u64 = std.math.maxInt(T);
                    const after = (word & ~(width_mask << shift)) | ((y & width_mask) << shift);
                    const tick: u32 = @intCast(4 * pos);
                    if (!cap.fastWord(address & ~@as(u64, 7), word, after, 3, tick + 4)) break :sw;
                    std.mem.writeInt(u64, bytes, after, .little);
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = y, .previous_rd = 0, .result = 0, .memory_index = @intCast(before.items.len), .flags = 0 };
                    before.appendAssumeCapacity(word);
                    clocks[s.rs1] = tick + 1;
                    clocks[s.rs2] = tick + 2;
                    pos += 1;
                    i += 1;
                    continue :sw slots[i].op;
                },
                inline .beq, .bne, .blt, .bge, .bltu, .bgeu => |op| {
                    const s = slots[i];
                    const x = r[s.rs1];
                    const y = r[s.rs2];
                    const sx: i64 = @bitCast(x);
                    const sy: i64 = @bitCast(y);
                    const taken = switch (op) {
                        .beq => x == y,
                        .bne => x != y,
                        .blt => sx < sy,
                        .bge => sx >= sy,
                        .bltu => x < y,
                        .bgeu => x >= y,
                        else => unreachable,
                    };
                    const next: usize = if (taken) s.target else i + 1;
                    const tick: u32 = @intCast(4 * pos);
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, next), .lhs = x, .rhs = y, .previous_rd = 0, .result = 0, .memory_index = compact_tape.NO_MEMORY, .flags = @intFromBool(taken) };
                    clocks[s.rs1] = tick + 1;
                    clocks[s.rs2] = tick + 2;
                    pos += 1;
                    i = next;
                    continue :sw .enter;
                },
                .jal => {
                    const s = slots[i];
                    const tick: u32 = @intCast(4 * pos);
                    steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, s.target), .lhs = 0, .rhs = 0, .previous_rd = r[s.rd], .result = s.imm, .memory_index = compact_tape.NO_MEMORY, .flags = 1 };
                    clocks[s.rd] = tick + 3;
                    r[s.rd] = s.imm;
                    r[SINK] = 0;
                    pos += 1;
                    i = s.target;
                    continue :sw .enter;
                },
                .jalr => {
                    const s = slots[i];
                    const x = r[s.rs1];
                    const target = (x +% s.imm) & ~@as(u64, 1);
                    if (target & 3 != 0 or target < code_lo or target >= self.code_hi) break :sw;
                    const link = code_lo + 4 * @as(u64, i) + 4;
                    const tick: u32 = @intCast(4 * pos);
                    steps[pos] = .{ .next_pc = target, .lhs = x, .rhs = 0, .previous_rd = r[s.rd], .result = link, .memory_index = compact_tape.NO_MEMORY, .flags = 1 };
                    clocks[s.rs1] = tick + 1;
                    clocks[s.rd] = tick + 3;
                    r[s.rd] = link;
                    r[SINK] = 0;
                    pos += 1;
                    i = @intCast((target - code_lo) / 4);
                    continue :sw .enter;
                },
            }
            const retired = pos - start;
            clocks[0] = saved_zero;
            trace.clocks = clocks;
            trace.len = pos;
            trace.divisions += divisions;
            trace.multiplications += multiplications;
            if (retired != 0) {
                @memcpy(&cpu.regs, r[0..32]);
                cpu.regs[0] = 0;
                cpu.pc = code_lo + 4 * @as(u64, i);
                cpu.retired += retired;
                cap.steps += @intCast(retired);
                self.fast_retired += retired;
            }
            return if (pos == end_pos) .limit else .slow;
        }
    };
}
