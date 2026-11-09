//! Bounded device functions for long serial witness deduction chains.
//! Liveness follows emitted stores rather than deferred IR output markers.
const std = @import("std");
const model = @import("cairo_witness_model");
const schedule_mod = @import("schedule.zig");

pub const Plan = struct {
    allocator: std.mem.Allocator,
    boundaries: []usize,
    live: [][]u32,
    max_carry: usize,

    pub fn deinit(self: *Plan) void {
        for (self.live) |registers| self.allocator.free(registers);
        self.allocator.free(self.live);
        self.allocator.free(self.boundaries);
        self.* = undefined;
    }
};

pub fn required(program: model.Program) bool {
    var count: usize = 0;
    for (program.insts) |inst| {
        if (inst.op == .deduce_call) count += 1;
    }
    return count > 64;
}

pub fn build(allocator: std.mem.Allocator, program: model.Program, schedule: schedule_mod.Schedule) !Plan {
    const absent = std.math.maxInt(usize);
    const definitions = try allocator.alloc(usize, program.n_regs);
    defer allocator.free(definitions);
    @memset(definitions, absent);
    const last = try allocator.alloc(usize, program.n_regs);
    defer allocator.free(last);
    @memset(last, 0);
    var pending: std.ArrayList(u32) = .empty;
    defer pending.deinit(allocator);
    var boundaries: std.ArrayList(usize) = .empty;
    defer boundaries.deinit(allocator);
    try boundaries.append(allocator, 0);
    var calls: usize = 0;
    for (program.insts, 0..) |inst, index| {
        switch (inst.op) {
            .col_write, .lookup_word, .sub_word => {},
            .deduce_arg => try pending.append(allocator, inst.a),
            .deduce_call => {
                for (pending.items) |register| last[register] = @max(last[register], index);
                pending.clearRetainingCapacity();
                const kind = try std.meta.intToEnum(model.DeduceKind, inst.imm);
                for (inst.dst..@as(usize, inst.dst) + kind.shape().outputs) |register| {
                    definitions[register] = index;
                    for (schedule.after_deduce_register[register].items) |store|
                        last[store.register] = @max(last[store.register], index);
                }
                calls += 1;
                if (calls % 16 == 0 and index + 1 < program.insts.len)
                    try boundaries.append(allocator, index + 1);
            },
            .mult_push => last[inst.a] = @max(last[inst.a], index),
            .input, .constant => definitions[inst.dst] = index,
            else => {
                definitions[inst.dst] = index;
                last[inst.a] = @max(last[inst.a], index);
                switch (inst.op) {
                    .m31_add,
                    .m31_sub,
                    .m31_mul,
                    .u16_add,
                    .u32_add,
                    .u32_sub,
                    .u32_mul,
                    .u32_xor,
                    .m31_eq,
                    => last[inst.b] = @max(last[inst.b], index),
                    else => {},
                }
            },
        }
        for (schedule.after_instruction[index].items) |store|
            last[store.register] = @max(last[store.register], index);
        for (schedule.after_deduce_arguments[index].items) |store|
            last[store.register] = @max(last[store.register], index);
    }
    if (pending.items.len != 0) return error.InvalidDeduce;
    try boundaries.append(allocator, program.insts.len);
    const live = try allocator.alloc([]u32, boundaries.items.len);
    errdefer allocator.free(live);
    var initialized: usize = 0;
    errdefer for (live[0..initialized]) |registers| allocator.free(registers);
    var max_carry: usize = 0;
    for (boundaries.items, 0..) |boundary, ordinal| {
        var registers: std.ArrayList(u32) = .empty;
        defer registers.deinit(allocator);
        for (definitions, last, 0..) |definition, use, register| {
            if (definition < boundary and use >= boundary)
                try registers.append(allocator, @intCast(register));
        }
        max_carry = @max(max_carry, registers.items.len);
        live[ordinal] = try registers.toOwnedSlice(allocator);
        initialized += 1;
    }
    return .{ .allocator = allocator, .boundaries = try boundaries.toOwnedSlice(allocator), .live = live, .max_carry = max_carry };
}
