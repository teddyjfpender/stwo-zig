const std = @import("std");
const witness = @import("stwo_cairo_frontend").witness.program;
const shader_manifest = @import("stwo_metal_backend").shaders.manifest;

pub const codegen_version: u64 = 7;
pub const support_version: u64 = shader_manifest.witness_codegen_support_version;

const base_support = @embedFile("../../backends/metal/shaders/include/base.metal");
const m31_support = @embedFile("../../backends/metal/shaders/include/m31.metal");
const felt252_support = @embedFile("../../backends/metal/shaders/include/felt252.metal");
const ec_support = @embedFile("../../backends/metal/shaders/include/ec.metal");
const witness_abi_support = @embedFile("../../backends/metal/shaders/include/witness_abi.metal");
const witness_tables_support = @embedFile("../../backends/metal/shaders/include/witness_tables.metal");
const witness_deductions_support = @embedFile("../../backends/metal/shaders/include/witness_deductions.metal");
const generated_support = "#define STWO_ZIG_AMALGAMATED 1\n" ++ base_support ++ m31_support;
const common_witness_support = witness_abi_support ++ witness_tables_support;
const deduction_witness_support = felt252_support ++ ec_support ++ witness_deductions_support;

pub const KernelMode = enum {
    all,
    base,
    base_lookup,
    interaction,
    interaction_subwords,
};

pub fn preambleParts() [3][]const u8 {
    return .{
        generated_support,
        common_witness_support,
        deduction_witness_support,
    };
}

pub fn preamblePartsForProgram(program: witness.Program) [5][]const u8 {
    var needs_deduction = false;
    for (program.insts) |inst| {
        if (@as(witness.Op, @enumFromInt(inst.op)) == .deduce_call) {
            needs_deduction = true;
            break;
        }
    }
    if (needs_deduction) {
        const full = preambleParts();
        return .{ full[0], full[1], full[2], "", "" };
    }

    return .{
        "#define STWO_ZIG_AMALGAMATED 1\n" ++ base_support,
        m31_support,
        witness_abi_support,
        witness_tables_support,
        "",
    };
}

pub fn kernelName(
    allocator: std.mem.Allocator,
    semantic_identity: [32]u8,
) ![]u8 {
    const encoded = std.fmt.bytesToHex(semantic_identity, .lower);
    return std.fmt.allocPrint(
        allocator,
        "stwo_zig_witness_{s}",
        .{encoded[0..]},
    );
}

pub fn kernelNameForMode(
    allocator: std.mem.Allocator,
    semantic_identity: [32]u8,
    mode: KernelMode,
) ![]u8 {
    const base_name = try kernelName(allocator, semantic_identity);
    defer allocator.free(base_name);
    return switch (mode) {
        .all => allocator.dupe(u8, base_name),
        .base => std.fmt.allocPrint(allocator, "{s}_base", .{base_name}),
        .base_lookup => std.fmt.allocPrint(
            allocator,
            "{s}_base_lookup_v{}",
            .{ base_name, codegen_version },
        ),
        .interaction => std.fmt.allocPrint(
            allocator,
            "{s}_interaction",
            .{base_name},
        ),
        .interaction_subwords => std.fmt.allocPrint(
            allocator,
            "{s}_interaction_subwords_v{}",
            .{ base_name, codegen_version },
        ),
    };
}

pub fn generateKernel(
    allocator: std.mem.Allocator,
    program: witness.Program,
) ![]u8 {
    return generateKernelForMode(allocator, program, .all);
}

pub fn generateKernelForMode(
    allocator: std.mem.Allocator,
    program: witness.Program,
    mode: KernelMode,
) ![]u8 {
    try program.validate();
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    const name = try kernelNameForMode(
        allocator,
        program.semanticIdentity(),
        mode,
    );
    defer allocator.free(name);
    try writer.print(
        \\kernel void {s}(
        \\    device uint *arena [[buffer(0)]],
        \\    constant WitnessArgs &args [[buffer(1)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= args.row_count) return;
        \\
    , .{name});

    const keep = try liveInstructions(allocator, program, mode);
    defer allocator.free(keep);
    const last_uses = try retainedLastUses(allocator, program, keep);
    defer allocator.free(last_uses);
    var temps = try TempPool.init(allocator, program.n_regs);
    defer temps.deinit();
    var deduce_args = std.ArrayList(u32).empty;
    defer deduce_args.deinit(allocator);
    var deduce_sequence: u32 = 0;

    for (program.insts, keep, 0..) |inst, retain, inst_index| {
        if (!retain) continue;
        const op: witness.Op = @enumFromInt(inst.op);
        switch (op) {
            .col_write => {
                try writer.print("    arena[arena[args.output_offsets + {}u] + row] = t{};\n", .{ inst.imm, try temps.read(inst.a) });
                try releaseIfLastUse(&temps, last_uses, inst.a, inst_index);
                continue;
            },
            .mult_push => {
                try writer.print(
                    "    atomic_fetch_add_explicit((device atomic_uint *)(arena + arena[args.multiplicity_offsets + {}u] + t{}), 1u, memory_order_relaxed);\n",
                    .{ inst.imm, try temps.read(inst.a) },
                );
                try releaseIfLastUse(&temps, last_uses, inst.a, inst_index);
                continue;
            },
            .lookup_word => {
                try writer.print("    arena[args.lookup_words + {}u * args.row_count + row] = t{};\n", .{ inst.imm, try temps.read(inst.a) });
                try releaseIfLastUse(&temps, last_uses, inst.a, inst_index);
                continue;
            },
            .sub_word => {
                try writer.print("    arena[args.sub_words + {}u * args.row_count + row] = t{};\n", .{ inst.imm, try temps.read(inst.a) });
                try releaseIfLastUse(&temps, last_uses, inst.a, inst_index);
                continue;
            },
            .deduce_arg => {
                try deduce_args.append(allocator, inst.a);
                continue;
            },
            .deduce_call => {
                if (deduce_args.items.len == 0 or inst.b == 0) return error.InvalidDeduce;
                try writer.print("    uint dargs{}[{}] = {{ ", .{ deduce_sequence, deduce_args.items.len });
                for (deduce_args.items, 0..) |register, index| {
                    if (index != 0) try writer.writeAll(", ");
                    try writer.print("t{}", .{try temps.read(register)});
                }
                try writer.writeAll(" };\n");
                try writer.print("    uint douts{}[{}];\n", .{ deduce_sequence, inst.b });
                try writer.print(
                    "    witness_deduce_{}(arena, args, dargs{}, douts{});\n",
                    .{ inst.imm, deduce_sequence, deduce_sequence },
                );
                for (0..inst.b) |output| {
                    const register = @as(usize, inst.dst) + output;
                    const assignment = try temps.write(register);
                    const declaration = if (assignment.declare) "uint " else "";
                    try writer.print("    {s}t{} = douts{}[{}];\n", .{ declaration, assignment.slot, deduce_sequence, output });
                }
                for (deduce_args.items) |register| try releaseIfLastUse(&temps, last_uses, register, inst_index);
                for (0..inst.b) |output|
                    try releaseIfDeadAfterWrite(&temps, last_uses, @as(usize, inst.dst) + output, inst_index);
                deduce_args.clearRetainingCapacity();
                deduce_sequence += 1;
                continue;
            },
            else => {},
        }

        const destination: usize = inst.dst;
        const assignment = try temps.write(destination);
        const declaration = if (assignment.declare) "uint " else "";
        try writer.print("    {s}t{} = ", .{ declaration, assignment.slot });
        switch (op) {
            .input => try writer.print("arena[arena[args.input_offsets + {}u] + row]", .{inst.a}),
            .constant => try writer.print("{}u", .{inst.imm}),
            .m31_add => try writer.print("m31_add(t{}, t{})", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .m31_sub => try writer.print("m31_sub(t{}, t{})", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .m31_mul => try writer.print("m31_mul(t{}, t{})", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .m31_neg => try writer.print("m31_neg(t{})", .{try temps.read(inst.a)}),
            .u16_add => try writer.print("(t{} + t{}) & 0xffffu", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .u16_shl => try writer.print("(t{} << {}u) & 0xffffu", .{ try temps.read(inst.a), inst.imm }),
            .u16_shr => try writer.print("(t{} & 0xffffu) >> {}u", .{ try temps.read(inst.a), inst.imm }),
            .u16_and, .u32_and => try writer.print("t{} & {}u", .{ try temps.read(inst.a), inst.imm }),
            .u32_add => try writer.print("t{} + t{}", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .u32_sub => try writer.print("t{} - t{}", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .u32_mul => try writer.print("t{} * t{}", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .u32_shl => try writer.print("t{} << {}u", .{ try temps.read(inst.a), inst.imm }),
            .u32_shr => try writer.print("t{} >> {}u", .{ try temps.read(inst.a), inst.imm }),
            .u32_xor => try writer.print("t{} ^ t{}", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            .as_m31 => try writer.print("t{} % 0x7fffffffu", .{try temps.read(inst.a)}),
            .trunc16 => try writer.print("t{} & 0xffffu", .{try temps.read(inst.a)}),
            .table_limb => switch (inst.b) {
                0 => try writer.print(
                    "t{} < arena[args.table_strides] ? arena[arena[args.table_offsets] + t{}] : 0u",
                    .{ try temps.read(inst.a), try temps.read(inst.a) },
                ),
                1 => try writer.print("witness_table_limb(arena, args, t{}, {}u)", .{ try temps.read(inst.a), inst.imm }),
                else => return error.UnsupportedTable,
            },
            .m31_inverse => try writer.print("m31_inv(t{})", .{try temps.read(inst.a)}),
            .m31_eq => try writer.print("t{} == t{} ? 1u : 0u", .{ try temps.read(inst.a), try temps.read(inst.b) }),
            else => unreachable,
        }
        try writer.writeAll(";\n");
        if (instructionReadsA(op)) try releaseIfLastUse(&temps, last_uses, inst.a, inst_index);
        if (instructionReadsB(op)) try releaseIfLastUse(&temps, last_uses, inst.b, inst_index);
        try releaseIfDeadAfterWrite(&temps, last_uses, destination, inst_index);
    }
    if (deduce_args.items.len != 0) return error.InvalidDeduce;
    try writer.writeAll("}\n\n");
    return source.toOwnedSlice(allocator);
}

/// Emits one self-contained translation unit for diagnostic compilation.
/// Production AOT builds should shard multiple kernels under one preamble.
pub fn generateStandaloneKernel(
    allocator: std.mem.Allocator,
    program: witness.Program,
    mode: KernelMode,
) ![]u8 {
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    for (preamblePartsForProgram(program)) |part|
        try source.appendSlice(allocator, part);
    const kernel = try generateKernelForMode(allocator, program, mode);
    defer allocator.free(kernel);
    try source.appendSlice(allocator, kernel);
    return source.toOwnedSlice(allocator);
}

const TempAssignment = struct { slot: u32, declare: bool };

const TempPool = struct {
    allocator: std.mem.Allocator,
    register_slots: []?u32,
    free_slots: std.ArrayList(u32),
    next_slot: u32 = 0,

    fn init(allocator: std.mem.Allocator, register_count: usize) !TempPool {
        const register_slots = try allocator.alloc(?u32, register_count);
        @memset(register_slots, null);
        return .{ .allocator = allocator, .register_slots = register_slots, .free_slots = .empty };
    }

    fn deinit(self: *TempPool) void {
        self.free_slots.deinit(self.allocator);
        self.allocator.free(self.register_slots);
        self.* = undefined;
    }

    fn read(self: TempPool, register: usize) !u32 {
        if (register >= self.register_slots.len) return error.InvalidRegister;
        return self.register_slots[register] orelse error.InvalidRegisterLifetime;
    }

    fn write(self: *TempPool, register: usize) !TempAssignment {
        if (register >= self.register_slots.len) return error.InvalidRegister;
        if (self.register_slots[register]) |slot| return .{ .slot = slot, .declare = false };
        if (self.free_slots.items.len != 0) {
            const slot = self.free_slots.items[self.free_slots.items.len - 1];
            self.free_slots.items.len -= 1;
            self.register_slots[register] = slot;
            return .{ .slot = slot, .declare = false };
        }
        const slot = self.next_slot;
        self.next_slot = std.math.add(u32, self.next_slot, 1) catch return error.TooManyTemporaries;
        self.register_slots[register] = slot;
        return .{ .slot = slot, .declare = true };
    }

    fn release(self: *TempPool, register: usize) !void {
        if (register >= self.register_slots.len) return error.InvalidRegister;
        const slot = self.register_slots[register] orelse return;
        self.register_slots[register] = null;
        try self.free_slots.append(self.allocator, slot);
    }
};

fn releaseIfLastUse(temps: *TempPool, last_uses: []const ?usize, register: usize, inst_index: usize) !void {
    if (last_uses[register] == inst_index) try temps.release(register);
}

fn releaseIfDeadAfterWrite(temps: *TempPool, last_uses: []const ?usize, register: usize, inst_index: usize) !void {
    const last_use = last_uses[register];
    if (last_use == null or last_use.? <= inst_index) try temps.release(register);
}

/// Generates one Metal translation unit for a canonical witness bundle. Metal
/// source compilation has substantial fixed overhead, so sharing the preamble
/// and compiling all component kernels together is materially faster than one
/// source library per component.
pub fn generateBatchForMode(
    allocator: std.mem.Allocator,
    entries: anytype,
    mode: KernelMode,
) ![]u8 {
    if (entries.len == 0) return error.EmptyWitnessBatch;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    for (preambleParts()) |part| try source.appendSlice(allocator, part);
    for (entries) |entry| {
        const kernel = try generateKernelForMode(allocator, entry.program, mode);
        defer allocator.free(kernel);
        try source.appendSlice(allocator, kernel);
    }
    return source.toOwnedSlice(allocator);
}

pub fn generateBatchForModes(
    allocator: std.mem.Allocator,
    entries: anytype,
    modes: []const KernelMode,
) ![]u8 {
    if (entries.len == 0) return error.EmptyWitnessBatch;
    if (entries.len != modes.len) return error.InvalidModeCount;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    for (preambleParts()) |part| try source.appendSlice(allocator, part);
    for (entries, modes) |entry, mode| {
        const kernel = try generateKernelForMode(allocator, entry.program, mode);
        defer allocator.free(kernel);
        try source.appendSlice(allocator, kernel);
    }
    return source.toOwnedSlice(allocator);
}

pub fn generateSpecializedBatch(allocator: std.mem.Allocator, entries: anytype) ![]u8 {
    if (entries.len == 0) return error.EmptyWitnessBatch;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    for (preambleParts()) |part| try source.appendSlice(allocator, part);
    for (entries) |entry| {
        inline for (.{ KernelMode.base, KernelMode.interaction }) |mode| {
            const kernel = try generateKernelForMode(allocator, entry.program, mode);
            defer allocator.free(kernel);
            try source.appendSlice(allocator, kernel);
        }
    }
    return source.toOwnedSlice(allocator);
}

fn retainedLastUses(
    allocator: std.mem.Allocator,
    program: witness.Program,
    keep: []const bool,
) ![]?usize {
    const last_uses = try allocator.alloc(?usize, program.n_regs);
    errdefer allocator.free(last_uses);
    @memset(last_uses, null);
    var deduce_args = std.ArrayList(u32).empty;
    defer deduce_args.deinit(allocator);
    for (program.insts, keep, 0..) |inst, retain, inst_index| {
        if (!retain) continue;
        const op: witness.Op = @enumFromInt(inst.op);
        if (op == .deduce_arg) {
            try deduce_args.append(allocator, inst.a);
            continue;
        }
        if (op == .deduce_call) {
            if (deduce_args.items.len == 0) return error.InvalidDeduce;
            for (deduce_args.items) |register| last_uses[register] = inst_index;
            deduce_args.clearRetainingCapacity();
            continue;
        }
        if (instructionReadsA(op)) last_uses[inst.a] = inst_index;
        if (instructionReadsB(op)) last_uses[inst.b] = inst_index;
    }
    if (deduce_args.items.len != 0) return error.InvalidDeduce;
    return last_uses;
}

fn instructionReadsA(op: witness.Op) bool {
    return switch (op) {
        .input, .constant, .deduce_call => false,
        else => true,
    };
}

fn instructionReadsB(op: witness.Op) bool {
    return switch (op) {
        .m31_add, .m31_sub, .m31_mul, .m31_eq, .u16_add, .u32_add, .u32_sub, .u32_mul, .u32_xor => true,
        else => false,
    };
}

fn liveInstructions(allocator: std.mem.Allocator, program: witness.Program, mode: KernelMode) ![]bool {
    const keep = try allocator.alloc(bool, program.insts.len);
    errdefer allocator.free(keep);
    @memset(keep, false);
    const roots = try allocator.alloc(bool, program.insts.len);
    defer allocator.free(roots);
    for (program.insts, roots) |inst, *root| {
        const op: witness.Op = @enumFromInt(inst.op);
        root.* = sideEffectForMode(op, mode);
    }

    const call_arg_start = try allocator.alloc(usize, program.insts.len);
    defer allocator.free(call_arg_start);
    const call_arg_count = try allocator.alloc(usize, program.insts.len);
    defer allocator.free(call_arg_count);
    @memset(call_arg_start, 0);
    @memset(call_arg_count, 0);
    var deduce_registers = std.ArrayList(u32).empty;
    defer deduce_registers.deinit(allocator);
    var deduce_instructions = std.ArrayList(usize).empty;
    defer deduce_instructions.deinit(allocator);
    var pending_start: usize = 0;
    for (program.insts, 0..) |inst, inst_index| {
        const op: witness.Op = @enumFromInt(inst.op);
        switch (op) {
            .deduce_arg => {
                try deduce_registers.append(allocator, inst.a);
                try deduce_instructions.append(allocator, inst_index);
            },
            .deduce_call => {
                if (deduce_registers.items.len == pending_start) return error.InvalidDeduce;
                call_arg_start[inst_index] = pending_start;
                call_arg_count[inst_index] = deduce_registers.items.len - pending_start;
                pending_start = deduce_registers.items.len;
            },
            else => {},
        }
    }
    if (pending_start != deduce_registers.items.len) return error.InvalidDeduce;

    const live = try allocator.alloc(bool, program.n_regs);
    defer allocator.free(live);
    @memset(live, false);
    var index = program.insts.len;
    while (index != 0) {
        index -= 1;
        const inst = program.insts[index];
        const op: witness.Op = @enumFromInt(inst.op);
        const writes_register = switch (op) {
            .col_write, .mult_push, .lookup_word, .sub_word, .deduce_arg => false,
            else => true,
        };
        if (op == .deduce_arg) continue;
        var needed = roots[index];
        if (writes_register) {
            const output_count: usize = if (op == .deduce_call) inst.b else 1;
            for (0..output_count) |output| needed = needed or live[@as(usize, inst.dst) + output];
        }
        if (!needed) continue;
        keep[index] = true;
        if (writes_register) {
            const output_count: usize = if (op == .deduce_call) inst.b else 1;
            for (0..output_count) |output| live[@as(usize, inst.dst) + output] = false;
        }
        if (op == .deduce_call) {
            const start = call_arg_start[index];
            const count = call_arg_count[index];
            for (deduce_registers.items[start .. start + count], deduce_instructions.items[start .. start + count]) |register, arg_inst_index| {
                live[register] = true;
                keep[arg_inst_index] = true;
            }
            continue;
        }
        if (instructionReadsA(op)) live[inst.a] = true;
        if (instructionReadsB(op)) live[inst.b] = true;
    }
    return keep;
}

fn sideEffectForMode(op: witness.Op, mode: KernelMode) bool {
    return switch (op) {
        .col_write, .mult_push => mode == .all or mode == .base or mode == .base_lookup,
        .lookup_word => mode == .all or mode == .base_lookup or mode == .interaction,
        // Producer words are replayed in both phases for downstream consumers.
        .sub_word => true,
        else => false,
    };
}

test "Metal witness codegen emits arena-native SSA kernel" {
    const insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 3 },
        .{ .op = @intFromEnum(witness.Op.m31_mul), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 0 },
    };
    const program = witness.Program{ .insts = &insts, .n_regs = 3, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    const source = try generateKernel(std.testing.allocator, program);
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "m31_mul(t0, t1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "args.output_offsets") != null);
}

test "Metal witness codegen specializes base and interaction outputs" {
    const insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.lookup_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.sub_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const program = witness.Program{ .insts = &insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 1, .n_sub_words = 1 };
    const base = try generateKernelForMode(std.testing.allocator, program, .base);
    defer std.testing.allocator.free(base);
    try std.testing.expect(std.mem.indexOf(u8, base, "args.output_offsets") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "args.sub_words") != null);
    try std.testing.expect(std.mem.indexOf(u8, base, "args.lookup_words") == null);

    const base_lookup = try generateKernelForMode(
        std.testing.allocator,
        program,
        .base_lookup,
    );
    defer std.testing.allocator.free(base_lookup);
    try std.testing.expect(std.mem.indexOf(u8, base_lookup, "_base_lookup_v7") != null);
    try std.testing.expect(std.mem.indexOf(u8, base_lookup, "args.output_offsets") != null);
    try std.testing.expect(std.mem.indexOf(u8, base_lookup, "args.sub_words") != null);
    try std.testing.expect(std.mem.indexOf(u8, base_lookup, "args.lookup_words") != null);

    const interaction = try generateKernelForMode(
        std.testing.allocator,
        program,
        .interaction,
    );
    defer std.testing.allocator.free(interaction);
    try std.testing.expect(std.mem.indexOf(u8, interaction, "args.output_offsets") == null);
    try std.testing.expect(std.mem.indexOf(u8, interaction, "args.sub_words") != null);
    try std.testing.expect(std.mem.indexOf(u8, interaction, "args.lookup_words") != null);

    const interaction_subwords = try generateKernelForMode(
        std.testing.allocator,
        program,
        .interaction_subwords,
    );
    defer std.testing.allocator.free(interaction_subwords);
    try std.testing.expect(std.mem.indexOf(u8, interaction_subwords, "_interaction_subwords_v7") != null);
    try std.testing.expect(std.mem.indexOf(u8, interaction_subwords, "args.output_offsets") == null);
    try std.testing.expect(std.mem.indexOf(u8, interaction_subwords, "args.lookup_words") == null);
    try std.testing.expect(std.mem.indexOf(u8, interaction_subwords, "args.sub_words") != null);
}

test "Metal witness codegen combines a batch under one preamble" {
    const first_insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const second_insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.constant), .dst = 0, .a = 0, .b = 0, .imm = 7 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const Entry = struct { program: witness.Program, semantic_hash: u64 };
    const entries = [_]Entry{
        .{
            .program = .{ .insts = &first_insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 },
            .semantic_hash = 1,
        },
        .{
            .program = .{ .insts = &second_insts, .n_regs = 1, .n_inputs = 0, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 },
            .semantic_hash = 2,
        },
    };
    const source = try generateBatchForMode(std.testing.allocator, &entries, .base);
    defer std.testing.allocator.free(source);
    const first_name = try kernelName(
        std.testing.allocator,
        entries[0].program.semanticIdentity(),
    );
    defer std.testing.allocator.free(first_name);
    const second_name = try kernelName(
        std.testing.allocator,
        entries[1].program.semanticIdentity(),
    );
    defer std.testing.allocator.free(second_name);
    const first_export = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}_base",
        .{first_name},
    );
    defer std.testing.allocator.free(first_export);
    const second_export = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}_base",
        .{second_name},
    );
    defer std.testing.allocator.free(second_export);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "#include <metal_stdlib>"));
    try std.testing.expect(std.mem.indexOf(u8, source, first_export) != null);
    try std.testing.expect(std.mem.indexOf(u8, source, second_export) != null);
}

test "Metal witness codegen combines per-entry mode specializations" {
    const insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.lookup_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const Entry = struct { program: witness.Program, semantic_hash: u64 };
    const entries = [_]Entry{
        .{
            .program = .{ .insts = &insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 1, .n_sub_words = 0 },
            .semantic_hash = 1,
        },
        .{
            .program = .{ .insts = &insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 1, .n_sub_words = 0 },
            .semantic_hash = 2,
        },
    };
    const source = try generateBatchForModes(std.testing.allocator, &entries, &.{ .base, .base_lookup });
    defer std.testing.allocator.free(source);
    const first_name = try kernelName(
        std.testing.allocator,
        entries[0].program.semanticIdentity(),
    );
    defer std.testing.allocator.free(first_name);
    const second_name = try kernelName(
        std.testing.allocator,
        entries[1].program.semanticIdentity(),
    );
    defer std.testing.allocator.free(second_name);
    const first_export = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}_base",
        .{first_name},
    );
    defer std.testing.allocator.free(first_export);
    const second_export = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}_base_lookup_v7",
        .{second_name},
    );
    defer std.testing.allocator.free(second_export);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "#include <metal_stdlib>"));
    try std.testing.expect(std.mem.indexOf(u8, source, first_export) != null);
    try std.testing.expect(std.mem.indexOf(u8, source, second_export) != null);
}

test "Metal witness preamble excludes unrelated backend kernels" {
    const parts = preambleParts();
    var bytes: usize = 0;
    for (parts) |part| {
        bytes += part.len;
        try std.testing.expect(std.mem.indexOf(u8, part, "kernel void stwo_zig_") == null);
    }
    try std.testing.expect(bytes < 20 * 1024);
    try std.testing.expect(std.mem.indexOf(u8, parts[1], "struct WitnessArgs") != null);
    try std.testing.expect(std.mem.indexOf(u8, parts[2], "witness_deduce_11") != null);
}

test "Metal witness preamble omits Felt252 helpers without deductions" {
    const insts = [_]witness.Inst{
        .{ .op = @intFromEnum(witness.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(witness.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const program = witness.Program{ .insts = &insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    const parts = preamblePartsForProgram(program);
    for (parts) |part| try std.testing.expect(std.mem.indexOf(u8, part, "Felt252Metal") == null);
    try std.testing.expect(std.mem.indexOf(u8, parts[1], "m31_mul") != null);
    try std.testing.expect(std.mem.indexOf(u8, parts[2], "struct WitnessArgs") != null);
    try std.testing.expect(std.mem.indexOf(u8, parts[3], "witness_table_limb") != null);
}

test "Metal witness codegen consumes only explicit support headers" {
    const implementation = @embedFile("witness_codegen.zig");
    try std.testing.expectEqual(
        shader_manifest.witness_codegen_support_version,
        support_version,
    );
    try std.testing.expectEqual(@as(u64, 6), support_version);
    try std.testing.expectEqual(@as(u64, 7), codegen_version);
    try std.testing.expect(std.mem.indexOf(
        u8,
        implementation,
        "@embedFile(\"../../backends/metal/kernels.metal\")",
    ) == null);

    const full = preambleParts();
    try std.testing.expect(std.mem.indexOf(u8, full[1], "struct WitnessArgs") != null);
    try std.testing.expect(std.mem.indexOf(u8, full[1], "witness_table_limb") != null);
    try std.testing.expect(std.mem.indexOf(u8, full[2], "struct Felt252Metal") != null);
    try std.testing.expect(std.mem.indexOf(u8, full[2], "struct EcPointMetal") != null);
    try std.testing.expect(std.mem.indexOf(u8, full[2], "witness_deduce_11") != null);
}
