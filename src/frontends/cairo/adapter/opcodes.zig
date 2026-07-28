//! Cairo opcode classification.
//!
//! Classifies decoded instructions into one of 20 opcode categories.
//! Each category corresponds to an AIR component with specific constraint logic.

const std = @import("std");
const cpu = @import("../common/cpu.zig");
const decode = @import("decode.zig");

const CasmState = cpu.CasmState;
const Instruction = decode.Instruction;

/// The 20 opcode categories used by the Cairo AIR.
pub const OpcodeTag = enum {
    generic_opcode,
    add_ap_opcode,
    add_opcode,
    add_opcode_small,
    assert_eq_opcode,
    assert_eq_opcode_double_deref,
    assert_eq_opcode_imm,
    call_opcode_abs,
    call_opcode_rel_imm,
    jnz_opcode_non_taken,
    jnz_opcode_taken,
    jump_opcode_rel_imm,
    jump_opcode_rel,
    jump_opcode_double_deref,
    jump_opcode_abs,
    mul_opcode_small,
    mul_opcode,
    ret_opcode,
    blake_compress_opcode,
    qm_31_add_mul_opcode,
};

/// Number of opcode categories.
pub const N_OPCODES: usize = @typeInfo(OpcodeTag).@"enum".fields.len;

/// One opcode component whose adapted CASM states directly seed a recorded
/// witness program.
pub const DirectWitnessLane = struct {
    label: []const u8,
    tag: OpcodeTag,
    includes_iota: bool = false,
};

pub const direct_witness_lanes = [_]DirectWitnessLane{
    .{ .label = "generic_opcode", .tag = .generic_opcode },
    .{ .label = "add_ap_opcode", .tag = .add_ap_opcode },
    .{ .label = "add_opcode", .tag = .add_opcode },
    .{ .label = "add_opcode_small", .tag = .add_opcode_small },
    .{ .label = "assert_eq_opcode", .tag = .assert_eq_opcode },
    .{ .label = "assert_eq_opcode_double_deref", .tag = .assert_eq_opcode_double_deref },
    .{ .label = "assert_eq_opcode_imm", .tag = .assert_eq_opcode_imm },
    .{ .label = "call_opcode_abs", .tag = .call_opcode_abs },
    .{ .label = "call_opcode_rel_imm", .tag = .call_opcode_rel_imm },
    .{ .label = "jnz_opcode_non_taken", .tag = .jnz_opcode_non_taken },
    .{ .label = "jnz_opcode_taken", .tag = .jnz_opcode_taken },
    .{ .label = "jump_opcode_abs", .tag = .jump_opcode_abs },
    .{ .label = "jump_opcode_double_deref", .tag = .jump_opcode_double_deref },
    .{ .label = "jump_opcode_rel", .tag = .jump_opcode_rel },
    .{ .label = "jump_opcode_rel_imm", .tag = .jump_opcode_rel_imm },
    .{ .label = "mul_opcode", .tag = .mul_opcode },
    .{ .label = "mul_opcode_small", .tag = .mul_opcode_small },
    .{ .label = "ret_opcode", .tag = .ret_opcode },
    .{ .label = "blake_compress_opcode", .tag = .blake_compress_opcode, .includes_iota = true },
    .{ .label = "qm_31_add_mul_opcode", .tag = .qm_31_add_mul_opcode },
};

/// CPU states grouped by opcode category.
pub const CasmStatesByOpcode = struct {
    states: [N_OPCODES]std.ArrayList(CasmState),

    pub fn init(allocator: std.mem.Allocator) CasmStatesByOpcode {
        _ = allocator;
        var self: CasmStatesByOpcode = undefined;
        for (&self.states) |*list| list.* = .empty;
        return self;
    }

    pub fn deinit(self: *CasmStatesByOpcode, allocator: std.mem.Allocator) void {
        for (&self.states) |*list| list.deinit(allocator);
        self.* = undefined;
    }

    /// Get the state list for a specific opcode category.
    pub fn get(self: *CasmStatesByOpcode, tag: OpcodeTag) *std.ArrayList(CasmState) {
        return &self.states[@intFromEnum(tag)];
    }

    /// Get the state list for a specific opcode category (const).
    pub fn getConst(self: *const CasmStatesByOpcode, tag: OpcodeTag) []const CasmState {
        return self.states[@intFromEnum(tag)].items;
    }

    /// Total number of classified states across all categories.
    pub fn totalCount(self: *const CasmStatesByOpcode) usize {
        var total: usize = 0;
        for (self.states) |list| total += list.items.len;
        return total;
    }

    /// Classify an instruction and push the state into the appropriate category.
    pub fn pushInstruction(
        self: *CasmStatesByOpcode,
        allocator: std.mem.Allocator,
        inst: Instruction,
        state: CasmState,
    ) !void {
        const tag = classifyInstruction(inst);
        try self.get(tag).append(allocator, state);
    }
};

/// Classify a decoded instruction into an opcode category.
///
/// The classification logic mirrors `stwo_cairo_prover/crates/adapter/src/opcodes.rs`.
pub fn classifyInstruction(inst: Instruction) OpcodeTag {
    // Extension opcodes.
    if (inst.opcode_extension != .stone) {
        return switch (inst.opcode_extension) {
            .blake, .blake_finalize => .blake_compress_opcode,
            .qm31_operation => .qm_31_add_mul_opcode,
            .stone => unreachable,
        };
    }

    // ret: opcode_ret set, no jump/call/assert_eq.
    if (inst.opcode_ret and !inst.opcode_call and !inst.opcode_assert_eq) {
        return .ret_opcode;
    }

    // call variants.
    if (inst.opcode_call) {
        if (inst.pc_update_jump) return .call_opcode_abs;
        if (inst.pc_update_jump_rel and inst.op_1_imm) return .call_opcode_rel_imm;
        return .generic_opcode;
    }

    // assert_eq variants.
    if (inst.opcode_assert_eq) {
        if (inst.op_1_imm) return .assert_eq_opcode_imm;
        if (inst.op_1_base_fp or inst.op_1_base_ap) {
            // double deref: op1 from register, not immediate
            if (!inst.res_add and !inst.res_mul) return .assert_eq_opcode_double_deref;
        }
        return .assert_eq_opcode;
    }

    // jnz variants.
    if (inst.pc_update_jnz) {
        // The "taken" vs "non_taken" distinction depends on runtime value,
        // not instruction encoding. Default to taken here; the adapter
        // resolves this at trace time using the actual register value.
        return .jnz_opcode_taken;
    }

    // jump variants.
    if (inst.pc_update_jump) {
        if (inst.op_1_base_fp or inst.op_1_base_ap) {
            if (!inst.op_1_imm) return .jump_opcode_double_deref;
        }
        return .jump_opcode_abs;
    }
    if (inst.pc_update_jump_rel) {
        if (inst.op_1_imm) return .jump_opcode_rel_imm;
        return .jump_opcode_rel;
    }

    // add_ap: ap_update_add set, no opcode flags.
    if (inst.ap_update_add and !inst.opcode_call and !inst.opcode_ret and !inst.opcode_assert_eq) {
        return .add_ap_opcode;
    }

    // Arithmetic: res_add or res_mul with no control flow.
    if (inst.res_add) {
        // "small" variant when all operands fit in small representation.
        // Full classification requires runtime values; default to full add.
        return .add_opcode;
    }
    if (inst.res_mul) {
        return .mul_opcode;
    }

    return .generic_opcode;
}

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

test "opcodes: ret classification" {
    const inst = Instruction{
        .offset0 = 0,
        .offset1 = 0,
        .offset2 = 0,
        .dst_base_fp = false,
        .op0_base_fp = false,
        .op_1_imm = false,
        .op_1_base_fp = false,
        .op_1_base_ap = false,
        .res_add = false,
        .res_mul = false,
        .pc_update_jump = false,
        .pc_update_jump_rel = false,
        .pc_update_jnz = false,
        .ap_update_add = false,
        .ap_update_add_1 = false,
        .opcode_call = false,
        .opcode_ret = true,
        .opcode_assert_eq = false,
        .opcode_extension = .stone,
    };
    try std.testing.expectEqual(OpcodeTag.ret_opcode, classifyInstruction(inst));
}

test "opcodes: call_abs classification" {
    const inst = Instruction{
        .offset0 = 0,
        .offset1 = 0,
        .offset2 = 0,
        .dst_base_fp = false,
        .op0_base_fp = false,
        .op_1_imm = false,
        .op_1_base_fp = false,
        .op_1_base_ap = false,
        .res_add = false,
        .res_mul = false,
        .pc_update_jump = true,
        .pc_update_jump_rel = false,
        .pc_update_jnz = false,
        .ap_update_add = false,
        .ap_update_add_1 = false,
        .opcode_call = true,
        .opcode_ret = false,
        .opcode_assert_eq = false,
        .opcode_extension = .stone,
    };
    try std.testing.expectEqual(OpcodeTag.call_opcode_abs, classifyInstruction(inst));
}

test "opcodes: state_by_opcode total count" {
    const alloc = std.testing.allocator;
    var states = CasmStatesByOpcode.init(alloc);
    defer states.deinit(alloc);

    const M31 = @import("stwo_core").fields.m31.M31;
    const s = CasmState{ .pc = M31.fromCanonical(1), .ap = M31.fromCanonical(2), .fp = M31.fromCanonical(3) };

    try states.get(.ret_opcode).append(alloc, s);
    try states.get(.ret_opcode).append(alloc, s);
    try states.get(.add_opcode).append(alloc, s);

    try std.testing.expectEqual(@as(usize, 3), states.totalCount());
}

test "opcodes: direct witness lanes are explicit and unique" {
    var seen = [_]bool{false} ** N_OPCODES;
    var iota_lanes: usize = 0;
    for (direct_witness_lanes) |lane| {
        const index = @intFromEnum(lane.tag);
        try std.testing.expect(!seen[index]);
        seen[index] = true;
        try std.testing.expectEqualStrings(@tagName(lane.tag), lane.label);
        if (lane.includes_iota) {
            iota_lanes += 1;
            try std.testing.expectEqual(OpcodeTag.blake_compress_opcode, lane.tag);
        }
    }
    try std.testing.expect(!seen[@intFromEnum(OpcodeTag.generic_opcode)]);
    try std.testing.expectEqual(N_OPCODES - 1, direct_witness_lanes.len);
    try std.testing.expectEqual(@as(usize, 1), iota_lanes);
}
