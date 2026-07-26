//! Semantic admission and ownership conversion for official Cairo inputs.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const adapter = @import("../mod.zig");
const cpu = @import("../../common/cpu.zig");
const memory_mod = @import("../../common/memory.zig");
const opcodes = @import("../opcodes.zig");
const wire = @import("wire.zig");

pub const Limits = struct {
    max_file_bytes: u64 = 2 * 1024 * 1024 * 1024,
    max_states: usize = cpu.MEMORY_ADDRESS_BOUND,
    max_memory_addresses: usize = cpu.MEMORY_ADDRESS_BOUND,
    max_memory_values: usize = memory_mod.DEFAULT_ID,
    max_public_memory_addresses: usize = cpu.MEMORY_ADDRESS_BOUND,
};

pub const Error = error{
    BuiltinInstanceCountNotPowerOfTwo,
    BuiltinSegmentMisaligned,
    EmptyInput,
    F252ValueNotCanonical,
    InputTooLarge,
    InvalidMemoryId,
    InvalidMemoryTag,
    InvalidPcCount,
    InvalidPublicMemoryAddress,
    InvalidPublicSegmentContext,
    InvalidSegmentBounds,
    InvalidSmallValue,
    InvalidSmallValueCapacity,
    LengthOverflow,
    StateAddressOutOfRange,
};

pub fn fromWire(
    allocator: std.mem.Allocator,
    input: wire.ProverInput,
    limits: Limits,
) (Error || std.mem.Allocator.Error)!adapter.ProverInput {
    try validateLengths(input, limits);
    try validateMemory(input.memory);
    try validateSegments(input.builtin_segments, input.memory.address_to_id.len);
    try validatePublicAddresses(input.public_memory_addresses, input.memory.address_to_id);
    try validatePublicContext(input.public_segment_context, input.state_transitions);

    var pc_set = std.AutoHashMap(u32, void).init(allocator);
    defer pc_set.deinit();

    var grouped = opcodes.CasmStatesByOpcode.init(allocator);
    errdefer grouped.deinit(allocator);
    var state_count: usize = 0;
    const states = input.state_transitions.casm_states_by_opcode;
    try appendStates(allocator, &grouped, .generic_opcode, states.generic_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .add_ap_opcode, states.add_ap_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .add_opcode, states.add_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .add_opcode_small, states.add_opcode_small, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .assert_eq_opcode, states.assert_eq_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .assert_eq_opcode_double_deref, states.assert_eq_opcode_double_deref, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .assert_eq_opcode_imm, states.assert_eq_opcode_imm, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .call_opcode_abs, states.call_opcode_abs, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .call_opcode_rel_imm, states.call_opcode_rel_imm, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jnz_opcode_non_taken, states.jnz_opcode_non_taken, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jnz_opcode_taken, states.jnz_opcode_taken, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jump_opcode_rel_imm, states.jump_opcode_rel_imm, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jump_opcode_rel, states.jump_opcode_rel, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jump_opcode_double_deref, states.jump_opcode_double_deref, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .jump_opcode_abs, states.jump_opcode_abs, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .mul_opcode_small, states.mul_opcode_small, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .mul_opcode, states.mul_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .ret_opcode, states.ret_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .blake_compress_opcode, states.blake_compress_opcode, &pc_set, &state_count);
    try appendStates(allocator, &grouped, .qm_31_add_mul_opcode, states.qm_31_add_mul_opcode, &pc_set, &state_count);
    if (state_count > limits.max_states or pc_set.count() != input.pc_count)
        return Error.InvalidPcCount;

    const address_to_id = try allocator.alloc(
        memory_mod.EncodedMemoryValueId,
        input.memory.address_to_id.len,
    );
    errdefer allocator.free(address_to_id);
    for (address_to_id, input.memory.address_to_id) |*destination, raw| {
        destination.* = .{ .raw = raw };
    }
    const f252_values = try allocator.dupe([8]u32, input.memory.f252_values);
    errdefer allocator.free(f252_values);
    const small_values = try allocator.dupe(u128, input.memory.small_values);
    errdefer allocator.free(small_values);
    const public_memory_addresses = try allocator.dupe(u32, input.public_memory_addresses);
    errdefer allocator.free(public_memory_addresses);

    return .{
        .state_transitions = .{
            .initial_state = try decodeState(input.state_transitions.initial_state),
            .final_state = try decodeState(input.state_transitions.final_state),
            .casm_states_by_opcode = grouped,
        },
        .memory = .{
            .config = .{
                .small_max = input.memory.config.small_max,
                .log_small_value_capacity = input.memory.config.log_small_value_capacity,
            },
            .address_to_id = address_to_id,
            .f252_values = f252_values,
            .small_values = small_values,
        },
        .pc_count = input.pc_count,
        .public_memory_addresses = public_memory_addresses,
        .builtin_segments = decodeSegments(input.builtin_segments),
        .public_segment_context = input.public_segment_context.present,
    };
}

fn appendStates(
    allocator: std.mem.Allocator,
    grouped: *opcodes.CasmStatesByOpcode,
    tag: opcodes.OpcodeTag,
    source: []const wire.CasmState,
    pc_set: *std.AutoHashMap(u32, void),
    total: *usize,
) (Error || std.mem.Allocator.Error)!void {
    total.* = std.math.add(usize, total.*, source.len) catch return Error.LengthOverflow;
    const destination = grouped.get(tag);
    try destination.ensureTotalCapacity(allocator, source.len);
    for (source) |state| {
        try pc_set.put(state.pc, {});
        destination.appendAssumeCapacity(try decodeState(state));
    }
}

fn decodeState(state: wire.CasmState) Error!cpu.CasmState {
    if (state.pc >= cpu.MEMORY_ADDRESS_BOUND or
        state.ap >= cpu.MEMORY_ADDRESS_BOUND or
        state.fp >= cpu.MEMORY_ADDRESS_BOUND)
    {
        return Error.StateAddressOutOfRange;
    }
    return .{
        .pc = M31.fromCanonical(state.pc),
        .ap = M31.fromCanonical(state.ap),
        .fp = M31.fromCanonical(state.fp),
    };
}

fn validateLengths(input: wire.ProverInput, limits: Limits) Error!void {
    if (input.memory.address_to_id.len > limits.max_memory_addresses or
        input.memory.f252_values.len > limits.max_memory_values or
        input.memory.small_values.len > limits.max_memory_values or
        input.public_memory_addresses.len > limits.max_public_memory_addresses)
    {
        return Error.InputTooLarge;
    }
    var total: usize = 0;
    inline for (@typeInfo(wire.CasmStatesByOpcode).@"struct".fields) |field| {
        total = std.math.add(
            usize,
            total,
            @field(input.state_transitions.casm_states_by_opcode, field.name).len,
        ) catch return Error.LengthOverflow;
    }
    if (total > limits.max_states) return Error.InputTooLarge;
}

fn validateMemory(memory: wire.Memory) Error!void {
    if (memory.config.small_max >= (@as(u128, 1) << 72))
        return Error.InvalidSmallValue;
    if (memory.config.log_small_value_capacity >= @bitSizeOf(usize))
        return Error.InvalidSmallValueCapacity;
    const small_capacity = @as(usize, 1) << @intCast(memory.config.log_small_value_capacity);
    if (memory.small_values.len > small_capacity)
        return Error.InvalidSmallValueCapacity;
    for (memory.small_values) |value| {
        if (value > memory.config.small_max) return Error.InvalidSmallValue;
    }
    for (memory.f252_values) |value| {
        if (!isCanonicalF252(value)) return Error.F252ValueNotCanonical;
    }
    for (memory.address_to_id) |raw| {
        if (raw == memory_mod.DEFAULT_ID) continue;
        const index = raw & (memory_mod.LARGE_MEMORY_VALUE_ID_BASE - 1);
        switch (raw >> 30) {
            0 => if (index >= memory.small_values.len) return Error.InvalidMemoryId,
            1 => if (index >= memory.f252_values.len) return Error.InvalidMemoryId,
            else => return Error.InvalidMemoryTag,
        }
    }
}

fn isCanonicalF252(value: [8]u32) bool {
    const prime = [8]u32{ 1, 0, 0, 0, 0, 0, 0x11, 0x0800_0000 };
    var index: usize = value.len;
    while (index != 0) {
        index -= 1;
        if (value[index] < prime[index]) return true;
        if (value[index] > prime[index]) return false;
    }
    return false;
}

fn validatePublicAddresses(addresses: []const u32, memory_ids: []const u32) Error!void {
    for (addresses) |address| {
        if (address >= memory_ids.len or memory_ids[address] == memory_mod.DEFAULT_ID)
            return Error.InvalidPublicMemoryAddress;
    }
}

fn validatePublicContext(
    context: wire.PublicSegmentContext,
    states: wire.StateTransitions,
) Error!void {
    if (!context.present[0]) return Error.InvalidPublicSegmentContext;
    var count: u32 = 0;
    for (context.present) |present| count += @intFromBool(present);
    if (states.initial_state.ap > cpu.MEMORY_ADDRESS_BOUND - count or
        states.final_state.ap < count)
    {
        return Error.InvalidPublicSegmentContext;
    }
}

fn validateSegments(segments: wire.BuiltinSegments, memory_len: usize) Error!void {
    try validateSegment(segments.add_mod_builtin, memory_len, 7, true);
    try validateSegment(segments.bitwise_builtin, memory_len, 5, true);
    try validateSegment(segments.output, memory_len, 1, false);
    try validateSegment(segments.mul_mod_builtin, memory_len, 7, true);
    try validateSegment(segments.pedersen_builtin, memory_len, 3, true);
    try validateSegment(segments.poseidon_builtin, memory_len, 6, true);
    try validateSegment(segments.range_check96_builtin, memory_len, 1, true);
    try validateSegment(segments.range_check_builtin, memory_len, 1, true);
    try validateSegment(segments.ec_op_builtin, memory_len, 7, true);
}

fn validateSegment(
    segment: ?wire.MemorySegmentAddresses,
    memory_len: usize,
    cells_per_instance: usize,
    requires_power_of_two: bool,
) Error!void {
    const present = segment orelse return;
    if (present.begin_addr > present.stop_ptr or
        present.stop_ptr > memory_len or
        present.stop_ptr > cpu.MEMORY_ADDRESS_BOUND)
    {
        return Error.InvalidSegmentBounds;
    }
    const cells = present.stop_ptr - present.begin_addr;
    if (cells % cells_per_instance != 0) return Error.BuiltinSegmentMisaligned;
    const instances = cells / cells_per_instance;
    if (requires_power_of_two and !std.math.isPowerOfTwo(instances))
        return Error.BuiltinInstanceCountNotPowerOfTwo;
}

fn decodeSegments(segments: wire.BuiltinSegments) adapter.BuiltinSegments {
    return .{
        .add_mod_builtin = decodeSegment(segments.add_mod_builtin),
        .bitwise_builtin = decodeSegment(segments.bitwise_builtin),
        .output = decodeSegment(segments.output),
        .mul_mod_builtin = decodeSegment(segments.mul_mod_builtin),
        .pedersen_builtin = decodeSegment(segments.pedersen_builtin),
        .poseidon_builtin = decodeSegment(segments.poseidon_builtin),
        .range_check96_builtin = decodeSegment(segments.range_check96_builtin),
        .range_check_builtin = decodeSegment(segments.range_check_builtin),
        .ec_op_builtin = decodeSegment(segments.ec_op_builtin),
    };
}

fn decodeSegment(segment: ?wire.MemorySegmentAddresses) ?adapter.MemorySegmentAddresses {
    const present = segment orelse return null;
    return .{ .begin_addr = present.begin_addr, .stop_ptr = present.stop_ptr };
}
