//! Stable semantic summary shared by adapter differential gates.

const std = @import("std");
const adapter = @import("../mod.zig");
const opcodes = @import("../opcodes.zig");

pub const Digest = [std.crypto.hash.sha2.Sha256.digest_length]u8;

pub const TableDigest = struct {
    count: usize,
    sha256_le: Digest,
};

pub const OpcodeStates = struct {
    values: [opcodes.N_OPCODES]TableDigest,

    pub fn get(self: *const OpcodeStates, tag: opcodes.OpcodeTag) TableDigest {
        return self.values[@intFromEnum(tag)];
    }
};

pub const Memory = struct {
    small_max: u128,
    log_small_value_capacity: u32,
    address_to_id: TableDigest,
    f252_values: TableDigest,
    small_values: TableDigest,
};

pub const BuiltinCounts = struct {
    add_mod_builtin: usize,
    bitwise_builtin: usize,
    ec_op_builtin: usize,
    mul_mod_builtin: usize,
    output_builtin: usize,
    pedersen_builtin: usize,
    poseidon_builtin: usize,
    range_check96_builtin: usize,
    range_check_builtin: usize,
};

pub const ExecutionResources = struct {
    opcode_counts: [opcodes.N_OPCODES]usize,
    builtin_counts: BuiltinCounts,
    memory_address_to_id: usize,
    memory_id_to_big: usize,
    memory_id_to_small: usize,
    verify_instruction: usize,
};

pub const Summary = struct {
    input_sha256: Digest,
    initial_state: [3]u32,
    final_state: [3]u32,
    opcode_states: OpcodeStates,
    memory: Memory,
    pc_count: usize,
    public_memory_addresses: TableDigest,
    builtin_segments: adapter.BuiltinSegments,
    public_segment_context: adapter.PublicSegmentContext,
    execution_resources: ExecutionResources,
};

pub fn fromInput(input: *const adapter.ProverInput, input_sha256: Digest) Summary {
    var state_digests: [opcodes.N_OPCODES]TableDigest = undefined;
    var opcode_counts: [opcodes.N_OPCODES]usize = undefined;
    for (&state_digests, &opcode_counts, 0..) |*digest, *count, index| {
        const states = input.state_transitions.casm_states_by_opcode.states[index].items;
        digest.* = stateDigest(states);
        count.* = states.len;
    }
    const segments = input.builtin_segments;
    return .{
        .input_sha256 = input_sha256,
        .initial_state = state(input.state_transitions.initial_state),
        .final_state = state(input.state_transitions.final_state),
        .opcode_states = .{ .values = state_digests },
        .memory = .{
            .small_max = input.memory.config.small_max,
            .log_small_value_capacity = input.memory.config.log_small_value_capacity,
            .address_to_id = encodedIdDigest(input.memory.address_to_id),
            .f252_values = f252Digest(input.memory.f252_values),
            .small_values = u128Digest(input.memory.small_values),
        },
        .pc_count = input.pc_count,
        .public_memory_addresses = u32Digest(input.public_memory_addresses),
        .builtin_segments = segments,
        .public_segment_context = input.public_segment_context,
        .execution_resources = .{
            .opcode_counts = opcode_counts,
            .builtin_counts = .{
                .add_mod_builtin = instances(segments.add_mod_builtin, 7),
                .bitwise_builtin = instances(segments.bitwise_builtin, 5),
                .ec_op_builtin = instances(segments.ec_op_builtin, 7),
                .mul_mod_builtin = instances(segments.mul_mod_builtin, 7),
                .output_builtin = instances(segments.output, 1),
                .pedersen_builtin = instances(segments.pedersen_builtin, 3),
                .poseidon_builtin = instances(segments.poseidon_builtin, 6),
                .range_check96_builtin = instances(segments.range_check96_builtin, 1),
                .range_check_builtin = instances(segments.range_check_builtin, 1),
            },
            .memory_address_to_id = input.memory.address_to_id.len,
            .memory_id_to_big = input.memory.f252_values.len,
            .memory_id_to_small = input.memory.small_values.len,
            .verify_instruction = input.pc_count,
        },
    };
}

fn state(value: @import("../../common/cpu.zig").CasmState) [3]u32 {
    return .{ value.pc.toU32(), value.ap.toU32(), value.fp.toU32() };
}

fn stateDigest(states: []const @import("../../common/cpu.zig").CasmState) TableDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (states) |value| {
        updateInt(&hasher, u32, value.pc.toU32());
        updateInt(&hasher, u32, value.ap.toU32());
        updateInt(&hasher, u32, value.fp.toU32());
    }
    return finish(&hasher, states.len);
}

fn encodedIdDigest(values: []const @import("../../common/memory.zig").EncodedMemoryValueId) TableDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (values) |value| updateInt(&hasher, u32, value.raw);
    return finish(&hasher, values.len);
}

fn u32Digest(values: []const u32) TableDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (values) |value| updateInt(&hasher, u32, value);
    return finish(&hasher, values.len);
}

fn f252Digest(values: []const [8]u32) TableDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (values) |value| {
        for (value) |word| updateInt(&hasher, u32, word);
    }
    return finish(&hasher, values.len);
}

fn u128Digest(values: []const u128) TableDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (values) |value| updateInt(&hasher, u128, value);
    return finish(&hasher, values.len);
}

fn updateInt(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn finish(hasher: *std.crypto.hash.sha2.Sha256, count: usize) TableDigest {
    var digest: Digest = undefined;
    hasher.final(&digest);
    return .{ .count = count, .sha256_le = digest };
}

fn instances(segment: ?adapter.MemorySegmentAddresses, cells_per_instance: usize) usize {
    const present = segment orelse return 0;
    return (present.stop_ptr - present.begin_addr) / cells_per_instance;
}
