//! Official Cairo public-data contribution to the global LogUp sum.

const std = @import("std");
const core = @import("stwo_core");
const adapter = @import("../adapter/mod.zig");
const memory = @import("../common/memory.zig");
const public_data = @import("public_data.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const memory_address_relation_id: u32 = 1_444_891_767;
const memory_big_relation_id: u32 = 1_662_111_297;
const opcodes_relation_id: u32 = 428_564_188;
const big_limb_count: usize = 28;
const max_relation_words: usize = big_limb_count + 2;

pub fn sum(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    lookup_z: QM31,
    lookup_alpha: QM31,
) !QM31 {
    const alpha_powers = deriveAlphaPowers(lookup_alpha);
    var denominators = std.ArrayList(QM31).empty;
    defer denominators.deinit(allocator);

    const initial = input.state_transitions.initial_state;
    const final = input.state_transitions.final_state;
    const initial_pc = initial.pc.toU32();
    const initial_ap = initial.ap.toU32();
    const final_ap = final.ap.toU32();
    if (initial_ap < 2 or initial_ap - 2 < initial_pc)
        return error.InvalidProgramRange;

    const program_len = initial_ap - 2 - initial_pc;
    for (0..program_len) |offset| {
        const address = std.math.add(u32, initial_pc, @intCast(offset)) catch
            return error.SegmentPointerOverflow;
        try appendMemoryEntry(
            allocator,
            &denominators,
            lookup_z,
            &alpha_powers,
            address,
            try public_data.memoryEntryAt(input.memory, address),
        );
    }

    inline for (0..2) |offset| {
        const address = initial_ap - 2 + @as(u32, @intCast(offset));
        try appendMemoryEntry(
            allocator,
            &denominators,
            lookup_z,
            &alpha_powers,
            address,
            try public_data.memoryEntryAt(input.memory, address),
        );
    }

    const segments = try public_data.extractPublicSegments(input);
    var segment_count: u32 = 0;
    for (segments) |segment| segment_count += @intFromBool(segment != null);
    if (final_ap < segment_count) return error.SegmentPointerOverflow;
    var packed_index: u32 = 0;
    for (segments) |maybe_segment| {
        const segment = maybe_segment orelse continue;
        const start_address = std.math.add(u32, initial_ap, packed_index) catch
            return error.SegmentPointerOverflow;
        const stop_address = std.math.add(
            u32,
            final_ap - segment_count,
            packed_index,
        ) catch return error.SegmentPointerOverflow;
        try appendPointer(
            allocator,
            &denominators,
            lookup_z,
            &alpha_powers,
            start_address,
            segment.start,
        );
        try appendPointer(
            allocator,
            &denominators,
            lookup_z,
            &alpha_powers,
            stop_address,
            segment.stop,
        );
        packed_index += 1;
    }

    const output = segments[0] orelse return error.InvalidPublicSegmentContext;
    if (output.stop.value < output.start.value) return error.InvalidOutputSegment;
    const output_len = output.stop.value - output.start.value;
    for (0..output_len) |offset| {
        const address = std.math.add(u32, output.start.value, @intCast(offset)) catch
            return error.SegmentPointerOverflow;
        try appendMemoryEntry(
            allocator,
            &denominators,
            lookup_z,
            &alpha_powers,
            address,
            try public_data.memoryEntryAt(input.memory, address),
        );
    }

    const final_words = [_]M31{
        M31.fromCanonical(opcodes_relation_id),
        final.pc,
        final.ap,
        final.fp,
    };
    try denominators.append(
        allocator,
        combine(lookup_z, &alpha_powers, &final_words),
    );
    const initial_words = [_]M31{
        M31.fromCanonical(opcodes_relation_id),
        initial.pc,
        initial.ap,
        initial.fp,
    };
    try denominators.append(
        allocator,
        combine(lookup_z, &alpha_powers, &initial_words).neg(),
    );

    const inverses = try core.fields.batchInverse(
        QM31,
        allocator,
        denominators.items,
    );
    defer allocator.free(inverses);
    var result = QM31.zero();
    for (inverses) |inverse| result = result.add(inverse);
    return result;
}

fn appendMemoryEntry(
    allocator: std.mem.Allocator,
    denominators: *std.ArrayList(QM31),
    lookup_z: QM31,
    alpha_powers: []const QM31,
    address: u32,
    entry: public_data.MemoryEntry,
) !void {
    try appendAddress(
        allocator,
        denominators,
        lookup_z,
        alpha_powers,
        address,
        entry.id,
    );
    var words: [max_relation_words]M31 = undefined;
    words[0] = M31.fromCanonical(memory_big_relation_id);
    words[1] = M31.fromCanonical(entry.id);
    splitF252(entry.value, words[2..]);
    try denominators.append(
        allocator,
        combine(lookup_z, alpha_powers, &words),
    );
}

fn appendPointer(
    allocator: std.mem.Allocator,
    denominators: *std.ArrayList(QM31),
    lookup_z: QM31,
    alpha_powers: []const QM31,
    address: u32,
    pointer: public_data.SmallPointer,
) !void {
    try appendAddress(
        allocator,
        denominators,
        lookup_z,
        alpha_powers,
        address,
        pointer.id,
    );
    var value = [_]u32{0} ** 8;
    value[0] = pointer.value;
    try appendMemoryEntryValue(
        allocator,
        denominators,
        lookup_z,
        alpha_powers,
        pointer.id,
        .{ .f252 = value },
    );
}

fn appendAddress(
    allocator: std.mem.Allocator,
    denominators: *std.ArrayList(QM31),
    lookup_z: QM31,
    alpha_powers: []const QM31,
    address: u32,
    id: u32,
) !void {
    const words = [_]M31{
        M31.fromCanonical(memory_address_relation_id),
        M31.fromCanonical(address),
        M31.fromCanonical(id),
    };
    try denominators.append(
        allocator,
        combine(lookup_z, alpha_powers, &words),
    );
}

fn appendMemoryEntryValue(
    allocator: std.mem.Allocator,
    denominators: *std.ArrayList(QM31),
    lookup_z: QM31,
    alpha_powers: []const QM31,
    id: u32,
    value: memory.MemoryValue,
) !void {
    var words: [max_relation_words]M31 = undefined;
    words[0] = M31.fromCanonical(memory_big_relation_id);
    words[1] = M31.fromCanonical(id);
    splitF252(value, words[2..]);
    try denominators.append(
        allocator,
        combine(lookup_z, alpha_powers, &words),
    );
}

fn splitF252(value: memory.MemoryValue, output: []M31) void {
    std.debug.assert(output.len == big_limb_count);
    const dense = public_data.memoryValueWords(value);
    for (output, 0..) |*limb, index| {
        const bit_offset = index * 9;
        const word = bit_offset / 32;
        const shift: u5 = @intCast(bit_offset % 32);
        var raw = dense[word] >> shift;
        if (shift > 23 and word + 1 < dense.len)
            raw |= dense[word + 1] << @intCast(32 - @as(u6, shift));
        limb.* = M31.fromCanonical(raw & 0x1ff);
    }
}

fn combine(
    lookup_z: QM31,
    alpha_powers: []const QM31,
    words: []const M31,
) QM31 {
    std.debug.assert(words.len <= alpha_powers.len);
    var result = lookup_z.neg();
    for (words, alpha_powers[0..words.len]) |word, power|
        result = result.add(power.mulM31(word));
    return result;
}

fn deriveAlphaPowers(alpha: QM31) [max_relation_words]QM31 {
    var result: [max_relation_words]QM31 = undefined;
    var power = QM31.one();
    for (&result) |*value| {
        value.* = power;
        power = power.mul(alpha);
    }
    return result;
}
