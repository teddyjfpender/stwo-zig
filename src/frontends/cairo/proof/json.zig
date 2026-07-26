//! Serde-compatible JSON encoding for the pinned Stwo-Cairo Rust verifier.

const std = @import("std");
const core = @import("stwo_core");
const adapter = @import("../adapter/mod.zig");
const registry = @import("../air/official_claim_registry.zig");
const public_data = @import("../statement/public_data.zig");
const preprocessed = @import("../preprocessed/trace.zig");
const composition_bundle = @import("../witness/composition_bundle.zig");
const stwo_json = @import("../../../interop/stwo_json.zig");

const QM31 = core.fields.qm31.QM31;

const segment_names = [_][]const u8{
    "output",
    "pedersen",
    "range_check_128",
    "ecdsa",
    "bitwise",
    "ec_op",
    "keccak",
    "poseidon",
    "range_check_96",
    "add_mod",
    "mul_mod",
};

pub fn Document(comptime StarkProof: type) type {
    return struct {
        input: *const adapter.ProverInput,
        composition: *const composition_bundle.Bundle,
        claimed_sums: []const QM31,
        interaction_pow: u64,
        channel_salt: u32,
        preprocessed_variant: preprocessed.Variant,
        stark_proof: *const StarkProof,

        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            writeDocument(
                writer,
                self.input,
                self.composition,
                self.claimed_sums,
                self.interaction_pow,
                self.channel_salt,
                self.preprocessed_variant,
                self.stark_proof,
            ) catch return error.WriteFailed;
        }
    };
}

pub fn writeDocument(
    writer: anytype,
    input: *const adapter.ProverInput,
    composition: *const composition_bundle.Bundle,
    claimed_sums: []const QM31,
    interaction_pow: u64,
    channel_salt: u32,
    variant: preprocessed.Variant,
    stark_proof: anytype,
) !void {
    if (composition.components.len != claimed_sums.len)
        return error.InvalidInteractionClaimGeometry;
    try validateComponents(composition);

    try writer.beginObject();
    try writer.objectField("claim");
    try writeClaim(writer, input, composition);
    try writer.objectField("interaction_pow");
    try writer.write(interaction_pow);
    try writer.objectField("interaction_claim");
    try writeInteractionClaim(writer, composition, claimed_sums);
    try writer.objectField("stark_proof");
    try stwo_json.writeStarkProof(writer, stark_proof);
    try writer.objectField("channel_salt");
    try writer.write(channel_salt);
    try writer.objectField("preprocessed_trace_variant");
    try writer.write(@tagName(variant));
    try writer.endObject();
}

fn writeClaim(
    writer: anytype,
    input: *const adapter.ProverInput,
    composition: *const composition_bundle.Bundle,
) !void {
    try writer.beginObject();
    try writer.objectField("public_data");
    try writePublicData(writer, input);
    for (registry.claim_fields) |field| {
        const span = componentSpan(composition, field.name);
        try writer.objectField(field.name);
        if (span.len == 0) {
            try writer.write(null);
        } else if (std.mem.eql(u8, field.name, "memory_id_to_big")) {
            try writer.beginObject();
            try writer.objectField("big_log_sizes");
            try writer.beginArray();
            for (composition.components[span.start..][0..span.len]) |component|
                try writer.write(component.trace_log_size);
            try writer.endArray();
            try writer.endObject();
        } else {
            if (span.len != 1) return error.InvalidClaimGeometry;
            try writer.beginObject();
            try writer.objectField("log_size");
            try writer.write(composition.components[span.start].trace_log_size);
            try writer.endObject();
        }
    }
    try writer.endObject();
}

fn writeInteractionClaim(
    writer: anytype,
    composition: *const composition_bundle.Bundle,
    claimed_sums: []const QM31,
) !void {
    try writer.beginObject();
    for (registry.claim_fields) |field| {
        const span = componentSpan(composition, field.name);
        try writer.objectField(field.name);
        if (span.len == 0) {
            try writer.write(null);
        } else if (std.mem.eql(u8, field.name, "memory_id_to_big")) {
            var sum = QM31.zero();
            try writer.beginObject();
            try writer.objectField("big_claimed_sums");
            try writer.beginArray();
            for (claimed_sums[span.start..][0..span.len]) |claimed_sum| {
                try stwo_json.writeQm31(writer, claimed_sum);
                sum = sum.add(claimed_sum);
            }
            try writer.endArray();
            try writer.objectField("claimed_sum");
            try stwo_json.writeQm31(writer, sum);
            try writer.endObject();
        } else {
            if (span.len != 1) return error.InvalidInteractionClaimGeometry;
            try writer.beginObject();
            try writer.objectField("claimed_sum");
            try stwo_json.writeQm31(writer, claimed_sums[span.start]);
            try writer.endObject();
        }
    }
    try writer.endObject();
}

fn writePublicData(writer: anytype, input: *const adapter.ProverInput) !void {
    const initial = input.state_transitions.initial_state;
    const final = input.state_transitions.final_state;
    const initial_pc = initial.pc.toU32();
    const initial_ap = initial.ap.toU32();
    if (initial_ap < 2 or initial_ap - 2 < initial_pc)
        return error.InvalidProgramRange;
    const segments = try public_data.extractPublicSegments(input);
    const output = segments[0] orelse return error.InvalidPublicSegmentContext;
    if (output.stop.value < output.start.value)
        return error.InvalidOutputSegment;
    const safe0 = try public_data.memoryEntryAt(input.memory, initial_ap - 2);
    const safe1 = try public_data.memoryEntryAt(input.memory, initial_ap - 1);
    if (!public_data.memoryValueEqualsU32(safe0.value, initial_ap) or
        !public_data.memoryValueIsZero(safe1.value))
        return error.InvalidSafeCall;

    try writer.beginObject();
    try writer.objectField("public_memory");
    try writer.beginObject();
    try writer.objectField("program");
    try writeMemorySection(writer, input, initial_pc, initial_ap - 2);
    try writer.objectField("public_segments");
    try writer.beginObject();
    for (segment_names, segments) |name, segment| {
        try writer.objectField(name);
        if (segment) |range| try writeSegment(writer, range) else try writer.write(null);
    }
    try writer.endObject();
    try writer.objectField("output");
    try writeMemorySection(writer, input, output.start.value, output.stop.value);
    try writer.objectField("safe_call_ids");
    try writer.beginArray();
    try writer.write(safe0.id);
    try writer.write(safe1.id);
    try writer.endArray();
    try writer.endObject();
    try writer.objectField("initial_state");
    try writeState(writer, initial);
    try writer.objectField("final_state");
    try writeState(writer, final);
    try writer.endObject();
}

fn writeMemorySection(
    writer: anytype,
    input: *const adapter.ProverInput,
    start: u32,
    stop: u32,
) !void {
    try writer.beginArray();
    var address = start;
    while (address < stop) : (address += 1) {
        const entry = try public_data.memoryEntryAt(input.memory, address);
        try writer.beginArray();
        try writer.write(entry.id);
        try writer.write(public_data.memoryValueWords(entry.value));
        try writer.endArray();
    }
    try writer.endArray();
}

fn writeSegment(writer: anytype, range: public_data.SegmentRange) !void {
    try writer.beginObject();
    try writer.objectField("start_ptr");
    try writeSmallPointer(writer, range.start);
    try writer.objectField("stop_ptr");
    try writeSmallPointer(writer, range.stop);
    try writer.endObject();
}

fn writeSmallPointer(writer: anytype, pointer: public_data.SmallPointer) !void {
    try writer.beginObject();
    try writer.objectField("id");
    try writer.write(pointer.id);
    try writer.objectField("value");
    try writer.write(pointer.value);
    try writer.endObject();
}

fn writeState(writer: anytype, state: anytype) !void {
    try writer.beginObject();
    try writer.objectField("pc");
    try writer.write(state.pc.toU32());
    try writer.objectField("ap");
    try writer.write(state.ap.toU32());
    try writer.objectField("fp");
    try writer.write(state.fp.toU32());
    try writer.endObject();
}

const ComponentSpan = struct {
    start: usize = 0,
    len: usize = 0,
};

fn componentSpan(
    composition: *const composition_bundle.Bundle,
    field_name: []const u8,
) ComponentSpan {
    var result = ComponentSpan{};
    for (composition.components, 0..) |component, index| {
        if (!std.mem.eql(u8, canonicalName(component.label), field_name)) continue;
        if (result.len == 0) result.start = index;
        result.len += 1;
    }
    return result;
}

fn validateComponents(composition: *const composition_bundle.Bundle) !void {
    var seen = [_]bool{false} ** registry.claim_field_count;
    var last_field: ?usize = null;
    var last_instance: u32 = 0;
    for (composition.components) |component| {
        const field_index = fieldIndex(canonicalName(component.label)) orelse
            return error.UnknownClaimComponent;
        if (last_field == field_index) {
            if (component.instance != last_instance + 1)
                return error.InvalidClaimGeometry;
        } else {
            if (seen[field_index] or component.instance != 0)
                return error.InvalidClaimGeometry;
            seen[field_index] = true;
        }
        last_field = field_index;
        last_instance = component.instance;
    }
}

fn fieldIndex(name: []const u8) ?usize {
    for (registry.claim_fields, 0..) |field, index|
        if (std.mem.eql(u8, field.name, name)) return index;
    return null;
}

fn canonicalName(label: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, label, "memory_id_to_big["))
        "memory_id_to_big"
    else
        label;
}

test "Cairo proof JSON: official field registry remains schema-complete" {
    try std.testing.expectEqual(@as(usize, 68), registry.claim_fields.len);
    try std.testing.expectEqual(@as(usize, 11), segment_names.len);
    try std.testing.expectEqualStrings("memory_id_to_big", canonicalName("memory_id_to_big[15]"));
}
