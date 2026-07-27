//! Cairo claim and public-data serialization.

const std = @import("std");
const adapter = @import("../../adapter/mod.zig");
const registry = @import("../../air/official_claim_registry.zig");
const composition = @import("../../witness/composition_bundle.zig");
const public_data = @import("../../statement/public_data.zig");
const layout = @import("../layout.zig");
const felt_json = @import("felt_json.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn validateInput(input: *const adapter.ProverInput) !void {
    const segments = try public_data.extractPublicSegments(input);
    for (segments) |segment|
        if (segment == null) return error.CairoSerdeRequiresAllSegments;
}

pub fn writeClaim(
    writer: anytype,
    state: *felt_json.State,
    input: *const adapter.ProverInput,
    bundle: *const composition.Bundle,
) !void {
    try validateInput(input);
    try layout.validateComponents(bundle);
    try writePublicData(writer, state, input);
    for (registry.claim_fields) |field| {
        const span = layout.componentSpan(bundle, field.name);
        if (!layout.claimFieldPresent(field.name, span)) {
            try felt_json.write(writer, state, 1);
            continue;
        }
        try felt_json.write(writer, state, 0);
        switch (field.log_size_shape) {
            .fixed => if (span.len != 1) return error.InvalidClaimGeometry,
            .dynamic => {
                if (span.len != 1) return error.InvalidClaimGeometry;
                try felt_json.write(
                    writer,
                    state,
                    bundle.components[span.start].trace_log_size,
                );
            },
            .special_dynamic_prefix => {
                try felt_json.write(writer, state, span.len);
                for (bundle.components[span.start..][0..span.len]) |component|
                    try felt_json.write(
                        writer,
                        state,
                        component.trace_log_size,
                    );
            },
        }
    }
}

pub fn writeFlattenedInteractionClaim(
    writer: anytype,
    state: *felt_json.State,
    bundle: *const composition.Bundle,
    claimed_sums: []const QM31,
) !void {
    if (bundle.components.len != claimed_sums.len)
        return error.InvalidInteractionClaimGeometry;
    try layout.validateComponents(bundle);
    try felt_json.write(writer, state, claimed_sums.len);
    for (claimed_sums) |value| try writeQm31(writer, state, value);
}

fn writePublicData(
    writer: anytype,
    state: *felt_json.State,
    input: *const adapter.ProverInput,
) !void {
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

    try writeMemorySection(writer, state, input, initial_pc, initial_ap - 2);
    for (segments) |segment| {
        const range = segment orelse return error.CairoSerdeRequiresAllSegments;
        try writePointer(writer, state, range.start);
        try writePointer(writer, state, range.stop);
    }
    try writeMemorySection(
        writer,
        state,
        input,
        output.start.value,
        output.stop.value,
    );
    try felt_json.write(writer, state, safe0.id);
    try felt_json.write(writer, state, safe1.id);
    try writeState(writer, state, initial);
    try writeState(writer, state, final);
}

fn writeMemorySection(
    writer: anytype,
    state: *felt_json.State,
    input: *const adapter.ProverInput,
    start: u32,
    stop: u32,
) !void {
    if (stop < start) return error.InvalidMemorySection;
    try felt_json.write(writer, state, stop - start);
    var address = start;
    while (address < stop) : (address += 1) {
        const entry = try public_data.memoryEntryAt(input.memory, address);
        try felt_json.write(writer, state, entry.id);
        for (public_data.memoryValueWords(entry.value)) |word|
            try felt_json.write(writer, state, word);
    }
}

fn writePointer(
    writer: anytype,
    state: *felt_json.State,
    pointer: public_data.SmallPointer,
) !void {
    try felt_json.write(writer, state, pointer.id);
    try felt_json.write(writer, state, pointer.value);
}

fn writeState(writer: anytype, state: *felt_json.State, value: anytype) !void {
    try felt_json.write(writer, state, value.pc.toU32());
    try felt_json.write(writer, state, value.ap.toU32());
    try felt_json.write(writer, state, value.fp.toU32());
}

fn writeQm31(
    writer: anytype,
    state: *felt_json.State,
    value: QM31,
) !void {
    for (value.toM31Array()) |coordinate|
        try felt_json.write(writer, state, coordinate.toU32());
}
