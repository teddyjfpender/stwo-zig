//! Official bincode layout for Cairo claims and public data.

const std = @import("std");
const adapter = @import("../../adapter/mod.zig");
const registry = @import("../../air/official_claim_registry.zig");
const composition = @import("../../witness/composition_bundle.zig");
const public_data = @import("../../statement/public_data.zig");
const layout = @import("../layout.zig");
const binary = @import("writer.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn writeClaim(
    output: anytype,
    input: *const adapter.ProverInput,
    bundle: *const composition.Bundle,
) !void {
    try layout.validateComponents(bundle);
    try writePublicData(output, input);
    for (registry.claim_fields) |field| {
        const span = layout.componentSpan(bundle, field.name);
        try binary.optional(output, span.len != 0);
        if (span.len == 0) continue;
        switch (field.log_size_shape) {
            .fixed => if (span.len != 1) return error.InvalidClaimGeometry,
            .dynamic => {
                if (span.len != 1) return error.InvalidClaimGeometry;
                try binary.int(
                    output,
                    u32,
                    bundle.components[span.start].trace_log_size,
                );
            },
            .special_dynamic_prefix => {
                try binary.length(output, span.len);
                for (bundle.components[span.start..][0..span.len]) |component|
                    try binary.int(output, u32, component.trace_log_size);
            },
        }
    }
}

pub fn writeInteractionClaim(
    output: anytype,
    bundle: *const composition.Bundle,
    claimed_sums: []const QM31,
) !void {
    if (bundle.components.len != claimed_sums.len)
        return error.InvalidInteractionClaimGeometry;
    try layout.validateComponents(bundle);
    for (registry.claim_fields) |field| {
        const span = layout.componentSpan(bundle, field.name);
        try binary.optional(output, span.len != 0);
        if (span.len == 0) continue;
        if (field.log_size_shape == .special_dynamic_prefix) {
            try binary.length(output, span.len);
            var total = QM31.zero();
            for (claimed_sums[span.start..][0..span.len]) |claimed_sum| {
                try writeQm31(output, claimed_sum);
                total = total.add(claimed_sum);
            }
            try writeQm31(output, total);
        } else {
            if (span.len != 1) return error.InvalidInteractionClaimGeometry;
            try writeQm31(output, claimed_sums[span.start]);
        }
    }
}

fn writePublicData(output: anytype, input: *const adapter.ProverInput) !void {
    const initial = input.state_transitions.initial_state;
    const final = input.state_transitions.final_state;
    const initial_pc = initial.pc.toU32();
    const initial_ap = initial.ap.toU32();
    if (initial_ap < 2 or initial_ap - 2 < initial_pc)
        return error.InvalidProgramRange;
    const segments = try public_data.extractPublicSegments(input);
    const output_segment =
        segments[0] orelse return error.InvalidPublicSegmentContext;
    if (output_segment.stop.value < output_segment.start.value)
        return error.InvalidOutputSegment;
    const safe0 = try public_data.memoryEntryAt(input.memory, initial_ap - 2);
    const safe1 = try public_data.memoryEntryAt(input.memory, initial_ap - 1);
    if (!public_data.memoryValueEqualsU32(safe0.value, initial_ap) or
        !public_data.memoryValueIsZero(safe1.value))
        return error.InvalidSafeCall;

    try writeMemorySection(output, input, initial_pc, initial_ap - 2);
    try writeSegment(output, output_segment);
    for (segments[1..]) |segment| {
        try binary.optional(output, segment != null);
        if (segment) |range| try writeSegment(output, range);
    }
    try writeMemorySection(
        output,
        input,
        output_segment.start.value,
        output_segment.stop.value,
    );
    try binary.int(output, u32, safe0.id);
    try binary.int(output, u32, safe1.id);
    try writeState(output, initial);
    try writeState(output, final);
}

fn writeMemorySection(
    output: anytype,
    input: *const adapter.ProverInput,
    start: u32,
    stop: u32,
) !void {
    if (stop < start) return error.InvalidMemorySection;
    try binary.length(output, stop - start);
    var address = start;
    while (address < stop) : (address += 1) {
        const entry = try public_data.memoryEntryAt(input.memory, address);
        try binary.int(output, u32, entry.id);
        for (public_data.memoryValueWords(entry.value)) |word|
            try binary.int(output, u32, word);
    }
}

fn writeSegment(output: anytype, range: public_data.SegmentRange) !void {
    inline for (.{ range.start, range.stop }) |pointer| {
        try binary.int(output, u32, pointer.id);
        try binary.int(output, u32, pointer.value);
    }
}

fn writeState(output: anytype, state: anytype) !void {
    try binary.int(output, u32, state.pc.toU32());
    try binary.int(output, u32, state.ap.toU32());
    try binary.int(output, u32, state.fp.toU32());
}

fn writeQm31(output: anytype, value: QM31) !void {
    for (value.toM31Array()) |coordinate|
        try binary.int(output, u32, coordinate.toU32());
}
