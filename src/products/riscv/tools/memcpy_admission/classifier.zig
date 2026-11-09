//! Existing byte/word disjointness admission for bounded memcpy observations.
const std = @import("std");
const data_address_limit: u32 = @as(u32, 1) << 30;

pub const Classification = enum {
    admitted,
    too_short,
    alignment_mismatch,
    endpoint_invalid,
    byte_overlap,
    aligned_word_overlap,
};

pub const CallObservation = struct {
    classification: Classification,
    length: u32,
    word_rows: u32,
    return_pc: u32,
    start_row: u64,
};

pub fn classify(
    destination: u32,
    source: u32,
    length: u32,
    return_pc: u32,
    start_row: u64,
) CallObservation {
    var result = CallObservation{
        .classification = .admitted,
        .length = length,
        .word_rows = 0,
        .return_pc = return_pc,
        .start_row = start_row,
    };
    if (length < 32) {
        result.classification = .too_short;
        return result;
    }
    if ((destination ^ source) & 3 != 0) {
        result.classification = .alignment_mismatch;
        return result;
    }
    const destination_end = std.math.add(u32, destination, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const source_end = std.math.add(u32, source, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    if (destination_end > data_address_limit or source_end > data_address_limit) {
        result.classification = .endpoint_invalid;
        return result;
    }
    if (!(source_end <= destination or destination_end <= source)) {
        result.classification = .byte_overlap;
        return result;
    }
    const start_offset = destination & 3;
    result.word_rows = (length + start_offset + 3) / 4;
    const source_first_word = source / 4;
    const destination_first_word = destination / 4;
    const source_word_end = std.math.add(
        u32,
        source_first_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const destination_word_end = std.math.add(
        u32,
        destination_first_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    if (!(source_word_end <= destination_first_word or
        destination_word_end <= source_first_word))
    {
        result.classification = .aligned_word_overlap;
    }
    return result;
}

test "classifier matches aligned-word candidate boundary" {
    const admitted = classify(0x2000, 0x1000, 32, 4, 0);
    try std.testing.expectEqual(Classification.admitted, admitted.classification);
    try std.testing.expectEqual(@as(u32, 8), admitted.word_rows);

    const boundary_collision = classify(0x1021, 0x1001, 32, 4, 0);
    try std.testing.expectEqual(
        Classification.aligned_word_overlap,
        boundary_collision.classification,
    );
    const mismatch = classify(0x2000, 0x1001, 32, 4, 0);
    try std.testing.expectEqual(
        Classification.alignment_mismatch,
        mismatch.classification,
    );
}

test "memcpy classifier retains every rejection class" {
    for ([_]struct { destination: u32, source: u32, length: u32, expected: Classification }{
        .{ .destination = 0x2000, .source = 0x1000, .length = 31, .expected = .too_short },
        .{ .destination = 0x2000, .source = 0x1001, .length = 32, .expected = .alignment_mismatch },
        .{ .destination = 0xfffffff0, .source = 0x1000, .length = 32, .expected = .endpoint_invalid },
        .{ .destination = 0x40000000, .source = 0x1000, .length = 32, .expected = .endpoint_invalid },
        .{ .destination = 0x1010, .source = 0x1000, .length = 32, .expected = .byte_overlap },
        .{ .destination = 0x1021, .source = 0x1001, .length = 32, .expected = .aligned_word_overlap },
    }) |case| try std.testing.expectEqual(case.expected, classify(case.destination, case.source, case.length, 4, 0).classification);
}
