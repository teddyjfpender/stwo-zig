//! Resident CUDA execution of authenticated Cairo multiplicity feeds.

const std = @import("std");
const abi = @import("../../../abi/stages/cairo_base.zig");
const common = @import("../common.zig");
const layout = @import("../resident_layout.zig");
const runtime_error = @import("../../error.zig");
const telemetry = @import("../../telemetry.zig");

pub const descriptor_words: u32 = 14;
const pointer_words = @sizeOf(u64) / @sizeOf(u32);

pub const Native = OpsFor(abi);

pub const Clear = struct {
    destination_pointer_table: common.Words,
    lengths: common.Words,
    destination_count: u32,
    maximum_words: u32,
};

pub const Feed = struct {
    sub_words_word_major: common.Words,
    column_length: u32,
    descriptors: common.Words,
    descriptor_count: u32,
    lut_pointer_table: common.Words,
    lut_count: u32,
    destination_pointer_table: common.Words,
    destination_count: u32,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn clear(
            session: anytype,
            prepared: Clear,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            if (prepared.destination_count == 0 or
                prepared.maximum_words == 0 or
                prepared.destination_pointer_table.len !=
                    @as(usize, prepared.destination_count) * pointer_words or
                prepared.lengths.len != prepared.destination_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const pointers = try layout.resident(
                session,
                u64,
                try prepared.destination_pointer_table.cast(u64),
                prepared.destination_count,
            );
            const lengths = try layout.resident(
                session,
                u32,
                prepared.lengths,
                prepared.destination_count,
            );
            try layout.requireDisjoint(
                &.{ pointers.range, lengths.range },
                &.{},
            );
            const status = Api.stwo_witness_feed_clear_on(
                pointers.pointer,
                lengths.pointer,
                prepared.destination_count,
                prepared.maximum_words,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn counts(
            session: anytype,
            prepared: Feed,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            if (prepared.column_length == 0 or
                prepared.descriptor_count == 0 or
                prepared.destination_count == 0 or
                prepared.sub_words_word_major.len % prepared.column_length !=
                    0 or
                prepared.descriptors.len !=
                    @as(usize, prepared.descriptor_count) * descriptor_words or
                prepared.lut_pointer_table.len !=
                    @as(usize, @max(prepared.lut_count, 1)) * pointer_words or
                prepared.destination_pointer_table.len !=
                    @as(usize, prepared.destination_count) * pointer_words)
            {
                return error.InvalidKernelDescriptor;
            }
            const source = try layout.resident(
                session,
                u32,
                prepared.sub_words_word_major,
                prepared.sub_words_word_major.len,
            );
            const descriptors = try layout.resident(
                session,
                u32,
                prepared.descriptors,
                prepared.descriptors.len,
            );
            const luts = try layout.resident(
                session,
                u64,
                try prepared.lut_pointer_table.cast(u64),
                @max(prepared.lut_count, 1),
            );
            const destinations = try layout.resident(
                session,
                u64,
                try prepared.destination_pointer_table.cast(u64),
                prepared.destination_count,
            );
            try layout.requireDisjoint(
                &.{
                    source.range,
                    descriptors.range,
                    luts.range,
                    destinations.range,
                },
                &.{},
            );
            const status = Api.stwo_witness_feed_counts_on(
                source.pointer,
                prepared.column_length,
                descriptors.pointer,
                prepared.descriptor_count,
                luts.pointer,
                destinations.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

test "feed metadata lengths are exact" {
    const Fake = struct {
        pub fn stwo_witness_feed_clear_on(
            _: [*]const u64,
            _: [*]const u32,
            _: u32,
            _: u32,
            _: *anyopaque,
        ) c_int {
            return 0;
        }
        pub fn stwo_witness_feed_counts_on(
            _: [*]const u32,
            _: u32,
            _: [*]const u32,
            _: u32,
            _: [*]const u64,
            _: [*]const u64,
            _: *anyopaque,
        ) c_int {
            return 0;
        }
    };
    _ = OpsFor(Fake);
    try std.testing.expectEqual(@as(u32, 14), descriptor_words);
}
