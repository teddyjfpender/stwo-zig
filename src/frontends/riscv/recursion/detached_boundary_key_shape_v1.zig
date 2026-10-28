//! Segment-child boundary geometry derived from an admitted key alone.
//! Public bytes, hashes and proof captures cannot choose its provider count.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const key_mod = @import("detached_segment_protocol_v1.zig");
const wire = @import("segment_statement_v2.zig");
const source = @import("segment_leaf_authority_v2.zig");
const section_mod = @import("detached_section_profile_v1.zig");
const memory_mod = @import("detached_memory_profile_v1.zig");
const graph = @import("detached_boundary_graph_v1.zig");
const continuation = @import("detached_boundary_continuation_v1.zig");
const channel = @import("poseidon2_channel.zig");
const identity = @import("segment_statement_v2_identity_preimage.zig");

pub const SegmentShapeV1 = struct {
    sections: [4]section_mod.SectionV1,
    memory: memory_mod.MemoryProfileV1,
    wire_word_count: usize,
    wire_calls: usize,
    context_calls: usize,
    authority_calls: usize,
    embedded_calls: usize,
    retained_calls: usize,
    memory_calls: usize,
    provider_calls: usize,

    pub fn init(allocator: std.mem.Allocator, key: *const key_mod.KeyV1) !SegmentShapeV1 {
        try key.validate();
        const topology = key.native_sum_topology orelse return error.DetachedBoundaryKeyShapeMissing;
        try topology.validate(key.retained_section_counts);
        const profile = section_mod.SectionProfileV1{ .counts = key.retained_section_counts };
        var wire_word_count: usize = wire.FIXED_CANONICAL_WORDS;
        for (profile.counts) |count| {
            const payload = try std.math.mul(usize, @as(usize, count), wire.RETAINED_ENTRY_WORDS);
            wire_word_count = try std.math.add(usize, wire_word_count, wire.SECTION_HEADER_WORDS);
            wire_word_count = try std.math.add(usize, wire_word_count, payload);
        }
        const sections = try profile.sections(wire_word_count);
        const entry_count: usize = profile.counts[0];
        const exit_count: usize = profile.counts[1];
        const memory = memory_mod.MemoryProfileV1{
            .entry_addresses = topology.addresses[0..entry_count],
            .exit_addresses = topology.addresses[entry_count..][0..exit_count],
        };
        try memory.validate(profile);

        var context_counter = graph.WordCounter{};
        const zero_context = std.mem.zeroes(source.NativeTemporalContextV2);
        source.emitContextIdentity(&zero_context, &context_counter);
        const wire_calls = channel.canonicalWordPermutationCount(wire_word_count);
        const context_calls = channel.canonicalWordPermutationCount(context_counter.count);
        const authority_calls = try key.native_descriptors.callCount();
        var embedded_calls: usize = 0;
        for (std.meta.tags(identity.Phase)) |phase|
            embedded_calls = try std.math.add(usize, embedded_calls, channel.canonicalWordPermutationCount(identity.wordCount(phase)));
        var retained_calls: usize = 0;
        for (sections) |section|
            retained_calls = try std.math.add(usize, retained_calls, channel.canonicalWordPermutationCount(identity.retainedWordCount(section.count)));

        var memory_counter = continuation.MemoryCounter{};
        for (sections[0..2], [_][]const u32{ memory.entry_addresses, memory.exit_addresses }) |section, addresses| {
            const bytes = try allocator.alloc([4]M31, section.count);
            defer allocator.free(bytes);
            @memset(bytes, @splat(M31.zero()));
            var iterator = memory_mod.ByteIterator(M31).init(addresses, bytes);
            _ = wire.continuationSubtreeRootWithHasher(&iterator, 0, 0, wire.MAX_RW_ADDRESS_EXCLUSIVE, &memory_counter);
            if (iterator.current != null) return error.DetachedBoundaryKeyShapeMismatch;
        }
        var provider_calls = wire_calls;
        inline for (.{ context_calls, authority_calls, embedded_calls, retained_calls, memory_counter.count }) |part|
            provider_calls = try std.math.add(usize, provider_calls, part);
        return .{
            .sections = sections,
            .memory = memory,
            .wire_word_count = wire_word_count,
            .wire_calls = wire_calls,
            .context_calls = context_calls,
            .authority_calls = authority_calls,
            .embedded_calls = embedded_calls,
            .retained_calls = retained_calls,
            .memory_calls = memory_counter.count,
            .provider_calls = provider_calls,
        };
    }
};
