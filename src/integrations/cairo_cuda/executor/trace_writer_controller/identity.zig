//! Stable identity for an authenticated trace-writer schedule and its feeds.

const std = @import("std");

pub fn compute(
    schedule_identity: [32]u8,
    bindings: anytype,
    feed_graph: anytype,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/trace-writer-controller/v1\x00");
    hash.update(&schedule_identity);
    hashInt(&hash, u64, bindings.len);
    for (bindings) |binding| {
        hashInt(&hash, u32, binding.component_index);
        hash.update(&binding.catalog_identity);
        hashInt(&hash, u8, @intFromEnum(binding.body));
        switch (binding.body) {
            .recorded => |prepared| hash.update(&prepared.binding_identity),
            .fixed => |fixed| hash.update(&fixed.binding_identity),
            .memory_address => |memory_address| {
                hash.update(&memory_address.binding_identity);
            },
            .memory_value_big => |memory_value| {
                hash.update(&memory_value.binding_identity);
            },
            .memory_value_small => |memory_value| {
                hash.update(&memory_value.binding_identity);
            },
            .native_ec => |native| {
                hashInt(&hash, u32, native.member_component_index);
                hash.update(&native.member_catalog_identity);
                hash.update(&native.prepared.binding_identity);
                hash.update(&native.prepared.partial_ec_mul.binding_identity);
            },
        }
    }
    hashInt(&hash, u8, @intFromBool(feed_graph != null));
    if (feed_graph) |graph| {
        hashFeedClear(&hash, graph.clear);
        hashInt(&hash, u64, graph.post_feeds.len);
        for (graph.post_feeds) |feed| {
            hashInt(&hash, u32, feed.component_index);
            hashFeed(&hash, feed.binding);
        }
    }
    return hash.finalResult();
}

fn hashFeedClear(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    hashWords(hash, value.destination_pointer_table);
    hashWords(hash, value.lengths);
    hashInt(hash, u32, value.destination_count);
    hashInt(hash, u32, value.maximum_words);
}

fn hashFeed(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    hashWords(hash, value.sub_words_word_major);
    hashInt(hash, u32, value.column_length);
    hashWords(hash, value.descriptors);
    hashInt(hash, u32, value.descriptor_count);
    hashWords(hash, value.lut_pointer_table);
    hashInt(hash, u32, value.lut_count);
    hashWords(hash, value.destination_pointer_table);
    hashInt(hash, u32, value.destination_count);
}

fn hashWords(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    hashInt(hash, u64, value.address);
    hashInt(hash, u64, value.len);
    hashInt(hash, u64, value.owner);
    hashInt(hash, u64, value.generation);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
