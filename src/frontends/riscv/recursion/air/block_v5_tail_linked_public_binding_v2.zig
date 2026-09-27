//! Attaches the exact ORIGINAL B5PD input-frame prefix fold to the SAME actual
//! bounded-window parent. Tail CVs/prefix are public requests, not fixed witness
//! authority; a genuine carrier at the common ancestor must supply them.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("../block_v5_tail_linked_public_windows_v2.zig");
const Bus = @import("../block_v5_tail_linked_public_windows_bus_v2.zig");
const Parent = @import("../blake3_execution_parent_preparation.zig");
const Digest = @import("block_v5_input_tail_public_digest_v1.zig");
const Consumer = @import("block_v5_input_tail_consumer_v1.zig");
const Rebase = @import("blake3_parent_rebase.zig");
const Join = @import("blake3_parent_join.zig");
pub const original_digest_equations_attached = true;
pub const carrier_ancestor_authority_pending = true;

pub fn sourceWord(field_words: u32, prefix_words: u32, request: Digest.Request) !u32 {
    return switch (request.source) {
        .public_field => |coordinate| if (coordinate < field_words) coordinate else error.InvalidTailLinkedPublicCell,
        .input_prefix => |coordinate| if (coordinate < prefix_words) try std.math.add(u32, try std.math.add(u32, field_words, 9), coordinate) else error.InvalidTailLinkedPublicCell,
        .frontier => |coordinate| if (coordinate.word < 8 and coordinate.ordinal < 64) try std.math.add(u32, try std.math.add(u32, try std.math.add(u32, field_words, 9), prefix_words), try std.math.add(u32, try std.math.mul(u32, coordinate.ordinal, 8), coordinate.word)) else error.InvalidTailLinkedPublicCell,
    };
}

pub fn attach(a: std.mem.Allocator, public: *const Public.Owner, parent: *Parent.Prepared, wires: *std.ArrayList(Bus.Wire), next: *u32, identities: *[5]core.channel.blake3.Channel, max_bytes: usize) !void {
    try public.validate();
    for (public.fields, 0..) |*field, local| {
        // All three sources share one disjoint caller circuit with exact word
        // offsets; the following prefix-fold/hash namespace is separate.
        const source_circuit: u32 = 4_310_000;
        const hash_namespace: u32 = 4_311_000;
        const prefix_start = field.word_count;
        const frontier_start = try std.math.add(u32, prefix_start, @intCast(public.input.prefix_count));
        var frontier: [64]Consumer.Caller = undefined;
        if (public.input.geometry.range_count > frontier.len) return error.InputTailResourceLimit;
        for (frontier[0..public.input.geometry.range_count], 0..) |*source, ordinal| source.* = .{ .circuit = source_circuit, .first_wire = try std.math.add(u32, frontier_start, try std.math.mul(u32, @intCast(ordinal), 8)) };
        const statement = Digest.Statement{ .namespace = hash_namespace, .fields = field, .carrier = public.input, .expected_input = public.policy.input_expected, .field_source = .{ .circuit = source_circuit, .first_wire = 0 }, .prefix_source = .{ .circuit = source_circuit, .first_wire = prefix_start }, .frontier_sources = frontier[0..public.input.geometry.range_count] };
        var hash = try Digest.prepareColumns(a, statement, public.policy.instances[local].key.config, max_bytes);
        defer hash.deinit();
        var namespace = try Rebase.prepare(a, &hash.recursive.rows, next.*);
        defer namespace.deinit();
        const end = try namespace.end();
        const namespace_id = try namespace.identity();
        const window = try std.math.add(u32, public.policy.first_window, @intCast(local));
        for (hash.requests) |request| try wires.append(a, .{ .circuit = namespace.map(request.circuit) orelse return error.MissingWidePublicNamespace, .wire = request.wire, .uses = request.uses, .source = .{ .public_word = .{ .window = window, .word = try sourceWord(field.word_count, @intCast(public.input.prefix_count), request) } } });
        try Rebase.apply(&hash.recursive.rows, &namespace, namespace_id);
        const joined = try Join.joinDraining(a, &parent.rows, &hash.recursive.rows, .{ .{ .first = 1, .end = next.* }, .{ .first = next.*, .end = end } });
        parent.rows.deinit();
        parent.rows = joined;
        for (identities) |*channel| {
            channel.mixRoot(hash.recursive.context.graph_ids[0]);
            channel.mixRoot(namespace_id);
            channel.mixU32s(&.{window});
        }
        next.* = end;
    }
}
