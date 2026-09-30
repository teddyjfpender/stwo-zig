//! Current Cairo fixed and memory feeds lowered to the resident CUDA ABI.
//! Descriptors come from authenticated source topology, never a captured run.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const geometry_mod = @import("canonical_geometry.zig");
const feeds = cairo.witness.feed_bundle;
const memory_tables = cairo.witness.memory_tables;
const none: u32 = 0xffff_ffff;

pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    bundle: feeds.Bundle,
    identity: [32]u8,

    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    input: *const cairo.adapter.ProverInput,
    claim: *const cairo.claim_generator.OwnedClaimGeometry,
    geometry: geometry_mod.Geometry,
    topology: cairo.witness.feed_topology.Loaded,
    fixed: cairo.witness.fixed_table_bundle.Bundle,
) !Owned {
    if (geometry.extents.len != claim.components.len) return error.CanonicalGeometryMismatch;
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const scratch = arena.allocator();
    var entries = std.ArrayList(feeds.Feed).empty;
    for (claim.components, geometry.extents) |component, extent| {
        const producer = topology.find(component.name) orelse {
            if (std.mem.eql(u8, component.name, "memory_id_to_big") or
                std.mem.eql(u8, component.name, "memory_id_to_small"))
                try entries.append(scratch, try memoryRangeFeed(scratch, component.name, extent, fixed));
            continue;
        };
        var descriptors = std.ArrayList(u32).empty;
        var destinations = std.ArrayList(feeds.Destination).empty;
        for (producer.feeds) |feed| {
            var descriptor: [14]u32 = @splat(0);
            descriptor[0] = feed.word_base;
            descriptor[1] = feed.words_per_instance;
            descriptor[7] = feed.relation;
            descriptor[9] = none;
            if (std.mem.eql(u8, feed.target, "memory_address_to_id")) {
                if (feed.words_per_instance != 1 or feed.relation != 0) return error.UnsupportedMemoryFeed;
                descriptor[8] = try cast(input.memory.address_to_id.len -| 1);
                descriptor[10] = try destination(scratch, &destinations, "memory_address_to_id", try memoryDestinationWords(input, "memory_address_to_id"));
                descriptor[12] = @bitCast(@as(i32, -1));
            } else if (std.mem.eql(u8, feed.target, "memory_id_to_big")) {
                if (feed.words_per_instance != 1 or feed.relation != 0) return error.UnsupportedMemoryFeed;
                descriptor[8] = try cast(input.memory.f252_values.len);
                descriptor[10] = try destination(scratch, &destinations, "memory_id_to_big", try memoryDestinationWords(input, "memory_id_to_big"));
                descriptor[11] = 1;
                descriptor[12] = try cast(input.memory.small_values.len);
                descriptor[13] = try destination(scratch, &destinations, "memory_id_to_big#small", try memoryDestinationWords(input, "memory_id_to_big#small"));
            } else if (cairo.claim_generator.isFixedComponent(feed.target)) {
                const entry = findFixed(fixed, feed.target) orelse return error.MissingCanonicalFixedTable;
                const plan = try cairo.conformance.fixed_feed_plan.Plan.init(entry, feed);
                descriptor[8] = entry.row_count;
                descriptor[10] = try destination(scratch, &destinations, entry.component, std.math.mul(u64, entry.row_count, entry.multiplicity_columns) catch return error.FeedExtentOverflow);
                switch (plan.kind) {
                    .range => {
                        if (plan.width_count > 5) return error.UnsupportedFeedWidth;
                        for (plan.widths[0..plan.width_count], 0..) |width, index| descriptor[2 + index] = width;
                    },
                    .xor => {
                        descriptor[2] = plan.xor_bits;
                        descriptor[11] = if (plan.xor_bits == 12) 3 else 2;
                    },
                    .indexed => {},
                }
            } else continue; // Gather/compact producers have separate input actions.
            if (descriptor[8] == 0 or feed.word_base > producer.sub_words_per_row or
                feed.words_per_instance > producer.sub_words_per_row - feed.word_base)
                return error.InvalidCanonicalFeed;
            try descriptors.appendSlice(scratch, &descriptor);
        }
        if (descriptors.items.len == 0) continue;
        try entries.append(scratch, .{
            .producer = try scratch.dupe(u8, component.name),
            .row_count = extent.padded_rows,
            .active_row_count = extent.active_rows,
            .sub_words_per_row = producer.sub_words_per_row,
            .descriptors = try descriptors.toOwnedSlice(scratch),
            .luts = try scratch.alloc([]u32, 0),
            .destinations = try destinations.toOwnedSlice(scratch),
        });
    }
    const bundle = feeds.Bundle{ .allocator = scratch, .feeds = try entries.toOwnedSlice(scratch) };
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/canonical-feeds/v1\x00");
    hash.update(&topology.sha256);
    for (bundle.feeds) |feed| {
        hash.update(feed.producer);
        const dimensions = [_]u32{ feed.row_count, feed.active_row_count.?, feed.sub_words_per_row, @intCast(feed.descriptors.len), @intCast(feed.destinations.len) };
        for (dimensions) |word| hashWord(&hash, word);
        for (feed.descriptors) |word| hashWord(&hash, word);
        for (feed.destinations) |target| {
            hash.update(target.name);
            var encoded: [8]u8 = undefined;
            std.mem.writeInt(u64, &encoded, target.words, .little);
            hash.update(&encoded);
        }
    }
    return .{ .allocator = allocator, .arena = arena, .bundle = bundle, .identity = hash.finalResult() };
}

// Every committed memory limb, including zero padding, participates in the
// range argument. Read the final AIR slab: multiplicity first, then limbs.
fn memoryRangeFeed(allocator: std.mem.Allocator, name: []const u8, extent: geometry_mod.Extent, fixed: cairo.witness.fixed_table_bundle.Bundle) !feeds.Feed {
    const big = std.mem.eql(u8, name, "memory_id_to_big");
    const limbs: u32 = if (big) memory_tables.big_limb_count else memory_tables.small_limb_count;
    const table = findFixed(fixed, "range_check_9_9") orelse return error.MissingCanonicalFixedTable;
    if (table.row_count != 1 << 18 or table.multiplicity_columns != 8)
        return error.InvalidCanonicalFeed;
    const descriptors = try allocator.alloc(u32, (limbs / 2) * 14);
    @memset(descriptors, 0);
    for (0..limbs / 2) |pair| {
        const descriptor = descriptors[pair * 14 ..][0..14];
        descriptor[0] = @intCast(1 + 2 * pair);
        descriptor[1] = 2;
        descriptor[2] = 9;
        descriptor[3] = 9;
        descriptor[7] = @intCast(pair % (if (big) @as(usize, 8) else 4));
        descriptor[8] = table.row_count;
        descriptor[9] = none;
    }
    const destinations = try allocator.alloc(feeds.Destination, 1);
    destinations[0] = .{ .name = try allocator.dupe(u8, "range_check_9_9"), .words = @as(u64, table.row_count) * table.multiplicity_columns };
    return .{
        .producer = try allocator.dupe(u8, name),
        .row_count = extent.padded_rows,
        .active_row_count = extent.padded_rows,
        .sub_words_per_row = limbs + 1,
        .descriptors = descriptors,
        .luts = try allocator.alloc([]u32, 0),
        .destinations = destinations,
    };
}

fn hashWord(hash: *std.crypto.hash.sha2.Sha256, word: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, word, .little);
    hash.update(&encoded);
}

fn cast(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.FeedExtentOverflow;
}

fn destination(allocator: std.mem.Allocator, values: *std.ArrayList(feeds.Destination), name: []const u8, words: u64) !u32 {
    for (values.items, 0..) |value, index| {
        if (!std.mem.eql(u8, value.name, name)) continue;
        if (value.words != words) return error.CanonicalDestinationMismatch;
        return @intCast(index);
    }
    const index = values.items.len;
    try values.append(allocator, .{ .name = try allocator.dupe(u8, name), .words = words });
    return @intCast(index);
}

// Counter storage follows padded table geometry. Descriptor bounds still
// follow the live ID domain, so padding never admits an out-of-range lookup.
fn memoryDestinationWords(input: *const cairo.adapter.ProverInput, name: []const u8) !u64 {
    if (std.mem.eql(u8, name, "memory_address_to_id"))
        return std.math.mul(u64, try memory_tables.addressRowCount(input), 16);
    if (std.mem.eql(u8, name, "memory_id_to_big#small"))
        return try memory_tables.smallRowCount(input);
    var words: u64 = 0;
    for (0..try memory_tables.bigComponentCount(input)) |instance|
        words = try std.math.add(u64, words, try memory_tables.bigRowCount(input, @intCast(instance)));
    return words;
}

fn findFixed(bundle: cairo.witness.fixed_table_bundle.Bundle, name: []const u8) ?cairo.witness.fixed_table_bundle.Entry {
    for (bundle.entries) |entry| if (std.mem.eql(u8, entry.component, name)) return entry;
    return null;
}

test "canonical CUDA feeds retain padded stride and authenticate active extent" {
    var input = try cairo.adapter.input.readFile(std.testing.allocator, "vectors/cairo/official/all_opcodes.prover_input.json");
    defer input.deinit(std.testing.allocator);
    var claim = try cairo.claim_generator.deriveFromProverInput(std.testing.allocator, &input, .{ .preprocessed_variant = .canonical_small });
    defer claim.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(std.testing.allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
    defer topology.deinit();
    var geometry = try geometry_mod.resolve(std.testing.allocator, &input, &claim, topology);
    defer geometry.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(std.testing.allocator, "vectors/cairo/cairo_fixed_tables.bin");
    defer fixed.deinit();
    var first = try compile(std.testing.allocator, &input, &claim, geometry, topology, fixed);
    defer first.deinit();
    var witnesses = try cairo.witness.bundle.Bundle.readFile(std.testing.allocator, "vectors/cairo/official/witness_programs_v1.bin");
    defer witnesses.deinit();
    const active_rows = try std.testing.allocator.alloc(u32, geometry.extents.len);
    defer std.testing.allocator.free(active_rows);
    for (geometry.extents, active_rows) |extent, *row| row.* = extent.active_rows;
    var proof = try cairo.proof_plan.CairoProofPlan.fromCanonicalGeometry(std.testing.allocator, &claim, active_rows, witnesses, first.bundle);
    defer proof.deinit();
    try std.testing.expectEqual(claim.components.len, proof.components.len);
    try std.testing.expect(proof.levels.len > 1);
    var tested_memory_padding = false;
    var tested_padding = false;
    var tested_native_ec_ownership = false;
    for (first.bundle.feeds) |feed| {
        if (std.mem.eql(u8, feed.producer, "ec_op_builtin")) {
            // The native EC graph owns exactly these direct counters. Its
            // partial-multiply edges have a separate composite writer path.
            try std.testing.expectEqual(@as(usize, 16 * 14), feed.descriptors.len);
            try std.testing.expectEqual(feed.row_count, feed.active_row_count.?);
            tested_native_ec_ownership = true;
        }
        for (feed.destinations) |target| {
            if (!std.mem.startsWith(u8, target.name, "memory_")) continue;
            try std.testing.expectEqual(try memoryDestinationWords(&input, target.name), target.words);
            const live: u64 = if (std.mem.eql(u8, target.name, "memory_address_to_id"))
                input.memory.address_to_id.len - 1
            else if (std.mem.eql(u8, target.name, "memory_id_to_big"))
                input.memory.f252_values.len
            else
                input.memory.small_values.len;
            try std.testing.expect(target.words >= live);
            tested_memory_padding = tested_memory_padding or target.words > live;
        }
        var offset: usize = 0;
        while (offset < feed.descriptors.len) : (offset += 14) {
            const d = feed.descriptors[offset..][0..14];
            const target = feed.destinations[d[10]].name;
            if (std.mem.eql(u8, target, "memory_address_to_id"))
                try std.testing.expectEqual(input.memory.address_to_id.len - 1, d[8]);
            if (std.mem.eql(u8, target, "memory_id_to_big")) {
                try std.testing.expectEqual(input.memory.f252_values.len, d[8]);
                try std.testing.expectEqual(input.memory.small_values.len, d[12]);
            }
        }
        try std.testing.expect(feed.active_row_count.? <= feed.row_count);
        try std.testing.expectEqual(@as(usize, 0), feed.luts.len);
        tested_padding = tested_padding or feed.active_row_count.? < feed.row_count;
    }
    try std.testing.expect(tested_padding);
    try std.testing.expect(tested_memory_padding);
    try std.testing.expectEqual(input.builtin_segments.ec_op_builtin != null, tested_native_ec_ownership);
    for (geometry.extents) |*extent| {
        if (extent.active_rows < extent.padded_rows) {
            extent.active_rows += 1;
            break;
        }
    }
    var changed = try compile(std.testing.allocator, &input, &claim, geometry, topology, fixed);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed.identity));
}

test "native EC feed ownership is exact for the official all-builtin input" {
    var input = try cairo.adapter.input.readFile(std.testing.allocator, "vectors/cairo/official/all_builtins.prover_input.json");
    defer input.deinit(std.testing.allocator);
    var claim = try cairo.claim_generator.deriveFromProverInput(std.testing.allocator, &input, .{ .preprocessed_variant = .canonical });
    defer claim.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(std.testing.allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
    defer topology.deinit();
    var geometry = try geometry_mod.resolve(std.testing.allocator, &input, &claim, topology);
    defer geometry.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(std.testing.allocator, "vectors/cairo/cairo_fixed_tables.bin");
    defer fixed.deinit();
    var compiled = try compile(std.testing.allocator, &input, &claim, geometry, topology, fixed);
    defer compiled.deinit();
    var witnesses = try cairo.witness.bundle.Bundle.readFile(std.testing.allocator, "vectors/cairo/official/witness_programs_v1.bin");
    defer witnesses.deinit();
    const active_rows = try std.testing.allocator.alloc(u32, geometry.extents.len);
    defer std.testing.allocator.free(active_rows);
    for (geometry.extents, active_rows) |extent, *row| row.* = extent.active_rows;
    var proof = try cairo.proof_plan.CairoProofPlan.fromCanonicalGeometry(std.testing.allocator, &claim, active_rows, witnesses, compiled.bundle);
    defer proof.deinit();
    var native_components: usize = 0;
    for (proof.components) |component| {
        if (!std.mem.eql(u8, component.name, "ec_op_builtin") and
            !std.mem.eql(u8, component.name, "partial_ec_mul_generic")) continue;
        try std.testing.expectEqual(cairo.proof_plan.WriterKind.native_backend, component.writer);
        native_components += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), native_components);
    for (compiled.bundle.feeds) |feed| {
        if (!std.mem.eql(u8, feed.producer, "ec_op_builtin")) continue;
        try std.testing.expectEqual(@as(usize, 16 * 14), feed.descriptors.len);
        try std.testing.expectEqual(feed.row_count, feed.active_row_count.?);
        for (0..16) |index| {
            const descriptor = feed.descriptors[index * 14 ..][0..14];
            try std.testing.expectEqual(@as(u32, @intCast(index)), descriptor[0]);
            try std.testing.expectEqual(@as(u32, 1), descriptor[1]);
            const target = feed.destinations[descriptor[10]].name;
            const expected = if (index < 7) "memory_address_to_id" else if (index < 14) "memory_id_to_big" else "range_check_8";
            try std.testing.expectEqualStrings(expected, target);
        }
        return;
    }
    return error.MissingCanonicalEcFeed;
}
