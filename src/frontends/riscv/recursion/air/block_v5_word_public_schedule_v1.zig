//! One original RAM/range external supplier routing body, shared by live and
//! fixed setup. This compiler accepts no values and confers no proof authority.
const std = @import("std");
const Plan = @import("blake3_transcript_plan.zig").Plan;
const Lower = @import("verifier_arithmetic_lowering.zig");
const Roots = @import("blake3_root_sources.zig");
pub const Family = @import("block_v5_word_recursive_shape_composition_v1.zig").Family;

pub fn For(comptime family: Family, comptime Bus: type) type {
    return struct {
        const invalid = if (family == .ram_lanes) error.InvalidRamPublicSchedule else error.InvalidRangePublicSchedule;
        const public_count = if (family == .ram_lanes) @import("block_v5_ram_lanes_composition_v1.zig").PUBLIC_COUNT else 2;
        fn append(a: std.mem.Allocator, wires: *std.ArrayList(Bus.Wire), wire: Bus.Wire) !void {
            if (wires.items.len >= Bus.MAX_WIRES) return invalid;
            try wires.append(a, wire);
        }
        /// The caller authenticates the original native graph and transcript.
        /// Both original live preparation and independently derived fixed
        /// setup select this exact emitter; public value equality stays live.
        pub fn collect(a: std.mem.Allocator, plan: *const Plan, composition: anytype, path_reads: u32) ![]Bus.Wire {
            if (path_reads == 0) return invalid;
            if (composition.sources.len != composition.circuit.input_count) return invalid;
            var wires: std.ArrayList(Bus.Wire) = .empty;
            errdefer wires.deinit(a);
            for (0..2) |root| for (0..8) |coordinate| {
                try append(a, &wires, .{ .circuit = Roots.CIRCUIT, .wire = @intCast(root * 8 + coordinate), .uses = path_reads, .source = if (root == 0) .fixed_root else .main_root, .coordinate = @intCast(coordinate) });
            };
            for (plan.fixed.root_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
                const source: Bus.Source = switch (receipt.source.first_wire) {
                    0 => .sealed,
                    8 => if (family == .ram_lanes) .pin_identity else .plan,
                    else => return invalid,
                };
                if (receipt.uses.len != 8) return invalid;
                for (receipt.uses, 0..) |uses, coordinate| try append(a, &wires, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = @intCast(coordinate) });
            };
            for (plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == Bus.PUBLIC_CIRCUIT) {
                if (family == .ram_lanes) {
                    if (receipt.source.first_wire < 16 or receipt.source.first_wire > 106 or receipt.uses.len > 106 - receipt.source.first_wire) return invalid;
                    for (receipt.uses, 0..) |uses, coordinate| try append(a, &wires, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = .claim_words, .coordinate = receipt.source.first_wire - 16 + @as(u32, @intCast(coordinate)) });
                } else {
                    const source: Bus.Source = switch (receipt.source.first_wire) {
                        16 => .shard_header,
                        22 => .request_count_words,
                        24 => .claim_count_words,
                        26...29 => .sum_words,
                        else => return invalid,
                    };
                    const width: usize = switch (source) {
                        .shard_header => 6,
                        .sum_words => 1,
                        else => 2,
                    };
                    if (receipt.uses.len != width) return invalid;
                    for (receipt.uses, 0..) |uses, coordinate| try append(a, &wires, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = if (source == .sum_words) receipt.source.first_wire - 26 else @intCast(coordinate) });
                }
            };
            const counts = try a.alloc(u32, composition.circuit.nodes.len);
            defer a.free(counts);
            const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), counts);
            for (composition.sources, 0..) |source, node| if (source == .public_input) {
                if (source.public_input >= public_count) return invalid;
                if (family == .ram_lanes and uses[node] == 0) continue;
                try append(a, &wires, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = if (family == .ram_lanes) .equation else if (source.public_input == 0) .sum else .count, .coordinate = if (family == .ram_lanes) source.public_input else 0 });
            };
            _ = try Bus.scheduleDigest(wires.items);
            return wires.toOwnedSlice(a);
        }
    };
}
