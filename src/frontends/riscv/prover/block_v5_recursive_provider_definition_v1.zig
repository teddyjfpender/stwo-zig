//! Actual provider types and public proposals for one shared transport kernel.
const std = @import("std");
const core = @import("stwo_core");
const Seal = @import("block_v5_source_seal_v1.zig");
const Family = @import("block_v5_recursive_provider_family_v1.zig").Family;
pub fn ForFamily(comptime family: Family) type {
    return struct {
        pub const FAMILY = family;
        pub const SINK_FIELD = switch (family) {
            .range16 => "put_range",
            .ram_lanes => "put_lanes",
            .program_table => "put_table",
            .native_lookup => "put_lookup",
        };
        pub const seal_family: Seal.Family = switch (family) {
            .range16 => .memory_range,
            .ram_lanes => .memory,
            .program_table => .program,
            .native_lookup => .native_lookup,
        };
        pub const Native = switch (family) {
            .range16 => @import("block_v5_range16_proof_v1.zig"),
            .ram_lanes => @import("block_v5_ram_lanes_proof_v1.zig"),
            .program_table => @import("block_v5_program_table_proof_v1.zig"),
            .native_lookup => @import("block_v5_native_lookup_proof_v1.zig"),
        };
        pub const Prepared = switch (family) {
            .range16 => @import("block_v5_range16_recursive_admission_v1.zig").Prepared,
            .ram_lanes => @import("block_v5_ram_lanes_recursive_admission_v1.zig").Prepared,
            .program_table => @import("block_v5_program_table_recursive_admission_v1.zig").Prepared,
            .native_lookup => @import("block_v5_native_lookup_recursive_admission_v1.zig").Prepared,
        };
        pub const Stage = switch (family) {
            .range16 => @import("block_v5_range16_recursive_stage_v1.zig"),
            .ram_lanes => @import("block_v5_ram_lanes_recursive_stage_v1.zig"),
            .program_table => @import("block_v5_program_table_recursive_stage_v1.zig"),
            .native_lookup => @import("block_v5_native_lookup_recursive_stage_v1.zig"),
        };
        pub const Bus = switch (family) {
            .range16 => @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig"),
            .ram_lanes => @import("../recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig"),
            .program_table => @import("../recursion/block_v5_program_table_recursive_public_bus_v1.zig"),
            .native_lookup => @import("../recursion/block_v5_native_lookup_recursive_public_bus_v1.zig"),
        };
        pub const Protocol = switch (family) {
            .range16 => @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig"),
            .ram_lanes => @import("../recursion/block_v5_reusable_ram_lanes_parent_protocol_v1.zig"),
            .program_table => @import("../recursion/block_v5_reusable_program_table_parent_protocol_v1.zig"),
            .native_lookup => @import("../recursion/block_v5_reusable_native_lookup_parent_protocol_v1.zig"),
        };
        pub const Receiver = switch (family) {
            .range16 => @import("../recursion/block_v5_range16_recursive_leaf_v1.zig"),
            .ram_lanes => @import("../recursion/block_v5_ram_lanes_recursive_leaf_v1.zig"),
            .program_table => @import("../recursion/block_v5_program_table_recursive_leaf_v1.zig"),
            .native_lookup => @import("../recursion/block_v5_native_lookup_recursive_leaf_v1.zig"),
        };
        pub const Claim = switch (family) {
            .range16 => @import("block_v5_range16_component_v1.zig").Claim,
            .ram_lanes => @import("block_v5_ram_lanes_interaction_v1.zig").Claim,
            .program_table => core.fields.qm31.QM31,
            .native_lookup => @FieldType(Native.OpenReceipt, "claims"),
        };
        pub const Open = if (family == .program_table) Native.VerifiedReceipt else Native.OpenReceipt;
        pub fn index(prepared: *const Prepared) u32 {
            return switch (family) {
                .range16 => prepared.shard.index,
                .ram_lanes => prepared.pin.index,
                .program_table, .native_lookup => prepared.index,
            };
        }
        pub fn claim(open: Open) Claim {
            return switch (family) {
                .ram_lanes => open.sums,
                .native_lookup => open.claims,
                else => open.claim,
            };
        }
        /// A file's claim is proposed public input. Only Receiver.verify can
        /// turn this reconstructed statement into a genuine open equation.
        pub fn proposal(prepared: *const Prepared, value: Claim) !Open {
            try prepared.validate(prepared.template_id);
            return switch (family) {
                .range16 => .{ .claim = value, .shard = prepared.shard, .roots = prepared.roots, .sealed_digest = prepared.sealed.digest },
                .ram_lanes => .{ .pin = prepared.pin, .sums = value, .sealed_digest = prepared.sealed.digest },
                .program_table => block: {
                    var channel = prepared.seal.sharedChannel();
                    break :block .{ .claim = value, .fetch_count = prepared.plan.expected_fetches, .program_root = prepared.plan.program_root, .plan_digest = prepared.seal.plan_digest, .sealed_channel_digest = channel.digestBytes(), .first_roots = prepared.roots };
                },
                .native_lookup => block: {
                    var total = core.fields.qm31.QM31.zero();
                    for (value) |item| {
                        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&item))
                            return error.NoncanonicalRecursiveProviderClaim;
                        total = total.add(item);
                    }
                    break :block .{ .claims = value, .total = total, .plan_id = try prepared.plan.identity(), .roots = prepared.roots, .sealed_digest = prepared.sealed.digest };
                },
            };
        }
        pub fn values(prepared: *const Prepared, open: Open) !Bus.Values {
            return switch (family) {
                .range16 => Bus.Values.fromRange(prepared, open),
                .ram_lanes => Bus.Values.fromLanes(prepared, open),
                .program_table => Bus.Values.fromTable(prepared, open),
                .native_lookup => Bus.Values.fromLookup(prepared, open),
            };
        }
        pub fn sameWires(a: []const Bus.Wire, b: []const Bus.Wire) bool {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!std.meta.eql(x, y)) return false;
            return true;
        }
    };
}
