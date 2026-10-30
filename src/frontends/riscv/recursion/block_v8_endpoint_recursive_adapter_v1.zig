//! Strategy binding for native endpoint theorem flavors. Upper recursion
//! machinery also accepts custom strategies (late bridge/global providers).
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return struct {
        const Self = @This();
        const Traits = @import("block_v8_endpoint_recursive_source_v1.zig").For(family);
        pub const Original = Traits.Proof;
        pub const Statement = Traits.Statement;
        pub const Ledger = Traits.Ledger;
        pub const Profile = @import("block_v8_endpoint_recursive_profile_v1.zig").For(family);
        pub const Composition = @import("air/block_v8_endpoint_recursive_composition_v1.zig").For(family);
        pub const Transcript = @import("air/block_v8_endpoint_recursive_transcript_v1.zig").For(family);
        pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(Self);
        pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(Self);
        pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(Self);
        pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(Self);
        pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(Self);
        pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").With(Self);
        pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").With(Self);
        pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").With(Self);
        pub const IDENTITY_TAG = Traits.IDENTITY_TAG;
        pub const SCHEDULE_TAG = Traits.SCHEDULE_TAG;
        pub const VALUES_TAG = Traits.VALUES_TAG;
        pub const ROSTER_TAG = Traits.ROSTER_TAG;
        pub const tags = Traits.tags;
        pub fn firstRoots(_: *const Profile.Owned) usize {
            return Profile.FIRST_ROOTS;
        }
        pub fn rootsShape(count: usize) bool {
            return count == Profile.FIRST_ROOTS;
        }
        pub fn epoch(p: *const Profile.Owned) @import("../prover/block_v7_execution_epoch_v1.zig").Epoch {
            return p.scope.epoch;
        }
        pub fn summary(p: *const Profile.Owned) !Ledger.Summary {
            var accesses: u64 = 0;
            for (p.statement.input.shape.component_descs[0..p.statement.input.shape.n_components]) |desc| {
                if (desc.family == .load_store) accesses = try @import("std").math.add(u64, accesses, desc.n_rows);
            }
            return if (Traits.is_local) .{ .source = p.scope.source(), .cycles = p.statement.input.shape.public_data.clock, .logical_ram_accesses = accesses, .program_fetches = p.statement.input.program_plan.expected_fetches } else .{ .cycles = p.statement.input.shape.public_data.clock, .logical_ram_accesses = accesses, .global_endpoint_events = p.statement.input.endpoint_count, .program_fetches = p.statement.input.program_plan.expected_fetches };
        }
    };
}
