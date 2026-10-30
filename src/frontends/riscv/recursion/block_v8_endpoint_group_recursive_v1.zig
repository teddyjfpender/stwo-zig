//! One native Group original -> conditional recursive source root. All native
//! member residuals and shared providers close in-circuit. Global RAM remains
//! OPEN until a join binds every exported endpoint root to bridge/global roots.
const Self = @This();
pub const Original = @import("../prover/block_v8_endpoint_group_proof_v1.zig");
pub const Statement = @import("../prover/block_v8_endpoint_group_statement_v1.zig");
pub const Profile = @import("block_v8_endpoint_group_profile_v1.zig");
pub const Composition = @import("air/block_v8_endpoint_group_composition_v1.zig");
pub const Transcript = @import("air/block_v8_endpoint_group_transcript_v1.zig");
const Sources = @import("../prover/block_v8_endpoint_local_scope_v1.zig").Source;
pub const Ledger = struct {
    pub const Claims = @import("../prover/block_v8_endpoint_group_ledger_v1.zig").Claims;
    /// Fixed bounded storage survives Profile destruction during fresh receiving.
    /// Unused slots are canonical zeros; only [0..cohorts) represent sources.
    pub const Summary = struct {
        sources: [32]Sources,
        initial_pc: u32,
        final_pc: u32,
        initial_regs: [32]u32,
        final_regs: [32]u32,
        first_cohort_ordinal: u32,
        last_cohort_ordinal: u32,
        global_first_cycle: u64,
        cycles: u64,
        cohorts: u32,
        endpoint_events: u32,
        logical_ram_accesses: u64,
        program_fetches: u64,
        scope: enum { group_execution_global_ram_open } = .group_execution_global_ram_open,
    };
};
pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(Self);
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(Self);
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(Self);
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(Self);
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(Self);
pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").With(Self);
pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").With(Self);
pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").With(Self);
pub const IDENTITY_TAG: u32 = 0x42384749;
pub const SCHEDULE_TAG: u32 = 0x42384753;
pub const VALUES_TAG: u32 = 0x42384756;
pub const ROSTER_TAG: u32 = 0x42384752;
pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = .{ .key = 0x4238474b, .public_input = 0x42384749, .proof = 0x42384750, .claims = 0x42384743 };
pub const production_active = false;
pub const global_ram_closed = false;
pub fn firstRoots(p: *const Profile.Owned) usize {
    return p.layout.firstRoots();
}
pub fn rootsShape(count: usize) bool {
    return count >= 6 and count <= 68 and (count - 4) % 2 == 0;
}
pub fn epoch(p: *const Profile.Owned) @import("../prover/block_v7_execution_epoch_v1.zig").Epoch {
    return p.scope.epoch;
}
pub fn summary(p: *const Profile.Owned) !Ledger.Summary {
    const original = try p.context.close();
    if (original.sources.len == 0 or original.sources.len > 32 or original.cohorts != original.sources.len) return error.InvalidGroupRecursiveSummary;
    const empty = Sources{ .local_epoch = @splat(0), .local_identity = @splat(0), .endpoint_root = @splat(0), .endpoint_count = 0, .policy = .{ .source_ordinal = 0, .max_local_clock = 0 }, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 0, .cycle_count = 0 } };
    var sources: [32]Sources = @splat(empty);
    @memcpy(sources[0..original.sources.len], original.sources);
    return .{ .sources = sources, .initial_pc = original.initial_pc, .final_pc = original.final_pc, .initial_regs = original.initial_regs, .final_regs = original.final_regs, .first_cohort_ordinal = original.first_cohort_ordinal, .last_cohort_ordinal = original.last_cohort_ordinal, .global_first_cycle = original.global_first_cycle, .cycles = original.cycles, .cohorts = original.cohorts, .endpoint_events = p.scope.endpoint_count_total, .logical_ram_accesses = original.logical_ram_accesses, .program_fetches = original.program_fetches };
}
