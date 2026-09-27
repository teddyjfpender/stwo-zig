//! Phased fixed 8x8 byte-table provider for the block-v2 transcript.
//! Multiplicity is witness-derived main PCS data and is committed before the
//! manifest seal; only the LogUp interaction is generated after challenges.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const bus = @import("../../prover/block_memory_relation_v2.zig");
const shared = @import("../../recursion/air/universal_provider_relations.zig");
const tables = @import("../lookups/tables/mod.zig");
const range = @import("memory_range_interaction_v2.zig");
const permutation = @import("../../infra_trace/permutation.zig");

pub const LOG_SIZE: u32 = 16;
pub const SIZE: usize = 1 << LOG_SIZE;
pub const FIXED_COUNT: usize = 3;
pub const MAIN_COUNT: usize = 1;
pub const INTERACTION_COUNT: usize = 4;
pub const CLAIM_TAG: u32 = 0x42325254; // B2RT

pub const Precommit = struct {
    fixed: [FIXED_COUNT][]M,
    multiplicity: []M,
    counter_snapshot: range.CounterSnapshot,

    pub fn takeFixed(self: *Precommit) [FIXED_COUNT][]M {
        const moved = self.fixed;
        self.fixed = .{&.{}} ** FIXED_COUNT;
        return moved;
    }
    pub fn takeMultiplicity(self: *Precommit) []M {
        const moved = self.multiplicity;
        self.multiplicity = &.{};
        return moved;
    }
    pub fn deinit(self: *Precommit, a: std.mem.Allocator) void {
        for (self.fixed) |column| if (column.len != 0) a.free(column);
        if (self.multiplicity.len != 0) a.free(self.multiplicity);
        self.* = undefined;
    }
};

/// Deterministic fixed tuple columns and the collected multiplicity main
/// column. Commit these with all memory main rows before sealing the manifest.
pub fn precommit(a: std.mem.Allocator, counter: *const tables.counter.Counter) !Precommit {
    try validateCounter(counter);
    var fixed: [FIXED_COUNT][]M = undefined;
    var allocated: usize = 0;
    errdefer for (fixed[0..allocated]) |column| a.free(column);
    for (&fixed) |*column| {
        column.* = try a.alloc(M, SIZE);
        allocated += 1;
    }
    @memset(fixed[0], M.zero());
    fixed[0][0] = M.one(); // Bit reversal keeps logical row zero at index zero.
    const table = try permutation.BitReversalTable.init(a, LOG_SIZE);
    defer table.deinit(a);
    for (0..SIZE) |logical| {
        const tuple = try tables.schema.tupleAt(.range_check_8_8, logical);
        const physical = table.map(logical);
        fixed[1][physical] = tuple.values[0];
        fixed[2][physical] = tuple.values[1];
    }
    const multiplicity = try counter.committedColumn(a);
    return .{
        .fixed = fixed,
        .multiplicity = multiplicity,
        .counter_snapshot = range.counterSnapshot(counter),
    };
}

pub const Interaction = struct {
    relations: shared.SharedProviderRelations,
    result: tables.interaction.Result,
    pub fn claim(self: *const Interaction) Q {
        return self.result.claim;
    }
    pub fn mixClaimInto(self: *const Interaction, channel: anytype) !void {
        return mixClaimValueInto(self.result.claim, channel);
    }
    pub fn takeColumns(self: *Interaction) [INTERACTION_COUNT][]M {
        return self.result.takeColumns();
    }
    pub fn deinit(self: *Interaction, a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }

    /// The shipped generic table AIR proves the fixed tuple, multiplicity and
    /// cumulative interaction columns at their shared PCS tree offsets.
    pub fn component(self: *const Interaction, fixed_offset: usize, main_offset: usize, interaction_offset: usize) !tables.component.LookupTableComponent {
        return tables.component.LookupTableComponent.initProver(
            .range_check_8_8,
            fixed_offset,
            &.{ fixed_offset + 1, fixed_offset + 2 },
            main_offset,
            interaction_offset,
            &self.relations.native,
            self.result.claim,
        );
    }
};

/// Receiver replay of the same table-claim transcript field without witness
/// columns or an owning prover-side `Interaction`.
pub fn mixClaimValueInto(claim: Q, channel: anytype) !void {
    if (!shared.secureIsCanonical(&claim)) return error.InvalidBlockRangeClaim;
    channel.mixU32s(&.{ CLAIM_TAG, range.FORMAT_VERSION });
    for (claim.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
}

/// This must run only after fixed/main commitments are sealed and challenges
/// drawn. The snapshot catches any mutation of the precommitted counter.
pub fn finishInteraction(
    a: std.mem.Allocator,
    counter: *const tables.counter.Counter,
    challenges: *const bus.Challenges,
    expected_snapshot: range.CounterSnapshot,
) !Interaction {
    try validateCounter(counter);
    if (!std.mem.eql(u8, &range.counterSnapshot(counter), &expected_snapshot))
        return error.BlockRangeCounterChangedAfterSeal;
    const relations = try shared.SharedProviderRelations.init(&challenges.universal_prefix);
    return .{
        .relations = relations,
        .result = try tables.interaction.generate(a, counter, &relations.native),
    };
}

/// Zero is meaningful only after every request quotient and the provider's
/// fixed/main/interaction quotient verify under the same challenge.
pub fn closed(requests: []const range.Claims, provider: *const Interaction) bool {
    return range.closed(requests, provider.claim());
}

fn validateCounter(counter: *const tables.counter.Counter) !void {
    if (counter.kind != .range_check_8_8 or counter.values.len != SIZE)
        return error.InvalidBlockRangeCounter;
}
