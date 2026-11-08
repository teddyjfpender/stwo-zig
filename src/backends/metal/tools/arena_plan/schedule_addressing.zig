//! Schedule epoch, ownership, and narrow-address validation policy.

const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const staged_arena_planner = stwo.frontends.cairo.staged_arena_planner;

const epoch_names = [_][]const u8{
    "Ingest",            "Witness", "BaseCommit", "Interaction", "InteractionCommit", "Composition",
    "CompositionCommit", "Oods",    "Quotient",   "Fri",         "Decommit",          "Assemble",
};

pub fn epochIndex(name: []const u8) ?u16 {
    for (epoch_names, 0..) |candidate, index| {
        if (std.mem.eql(u8, name, candidate)) return @intCast(index);
    }
    return null;
}

pub fn globalTick(phase: u16) u16 {
    return phase * 65;
}

pub fn localTick(phase: u16, component: u16) u16 {
    return phase * 65 + 1 + component;
}

pub fn stagedRole(purpose: []const u8) ?staged_arena_planner.BufferRole {
    if (std.mem.eql(u8, purpose, "WitnessInput") or std.mem.startsWith(u8, purpose, "WitnessInputCompact"))
        return .witness_input;
    if (std.mem.eql(u8, purpose, "SubcomponentInputs")) return .producer_slab;
    if (std.mem.eql(u8, purpose, "BaseTrace")) return .base_trace;
    if (std.mem.eql(u8, purpose, "BaseCoefficients")) return .base_coefficients;
    if (std.mem.eql(u8, purpose, "LookupInputs")) return .lookup_inputs;
    if (std.mem.eql(u8, purpose, "InteractionTrace")) return .interaction_trace;
    if (std.mem.eql(u8, purpose, "InteractionCoefficients")) return .interaction_coefficients;
    if (std.mem.eql(u8, purpose, "WitnessInputPointers") or
        std.mem.eql(u8, purpose, "WitnessOutputPointers") or
        std.mem.eql(u8, purpose, "WitnessMultiplicityPointers"))
        return .component_scratch;
    return null;
}

pub fn aotNarrowAddressPurpose(purpose: []const u8) bool {
    inline for ([_][]const u8{
        "WitnessInput",
        "BaseTrace",
        "LookupInputs",
        "SubcomponentInputs",
        "WitnessInputPointers",
        "WitnessOutputPointers",
        "WitnessMultiplicityPointers",
        "ExecutionTablePointers",
        "ExecutionTableStrides",
        "ExecutionTableRawAddressToId",
        "ExecutionTableRawF252Words",
        "ExecutionTableRawSmallWords",
        "ExecutionTableBigLimb",
        "ExecutionTableSmallLimb",
        "FixedTableSourcePointers",
        "FixedMultiplicity",
        "RuntimeMultiplicity",
        "WitnessFeedLut",
        "EcOpPartialIota",
        "EcOpSegmentStart",
    }) |candidate| if (std.mem.eql(u8, purpose, candidate)) return true;
    return false;
}

pub fn narrowAddressPurpose(purpose: []const u8) bool {
    if (aotNarrowAddressPurpose(purpose)) return true;
    if (std.mem.startsWith(u8, purpose, "WitnessInputCompact") or
        std.mem.startsWith(u8, purpose, "WitnessInputGather") or
        std.mem.startsWith(u8, purpose, "WitnessInputSeed")) return true;
    inline for ([_][]const u8{
        "PreprocessedEvaluations",
        "InteractionTrace",
        "RelationAlphaPowers",
        "RelationZ",
        "RelationClaimedSum",
        "RelationScanEvalScratch",
        "CompositionCoefficients",
        "CompositionDescriptors",
        "CompositionLdeTile",
        "CompositionAccumulators",
        "CompositionRandomCoefficientPowers",
        "CompositionExtParams",
        "CommitLdeTile",
        "MerkleLeafState",
        "MerkleLayerScratch",
        "ForwardTwiddles",
        "InverseTwiddles",
        "QuotientPartialNumerator",
        "QuotientSamplePoints",
        "QuotientFirstLinearTerms",
        "QuotientSubdomainValues",
        "QuotientDenominatorScratch",
        "QuotientInverseTwiddles",
        "QuotientTile",
        "FriRetainedEvaluation",
        "FriFoldingChallenge",
        "FriMerkleLayer",
        "FriPing",
        "FriPong",
        "FriFinalCoefficients",
        "FriFinalDegreeError",
        "DecommitTraceLdeTile",
        "TranscriptState",
        "TranscriptInput",
        "TranscriptOutput",
    }) |candidate| if (std.mem.eql(u8, purpose, candidate)) return true;
    return false;
}

pub fn validateNarrowAddressedBindings(schedule: []const std.json.Value, plan: arena.Plan) !void {
    for (schedule) |entry| {
        const wanted_purpose = try purposeOf(entry);
        if (!narrowAddressPurpose(wanted_purpose)) continue;
        const binding = plan.binding(try logicalIdOf(entry)) catch return error.MissingBinding;
        arena.validateNarrowWordBinding(binding) catch |err| {
            std.log.err(
                "u32 Metal arena range overflow purpose={s} id={} offset={} size={} end={} limit={}",
                .{
                    wanted_purpose,
                    binding.logical_id,
                    binding.offset_bytes,
                    binding.size_bytes,
                    std.math.add(u64, binding.offset_bytes, binding.size_bytes) catch std.math.maxInt(u64),
                    arena.narrow_word_address_space_bytes,
                },
            );
            return err;
        };
    }
}

pub fn purposeOf(entry: std.json.Value) ![]const u8 {
    if (entry != .object) return error.InvalidSchedule;
    const value = entry.object.get("purpose") orelse return error.InvalidSchedule;
    if (value != .string) return error.InvalidSchedule;
    return value.string;
}

pub fn logicalIdOf(entry: std.json.Value) !u32 {
    if (entry != .object) return error.InvalidSchedule;
    const value = entry.object.get("id") orelse return error.InvalidSchedule;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32))
        return error.InvalidSchedule;
    return @intCast(value.integer);
}

pub fn zeroMultiplicityComponent(component: []const u8) bool {
    return std.mem.eql(u8, component, "range_check_6") or
        std.mem.eql(u8, component, "range_check_12") or
        std.mem.eql(u8, component, "range_check_3_6_6_3");
}

pub fn compactComponent(component: []const u8) bool {
    return std.mem.eql(u8, component, "verify_instruction") or
        std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18") or
        std.mem.eql(u8, component, "poseidon_aggregator");
}

test "narrow address purpose covers memory and composition u32 kernels" {
    try std.testing.expect(narrowAddressPurpose("ExecutionTableBigLimb"));
    try std.testing.expect(narrowAddressPurpose("RuntimeMultiplicity"));
    try std.testing.expect(narrowAddressPurpose("FixedMultiplicity"));
    try std.testing.expect(narrowAddressPurpose("WitnessFeedLut"));
    try std.testing.expect(narrowAddressPurpose("BaseTrace"));
    try std.testing.expect(narrowAddressPurpose("CompositionLdeTile"));
    try std.testing.expect(narrowAddressPurpose("CompositionCoefficients"));
    try std.testing.expect(narrowAddressPurpose("TranscriptInput"));
    try std.testing.expect(!narrowAddressPurpose("BaseCoefficients"));
    try std.testing.expect(!narrowAddressPurpose("PreprocessedCoefficients"));
}

test "schedule epochs and component ownership remain explicit" {
    try std.testing.expectEqual(@as(?u16, 0), epochIndex("Ingest"));
    try std.testing.expectEqual(@as(?u16, 11), epochIndex("Assemble"));
    try std.testing.expectEqual(@as(?u16, null), epochIndex("Unknown"));
    try std.testing.expectEqual(@as(u16, 325), globalTick(5));
    try std.testing.expectEqual(@as(u16, 333), localTick(5, 7));
    try std.testing.expectEqual(staged_arena_planner.BufferRole.witness_input, stagedRole("WitnessInput"));
    try std.testing.expectEqual(@as(?staged_arena_planner.BufferRole, null), stagedRole("TranscriptInput"));
    try std.testing.expect(zeroMultiplicityComponent("range_check_12"));
    try std.testing.expect(compactComponent("verify_instruction"));
}
