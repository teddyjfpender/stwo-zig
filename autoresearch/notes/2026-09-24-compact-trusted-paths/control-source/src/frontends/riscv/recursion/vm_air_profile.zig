//! Verifier-derived authority for one Zig RISC-V VM AIR composition graph.
//!
//! Stark-V's recursive verifier builds its composition schedule by visiting
//! the same generated AIR components as the native verifier.  The Zig frontend
//! is shard-dynamic, so fixed Stark-V counts (47 relations, 101 constraints,
//! and 47 component claims) are not valid authority here.  This module derives
//! the corresponding values from the exact component slice assembled by the
//! production verifier and binds its declaration order to the admitted shard
//! geometry.
//!
//! No proof-selected allocation occurs.  `derive` walks the already-borrowed
//! verifier components once; `writeDetailedClaims` copies into caller-owned
//! exact-size storage.  The frozen V1 recursive proof wire remains unchanged:
//! its 28 aggregate sums are transcript claims, while this detailed sequence
//! is the additional composition input needed to replay shard-local AIR.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_components = stwo_core.air.components;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const clock_component = @import("../air/clock_update_component.zig");
const hash_component = @import("../air/memory_commitment/hash_component.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const program_interaction = @import("../air/program/interaction.zig");
const public_data = @import("../air/public_data.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const table_component = @import("../air/lookups/tables/component.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_DOMAIN = "stwo-zig/riscv/recursion/vm-air-profile/v1\x00";

pub const Error = error{
    AirInstructionCountOverflow,
    ClaimedSumCountOverflow,
    ComponentCountMismatch,
    ConstraintCountMismatch,
    EmptyComponentManifest,
    InconsistentCompositionLogSplit,
    InvalidClaimShape,
    InvalidComponentBound,
    InvalidStatementShape,
    NonCanonicalClaim,
    OutputLengthMismatch,
};

/// Semantic role at one index in the native verifier's component slice.
/// Values are stable manifest tags, not array ordinals inferred at runtime.
pub const ComponentRole = enum(u8) {
    opcode_semantic = 1,
    opcode_lookup = 2,
    program = 16,
    memory = 17,
    clock_update = 18,
    poseidon2 = 19,
    merkle = 20,
    bitwise = 32,
    range_check_20 = 33,
    range_check_8_11 = 34,
    range_check_8_8_4 = 35,
    range_check_8_8 = 36,
    range_check_m31 = 37,
};

/// Compact immutable description passed from successful native verification
/// to recursive graph construction.  The digest commits to every per-component
/// role, shard descriptor, constraint span, claim span, degree bound and split.
pub const Profile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    component_count: u32,
    air_instruction_count: u32,
    claimed_sum_count: u32,
    relation_challenge_count: u32,
    composition_log_split: u32,
    composition_log_degree_bound: u32,
    /// Degree bound passed to component mask/evaluation routines after split.
    max_log_degree_bound: u32,
    manifest_digest: [Sha256.digest_length]u8,

    pub fn validate(self: Profile) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            self.component_count == 0 or
            self.air_instruction_count == 0 or
            self.claimed_sum_count == 0 or
            self.relation_challenge_count != @as(u32, relation_challenges.RELATION_COUNT) or
            self.composition_log_split == 0 or
            self.composition_log_degree_bound <= self.composition_log_split or
            self.max_log_degree_bound !=
                self.composition_log_degree_bound - self.composition_log_split)
        {
            return error.InvalidStatementShape;
        }
        var nonzero: u8 = 0;
        for (self.manifest_digest) |byte| nonzero |= byte;
        if (nonzero == 0) return error.EmptyComponentManifest;
    }
};

const ComponentFacts = struct {
    n_constraints: usize,
    max_constraint_log_degree_bound: u32,
    composition_log_split: u32,
};

const NativeSource = struct {
    components: []const core_components.Component,

    fn len(self: NativeSource) usize {
        return self.components.len;
    }

    fn facts(self: NativeSource, index: usize) ComponentFacts {
        const component = self.components[index];
        return .{
            .n_constraints = component.nConstraints(),
            .max_constraint_log_degree_bound = component.maxConstraintLogDegreeBound(),
            .composition_log_split = component.compositionLogSplit(),
        };
    }
};

/// Derive the recursive composition profile from the exact declaration-ordered
/// components consumed by `core_verifier.verify`.
pub fn derive(
    statement: *const statement_mod.RiscVStatement,
    components: []const core_components.Component,
) Error!Profile {
    return deriveFromSource(statement, NativeSource{ .components = components });
}

/// Number of detailed (pre-aggregation) claimed sums consumed by the native
/// component evaluators in declaration order.
pub fn claimedSumCount(statement: *const statement_mod.RiscVStatement) Error!u32 {
    try validateStatementCounts(statement);
    var count: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        count = std.math.add(usize, count, opcode_entries.batchCount(descriptor.family)) catch
            return error.ClaimedSumCountOverflow;
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        count = std.math.add(
            usize,
            count,
            statement_mod.nClaimedSumsForInfra(descriptor.kind),
        ) catch return error.ClaimedSumCountOverflow;
    }
    if (count == 0 or count >= m31.Modulus)
        return error.ClaimedSumCountOverflow;
    return std.math.cast(u32, count) orelse error.ClaimedSumCountOverflow;
}

/// Copy the exact claim sequence used by native component evaluation into an
/// exact-size destination.  Publication is failure-atomic: all shape and
/// canonicity checks run before the first destination write.
pub fn writeDetailedClaims(
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    destination: []QM31,
) Error!void {
    const expected = try claimedSumCount(statement);
    if (destination.len != expected) return error.OutputLengthMismatch;
    if (claim.n_components != statement.n_components or
        claim.n_infra != statement.n_infra)
    {
        return error.InvalidClaimShape;
    }

    for (statement.component_descs[0..statement.n_components], 0..) |
        descriptor,
        index,
    | {
        const values = claim.opcodeClaims(descriptor.family, index) catch
            return error.InvalidClaimShape;
        for (values) |value| try validateQm31(value);
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        const values = claim.infraClaims(descriptor.kind, index) catch
            return error.InvalidClaimShape;
        for (values) |value| try validateQm31(value);
    }

    var cursor: usize = 0;
    for (statement.component_descs[0..statement.n_components], 0..) |
        descriptor,
        index,
    | {
        const values = claim.opcodeClaims(descriptor.family, index) catch unreachable;
        @memcpy(destination[cursor..][0..values.len], values);
        cursor += values.len;
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        const values = claim.infraClaims(descriptor.kind, index) catch unreachable;
        @memcpy(destination[cursor..][0..values.len], values);
        cursor += values.len;
    }
    std.debug.assert(cursor == destination.len);
}

fn deriveFromSource(statement: *const statement_mod.RiscVStatement, source: anytype) Error!Profile {
    try validateStatementCounts(statement);
    const expected_components = std.math.add(
        usize,
        std.math.mul(usize, @as(usize, statement.n_components), 2) catch
            return error.ComponentCountMismatch,
        @as(usize, statement.n_infra),
    ) catch return error.ComponentCountMismatch;
    if (source.len() != expected_components or expected_components == 0)
        return error.ComponentCountMismatch;

    var hash = Sha256.init(.{});
    hash.update(MANIFEST_DOMAIN);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, public_data.STATEMENT_TRANSCRIPT_DOMAIN);
    hashInt(&hash, u32, public_data.STATEMENT_TRANSCRIPT_VERSION);
    hashInt(&hash, u32, @intCast(relation_challenges.RELATION_COUNT));
    hashInt(&hash, u32, statement.n_components);
    hashInt(&hash, u32, statement.n_infra);
    hashInt(&hash, u32, statement.nPreprocessedColumns());
    hashInt(&hash, u32, statement.nMainColumns());
    hashInt(&hash, u32, statement.nInteractionColumns());

    var state = DeriveState{};
    for (statement.component_descs[0..statement.n_components], 0..) |
        descriptor,
        shard_index,
    | {
        if (!semantic_eval.isTraceCompatible(descriptor.family))
            return error.InvalidStatementShape;
        try absorbComponent(
            &state,
            &hash,
            source.facts(state.component_index),
            .opcode_semantic,
            @intFromEnum(descriptor.family),
            shard_index,
            descriptor.log_size,
            descriptor.n_rows,
            descriptor.n_columns,
            semantic_eval.constraintCount(descriptor.family),
            0,
        );
        const batches = opcode_entries.batchCount(descriptor.family);
        try absorbComponent(
            &state,
            &hash,
            source.facts(state.component_index),
            .opcode_lookup,
            @intFromEnum(descriptor.family),
            shard_index,
            descriptor.log_size,
            descriptor.n_rows,
            descriptor.n_columns,
            batches,
            batches,
        );
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, shard_index| {
        try absorbComponent(
            &state,
            &hash,
            source.facts(state.component_index),
            roleForInfra(descriptor.kind),
            @intFromEnum(descriptor.kind),
            shard_index,
            descriptor.log_size,
            descriptor.n_rows,
            descriptor.n_columns,
            constraintCountForInfra(descriptor.kind),
            statement_mod.nClaimedSumsForInfra(descriptor.kind),
        );
    }
    std.debug.assert(state.component_index == source.len());
    const detailed_claim_count = try claimedSumCount(statement);
    if (state.claimed_sum_count != @as(usize, detailed_claim_count))
        return error.ClaimedSumCountOverflow;
    const instruction_count = std.math.cast(u32, state.air_instruction_count) orelse
        return error.AirInstructionCountOverflow;
    if (instruction_count == 0 or instruction_count >= m31.Modulus)
        return error.AirInstructionCountOverflow;

    hashInt(&hash, u32, @intCast(state.component_index));
    hashInt(&hash, u32, instruction_count);
    hashInt(&hash, u32, detailed_claim_count);
    hashInt(&hash, u32, state.composition_log_split.?);
    hashInt(&hash, u32, state.max_constraint_log_degree_bound);
    const max_log_degree_bound = state.max_constraint_log_degree_bound -
        state.composition_log_split.?;
    const profile = Profile{
        .component_count = @intCast(state.component_index),
        .air_instruction_count = instruction_count,
        .claimed_sum_count = detailed_claim_count,
        .relation_challenge_count = @intCast(relation_challenges.RELATION_COUNT),
        .composition_log_split = state.composition_log_split.?,
        .composition_log_degree_bound = state.max_constraint_log_degree_bound,
        .max_log_degree_bound = max_log_degree_bound,
        .manifest_digest = hash.finalResult(),
    };
    try profile.validate();
    return profile;
}

const DeriveState = struct {
    component_index: usize = 0,
    air_instruction_count: usize = 0,
    claimed_sum_count: usize = 0,
    composition_log_split: ?u32 = null,
    max_constraint_log_degree_bound: u32 = 0,
};

fn absorbComponent(
    state: *DeriveState,
    hash: *Sha256,
    facts: ComponentFacts,
    role: ComponentRole,
    descriptor_kind: u32,
    shard_index: usize,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
    expected_constraints: usize,
    claimed_sums: usize,
) Error!void {
    if (facts.n_constraints != expected_constraints or facts.n_constraints == 0)
        return error.ConstraintCountMismatch;
    if (facts.max_constraint_log_degree_bound <= facts.composition_log_split or
        facts.composition_log_split == 0)
    {
        return error.InvalidComponentBound;
    }
    if (state.composition_log_split) |split| {
        if (split != facts.composition_log_split)
            return error.InconsistentCompositionLogSplit;
    } else {
        state.composition_log_split = facts.composition_log_split;
    }

    const first_instruction = state.air_instruction_count;
    const first_claimed_sum = state.claimed_sum_count;
    state.air_instruction_count = std.math.add(
        usize,
        state.air_instruction_count,
        facts.n_constraints,
    ) catch return error.AirInstructionCountOverflow;
    state.claimed_sum_count = std.math.add(
        usize,
        state.claimed_sum_count,
        claimed_sums,
    ) catch return error.ClaimedSumCountOverflow;
    state.max_constraint_log_degree_bound = @max(
        state.max_constraint_log_degree_bound,
        facts.max_constraint_log_degree_bound,
    );

    hashInt(hash, u32, @intCast(state.component_index));
    hashInt(hash, u8, @intFromEnum(role));
    hashInt(hash, u32, descriptor_kind);
    hashInt(hash, u32, @intCast(shard_index));
    hashInt(hash, u32, log_size);
    hashInt(hash, u32, n_rows);
    hashInt(hash, u32, n_columns);
    hashInt(hash, u32, @intCast(first_instruction));
    hashInt(hash, u32, @intCast(facts.n_constraints));
    hashInt(hash, u32, @intCast(first_claimed_sum));
    hashInt(hash, u32, @intCast(claimed_sums));
    hashInt(hash, u32, facts.max_constraint_log_degree_bound);
    hashInt(hash, u32, facts.composition_log_split);
    state.component_index += 1;
}

fn constraintCountForInfra(kind: statement_mod.InfraKind) usize {
    return switch (kind) {
        .program => program_interaction.N_CONSTRAINTS,
        .memory => memory_interaction.N_CONSTRAINTS,
        .clock_update => clock_component.N_CONSTRAINTS,
        .poseidon2 => hash_component.constraintCount(.poseidon2, .narrow_memory),
        .merkle => hash_component.constraintCount(.merkle, .narrow_memory),
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => table_component.N_CONSTRAINTS,
    };
}

fn roleForInfra(kind: statement_mod.InfraKind) ComponentRole {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .clock_update => .clock_update,
        .poseidon2 => .poseidon2,
        .merkle => .merkle,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn validateStatementCounts(statement: *const statement_mod.RiscVStatement) Error!void {
    if (statement.n_components == 0 or
        statement.n_components > statement_mod.MAX_COMPONENTS or
        statement.n_infra == 0 or
        statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidStatementShape;
    }
}

fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= m31.Modulus) return error.NonCanonicalClaim;
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

/// Narrow facts-only seam for this module's compile-isolated mutation tests.
/// Production call sites use `derive`, whose facts come from verifier vtables.
pub const testing = struct {
    pub const Facts = ComponentFacts;

    pub fn deriveFromFacts(
        statement: *const statement_mod.RiscVStatement,
        values: []const ComponentFacts,
    ) Error!Profile {
        const Source = struct {
            values: []const ComponentFacts,
            fn len(self: @This()) usize {
                return self.values.len;
            }
            fn facts(self: @This(), index: usize) ComponentFacts {
                return self.values[index];
            }
        };
        return deriveFromSource(statement, Source{ .values = values });
    }

    pub fn expectedFacts(
        statement: *const statement_mod.RiscVStatement,
        destination: []ComponentFacts,
    ) Error!void {
        try validateStatementCounts(statement);
        const expected = 2 * @as(usize, statement.n_components) + statement.n_infra;
        if (destination.len != expected) return error.OutputLengthMismatch;
        var cursor: usize = 0;
        for (statement.component_descs[0..statement.n_components]) |descriptor| {
            destination[cursor] = .{
                .n_constraints = semantic_eval.constraintCount(descriptor.family),
                .max_constraint_log_degree_bound = semantic_eval.constraintLogDegreeBound(
                    descriptor.family,
                    descriptor.log_size,
                ),
                .composition_log_split = stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
            };
            cursor += 1;
            destination[cursor] = .{
                .n_constraints = opcode_entries.batchCount(descriptor.family),
                .max_constraint_log_degree_bound = descriptor.log_size + 1,
                .composition_log_split = stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
            };
            cursor += 1;
        }
        for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
            destination[cursor] = .{
                .n_constraints = constraintCountForInfra(descriptor.kind),
                .max_constraint_log_degree_bound = descriptor.log_size + 1,
                .composition_log_split = stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
            };
            cursor += 1;
        }
        std.debug.assert(cursor == destination.len);
    }
};

comptime {
    if (relation_challenges.RELATION_COUNT != 12)
        @compileError("VM AIR profile relation count must follow the Zig frontend registry");
    if (merkle_node.N_CONSTRAINTS != hash_component.constraintCount(.merkle, .narrow_memory))
        @compileError("Merkle constraint authority drifted");
}
