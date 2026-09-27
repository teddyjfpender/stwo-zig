//! Legacy specialized and opt-in statement-root Ethereum composition profiles.
//! Both record native base, fourteen Ethereum AIRs and the incremental bridge
//! in native four-tree PCS order. The default keeps frozen V4 identities.
//! Schema 2 takes bridge roots through statement inputs; it requires the outer
//! provider cohort to close those lookups before independent-root admission.

const std = @import("std");

const graph_mod = @import("air/composition_circuit.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const base_geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const base_graph = @import("ethereum_vm_composition_graph_base_v2.zig");
const component_order = @import("../air/component_order.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const extension_geometry_mod =
    @import("ethereum_composition_extension_geometry_v2.zig");
const extension_graph =
    @import("ethereum_vm_composition_graph_extension_v2.zig");
const bridge = @import("../air/memory_commitment/incremental_bridge_v2.zig");
const bridge_external = @import("../prover/incremental_bridge_external_v3.zig");
const lookup_manifest = @import("../air/lang/lookup_physical_manifest_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const protocol = @import("protocol.zig");
const relations_mod = @import("ethereum_composition_relations_v2.zig");
const selected_lookup = @import("vm_selected_lookup_compiler_v2.zig");
const statement_mod = @import("../air/statement.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const transcript_claims = @import("../air/transcript/claims.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = support.Scalar;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = circuit.CIRCUIT_ID;
pub const TREE_COUNT: usize = base_geometry_mod.TREE_COUNT;
pub const BASE_TRANSCRIPT_CLAIM_COUNT: usize =
    transcript_claims.COMPONENT_COUNT;
pub const ETHEREUM_TRANSCRIPT_CLAIM_COUNT: usize =
    ethereum_statement.component_count;
pub const BRIDGE_TRANSCRIPT_CLAIM_COUNT: usize = 1;
pub const TRANSCRIPT_CLAIM_COUNT: usize =
    BASE_TRANSCRIPT_CLAIM_COUNT +
    ETHEREUM_TRANSCRIPT_CLAIM_COUNT +
    BRIDGE_TRANSCRIPT_CLAIM_COUNT;
pub const BRIDGE_SAMPLED_VALUE_COUNT: u32 =
    bridge_external.PREPROCESSED_COLUMNS +
    bridge_external.MAIN_COLUMNS +
    2 * bridge_external.INTERACTION_COLUMNS;
pub const BRIDGE_DETAILED_CLAIM_COUNT: u32 = 1;

const AIR_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/incremental-ethereum-vm-air-program/v4\x00";
const VERIFIER_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/incremental-ethereum-vm-verifier-program/v4\x00";
const PROTOCOL_PROFILE_DOMAIN =
    "stwo-zig/riscv/recursion/incremental-ethereum-vm-protocol-profile/v4\x00";

pub const Error = error{
    ArithmeticOverflow,
    InvalidBridgeCompositionGeometry,
    InvalidBridgeSampleLayout,
    InvalidClaimCount,
    InvalidInstructionCount,
    InvalidVerifierProgram,
    VerifierProgramMismatch,
};

const admission = @import("incremental_ethereum_composition_profile_v4.zig");
pub const BridgeInputV4 = admission.BridgeInputV4;
pub const CompilerInputV4 = admission.CompilerInputV4;
pub const StatementRootCompilerInput = admission.StatementRootCompilerInput;

/// Mutable compiler output containing owned graph buffers and typed bridge
/// roots. Runtime Ethereum preparation keeps it private inside
/// `vm_composition_preparation`; its metadata alone is not proof authority.
pub const ProgramV4 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    nodes: []graph_mod.Node,
    outputs: []u32,
    bindings: []graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    claim_routing: ?admission.ClaimRoutingPlan = null,
    base_profile_sha256: [32]u8,
    base_geometry_sha256: [32]u8,
    extension_geometry_sha256: [32]u8,
    selected_lookup_compiler_sha256: [32]u8,
    bridge_geometry_sha256: [32]u8,
    bridge_entry_root: u32,
    bridge_exit_root: u32,
    maximum_log_degree_bound: u32,
    protocol_profile_sha256: [32]u8,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,

    pub fn deinit(self: *ProgramV4) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graph(self: *const ProgramV4) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.graph_sha256,
        };
    }

    pub fn lane(self: *const ProgramV4) graph_mod.VmLane {
        return .{
            .circuit_id = CIRCUIT_ID,
            .graph = self.graph(),
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }

    pub fn validate(self: *const ProgramV4) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != (if (self.claim_routing != null) @as(u16, 3) else if (self.input_profile.vm_statement_root_count == 0) SCHEMA_VERSION else @as(u16, 2)) or
            (self.input_profile.vm_statement_root_count != 0 and self.input_profile.vm_statement_root_count != 2) or
            (self.input_profile.vm_statement_root_count == 2 and (self.bridge_entry_root != 0 or self.bridge_exit_root != 0)) or
            self.input_profile.relation_challenge_count !=
                relations_mod.RELATION_COUNT or
            self.input_profile.transcript_claimed_sum_count !=
                TRANSCRIPT_CLAIM_COUNT or
            self.input_profile.public_wire_boundary_count != 0 or
            self.maximum_log_degree_bound <= 1 or
            self.bridge_entry_root >= @import("stwo_core").fields.m31.Modulus or
            self.bridge_exit_root >= @import("stwo_core").fields.m31.Modulus or
            anyZero(.{
                self.base_profile_sha256,
                self.base_geometry_sha256,
                self.extension_geometry_sha256,
                self.selected_lookup_compiler_sha256,
                self.bridge_geometry_sha256,
                self.protocol_profile_sha256,
                self.graph_sha256,
                self.reference_sha256,
                self.schedule_sha256,
                self.air_program_identity,
                self.verifier_program_authority,
            }))
        {
            return error.InvalidVerifierProgram;
        }
        if (self.claim_routing) |routing| {
            try routing.validate();
            if (self.input_profile.vm_statement_root_count != 2 or
                self.input_profile.claimed_sum_count != routing.physical_count)
                return error.InvalidVerifierProgram;
        }
        try self.graph().validate();
        const lane_value = self.lane();
        const reference_sha256 = graph_mod.computeReferenceDigest(
            lane_value,
            &.{},
            &.{},
        );
        if (!std.mem.eql(u8, &reference_sha256, &self.reference_sha256))
            return error.InvalidVerifierProgram;
        const reference = try graph_mod.Reference.authenticate(
            lane_value,
            &.{},
            &.{},
            reference_sha256,
        );
        var schedule = try graph_mod.compile(self.allocator, &reference);
        defer schedule.deinit();
        if (!std.mem.eql(u8, &schedule.authority_digest, &self.schedule_sha256) or
            !std.mem.eql(u8, &protocolProfileIdentity(), &self.protocol_profile_sha256) or
            !std.mem.eql(u8, &self.computeAirProgramIdentity(), &self.air_program_identity) or
            !std.mem.eql(u8, &self.computeVerifierProgramAuthority(), &self.verifier_program_authority))
        {
            return error.InvalidVerifierProgram;
        }
    }

    pub fn validateAgainst(self: *const ProgramV4, input: CompilerInputV4) !void {
        try self.validate();
        var expected = try compileInternal(self.allocator, input, null, self.input_profile.vm_statement_root_count == 2, self.claim_routing != null, self.input_profile.vm_native_continuation_roots);
        defer expected.deinit();
        if (!programsEqual(self, &expected))
            return error.VerifierProgramMismatch;
    }

    fn computeAirProgramIdentity(self: *const ProgramV4) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(AIR_PROGRAM_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u32, CIRCUIT_ID);
        hash.update(&self.base_profile_sha256);
        hash.update(&self.base_geometry_sha256);
        hash.update(&self.extension_geometry_sha256);
        hash.update(&self.selected_lookup_compiler_sha256);
        hash.update(&self.bridge_geometry_sha256);
        hashInt(&hash, u32, self.bridge_entry_root);
        hashInt(&hash, u32, self.bridge_exit_root);
        hashInt(&hash, u32, self.maximum_log_degree_bound);
        hash.update(&self.graph_sha256);
        hash.update(&self.reference_sha256);
        hash.update(&self.schedule_sha256);
        hashInputProfile(&hash, self.input_profile);
        if (self.claim_routing) |routing| hash.update(&routing.identity());
        return hash.finalResult();
    }

    fn computeVerifierProgramAuthority(self: *const ProgramV4) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(VERIFIER_PROGRAM_DOMAIN);
        hash.update(&self.air_program_identity);
        hash.update(&self.protocol_profile_sha256);
        hash.update(&self.schedule_sha256);
        return hash.finalResult();
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    input: CompilerInputV4,
) !ProgramV4 {
    return compileInternal(allocator, input, null, false, false, false);
}

/// Retains the compiler's authenticated schedule for transfer to row 18.
/// Independent boundaries use `compile` and `ProgramV4.validateAgainst`.
pub fn compileRetainingSchedule(
    allocator: std.mem.Allocator,
    input: CompilerInputV4,
    retained_schedule: *graph_mod.CompiledSchedule,
) !ProgramV4 {
    return compileInternal(allocator, input, retained_schedule, false, false, false);
}

pub fn compileWithStatementRootsRetainingSchedule(
    allocator: std.mem.Allocator,
    input: StatementRootCompilerInput,
    retained_schedule: *graph_mod.CompiledSchedule,
) !ProgramV4 {
    return compileStatementRootProfile(allocator, input, retained_schedule, false);
}

pub fn compileWithClaimAliasesRetainingSchedule(
    allocator: std.mem.Allocator,
    input: StatementRootCompilerInput,
    retained_schedule: *graph_mod.CompiledSchedule,
) !ProgramV4 {
    return compileStatementRootProfile(allocator, input, retained_schedule, true);
}

fn compileStatementRootProfile(
    allocator: std.mem.Allocator,
    input: StatementRootCompilerInput,
    retained_schedule: *graph_mod.CompiledSchedule,
    claim_aliases: bool,
) !ProgramV4 {
    return compileInternal(allocator, .{
        .core_statement = input.core_statement,
        .extension_statement = input.extension_statement,
        .lookup_manifest = input.lookup_manifest,
        .authenticated_lookup = input.authenticated_lookup,
        .base_profile = input.base_profile,
        .bridge = .{ .geometry = input.bridge_geometry, .entry_root = 0, .exit_root = 0 },
    }, retained_schedule, true, claim_aliases, input.native_continuation_roots);
}

fn compileInternal(
    allocator: std.mem.Allocator,
    input: CompilerInputV4,
    retained_schedule: ?*graph_mod.CompiledSchedule,
    statement_roots: bool,
    claim_aliases: bool,
    native_continuation_roots: bool,
) !ProgramV4 {
    if (native_continuation_roots and !statement_roots) return error.InvalidVerifierProgram;
    try input.base_profile.validateAuthority(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
    );
    try input.extension_statement.validateStructure(input.core_statement);
    try (protocol.Profile{}).validate();

    var base_geometry = try base_geometry_mod.GeometryV2.init(
        allocator,
        input.base_profile,
    );
    defer base_geometry.deinit();
    var extension_geometry = try extension_geometry_mod.GeometryV2.init(
        allocator,
        input.base_profile,
        input.core_statement,
        input.extension_statement,
    );
    defer extension_geometry.deinit();
    const prefix = try bridgePrefix(input.base_profile, &extension_geometry);
    try input.bridge.validateAfterPrefix(prefix);
    const selected = try selected_lookup.CompilerV2.init(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
        input.base_profile,
    );
    try selected.validateAuthority(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
        input.base_profile,
    );

    const sampled_value_count = try add(
        try add(
            base_geometry.sampled_value_count,
            extension_geometry.sampled_value_count,
        ),
        try add(BRIDGE_SAMPLED_VALUE_COUNT, fixedProgramSampleCount(input.base_profile)),
    );
    const claimed_sum_count = try add(
        try add(
            input.base_profile.input_profile.claimed_sum_count,
            extension_geometry.detailed_claim_count,
        ),
        BRIDGE_DETAILED_CLAIM_COUNT,
    );
    const claim_routing: ?admission.ClaimRoutingPlan = if (claim_aliases) blk: {
        if (!statement_roots) return error.InvalidVerifierProgram;
        var counts: [ETHEREUM_TRANSCRIPT_CLAIM_COUNT]u32 = undefined;
        for (&counts, extension_geometry.components) |*count, component|
            count.* = component.interaction_batch_count;
        break :blk try admission.ClaimRoutingPlan.init(input.base_profile.input_profile.claimed_sum_count, counts);
    } else null;
    if (claim_routing) |routing| {
        if (routing.logical_count != claimed_sum_count) return error.InvalidClaimCount;
    }
    const input_profile = graph_mod.InputProfile{
        .sampled_value_count = sampled_value_count,
        .claimed_sum_count = if (claim_routing) |routing| routing.physical_count else claimed_sum_count,
        .relation_challenge_count = relations_mod.RELATION_COUNT,
        .transcript_claimed_sum_count = TRANSCRIPT_CLAIM_COUNT,
        .vm_statement_root_count = if (statement_roots) 2 else 0,
        .vm_native_continuation_roots = native_continuation_roots,
    };
    const input_count = try graph_mod.vmInputCount(input_profile);
    const air_instruction_count = try add(
        try add(
            input.base_profile.air_instruction_count,
            extension_geometry.air_instruction_count,
        ),
        bridge.N_CONSTRAINTS,
    );
    const maximum_log_degree_bound = @max(
        extension_geometry.max_log_degree_bound,
        try add(input.bridge.geometry.log_size, 1),
    );
    // Native verification evaluates trace quotients on the split domain.
    // Composition reconstruction below still uses the full degree bound.
    const mask_log_size = @import("stwo_core").verifier_types.compositionMaskLogSize(
        maximum_log_degree_bound,
        input.base_profile.composition_log_split,
    ) orelse return error.InvalidVerifierProgram;

    var builder = support.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(
        input_count,
        try add(air_instruction_count, TRANSCRIPT_CLAIM_COUNT + 1),
    );
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const selector = try builder.input(.segment_selector);
    const sampled = try allocator.alloc(Scalar, sampled_value_count);
    defer allocator.free(sampled);
    for (sampled, 0..) |*value, item| value.* = try support.secureInput(
        &builder,
        .sampled_value,
        @intCast(item),
    );
    const claims = try allocator.alloc(Scalar, claimed_sum_count);
    defer allocator.free(claims);
    for (claims, 0..) |*value, item| {
        const route: admission.ClaimRoutingPlan.Route = if (claim_routing) |routing|
            try routing.route(@intCast(item))
        else
            .{ .detailed = @intCast(item) };
        switch (route) {
            .detailed => |physical| value.* = try support.secureInput(&builder, .claimed_sum, physical),
            .canonical => {}, // Filled from authenticated canonical nodes below.
        }
    }
    var transcript_aggregates: [TRANSCRIPT_CLAIM_COUNT]Scalar = undefined;
    for (&transcript_aggregates, 0..) |*value, item| value.* =
        try support.secureInput(
            &builder,
            .transcript_claimed_sum,
            @intCast(item),
        );
    if (claim_routing) |routing| for (routing.aliases) |alias| {
        claims[alias.logical] = transcript_aggregates[alias.canonical];
    };
    var base_draws: [relations_mod.BASE_RELATION_COUNT][2]Scalar = undefined;
    for (&base_draws, 0..) |*pair, challenge| {
        pair[0] = try support.challengeInput(&builder, @intCast(challenge), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(challenge), 4);
    }
    var extension_draws: [relations_mod.EXTENSION_RELATION_COUNT][2]Scalar =
        undefined;
    for (&extension_draws, 0..) |*pair, extension_challenge| {
        const challenge = relations_mod.BASE_RELATION_COUNT + extension_challenge;
        pair[0] = try support.challengeInput(&builder, @intCast(challenge), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(challenge), 4);
    }
    const composition_randomness = try support.scalarInput(
        &builder,
        .composition_randomness,
    );
    const oods_seed = try support.scalarInput(&builder, .oods_point);
    const root_values: [2]Scalar = if (statement_roots) .{
        try builder.input(if (native_continuation_roots) .{ .native_continuation_root = 0 } else .{ .statement_word = @import("air/vm_statement_roots.zig").word_indices[0] }),
        try builder.input(if (native_continuation_roots) .{ .native_continuation_root = 1 } else .{ .statement_word = @import("air/vm_statement_roots.zig").word_indices[1] }),
    } else .{
        Scalar.fromBase(@import("stwo_core").fields.m31.M31.fromU64(input.bridge.entry_root)),
        Scalar.fromBase(@import("stwo_core").fields.m31.M31.fromU64(input.bridge.exit_root)),
    };
    try builder.check();

    try bindTranscriptAggregates(
        &builder,
        selector,
        input.base_profile,
        &extension_geometry,
        claims,
        transcript_aggregates,
    );
    const relations = relations_mod.RelationsV2.init(
        base_draws,
        extension_draws,
    );
    var split = try SplitSampleLayoutV4.init(
        allocator,
        &base_geometry,
        &extension_geometry,
        sampled,
        input.base_profile.circuit_profile.programPolicy() == .fixed_decoded_table_v1,
    );
    defer split.deinit();
    var layout = try support.SampleLayoutV2.init(
        allocator,
        &base_geometry,
        &extension_geometry,
        split.base_and_ethereum,
    );
    defer layout.deinit();
    const point = support.pointFromSeed(oods_seed);
    var denominators: [31]?Scalar = .{null} ** 31;
    const base_result = try base_graph.recordWithFixedProgram(
        .full_state_split_multiplicity_v3,
        input.base_profile,
        input.lookup_manifest,
        &selected,
        &layout,
        split.fixed_program_values,
        claims[0..@as(usize, input.base_profile.input_profile.claimed_sum_count)],
        &relations.base,
        point,
        composition_randomness,
        mask_log_size,
        &denominators,
    );
    const ethereum_claim_end: usize = @intCast(
        claimed_sum_count - BRIDGE_DETAILED_CLAIM_COUNT,
    );
    const extension_result = try extension_graph.record(
        &extension_geometry,
        &layout,
        claims[@as(usize, input.base_profile.input_profile.claimed_sum_count)..ethereum_claim_end],
        &relations,
        point,
        composition_randomness,
        mask_log_size,
        &denominators,
        base_result.accumulation,
    );
    const bridge_accumulation = try recordBridge(
        &split,
        input.bridge,
        root_values,
        claims[ethereum_claim_end],
        &relations,
        point,
        composition_randomness,
        mask_log_size,
        &denominators,
        extension_result.accumulation,
    );
    if (try add(
        try add(base_result.instruction_count, extension_result.instruction_count),
        bridge.N_CONSTRAINTS,
    ) != air_instruction_count) return error.InvalidInstructionCount;
    const composition = try support.reconstructComposition(
        &layout,
        point,
        maximum_log_degree_bound,
        input.base_profile.composition_log_split,
    );
    try builder.constrainZero(selector.mul(
        composition.sub(bridge_accumulation),
    ));
    try builder.check();

    const nodes = try builder.nodes.toOwnedSlice(allocator);
    errdefer allocator.free(nodes);
    const outputs = try builder.outputs.toOwnedSlice(allocator);
    errdefer allocator.free(outputs);
    const bindings = try builder.bindings.toOwnedSlice(allocator);
    errdefer allocator.free(bindings);
    const graph_sha256 = graph_mod.computeGraphDigest(nodes, outputs);
    const lane = graph_mod.VmLane{
        .circuit_id = CIRCUIT_ID,
        .graph = .{
            .nodes = nodes,
            .outputs = outputs,
            .identity_digest = graph_sha256,
        },
        .profile = input_profile,
        .bindings = bindings,
    };
    const reference_sha256 = graph_mod.computeReferenceDigest(lane, &.{}, &.{});
    const reference = try graph_mod.Reference.authenticate(
        lane,
        &.{},
        &.{},
        reference_sha256,
    );
    var schedule = try graph_mod.compile(allocator, &reference);
    var schedule_owned = true;
    defer if (schedule_owned) schedule.deinit();

    var result = ProgramV4{
        .allocator = allocator,
        .schema_version = if (claim_aliases) 3 else if (statement_roots) 2 else SCHEMA_VERSION,
        .nodes = nodes,
        .outputs = outputs,
        .bindings = bindings,
        .input_profile = input_profile,
        .claim_routing = claim_routing,
        .base_profile_sha256 = input.base_profile.identity_digest,
        .base_geometry_sha256 = base_geometry.identity_sha256,
        .extension_geometry_sha256 = extension_geometry.identity_sha256,
        .selected_lookup_compiler_sha256 = selected.identity_sha256,
        .bridge_geometry_sha256 = input.bridge.geometry.identity_sha256,
        .bridge_entry_root = if (statement_roots) 0 else input.bridge.entry_root,
        .bridge_exit_root = if (statement_roots) 0 else input.bridge.exit_root,
        .maximum_log_degree_bound = maximum_log_degree_bound,
        .protocol_profile_sha256 = protocolProfileIdentity(),
        .graph_sha256 = graph_sha256,
        .reference_sha256 = reference_sha256,
        .schedule_sha256 = schedule.authority_digest,
        .air_program_identity = undefined,
        .verifier_program_authority = undefined,
    };
    result.air_program_identity = result.computeAirProgramIdentity();
    result.verifier_program_authority =
        result.computeVerifierProgramAuthority();
    if (retained_schedule) |destination| {
        // The builder, authenticated reference, and retained compiled schedule
        // are the fresh construction authority.  Recompilation is reserved for
        // the explicit cold/deep `ProgramV4.validate*` boundary.
        destination.* = schedule;
        schedule_owned = false;
    } else {
        try result.validate();
    }
    return result;
}

const SplitSampleLayoutV4 = struct {
    allocator: std.mem.Allocator,
    base_and_ethereum: []Scalar,
    bridge_values: [BRIDGE_SAMPLED_VALUE_COUNT]Scalar,
    fixed_program_values: ?[@import("../air/program/interaction.zig").FIXED_COLUMN_COUNT]Scalar = null,

    fn init(
        allocator: std.mem.Allocator,
        base: *const base_geometry_mod.GeometryV2,
        extension: *const extension_geometry_mod.GeometryV2,
        all: []const Scalar,
        fixed_program: bool,
    ) !SplitSampleLayoutV4 {
        const compact_count = try add(
            base.sampled_value_count,
            extension.sampled_value_count,
        );
        if (all.len != @as(
            usize,
            @intCast(try add(try add(compact_count, BRIDGE_SAMPLED_VALUE_COUNT), if (fixed_program) @import("../air/program/interaction.zig").FIXED_COLUMN_COUNT else 0)),
        ))
            return error.InvalidBridgeSampleLayout;
        const compact = try allocator.alloc(Scalar, compact_count);
        errdefer allocator.free(compact);
        var result = SplitSampleLayoutV4{
            .allocator = allocator,
            .base_and_ethereum = compact,
            .bridge_values = undefined,
        };
        var source_at: usize = 0;
        var compact_at: usize = 0;
        var bridge_at: usize = 0;
        for (0..TREE_COUNT) |tree| {
            const base_count = try treeSampleCount(base.columns[tree]);
            const extension_count = if (tree < extension.columns.len)
                try treeSampleCount(extension.columns[tree])
            else
                0;
            const ordinary_count = try add(base_count, extension_count);
            const ordinary_end = try addUsize(source_at, ordinary_count);
            const compact_end = try addUsize(compact_at, ordinary_count);
            if (ordinary_end > all.len or compact_end > compact.len)
                return error.InvalidBridgeSampleLayout;
            @memcpy(compact[compact_at..compact_end], all[source_at..ordinary_end]);
            source_at = ordinary_end;
            compact_at = compact_end;
            if (tree == 0 and fixed_program) {
                const count = @import("../air/program/interaction.zig").FIXED_COLUMN_COUNT;
                if (source_at + count > all.len) return error.InvalidBridgeSampleLayout;
                result.fixed_program_values = all[source_at..][0..count].*;
                source_at += count;
            }
            const bridge_count: usize = switch (tree) {
                0 => bridge_external.PREPROCESSED_COLUMNS,
                1 => bridge_external.MAIN_COLUMNS,
                2 => 2 * bridge_external.INTERACTION_COLUMNS,
                3 => 0,
                else => unreachable,
            };
            const bridge_end = try addUsize(source_at, bridge_count);
            if (bridge_end > all.len or bridge_at + bridge_count >
                BRIDGE_SAMPLED_VALUE_COUNT)
            {
                return error.InvalidBridgeSampleLayout;
            }
            @memcpy(
                result.bridge_values[bridge_at..][0..bridge_count],
                all[source_at..bridge_end],
            );
            source_at = bridge_end;
            bridge_at += bridge_count;
        }
        if (source_at != all.len or compact_at != compact.len or
            bridge_at != BRIDGE_SAMPLED_VALUE_COUNT)
        {
            return error.InvalidBridgeSampleLayout;
        }
        return result;
    }

    fn deinit(self: *SplitSampleLayoutV4) void {
        self.allocator.free(self.base_and_ethereum);
        self.* = undefined;
    }

    fn bridgePreprocessed(self: *const SplitSampleLayoutV4, column: usize) !Scalar {
        if (column >= bridge_external.PREPROCESSED_COLUMNS)
            return error.InvalidBridgeSampleLayout;
        return self.bridge_values[column];
    }

    fn bridgeMain(self: *const SplitSampleLayoutV4, column: usize) !Scalar {
        if (column >= bridge_external.MAIN_COLUMNS)
            return error.InvalidBridgeSampleLayout;
        return self.bridge_values[bridge_external.PREPROCESSED_COLUMNS + column];
    }

    fn bridgeInteractionSecure(
        self: *const SplitSampleLayoutV4,
        column: usize,
        sample: usize,
    ) !Scalar {
        if (column + 4 > bridge_external.INTERACTION_COLUMNS or sample >= 2)
            return error.InvalidBridgeSampleLayout;
        const base_offset = bridge_external.PREPROCESSED_COLUMNS +
            bridge_external.MAIN_COLUMNS;
        var coordinates: [4]Scalar = undefined;
        for (&coordinates, 0..) |*value, coordinate| value.* =
            self.bridge_values[base_offset + 2 * (column + coordinate) + sample];
        return support.fromPartialEvals(coordinates);
    }
};

fn recordBridge(
    layout: *const SplitSampleLayoutV4,
    input: BridgeInputV4,
    root_values: [2]Scalar,
    claim: Scalar,
    relations: *const relations_mod.RelationsV2,
    point: anytype,
    randomness: Scalar,
    max_log_degree_bound: u32,
    denominators: *[31]?Scalar,
    initial: Scalar,
) !Scalar {
    var main: [bridge.N_MAIN_COLUMNS]Scalar = undefined;
    for (&main, 0..) |*value, column| value.* = try layout.bridgeMain(column);
    const constraints = bridge.evaluateGeneric(
        Scalar,
        main,
        try layout.bridgePreprocessed(1),
        try layout.bridgePreprocessed(0),
        try layout.bridgeInteractionSecure(0, 0),
        try layout.bridgeInteractionSecure(0, 1),
        claim,
        root_values[0],
        root_values[1],
        &relations.base,
    );
    const denominator = support.quotientDenominator(
        input.geometry.log_size,
        max_log_degree_bound,
        point,
        denominators,
    );
    var result = initial;
    for (constraints) |constraint|
        support.accumulate(&result, randomness, constraint, denominator);
    return result;
}

fn bindTranscriptAggregates(
    builder: *support.Builder,
    selector: Scalar,
    profile: *const profile_mod.ProfileV2,
    extension: *const extension_geometry_mod.GeometryV2,
    claims: []const Scalar,
    transcript: [TRANSCRIPT_CLAIM_COUNT]Scalar,
) !void {
    var reconstructed = [_]Scalar{Scalar.zero()} ** TRANSCRIPT_CLAIM_COUNT;
    for (profile.entries) |entry| switch (entry.registry) {
        .opcode_lookup => |key| try addClaimRange(
            &reconstructed[
                @intFromEnum(
                    component_order.transcriptComponentForOpcodeFamily(key.family),
                )
            ],
            claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
        .infrastructure => |key| try addClaimRange(
            &reconstructed[@intFromEnum(transcriptComponentForInfra(key.kind))],
            claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
        .opcode_semantic => {},
    };
    var cursor: u32 = profile.input_profile.claimed_sum_count;
    for (extension.components, 0..) |component, index| {
        try addClaimRange(
            &reconstructed[BASE_TRANSCRIPT_CLAIM_COUNT + index],
            claims,
            cursor,
            component.interaction_batch_count,
        );
        cursor = try add(cursor, component.interaction_batch_count);
    }
    if (@as(usize, cursor) + 1 != claims.len)
        return error.InvalidClaimCount;
    reconstructed[TRANSCRIPT_CLAIM_COUNT - 1] = claims[cursor];
    for (transcript, reconstructed) |authenticated, aggregate|
        try builder.constrainZero(selector.mul(authenticated.sub(aggregate)));
    try builder.check();
}

fn addClaimRange(
    destination: *Scalar,
    claims: []const Scalar,
    offset: u32,
    count: u32,
) !void {
    const end = try add(offset, count);
    if (@as(usize, end) > claims.len) return error.InvalidClaimCount;
    for (claims[@as(usize, offset)..@as(usize, end)]) |claim|
        destination.* = destination.add(claim);
}

fn transcriptComponentForInfra(
    kind: statement_mod.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn fixedProgramSampleCount(profile: *const profile_mod.ProfileV2) u32 {
    return if (profile.circuit_profile.programPolicy() == .fixed_decoded_table_v1) @import("../air/program/interaction.zig").FIXED_COLUMN_COUNT else 0;
}

fn bridgePrefix(
    profile: *const profile_mod.ProfileV2,
    extension: *const extension_geometry_mod.GeometryV2,
) !bridge_external.PrefixColumnsV3 {
    return .{
        .preprocessed = try add(try add(profile.preprocessed_column_count, extension.columns[0].len), fixedProgramSampleCount(profile)),
        .main = try add(profile.main_column_count, extension.columns[1].len),
        .interaction = try add(profile.interaction_column_count, extension.columns[2].len),
    };
}

fn treeSampleCount(columns: anytype) !u32 {
    var result: u32 = 0;
    for (columns) |column| result = try add(result, column.sample_count);
    return result;
}

fn protocolProfileIdentity() [32]u8 {
    const profile = protocol.Profile{};
    var hash = Sha256.init(.{});
    hash.update(PROTOCOL_PROFILE_DOMAIN);
    for (profile.words()) |word| hashInt(&hash, u32, word);
    for (protocol.protocolId()) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn programsEqual(left: *const ProgramV4, right: *const ProgramV4) bool {
    if (left.format_version != right.format_version or
        left.schema_version != right.schema_version or
        !std.meta.eql(left.input_profile, right.input_profile) or
        !std.meta.eql(left.claim_routing, right.claim_routing) or
        !std.meta.eql(left.base_profile_sha256, right.base_profile_sha256) or
        !std.meta.eql(left.base_geometry_sha256, right.base_geometry_sha256) or
        !std.meta.eql(left.extension_geometry_sha256, right.extension_geometry_sha256) or
        !std.meta.eql(left.selected_lookup_compiler_sha256, right.selected_lookup_compiler_sha256) or
        !std.meta.eql(left.bridge_geometry_sha256, right.bridge_geometry_sha256) or
        left.bridge_entry_root != right.bridge_entry_root or
        left.bridge_exit_root != right.bridge_exit_root or
        left.maximum_log_degree_bound != right.maximum_log_degree_bound or
        !std.meta.eql(left.protocol_profile_sha256, right.protocol_profile_sha256) or
        !std.meta.eql(left.graph_sha256, right.graph_sha256) or
        !std.meta.eql(left.reference_sha256, right.reference_sha256) or
        !std.meta.eql(left.schedule_sha256, right.schedule_sha256) or
        !std.meta.eql(left.air_program_identity, right.air_program_identity) or
        !std.meta.eql(left.verifier_program_authority, right.verifier_program_authority) or
        left.nodes.len != right.nodes.len or left.outputs.len != right.outputs.len or
        left.bindings.len != right.bindings.len)
    {
        return false;
    }
    for (left.nodes, right.nodes) |a, b| if (!std.meta.eql(a, b)) return false;
    for (left.outputs, right.outputs) |a, b| if (a != b) return false;
    for (left.bindings, right.bindings) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

const hashInputProfile = admission.hashInputProfile;

fn anyZero(values: anytype) bool {
    inline for (values) |value| if (std.mem.allEqual(u8, &value, 0)) return true;
    return false;
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        return error.ArithmeticOverflow;
}

fn addUsize(left: usize, right: anytype) !usize {
    return std.math.add(usize, left, @intCast(right)) catch
        return error.ArithmeticOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or TREE_COUNT != 4 or
        relations_mod.RELATION_COUNT != 25 or
        BASE_TRANSCRIPT_CLAIM_COUNT != 28 or
        ETHEREUM_TRANSCRIPT_CLAIM_COUNT != 14 or
        TRANSCRIPT_CLAIM_COUNT != 43 or BRIDGE_SAMPLED_VALUE_COUNT != 17 or
        bridge.N_CONSTRAINTS != 6)
    {
        @compileError("incremental Ethereum VM program V4 drifted");
    }
}
