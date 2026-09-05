//! Candidate-only integration of the U256 SWAP with one complete base VM.
//!
//! The standalone SWAP proof intentionally leaves program/state/register/
//! memory/range events as an external residual.  This module provides the
//! sound integration boundary: canonical base commitments are extended in
//! place, the real caller/word components share the base relation challenges,
//! and one global cancellation equation includes the base public boundary.
//! No production runner or execution profile imports this file.

const std = @import("std");

const core_air_components = @import("stwo_core").air.components;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;

const base_logup = @import("../../air/logup.zig");
const program_decode = @import("../../air/program/decode.zig");
const public_logup = @import("../../air/public_logup.zig");
const base_statement = @import("../../air/statement.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const private_registry = @import("../../isa/stack_swap_private_registry_v1.zig");
const contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const interaction_mod = @import("../../air/guest_precompile/stack_swap_interaction_v1.zig");
const profile_mod = @import("../../air/guest_precompile/stack_swap_vm_profile_v1.zig");
const relations_mod = @import("../../air/guest_precompile/stack_swap_relations_v1.zig");
const stark_component = @import("../../air/guest_precompile/stack_swap_stark_component_v1.zig");
const trace_mod = @import("../../air/guest_precompile/stack_swap_trace_v1.zig");
const program_commitment = @import("../../air/program/commitment.zig");
const memory_state = @import("../../runner/memory_state.zig");
const external_tree = @import("external_profile_tree.zig");
const proof_workspace = @import("../proof_workspace.zig");

pub const production_active = false;
pub const appended_component_count: usize = 2;
pub const max_component_handles =
    proof_workspace.MAX_COMPONENT_HANDLES + appended_component_count;

const CallerComponent = stark_component.Component(contract.Caller);
const WordComponent = stark_component.Component(contract.Word);

/// Decoder object for the pending generic declared-program commitment seam.
/// Ordinary words use the canonical base decoder; exactly one allocated word
/// maps to the private program tuple. Every other CUSTOM-0 word is rejected.
pub const DeclaredDecodeAuthority = struct {
    authority: abi.Authority,

    pub fn init(authority: abi.Authority) !DeclaredDecodeAuthority {
        try private_registry.validateAuthority(authority);
        return .{ .authority = authority };
    }

    pub fn validate(self: DeclaredDecodeAuthority) !void {
        try private_registry.validateAuthority(self.authority);
    }

    pub fn decodeFetchedWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        try self.validate();
        if (@as(u7, @truncate(word)) != abi.major_opcode)
            return program_decode.decodeProgramWord(word);
        _ = try self.authority.decode(word);
        return .{
            self.authority.allocation.proof_opcode_id,
            abi.destination_register,
            abi.lhs_pointer_register,
            abi.rhs_pointer_register,
        };
    }

    pub fn decodeDeclaredWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        return self.decodeFetchedWord(word);
    }

    pub fn isDeclaredPadding(_: DeclaredDecodeAuthority, _: u32) bool {
        return false;
    }
};

/// Stable borrowed column arrays for `external_profile_tree`.
///
/// The arrays live in this object; the returned blocks may not outlive it or
/// the underlying trace/interaction buffers.
pub const TraceBlocks = struct {
    caller_preprocessed: [trace_mod.preprocessed_column_count][]const M31,
    word_preprocessed: [trace_mod.preprocessed_column_count][]const M31,
    caller_main: [contract.Caller.main_column_count][]const M31,
    word_main: [contract.Word.main_column_count][]const M31,
    caller_interaction: [contract.Caller.interaction_column_count][]const M31,
    word_interaction: [contract.Word.interaction_column_count][]const M31,
    caller_log_size: u32,
    word_log_size: u32,

    pub fn init(
        traces: *const trace_mod.Bundle,
        caller_interaction: *const interaction_mod.Result(contract.Caller),
        word_interaction: *const interaction_mod.Result(contract.Word),
    ) TraceBlocks {
        var result: TraceBlocks = undefined;
        for (&result.caller_preprocessed, 0..) |*column, index|
            column.* = traces.caller.preprocessedColumn(index);
        for (&result.word_preprocessed, 0..) |*column, index|
            column.* = traces.words.preprocessedColumn(index);
        for (&result.caller_main, 0..) |*column, index|
            column.* = traces.caller.mainColumn(index);
        for (&result.word_main, 0..) |*column, index|
            column.* = traces.words.mainColumn(index);
        for (&result.caller_interaction, caller_interaction.columns) |*out, column|
            out.* = column;
        for (&result.word_interaction, word_interaction.columns) |*out, column|
            out.* = column;
        result.caller_log_size = traces.caller.log_size;
        result.word_log_size = traces.words.log_size;
        return result;
    }

    pub fn validateAgainst(
        self: *const TraceBlocks,
        profile: *const profile_mod.Profile,
        core: *const base_statement.RiscVStatement,
    ) !void {
        try profile.validateAgainst(core);
        if (self.caller_log_size != profile.components[0].log_size or
            self.word_log_size != profile.components[1].log_size)
        {
            return error.StackSwapVmTraceGeometryMismatch;
        }
        try validateColumnLengths(self.caller_preprocessed, self.caller_log_size);
        try validateColumnLengths(self.caller_main, self.caller_log_size);
        try validateColumnLengths(self.caller_interaction, self.caller_log_size);
        try validateColumnLengths(self.word_preprocessed, self.word_log_size);
        try validateColumnLengths(self.word_main, self.word_log_size);
        try validateColumnLengths(self.word_interaction, self.word_log_size);
    }

    pub fn tree0(self: *const TraceBlocks) [2]external_tree.BorrowedBlock {
        return .{
            .{ .log_size = self.caller_log_size, .columns = &self.caller_preprocessed },
            .{ .log_size = self.word_log_size, .columns = &self.word_preprocessed },
        };
    }

    pub fn tree1(self: *const TraceBlocks) [2]external_tree.BorrowedBlock {
        return .{
            .{ .log_size = self.caller_log_size, .columns = &self.caller_main },
            .{ .log_size = self.word_log_size, .columns = &self.word_main },
        };
    }

    pub fn tree2(self: *const TraceBlocks) [2]external_tree.BorrowedBlock {
        return .{
            .{ .log_size = self.caller_log_size, .columns = &self.caller_interaction },
            .{ .log_size = self.word_log_size, .columns = &self.word_interaction },
        };
    }
};

pub const ProverAssembly = struct {
    caller: CallerComponent,
    words: WordComponent,
    handles: [max_component_handles]prover_component.ComponentProver,
    len: usize,

    pub fn create(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        profile: *const profile_mod.Profile,
        relations: *const relations_mod.Relations,
        base: []const prover_component.ComponentProver,
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) !*ProverAssembly {
        try validateClaims(core, profile, caller_claim, word_claim);
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        const result = try allocator.create(ProverAssembly);
        errdefer allocator.destroy(result);
        const inputs = contract.Inputs{
            .relations = relations,
            .authority = &profile.authority,
        };
        result.caller = try .init(
            caller_claim,
            starkPlacement(profile.placements.caller),
            inputs,
        );
        result.words = try .init(
            word_claim,
            starkPlacement(profile.placements.words),
            inputs,
        );
        @memcpy(result.handles[0..base.len], base);
        result.handles[base.len] = result.caller.asProverComponent();
        result.handles[base.len + 1] = result.words.asProverComponent();
        result.len = base.len + appended_component_count;
        return result;
    }

    pub fn active(self: *const ProverAssembly) []const prover_component.ComponentProver {
        return self.handles[0..self.len];
    }

    pub fn destroy(self: *ProverAssembly, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

pub const VerifierAssembly = struct {
    caller: CallerComponent,
    words: WordComponent,
    handles: [max_component_handles]core_air_components.Component,
    len: usize,

    pub fn create(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        profile: *const profile_mod.Profile,
        relations: *const relations_mod.Relations,
        base: []const core_air_components.Component,
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) !*VerifierAssembly {
        try validateClaims(core, profile, caller_claim, word_claim);
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        const result = try allocator.create(VerifierAssembly);
        errdefer allocator.destroy(result);
        const inputs = contract.Inputs{
            .relations = relations,
            .authority = &profile.authority,
        };
        result.caller = try .init(
            caller_claim,
            starkPlacement(profile.placements.caller),
            inputs,
        );
        result.words = try .init(
            word_claim,
            starkPlacement(profile.placements.words),
            inputs,
        );
        @memcpy(result.handles[0..base.len], base);
        result.handles[base.len] = result.caller.asVerifierComponent();
        result.handles[base.len + 1] = result.words.asVerifierComponent();
        result.len = base.len + appended_component_count;
        return result;
    }

    pub fn active(self: *const VerifierAssembly) []const core_air_components.Component {
        return self.handles[0..self.len];
    }

    pub fn destroy(self: *VerifierAssembly, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

/// Exact base context required to close SWAP's externally emitted events.
/// Internal caller/word call cancellation is checked independently first.
pub const ExternalBaseRelationContext = struct {
    core: *const base_statement.RiscVStatement,
    base_claim: *const base_statement.RiscVInteractionClaim,
    relations: *const relations_mod.Relations,
    interaction_pow: u64,

    pub fn verify(
        self: ExternalBaseRelationContext,
        allocator: std.mem.Allocator,
        profile: *const profile_mod.Profile,
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) !void {
        try validateClaims(self.core, profile, caller_claim, word_claim);
        if (self.base_claim.interaction_pow != self.interaction_pow)
            return error.StackSwapVmInteractionPowMismatch;
        if (!callRelationSum(caller_claim, word_claim).isZero())
            return error.StackSwapVmCallRelationUnclosed;

        const canonical = try allocator.create(base_statement.CanonicalInteractionClaim);
        defer allocator.destroy(canonical);
        canonical.* = try self.base_claim.canonical(self.core);
        const base_view = canonical.view();
        const boundary = try public_logup.sum(
            &self.core.public_data,
            &self.relations.base,
        );
        try base_logup.verifyGlobalCancellation(
            &.{ base_view.total(), caller_claim.component_sum, word_claim.component_sum },
            boundary,
        );
    }
};

/// Bind the complete field authority before Tree 0. The SHA profile checksum
/// is not mixed or trusted; `Profile.mixFieldAuthority` emits every field.
pub fn mixPreTree0Authority(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    profile: *const profile_mod.Profile,
) !void {
    try profile.mixFieldAuthority(core, channel);
}

/// Base main-claim/shard order is preserved, followed by one explicit frame
/// for the appended caller and word component geometry.
pub fn mixPostTree1Authority(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    profile: *const profile_mod.Profile,
) !void {
    try profile.validateAgainst(core);
    const base_main = core.canonicalMainClaim();
    base_main.mixInto(channel);
    core.mixShardManifest(channel);
    channel.mixU32s(&.{
        0x4757_5453, // STWG
        0x314d_5353, // SSM1
        appended_component_count,
        profile.components[0].log_size,
        profile.components[1].log_size,
    });
    for (profile.components) |component| channel.mixU32s(&.{
        @intFromEnum(component.kind),
        component.n_rows,
        component.log_size,
        component.preprocessed_columns,
        component.main_columns,
        component.interaction_columns,
        component.direct_constraints,
        component.batch_count,
        component.maximum_constraint_degree,
        component.composition_log_split,
    });
}

/// Mix aggregate and detailed claims before Tree 2. Every base batch remains
/// in statement order; the fixed caller nine and word four batches follow.
pub fn mixInteractionClaim(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    profile: *const profile_mod.Profile,
    base_claim: *const base_statement.RiscVInteractionClaim,
    caller_claim: contract.CallerClaim,
    word_claim: contract.WordClaim,
) !void {
    try validateClaims(core, profile, caller_claim, word_claim);
    const canonical = try allocator.create(base_statement.CanonicalInteractionClaim);
    defer allocator.destroy(canonical);
    canonical.* = try base_claim.canonical(core);
    const base_view = canonical.view();
    base_view.mixInto(channel);
    channel.mixFelts(&.{ caller_claim.component_sum, word_claim.component_sum });
    channel.mixU32s(&.{
        0x4757_5453, // STWG
        0x3143_5353, // SSC1
        baseDetailedClaimCount(core) catch
            return error.StackSwapVmDetailedClaimGeometryMismatch,
        contract.Caller.batch_count,
        contract.Word.batch_count,
        profile.components[0].log_size,
        profile.components[1].log_size,
    });
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index|
        channel.mixFelts(try base_claim.opcodeClaims(descriptor.family, index));
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index|
        channel.mixFelts(try base_claim.infraClaims(descriptor.kind, index));
    channel.mixFelts(&caller_claim.batch_sums);
    channel.mixFelts(&word_claim.batch_sums);
}

pub fn callRelationSum(
    caller_claim: contract.CallerClaim,
    word_claim: contract.WordClaim,
) QM31 {
    return caller_claim.batch_sums[contract.Caller.batch_count - 1].add(
        word_claim.batch_sums[contract.Word.batch_count - 1],
    );
}

fn validateClaims(
    core: *const base_statement.RiscVStatement,
    profile: *const profile_mod.Profile,
    caller_claim: contract.CallerClaim,
    word_claim: contract.WordClaim,
) !void {
    try profile.validateAgainst(core);
    try caller_claim.validate();
    try word_claim.validate();
    if (caller_claim.n_rows != profile.components[0].n_rows or
        caller_claim.log_size != profile.components[0].log_size or
        word_claim.n_rows != profile.components[1].n_rows or
        word_claim.log_size != profile.components[1].log_size)
    {
        return error.StackSwapVmClaimGeometryMismatch;
    }
}

fn baseDetailedClaimCount(core: *const base_statement.RiscVStatement) !u32 {
    var count: u32 = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        count = std.math.add(
            u32,
            count,
            @intCast(@import("../../air/lookups/opcode_entries.zig").batchCount(
                descriptor.family,
            )),
        ) catch return error.StackSwapVmDetailedClaimGeometryMismatch;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        count = std.math.add(
            u32,
            count,
            base_statement.nClaimedSumsForInfra(descriptor.kind),
        ) catch return error.StackSwapVmDetailedClaimGeometryMismatch;
    }
    return count;
}

fn starkPlacement(value: profile_mod.Placement) stark_component.Placement {
    return .{
        .preprocessed_offset = value.preprocessed_offset,
        .main_offset = value.main_offset,
        .interaction_offset = value.interaction_offset,
    };
}

fn validateColumnLengths(columns: anytype, log_size: u32) !void {
    if (log_size >= @bitSizeOf(usize))
        return error.StackSwapVmTraceGeometryMismatch;
    const expected = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != expected)
        return error.StackSwapVmTraceGeometryMismatch;
}

test "stack-swap private decoder binds the exact declared program tuple" {
    const ExecutionRow = struct { pc: u32, inst_word: u32 };
    const authority = try private_registry.authority();
    const decoder = try DeclaredDecodeAuthority.init(authority);
    const ordinary_word: u32 = 0x0010_0093; // addi x1, x0, 1
    const program_words = [_]memory_state.WordState{
        .{
            .addr = 0x1000,
            .initial_word = ordinary_word,
            .final_word = ordinary_word,
            .final_clock = 0,
        },
        .{
            .addr = 0x1004,
            .initial_word = authority.fixed_word,
            .final_word = authority.fixed_word,
            .final_clock = 0,
        },
    };
    const base_rows = [_]ExecutionRow{.{
        .pc = 0x1000,
        .inst_word = ordinary_word,
    }};
    const swap_rows = [_]ExecutionRow{.{
        .pc = 0x1004,
        .inst_word = authority.fixed_word,
    }};

    var committed = try program_commitment.buildDeclaredWithDecodeAuthoritySources(
        std.testing.allocator,
        decoder,
        .{ &base_rows, &swap_rows },
        &program_words,
        null,
    );
    defer committed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), committed.rows.len);
    try std.testing.expectEqual(
        try program_decode.decodeProgramWord(ordinary_word),
        committed.rows[0].values,
    );
    const tuple = try authority.programTuple(0x1004);
    try std.testing.expectEqual(
        program_decode.ProgramValues{ tuple[1], tuple[2], tuple[3], tuple[4] },
        committed.rows[1].values,
    );
    try std.testing.expectEqual(@as(u32, 1), committed.rows[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 1), committed.rows[1].multiplicity);

    var base_only = try program_commitment.buildDeclaredWithDecodeAuthoritySources(
        std.testing.allocator,
        decoder,
        .{&base_rows},
        program_words[0..1],
        null,
    );
    defer base_only.deinit(std.testing.allocator);
    try std.testing.expect(committed.tree.root != base_only.tree.root);

    var changed_authority = authority;
    changed_authority.allocation.registry_identity[0] ^= 1;
    try std.testing.expectError(
        error.StackSwapPrivateRegistryAuthorityMismatch,
        DeclaredDecodeAuthority.init(changed_authority),
    );

    var malformed_words = program_words;
    malformed_words[1].initial_word ^= @as(u32, 1) << 12;
    malformed_words[1].final_word = malformed_words[1].initial_word;
    const no_swap_rows = [_]ExecutionRow{};
    try std.testing.expectError(
        error.InvalidStackSwapEncoding,
        program_commitment.buildDeclaredWithDecodeAuthoritySources(
            std.testing.allocator,
            decoder,
            .{ &base_rows, &no_swap_rows },
            &malformed_words,
            null,
        ),
    );
}

comptime {
    if (production_active or profile_mod.production_active or
        private_registry.production_active or appended_component_count != 2 or
        contract.Caller.batch_count != 9 or contract.Word.batch_count != 4)
    {
        @compileError("stack-swap VM integration geometry drifted");
    }
}
