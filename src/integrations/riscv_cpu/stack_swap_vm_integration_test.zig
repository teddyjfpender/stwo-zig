//! Candidate-only full-VM boundary tests for the private U256 SWAP profile.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const stwo_core = @import("stwo_core");

const commitment = frontend.air.program.commitment;
const program_decode = frontend.air.program.decode;
const memory_state = frontend.runner.memory_state;
const public_data = frontend.air.public_data;
const statement_mod = frontend.air.statement;
const merkle_node = frontend.air.memory_commitment.merkle_node;
const abi = frontend.testing.stack_swap_candidate_abi_v1;
const contract = frontend.testing.stack_swap_proof_component_v1;
const integration = frontend.testing.stack_swap_vm_integration_v1;
const profile_mod = frontend.testing.stack_swap_vm_profile_v1;
const registry = frontend.testing.stack_swap_private_registry_v1;
const relations_mod = frontend.testing.stack_swap_relations_v1;
const QM31 = stwo_core.fields.qm31.QM31;

test "stack swap VM private authority mints one exact declared program root" {
    const ExecutionRow = struct { pc: u32, inst_word: u32 };
    const authority = try registry.authority();
    const decoder = try integration.DeclaredDecodeAuthority.init(authority);
    const ordinary_word: u32 = 0x0010_0093;
    const words = [_]memory_state.WordState{
        wordState(0x1000, ordinary_word),
        wordState(0x1004, authority.fixed_word),
    };
    const base_rows = [_]ExecutionRow{.{
        .pc = 0x1000,
        .inst_word = ordinary_word,
    }};
    const swap_rows = [_]ExecutionRow{.{
        .pc = 0x1004,
        .inst_word = authority.fixed_word,
    }};

    var full = try commitment.buildDeclaredWithDecodeAuthoritySources(
        std.testing.allocator,
        decoder,
        .{ &base_rows, &swap_rows },
        &words,
        null,
    );
    defer full.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), full.rows.len);
    const tuple = try authority.programTuple(0x1004);
    try std.testing.expectEqual(
        program_decode.ProgramValues{ tuple[1], tuple[2], tuple[3], tuple[4] },
        full.rows[1].values,
    );
    try std.testing.expectEqual(@as(u32, 1), full.rows[1].multiplicity);

    var ordinary_only = try commitment.buildDeclaredWithDecodeAuthoritySources(
        std.testing.allocator,
        decoder,
        .{&base_rows},
        words[0..1],
        null,
    );
    defer ordinary_only.deinit(std.testing.allocator);
    try std.testing.expect(full.tree.root != ordinary_only.tree.root);

    var changed_authority = authority;
    changed_authority.allocation.registry_identity[0] ^= 1;
    // The authority validates its program binding before the private registry
    // revalidates the allocation manifest.
    try std.testing.expectError(
        error.InvalidStackSwapProgramAuthority,
        integration.DeclaredDecodeAuthority.init(changed_authority),
    );

    var malformed = words;
    malformed[1] = wordState(0x1004, authority.fixed_word ^ (@as(u32, 1) << 12));
    const no_swap = [_]ExecutionRow{};
    try std.testing.expectError(
        error.InvalidStackSwapEncoding,
        commitment.buildDeclaredWithDecodeAuthoritySources(
            std.testing.allocator,
            decoder,
            .{ &base_rows, &no_swap },
            &malformed,
            null,
        ),
    );
}

test "stack swap VM component profile is appended and mutation closed" {
    var core = coreFixture(false);
    const authority = try registry.authority();
    const profile = try profile_mod.Profile.createInactive(
        &core,
        authority,
        1,
        null,
    );
    try profile.validateAgainst(&core);
    try std.testing.expect(!profile.activation_enabled);
    try std.testing.expect(!profile.production_eligible);
    try std.testing.expectEqual(
        core.nPreprocessedColumns(),
        profile.placements.caller.preprocessed_offset,
    );
    try std.testing.expectEqual(
        core.nMainColumns(),
        profile.placements.caller.main_offset,
    );
    try std.testing.expectEqual(
        core.nInteractionColumns(),
        profile.placements.caller.interaction_offset,
    );

    const caller_claim = try zeroCallerClaim(&profile);
    const word_claim = try zeroWordClaim(&profile);
    const relations = relations_mod.Relations.dummy();
    const no_base = [_]stwo_core.air.components.Component{};
    const assembly = try integration.VerifierAssembly.create(
        std.testing.allocator,
        &core,
        &profile,
        &relations,
        &no_base,
        caller_claim,
        word_claim,
    );
    defer assembly.destroy(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), assembly.active().len);

    var changed_component = profile;
    changed_component.components[0].main_columns += 1;
    try std.testing.expectError(
        error.StackSwapVmComponentDescriptorMismatch,
        changed_component.validateAgainst(&core),
    );
    var changed_placement = profile;
    changed_placement.placements.words.main_offset += 1;
    try std.testing.expectError(
        error.StackSwapVmProfileMismatch,
        changed_placement.validateAgainst(&core),
    );
}

test "stack swap VM cancellation requires the exact external base context" {
    var core = coreFixture(true);
    const authority = try registry.authority();
    const profile = try profile_mod.Profile.createInactive(
        &core,
        authority,
        1,
        null,
    );
    const relations = relations_mod.Relations.dummy();
    const interaction_pow: u64 = 17;
    const base_claim = try std.testing.allocator.create(
        statement_mod.RiscVInteractionClaim,
    );
    defer std.testing.allocator.destroy(base_claim);
    base_claim.initZeroInto();
    base_claim.n_components = core.n_components;
    base_claim.n_infra = core.n_infra;
    base_claim.interaction_pow = interaction_pow;
    const boundary = try frontend.air.public_logup.sum(
        &core.public_data,
        &relations.base,
    );
    try base_claim.setInfraClaim(.merkle, 0, 0, boundary.neg());

    const caller_claim = try zeroCallerClaim(&profile);
    const word_claim = try zeroWordClaim(&profile);
    const context = integration.ExternalBaseRelationContext{
        .core = &core,
        .base_claim = base_claim,
        .relations = &relations,
        .interaction_pow = interaction_pow,
    };
    try context.verify(
        std.testing.allocator,
        &profile,
        caller_claim,
        word_claim,
    );

    try base_claim.setInfraClaim(
        .merkle,
        0,
        0,
        boundary.neg().add(QM31.one()),
    );
    try std.testing.expectError(
        error.LogupSumNonZero,
        context.verify(
            std.testing.allocator,
            &profile,
            caller_claim,
            word_claim,
        ),
    );
    try base_claim.setInfraClaim(.merkle, 0, 0, boundary.neg());

    var altered_base_batch = [_]QM31{QM31.zero()} ** contract.Caller.batch_count;
    altered_base_batch[0] = QM31.one();
    const altered_caller = try contract.CallerClaim.canonical(
        profile.components[0].log_size,
        profile.components[0].n_rows,
        altered_base_batch,
    );
    try std.testing.expectError(
        error.LogupSumNonZero,
        context.verify(
            std.testing.allocator,
            &profile,
            altered_caller,
            word_claim,
        ),
    );

    var altered_call_batch = [_]QM31{QM31.zero()} ** contract.Caller.batch_count;
    altered_call_batch[contract.Caller.batch_count - 1] = QM31.one();
    const unclosed_caller = try contract.CallerClaim.canonical(
        profile.components[0].log_size,
        profile.components[0].n_rows,
        altered_call_batch,
    );
    try std.testing.expectError(
        error.StackSwapVmCallRelationUnclosed,
        context.verify(
            std.testing.allocator,
            &profile,
            unclosed_caller,
            word_claim,
        ),
    );
}

fn coreFixture(with_merkle: bool) statement_mod.RiscVStatement {
    const pc: u32 = 0x1000;
    var result: statement_mod.RiscVStatement = undefined;
    result.n_components = 0;
    result.component_descs = undefined;
    result.initial_pc = pc;
    result.final_pc = pc;
    result.total_steps = 0;
    result.public_data = .{
        .initial_pc = pc,
        .final_pc = pc,
        .clock = 0,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = 1,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = public_data.Completion.canonicalSelfLoop(pc),
        .io_entries = .{
            .input_start = 0x4000,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0x5000,
            .output_data_addr = 0x5004,
            .output_words = &.{},
        },
    };
    result.n_infra = @intFromBool(with_merkle);
    result.infra_descs = undefined;
    if (with_merkle) result.infra_descs[0] = .{
        .kind = .merkle,
        .log_size = 1,
        .n_rows = 0,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    return result;
}

fn zeroCallerClaim(profile: *const profile_mod.Profile) !contract.CallerClaim {
    return contract.CallerClaim.canonical(
        profile.components[0].log_size,
        profile.components[0].n_rows,
        .{QM31.zero()} ** contract.Caller.batch_count,
    );
}

fn zeroWordClaim(profile: *const profile_mod.Profile) !contract.WordClaim {
    return contract.WordClaim.canonical(
        profile.components[1].log_size,
        profile.components[1].n_rows,
        .{QM31.zero()} ** contract.Word.batch_count,
    );
}

fn wordState(address: u32, word: u32) memory_state.WordState {
    return .{
        .addr = address,
        .initial_word = word,
        .final_word = word,
        .final_clock = 0,
    };
}

comptime {
    if (abi.production_active or registry.production_active or
        profile_mod.production_active or integration.production_active)
    {
        @compileError("stack-swap VM integration test reached production");
    }
}
