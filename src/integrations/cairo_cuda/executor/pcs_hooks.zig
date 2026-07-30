//! Allocation-free Cairo bindings for the AIR-neutral resident CUDA PCS.
//!
//! This facade binds every post-trace slot without allocation, transfer,
//! dispatch, host read, fallback, or synchronization. Stage semantics which
//! are not yet authenticated remain explicit fail-closed gaps.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const cairo_identity = @import("../identity.zig");
const resident_plan = @import("resident_plan.zig");
const quotient_fri = @import("pcs_quotient_fri.zig");
const slot_binding = @import("pcs_slot_binding.zig");
const terminal = @import("pcs_terminal.zig");
const trace_oods = @import("pcs_trace_oods.zig");
const types = @import("pcs_hooks_types.zig");

pub const production_ready = types.production_ready;
pub const blockers = types.blockers;
pub const Stage = types.Stage;
pub const Readiness = types.Readiness;
pub const Gap = types.Gap;
pub const CompactTree = types.CompactTree;
pub const TraceTrees = types.TraceTrees;
pub const Quotient = types.Quotient;
pub const Composition = types.Composition;
pub const Bindings = types.Bindings;
pub const readiness = types.readiness;
pub const requireExecutable = types.requireExecutable;
pub const bindOods = trace_oods.bindOods;

pub fn bind(
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !Bindings {
    try validateInputs(plan, program, protocol);
    const trees = try trace_oods.bindTrees(
        provider,
        plan,
        program,
        protocol,
    );
    const composition_tree = try trees.require(.composition);
    const composition_view = try trace_oods.uniformCompositionView(
        composition_tree,
        program,
    );
    const oods = try bindOods(
        provider,
        plan,
        protocol.sampled_value_words / 4,
        program.quotient.evaluation_log_rows,
    );
    const fri = try quotient_fri.bindFri(
        provider,
        plan,
        program,
        protocol,
    );
    const quotient = try quotient_fri.bindQuotient(
        provider,
        plan,
    );
    const result_words = try slot_binding.coordinateStorage(
        quotient.result_coordinates,
    );
    const proof = try terminal.bindProof(provider, plan);
    const decommit_assembly = try slot_binding.exact(
        provider,
        plan,
        .decommit_assembly,
        0,
    );
    return .{
        .identity = plan.identity,
        .trees = trees,
        .composition = .{
            .tree = composition_view,
            .interaction_claims = try (try slot_binding.exact(
                provider,
                plan,
                .interaction_claims,
                0,
            )).cast(field.SecureField),
            .alpha = try (try slot_binding.exactWords(
                provider,
                plan,
                .composition_alpha,
                0,
                4,
            )).cast(field.SecureField),
            .random_powers = try (try slot_binding.exact(
                provider,
                plan,
                .constraint_random_powers,
                0,
            )).cast(field.SecureField),
            .denominator_inverses = try slot_binding.exact(
                provider,
                plan,
                .constraint_denominators,
                0,
            ),
        },
        .transcript_storage = try slot_binding.exact(
            provider,
            plan,
            .transcript,
            0,
        ),
        .twiddles_forward = try slot_binding.exact(
            provider,
            plan,
            .twiddles_forward,
            0,
        ),
        .twiddles_inverse = try slot_binding.exact(
            provider,
            plan,
            .twiddles_inverse,
            0,
        ),
        .oods = oods,
        .quotient = quotient,
        .fri = fri,
        .pow = try terminal.bindPow(provider, plan, 0),
        .query_pow = try terminal.bindPow(provider, plan, 1),
        .decommit = try terminal.bindDecommit(
            provider,
            plan,
            program,
            protocol,
        ),
        .decommit_assembly = decommit_assembly,
        .proof = proof,
        .fri_terminal_extent_matches = try quotient_fri.terminalFriMatches(fri, program),
        .quotient_result_aliases_fri_zero = slot_binding.sameWords(
            result_words,
            fri.layers[0].coordinates.storage,
        ),
        .terminal_decommitment_fits = decommit_assembly.len <= proof.decommitment.len,
    };
}

fn validateInputs(
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !void {
    try program.validate();
    try protocol.validate();
    if (program.identity.frontend != .cairo or
        program.commitments.len != types.max_trace_trees or
        program.fri_layers.len != protocol.fri_tree_count or
        !std.mem.eql(
            u8,
            &plan.program_identity,
            &program.program_digest,
        ) or
        !std.mem.eql(
            u8,
            &plan.protocol_identity,
            &(try cairo_identity.protocolDigest(protocol)),
        ) or
        std.mem.allEqual(u8, &plan.identity, 0) or
        plan.terminal_bundle.total_words != plan.summary.terminal_words)
    {
        return error.InvalidKernelDescriptor;
    }
}
