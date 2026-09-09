//! Tree-1 composition for the base trace plus combined Ethereum components.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const stage_profile = @import("stwo_prover_api").stage_profile;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const secp_trace = @import("../../air/guest_precompile/secp256k1_component_trace.zig");
const lookup_registration = @import("../../air/guest_precompile/ethereum_lookup_registration.zig");
const base_statement = @import("../../air/statement.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const commitment_witness = @import("../commitment_witness.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const external_tree = @import("external_profile_tree.zig");
const ethereum_witness = @import("ethereum_witness.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;

pub fn commit(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record,
    recovery_calls: []const @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record,
) !external_tree.MainRetained {
    return commitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        geometry,
        opt_chain,
        extension,
        keccak_calls,
        recovery_calls,
        null,
        &.{},
        null,
    );
}

pub fn commitWithoutNativePoseidon(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const CommitmentWitness,
    full_geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record,
    recovery_calls: []const @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record,
    projection: *const native_provider_omit.ProjectionV1,
) !external_tree.MainRetained {
    return commitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        full_geometry,
        opt_chain,
        extension,
        keccak_calls,
        recovery_calls,
        projection,
        &.{},
        null,
    );
}

/// Ordinary authenticated-core Tree-1 sibling with append-only external
/// blocks. Ethereum keeps sole fixed-table registration ownership; components
/// such as the incremental bridge that issue no fixed-table lookups require
/// no synthetic registration context.
pub fn commitWithExternalBlocks(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record,
    recovery_calls: []const @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record,
    additional_blocks: []const external_tree.BorrowedBlock,
) !external_tree.MainRetained {
    return commitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        geometry,
        opt_chain,
        extension,
        keccak_calls,
        recovery_calls,
        null,
        additional_blocks,
        null,
    );
}

/// Candidate-only Tree-1 sibling. The canonical projected core and fourteen
/// Ethereum blocks retain their exact order; typed caller-owned blocks follow
/// them, and their fixed-table requests join the same multiplicity columns.
/// `additional_registration` may be `null` when the caller-owned blocks issue no
/// fixed-table lookups; the canonical Ethereum registration is then used alone,
/// exactly as in the no-extra-blocks case.
pub fn commitWithoutNativePoseidonWithExternalBlocks(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const CommitmentWitness,
    full_geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record,
    recovery_calls: []const @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record,
    projection: *const native_provider_omit.ProjectionV1,
    additional_blocks: []const external_tree.BorrowedBlock,
    additional_registration: ?external_tree.LookupRegistration,
) !external_tree.MainRetained {
    return commitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        full_geometry,
        opt_chain,
        extension,
        keccak_calls,
        recovery_calls,
        projection,
        additional_blocks,
        additional_registration,
    );
}

fn commitInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record,
    recovery_calls: []const @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig").Record,
    projection: ?*const native_provider_omit.ProjectionV1,
    additional_blocks: []const external_tree.BorrowedBlock,
    additional_registration: ?external_tree.LookupRegistration,
) !external_tree.MainRetained {
    const shard = keccakMainColumns(&extension.keccak_shard);
    const chi_values = try extension.keccak_counters.committedColumn(allocator, .chi);
    defer allocator.free(chi_values);
    const xor_values = try extension.keccak_counters.committedColumn(allocator, .xor5);
    defer allocator.free(xor_values);
    const chi = [1][]const M31{chi_values};
    const xor5 = [1][]const M31{xor_values};
    const product_base = secpMainColumns(secp_bundle.ProductBase, &extension.secp.product_base);
    const product_scalar = secpMainColumns(secp_bundle.ProductScalar, &extension.secp.product_scalar);
    const linear_base = secpMainColumns(secp_bundle.LinearBase, &extension.secp.linear_base);
    const linear_scalar = secpMainColumns(secp_bundle.LinearScalar, &extension.secp.linear_scalar);
    const point = secpMainColumns(secp_config.Point, &extension.secp.point);
    const split = secpMainColumns(secp_config.Split, &extension.secp.split);
    const scalar = secpMainColumns(secp_config.ScalarProgram, &extension.secp.scalar);
    const table = secpMainColumns(secp_config.Table, &extension.secp.table);
    const recovery = secpMainColumns(secp_config.Recovery, &extension.secp.recovery);
    const byte = secpMainColumns(secp_config.ByteTable, &extension.secp.byte);
    const caller = secpMainColumns(secp_config.RecoveryCaller, &extension.recovery_caller);
    const ethereum_blocks = [_]external_tree.BorrowedBlock{
        block(extension.keccak_shard.log_size, &shard),
        block(@import("../../air/guest_precompile/keccakf_tables.zig").logSize(.chi), &chi),
        block(@import("../../air/guest_precompile/keccakf_tables.zig").logSize(.xor5), &xor5),
        block(extension.secp.product_base.log_size, &product_base),
        block(extension.secp.product_scalar.log_size, &product_scalar),
        block(extension.secp.linear_base.log_size, &linear_base),
        block(extension.secp.linear_scalar.log_size, &linear_scalar),
        block(extension.secp.point.log_size, &point),
        block(extension.secp.split.log_size, &split),
        block(extension.secp.scalar.log_size, &scalar),
        block(extension.secp.table.log_size, &table),
        block(extension.secp.recovery.log_size, &recovery),
        block(extension.secp.byte.log_size, &byte),
        block(extension.recovery_caller.log_size, &caller),
    };
    const lookup_context = lookup_registration.Context{
        .keccak = keccak_calls,
        .recovery = recovery_calls,
    };
    const registration = external_tree.LookupRegistration{
        .context = &lookup_context,
        .register_fn = lookup_registration.Context.erased,
    };
    if (additional_blocks.len == 0 and additional_registration == null) {
        if (projection) |omission| {
            return external_tree.commitMainWithoutNativePoseidon(
                Engine,
                allocator,
                workspace,
                scheme,
                channel,
                recorder,
                exec_trace,
                base_witness,
                omission.projected_geometry,
                opt_chain,
                &ethereum_blocks,
                registration,
            );
        }
        return external_tree.commitMain(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            exec_trace,
            base_witness,
            geometry,
            opt_chain,
            &ethereum_blocks,
            registration,
        );
    }

    const blocks = try allocator.alloc(
        external_tree.BorrowedBlock,
        ethereum_blocks.len + additional_blocks.len,
    );
    defer allocator.free(blocks);
    @memcpy(blocks[0..ethereum_blocks.len], &ethereum_blocks);
    @memcpy(blocks[ethereum_blocks.len..], additional_blocks);
    if (additional_registration == null) {
        if (projection) |omission| {
            return external_tree.commitMainWithoutNativePoseidon(
                Engine,
                allocator,
                workspace,
                scheme,
                channel,
                recorder,
                exec_trace,
                base_witness,
                omission.projected_geometry,
                opt_chain,
                blocks,
                registration,
            );
        }
        return external_tree.commitMain(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            exec_trace,
            base_witness,
            geometry,
            opt_chain,
            blocks,
            registration,
        );
    }
    const combined_context = CombinedLookupRegistration{
        .ethereum = registration,
        .additional = additional_registration.?,
    };
    const combined_registration = external_tree.LookupRegistration{
        .context = &combined_context,
        .register_fn = CombinedLookupRegistration.erased,
    };
    if (projection) |omission| {
        return external_tree.commitMainWithoutNativePoseidon(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            exec_trace,
            base_witness,
            omission.projected_geometry,
            opt_chain,
            blocks,
            combined_registration,
        );
    }
    return external_tree.commitMain(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        geometry,
        opt_chain,
        blocks,
        combined_registration,
    );
}

pub fn logSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const @import("../../air/guest_precompile/ethereum_statement.zig").Statement,
) ![]u32 {
    var total: usize = @intCast(core.nMainColumns());
    for (extension.components) |descriptor| total = std.math.add(
        usize,
        total,
        @as(usize, @intCast(descriptor.main_columns)),
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(u32, total);
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        @memset(result[cursor..][0..descriptor.n_columns], descriptor.log_size);
        cursor += descriptor.n_columns;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        @memset(result[cursor..][0..descriptor.n_columns], descriptor.log_size);
        cursor += descriptor.n_columns;
    }
    for (extension.components) |descriptor| {
        @memset(result[cursor..][0..descriptor.main_columns], descriptor.log_size);
        cursor += descriptor.main_columns;
    }
    if (cursor != result.len) return error.InvalidTraceShape;
    return result;
}

pub fn logSizesWithExternalBlocks(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const @import("../../air/guest_precompile/ethereum_statement.zig").Statement,
    blocks: []const external_tree.BorrowedBlock,
) ![]u32 {
    const ordinary = try logSizes(allocator, core, extension);
    defer allocator.free(ordinary);
    return external_tree.appendLogSizes(allocator, ordinary, blocks);
}

const CombinedLookupRegistration = struct {
    ethereum: external_tree.LookupRegistration,
    additional: external_tree.LookupRegistration,

    fn erased(
        context: *const anyopaque,
        counters: *@import("../../air/lookups/tables/counter.zig").Set,
    ) anyerror!void {
        const self: *const CombinedLookupRegistration = @ptrCast(@alignCast(context));
        try self.ethereum.register(counters);
        try self.additional.register(counters);
    }
};

fn block(log_size: u32, columns: []const []const M31) external_tree.BorrowedBlock {
    return .{ .log_size = log_size, .columns = columns };
}

fn keccakMainColumns(
    trace: *const @import("../../air/guest_precompile/keccakf_trace.zig").Shard,
) [keccak_component.main_column_count][]const M31 {
    var result: [keccak_component.main_column_count][]const M31 = undefined;
    for (&result, 0..) |*column, index| column.* = trace.mainColumn(index);
    return result;
}

fn secpMainColumns(
    comptime Config: type,
    trace: *const secp_trace.Trace(Config),
) [Config.main_column_count][]const M31 {
    var result: [Config.main_column_count][]const M31 = undefined;
    for (&result, 0..) |*column, index| column.* = trace.mainColumn(index);
    return result;
}
