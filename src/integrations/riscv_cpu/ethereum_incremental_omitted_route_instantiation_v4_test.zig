//! Analysis-only instantiation gate for the omitted-provider V4 route.
//!
//! `provePreparedOmittedProviderWithEngineUsingChannel` and
//! `verifyOmittedProviderWithEngineUsingChannel` are generic over the engine,
//! so Zig analyses neither of them until something instantiates them with a
//! concrete engine. The frontend package owns no backend and therefore cannot;
//! without this file the first thing to type-check the two bodies would be a
//! ten-minute product build.
//!
//! The two wrappers below bind them to the q193 Poseidon2 CPU engine and the
//! real `AuthorityV4` profile and are referenced at comptime, which forces full
//! semantic analysis of both transactions -- every generator, assembly and
//! authority call they make -- in the time one focused test root costs.
//! Nothing here proves or verifies: the end-to-end arm is
//! `test-riscv-ethereum-incremental-omitted-leaf-proof-v1`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const prepared_transaction =
    @import("ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig");

const prover = frontend.prover_mod;
const runner = frontend.runner;
const public_data = frontend.air.public_data;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const ethereum_types = prover.guest_precompile.ethereum_types;
const witness_v3 = prover.incremental_commitment_witness_v3;
const provider_protocol = prover.ethereum_native_provider_omit_protocol_v1;
const route =
    frontend.testing.incremental_ethereum_omit_orchestration_v4_internal;

const QM31 = stwo_core.fields.qm31.QM31;
const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Profile = profile_mod.AuthorityV4;
const Proof = stwo_core.proof.StarkProof(Engine.Hasher);

/// Concrete binding of the omitted-provider prover. The argument list is the
/// plan's, verbatim, so a drift in either side is a compile error here.
fn proveOmittedRoute(
    allocator: std.mem.Allocator,
    pcs_config: stwo_core.pcs.PcsConfig,
    exec_trace: *const runner.trace.Trace,
    opt_chain: ?*const runner.state_chain.StateChainTracker,
    full_witness: *const witness_v3.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data.PublicData,
    keccak_calls: *const runner.guest_precompile.keccakf_call_buffer.Frozen,
    keccak_rows: *const runner.guest_precompile.keccakf_v1.FrozenExecutionRows,
    recovery_calls: *const runner.guest_precompile
        .secp256k1_recover_call_buffer.Frozen,
    recovery_rows: *const runner.guest_precompile.secp256k1_recover_v1
        .FrozenExecutionRows,
    prepared: route.PreparedProofInputsV4,
    profile: *const Profile,
    recorder: ?*prover_api.stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: route.ExecutionOptions,
    extension: *provider_protocol.Extension(Engine),
    options: route.OmittedRouteOptionsV1,
) !route.ProveOutputV4Omitted(Engine) {
    return route.provePreparedOmittedProviderWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        full_witness,
        expected_statement,
        role_aware_public,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        prepared,
        profile,
        recorder,
        channel,
        execution,
        extension,
        options,
    );
}

/// Concrete binding of the omitted-provider cold verifier.
fn verifyOmittedRoute(
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    role_aware_public: *const public_data.PublicData,
    profile: *const Profile,
    proof_in: Proof,
    base_claim: *const statement_mod.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    decoded_omission: route.DecodedOmissionV1,
    channel: *Engine.Channel,
    extension: *provider_protocol.Extension(Engine),
) !route.FreshOmittedCoreV4(Engine) {
    return route.verifyOmittedProviderWithEngineUsingChannel(
        Engine,
        Profile,
        allocator,
        statement_value,
        extension_statement,
        role_aware_public,
        profile,
        proof_in,
        base_claim,
        extension_claim,
        bridge_claim,
        decoded_omission,
        channel,
        extension,
    );
}

/// Concrete binding of the prepared transaction's omitted prove entry (Step 7).
/// It is generic over the engine like the two route entries above, so without
/// this reference nothing would analyse its body short of a product build.
fn proveOmittedRouteFromPreparedTransaction(
    transaction: *const prepared_transaction
        .PreparedProofTransactionV4,
    allocator: std.mem.Allocator,
    recorder: ?*prover_api.stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: route.ExecutionOptions,
    extension: *provider_protocol.Extension(Engine),
    options: route.OmittedRouteOptionsV1,
) !route.ProveOutputV4Omitted(Engine) {
    return transaction.proveOmittedProviderWithEngineUsingChannel(
        Engine,
        allocator,
        recorder,
        channel,
        execution,
        extension,
        options,
    );
}

comptime {
    _ = &proveOmittedRoute;
    _ = &verifyOmittedRoute;
    _ = &proveOmittedRouteFromPreparedTransaction;
}

test "Ethereum omitted-provider V4 route instantiates against the q193 CPU engine" {
    // The comptime block above is the gate; these assertions keep the test
    // body honest about what it proved (nothing) and what it pinned.
    try std.testing.expect(!route.PRODUCTION_ACTIVE);
    try std.testing.expect(!route.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expectEqual(@as(u16, 4), route.FORMAT_VERSION);
    try std.testing.expectEqual(@as(usize, 4), route.COMMITMENT_TREE_COUNT);

    // The route's default is the fail-closed one: the serial cancellation
    // diagnostic stays off unless a caller asks for it (G7).
    const options = route.OmittedRouteOptionsV1{};
    try std.testing.expect(!options.diagnostic_cancellation);

    // Both entry points are real functions on this engine, not comptime stubs.
    try std.testing.expect(@TypeOf(proveOmittedRoute) != void);
    try std.testing.expect(@TypeOf(verifyOmittedRoute) != void);
}
