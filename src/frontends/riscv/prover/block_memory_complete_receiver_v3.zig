//! Canonical complete-block receiver. Public policy supplies every recursive
//! key and tree edge independently of proof bytes. This function retains the
//! freshly verified execution receipts until the exact forest has been linked.
const std = @import("std");
const core = @import("stwo_core");
const batch = @import("block_memory_batch_verify_v2.zig");
const recursive = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const span = @import("../recursion/span_statement_blake3.zig");

pub const ProofPin = struct {
    admission: parent.Admission,
    expected_key_id: [32]u8,
};

pub const DyadicPin = struct {
    /// Indices address leaves first, followed by earlier dyadic parents.
    left_index: u32,
    right_index: u32,
    proof: ProofPin,
};

pub const RecursionPins = struct {
    leaf: []const ProofPin,
    dyadic: []const DyadicPin,
    /// Ordered exact-forest roots. They must cover the job exactly once.
    root_indices: []const u32,
    outer: ProofPin,
};

pub const RecursionBytes = struct {
    leaf: []const []const u8,
    dyadic: []const []const u8,
    outer: []const u8,
};

/// A complete receipt is issued only after the same call fresh-verifies the
/// native execution/sidecar proofs, sorted memory and source closure, every
/// recursive forest proof, and the canonical exact-count outer proof.
pub fn verifyCanonicalEthereumSha(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pins: []const batch.EthereumShaExecutionPin(Backend),
    public_initial: batch.PublicInitialSource,
    recursion_pins: RecursionPins,
    recursion_bytes: RecursionBytes,
    config: core.pcs.PcsConfig,
) !batch.CompleteBlock {
    const complete = try preflight(statement, execution_pins.len, public_initial, recursion_pins, recursion_bytes, config);
    if (statement.seal.extension_rosters_bound)
        return error.ExtendedExecutionNeedsCombinedReceiver;
    var core_owned = try batch.verifyCoreOwned(
        Backend,
        a,
        statement,
        wire,
        execution_pins,
        public_initial,
        config,
    );
    defer core_owned.deinit(a);
    return verifyRecursiveForest(Backend, a, statement, execution_pins, recursion_pins, recursion_bytes, config, complete, &core_owned);
}

/// Canonical block receiver when native SHA/Keccak caller accesses are
/// committed in sparse extension sidecars. The v4 core fresh-verifies those
/// sidecars and their byte tables before the same v3 leaf/forest/root path.
pub fn verifyCanonicalEthereumShaWithExtension(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    execution_pins: []const batch.EthereumShaExecutionPin(Backend),
    public_initial: batch.PublicInitialSource,
    recursion_pins: RecursionPins,
    recursion_bytes: RecursionBytes,
    config: core.pcs.PcsConfig,
) !batch.CompleteBlock {
    const complete = try preflight(statement, execution_pins.len, public_initial, recursion_pins, recursion_bytes, config);
    if (!statement.seal.extension_rosters_bound)
        return error.MissingExecutionExtensionRoster;
    var core_owned = try batch.verifyCoreOwnedWithExtension(
        Backend,
        a,
        statement,
        wire,
        execution_pins,
        public_initial,
        config,
    );
    defer core_owned.deinit(a);
    return verifyRecursiveForest(Backend, a, statement, execution_pins, recursion_pins, recursion_bytes, config, complete, &core_owned);
}

fn preflight(
    statement: batch.PinnedStatement,
    execution_count: usize,
    public_initial: batch.PublicInitialSource,
    recursion_pins: RecursionPins,
    recursion_bytes: RecursionBytes,
    config: core.pcs.PcsConfig,
) !batch.CompletePins {
    if (recursion_pins.leaf.len != execution_count or
        recursion_bytes.leaf.len != execution_count or
        recursion_pins.dyadic.len != recursion_bytes.dyadic.len or
        recursion_pins.root_indices.len == 0 or
        recursion_pins.root_indices.len > span.MAX_SLOT_HEIGHT + 1)
        return error.InvalidBlockRecursiveProofCensus;
    if (!std.meta.eql(config, parent.CSP_CONFIG) or
        recursion_pins.outer.admission.key.profile != .csp_q70_pow26)
        return error.ExpectedCanonicalBlockSecurity;
    for (recursion_pins.leaf) |pin| {
        if (pin.admission.key.profile != .csp_q70_pow26)
            return error.ExpectedCanonicalBlockSecurity;
    }
    for (recursion_pins.dyadic) |pin| {
        if (pin.proof.admission.key.profile != .csp_q70_pow26)
            return error.ExpectedCanonicalBlockSecurity;
    }
    const complete = try statement.requireCompletePins(public_initial.pin.initial_rw_root.bytes);
    const forest_count: usize = @popCount(complete.expected_job.segment_count);
    if (recursion_pins.leaf.len != complete.expected_job.segment_count or
        recursion_pins.leaf.len < forest_count or
        recursion_pins.root_indices.len != forest_count or
        recursion_pins.dyadic.len != recursion_pins.leaf.len - forest_count)
        return error.InvalidBlockRecursiveProofCensus;
    for (recursion_pins.dyadic, 0..) |pin, i| {
        const current = recursion_pins.leaf.len + i;
        if (pin.left_index >= current or pin.right_index >= current or
            pin.left_index == pin.right_index)
            return error.InvalidBlockRecursiveTreeEdge;
    }
    const descriptor_count = recursion_pins.leaf.len + recursion_pins.dyadic.len;
    for (recursion_pins.root_indices) |index| {
        if (index >= descriptor_count) return error.InvalidBlockRecursiveRootIndex;
    }
    if (!std.mem.eql(u8, &recursion_pins.outer.expected_key_id, &complete.outer_recursive_key_id))
        return error.UntrustedBlockOuterKey;

    return complete;
}

fn verifyRecursiveForest(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    execution_pins: []const batch.EthereumShaExecutionPin(Backend),
    recursion_pins: RecursionPins,
    recursion_bytes: RecursionBytes,
    config: core.pcs.PcsConfig,
    complete: batch.CompletePins,
    core_owned: *const batch.VerifiedCoreOwned,
) !batch.CompleteBlock {
    const descriptor_count = recursion_pins.leaf.len + recursion_pins.dyadic.len;
    const descriptors = try a.alloc(recursive.Descriptor, descriptor_count);
    defer a.free(descriptors);
    for (execution_pins, recursion_pins.leaf, recursion_bytes.leaf, 0..) |execution, pin, bytes, i| {
        const receipt = &core_owned.executions[i];
        descriptors[i] = try recursive.verifyLeafBytes(
            a,
            bytes,
            pin.admission,
            pin.expected_key_id,
            execution.statement,
            &execution.prepared.native.public_data,
            config,
            statement.seal,
            execution.expected_key_id,
            receipt.native_roots,
            receipt.witness_root,
            receipt,
        );
    }
    for (recursion_pins.dyadic, recursion_bytes.dyadic, 0..) |pin, bytes, i| {
        const current = recursion_pins.leaf.len + i;
        descriptors[current] = try recursive.verifyDyadicBytes(
            a,
            bytes,
            pin.proof.admission,
            pin.proof.expected_key_id,
            descriptors[pin.left_index],
            descriptors[pin.right_index],
        );
    }

    const roots = try a.alloc(recursive.Descriptor, recursion_pins.root_indices.len);
    defer a.free(roots);
    for (recursion_pins.root_indices, roots) |index, *root| {
        root.* = descriptors[index];
    }
    const digest = try recursive.verifiedForestDigest(complete.expected_job, roots);
    if (!std.mem.eql(u8, &digest, &complete.forest_roster_digest))
        return error.UntrustedBlockForestRoster;
    var outer = try recursive.verifyExactBytes(
        a,
        recursion_bytes.outer,
        recursion_pins.outer.admission,
        recursion_pins.outer.expected_key_id,
        complete.expected_job,
        roots,
    );
    defer outer.deinit();
    _ = try outer.root();
    return .complete_block_verified;
}

test "complete block receiver rejects missing recursive keys before verifying proof bytes" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    try std.testing.expectError(error.InvalidBlockRecursiveProofCensus, verifyCanonicalEthereumSha(
        Cpu,
        std.testing.allocator,
        undefined,
        undefined,
        &.{},
        undefined,
        .{ .leaf = &.{}, .dyadic = &.{}, .root_indices = &.{}, .outer = undefined },
        .{ .leaf = &.{}, .dyadic = &.{}, .outer = &.{} },
        undefined,
    ));
}
