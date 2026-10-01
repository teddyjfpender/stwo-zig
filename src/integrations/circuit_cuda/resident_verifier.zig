//! Independent host verification of the one-read resident circuit proof.
//! This runs only after GPU publication; it never supplies proving work.
const std = @import("std");
const core = @import("stwo_core");
const cairo = @import("stwo_cairo_frontend");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const proof_module = @import("resident_prover.zig");
const prefix_module = @import("transcript_prefix.zig");
const geometry_module = @import("geometry.zig");

const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const QM31 = core.fields.qm31.QM31;
const components = circuit.common.component_list;
const Captured = cairo.proving.air.component.Component;
const Merkle = core.vcs_lifted.verifier.MerkleVerifierLifted(H);

pub const Verified = struct {
    allocator: std.mem.Allocator,
    capture: core.verifier.ProofCapture(H),

    pub fn deinit(self: *Verified) void {
        self.capture.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn verify(allocator: std.mem.Allocator, input: proof_module.Input, result: *const proof_module.Result) !Verified {
    return switch (input.profile) {
        .internal => verifyWith(cpu.prove.profiles.Blake2sM31MerkleChannel, allocator, input, result),
        .root => verifyWith(cpu.prove.profiles.Blake2sMerkleChannel, allocator, input, result),
    };
}

fn verifyWith(
    comptime MC: type,
    allocator: std.mem.Allocator,
    input: proof_module.Input,
    result: *const proof_module.Result,
) !Verified {
    comptime std.debug.assert(MC.MerkleHasher == H);
    if (!result.verdict.isResident() or
        result.stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidCircuitResidentProof;
    const layout = input.preprocessed.layout();
    var geometry = try geometry_module.Geometry.init(allocator, &layout, input.air, input.catalog, input.config);
    defer geometry.deinit();
    if (!std.mem.eql(u8, &geometry.identity, &result.geometry_identity))
        return error.CircuitResidentGeometryMismatch;
    // The production recursion lane binds this root to the registry or the
    // independently built canonical circuit. Standalone R7 fixtures without
    // such a binding still recompute it from the preprocessed columns.
    const pp_root = if (input.expected_preprocessed_root) |words|
        core.vcs.blake2_hash.digestFromU32s(words)
    else
        try input.preprocessed.preprocessedRoot(allocator, input.config.fri_config.log_blowup_factor);
    const roots = result.stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &pp_root, &roots[0])) return error.CircuitPreprocessedRootMismatch;
    const sizes = try components.circuitComponentLogSizes(&layout);
    const circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(sizes, input.config.fri_config.log_blowup_factor, pp_root);
    const output_start = circuit.witness.trace.U_VAR_IDX + 1;
    if (output_start + input.preprocessed.n_outputs > input.values.len) return error.InvalidCircuitResidentClaim;
    const outputs = input.values[output_start..][0..input.preprocessed.n_outputs];
    const claim_words = result.terminal_proof.decoded.words[result.terminal_proof.decoded.layout.interaction_claim.start..result.terminal_proof.decoded.layout.interaction_claim.end];
    if (claim_words.len != components.N_COMPONENTS * 4) return error.InvalidCircuitResidentClaim;
    var claimed: [components.N_COMPONENTS]QM31 = undefined;
    for (&claimed, 0..) |*out, index| {
        const words = claim_words[index * 4 ..][0..4];
        out.* = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
    }

    const Sink = prefix_module.HostSink(MC);
    var sink = Sink{};
    var replay = prefix_module.Prefix(Sink){ .sink = &sink };
    try replay.mixSalt(0);
    try replay.mixFriConfig(input.config);
    try replay.commitPreprocessed(roots[0]);
    try replay.mixCircuitHash(circuit_hash);
    try replay.mixClaim(outputs);
    try replay.commitBase(roots[1]);
    try replay.absorbInteractionNonce(result.terminal_proof.decoded.interactionNonce());
    const lookup = try replay.drawLookupElements();
    try replay.mixInteractionClaim(&claimed);
    try replay.commitInteraction(roots[2]);
    try replay.admitComposition();

    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, input.config);
    defer verifier.deinit(allocator);
    verifier.trees.deinit(allocator);
    const trees = try allocator.alloc(Merkle, 3);
    var initialized: usize = 0;
    var moved = false;
    errdefer if (!moved) {
        for (trees[0..initialized]) |*tree| tree.deinit(allocator);
        allocator.free(trees);
    };
    for (trees, geometry.trees[0..3], roots[0..3]) |*tree, shape, root| {
        const extended = try allocator.alloc(u32, shape.column_logs.len);
        defer allocator.free(extended);
        for (shape.column_logs, extended) |log, *item| item.* = log + input.config.fri_config.log_blowup_factor;
        tree.* = try Merkle.initWithHeight(allocator, root, extended, shape.lifted_log);
        initialized += 1;
    }
    verifier.trees = core.pcs.TreeVec(Merkle).initOwned(trees);
    moved = true;
    var pp_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    const lifting_bound = input.config.trace_lifting_log_size - input.config.fri_config.log_blowup_factor + 1;
    var captured: [components.N_COMPONENTS]Captured = undefined;
    var handles: [components.N_COMPONENTS]core.air.components.Component = undefined;
    for (input.air.components, &captured, &handles, claimed) |*source, *runtime, *handle, sum| {
        runtime.* = Captured.init(allocator, source, &pp_logs, lifting_bound, lookup.z, lookup.alpha, sum);
        handle.* = runtime.asVerifierComponent();
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        &handles,
        &sink.channel,
        &verifier,
        &result.stark,
        true,
        &capture,
    );
    return .{ .allocator = allocator, .capture = capture };
}

test "resident circuit verifier typechecks both channel profiles" {
    const entry: *const fn (std.mem.Allocator, proof_module.Input, *const proof_module.Result) anyerror!Verified = &verify;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
