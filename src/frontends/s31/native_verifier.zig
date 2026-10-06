//! S31's native proof format and independent host STARK verifier.
//! The verifier checks the circuit AIR directly; it does not execute the
//! recursive verifier circuit on the host.
const std = @import("std");
const core = @import("stwo_core");
const cairo = @import("stwo_cairo_frontend");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");

const QM31 = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const PerComponent = circuit.common.component_list.PerComponent;
const N_COMPONENTS = circuit.common.component_list.N_COMPONENTS;
const MAGIC = "S31NAT1\x00";
const HEADER_LEN = MAGIC.len + 8 + N_COMPONENTS * 16;
const HYBRID_MAGIC = "S31NAT2\x00";
const HYBRID_HEADER_LEN = HYBRID_MAGIC.len + 8 + (N_COMPONENTS + 1) * 16;
const chip = cpu.repeated_step_chip;
const M31 = core.fields.m31.M31;

pub const HybridSpec = struct {
    source_digest: [32]u8,
    rounds: u32,
    constant: M31,
};

pub fn serialize(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof) ![]u8 {
    if (proof.chip_claimed_sum != null) return error.WrongProofProfile;
    return serializeProfile(allocator, proof, false);
}

pub fn serializeHybrid(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof) ![]u8 {
    if (proof.chip_claimed_sum == null) return error.WrongProofProfile;
    return serializeProfile(allocator, proof, true);
}

fn serializeProfile(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof, hybrid: bool) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, if (hybrid) HYBRID_MAGIC else MAGIC);
    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, proof.interaction_pow_nonce, .little);
    try bytes.appendSlice(allocator, &nonce);
    for (proof.claimed_sums.toArray()) |sum| {
        for (sum.toM31Array()) |limb| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, limb.v, .little);
            try bytes.appendSlice(allocator, &encoded);
        }
    }
    if (hybrid) {
        for (proof.chip_claimed_sum.?.toM31Array()) |limb| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, limb.v, .little);
            try bytes.appendSlice(allocator, &encoded);
        }
    }
    try postcard.serializeProof(H, bytes.writer(allocator), proof.stark_proof.proof);
    return bytes.toOwnedSlice(allocator);
}

pub fn verify(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.preprocessed.ColumnLayout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
) !void {
    return verifyProfile(allocator, layout, template, pcs, preprocessed_root, circuit_hash, public_words, raw, null, null);
}

/// Authenticate a full gate-profile proof and retain the verifier's expanded
/// Merkle/FRI openings for the recursive circuit. No prover-side aux tree is
/// needed; conversion only runs after the native verifier accepts the proof.
pub fn verifyAndCapture(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.preprocessed.ColumnLayout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
) !cpu.verifier_proof.VerifierProof {
    var converted: cpu.verifier_proof.VerifierProof = undefined;
    try verifyProfile(allocator, layout, template, pcs, preprocessed_root, circuit_hash, public_words, raw, null, &converted);
    return converted;
}

pub fn verifyHybrid(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.preprocessed.ColumnLayout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    spec: HybridSpec,
) !void {
    return verifyProfile(allocator, layout, template, pcs, preprocessed_root, circuit_hash, public_words, raw, spec, null);
}

fn verifyProfile(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.preprocessed.ColumnLayout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    spec: ?HybridSpec,
    converted_out: ?*cpu.verifier_proof.VerifierProof,
) !void {
    const hybrid = spec != null;
    const magic = if (hybrid) HYBRID_MAGIC else MAGIC;
    const header_len = if (hybrid) HYBRID_HEADER_LEN else HEADER_LEN;
    if (raw.len < header_len or raw.len > (16 << 20) or !std.mem.eql(u8, raw[0..magic.len], magic))
        return error.InvalidNativeProof;
    const nonce = std.mem.readInt(u64, raw[magic.len..][0..8], .little);
    var sums: [N_COMPONENTS]QM31 = undefined;
    for (&sums, 0..) |*sum, index| {
        const start = magic.len + 8 + index * 16;
        var limbs: [4]u32 = undefined;
        for (&limbs, 0..) |*limb, j| {
            limb.* = std.mem.readInt(u32, raw[start + j * 4 ..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.InvalidNativeProof;
        }
        sum.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    var chip_sum = QM31.zero();
    if (hybrid) {
        const start = magic.len + 8 + N_COMPONENTS * 16;
        var limbs: [4]u32 = undefined;
        for (&limbs, 0..) |*limb, j| {
            limb.* = std.mem.readInt(u32, raw[start + j * 4 ..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.InvalidNativeProof;
        }
        chip_sum = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    // Decode with a hard allocation ceiling. Length prefixes in an external
    // postcard proof cannot request arbitrary amounts of host memory.
    const proof_bytes = raw[header_len..];
    const decode_memory = try allocator.alloc(u8, 64 << 20);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var stark = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer stark.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidNativeProof;
    if (!std.meta.eql(stark.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidProofConfig;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &preprocessed_root, &roots[0])) return error.InvalidPreprocessedRoot;

    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs) |word, *output|
        output.* = QM31.fromU32Unchecked(word & 0xffff, word >> 16, 0, 0);

    var channel = MC.Channel{};
    if (spec) |item| chip.mixProfile(&channel, item.source_digest, item.rounds, item.constant);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    MC.mixRoot(&channel, circuit_hash);
    channel.mixFelts(&outputs);

    const component_logs = try circuit.common.component_list.circuitComponentLogSizes(layout);
    const log_array = component_logs.toArray();
    const widths = circuit.witness.trace.traceWidths();
    const interaction_widths = circuit.witness.trace.interactionWidths();
    const main_logs = try logsFor(allocator, log_array, widths, if (spec) |item| try chip.validateRounds(item.rounds) else null, chip.main_width);
    defer allocator.free(main_logs);
    const interaction_logs = try logsFor(allocator, log_array, interaction_widths, if (spec) |item| try chip.validateRounds(item.rounds) else null, chip.interaction_width);
    defer allocator.free(interaction_logs);
    try scheme.commit(allocator, roots[1], main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce))
        return error.InvalidInteractionNonce;
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    if (!(try circuit.witness.trace.lookupSum(&outputs, PerComponent(QM31).fromArray(sums), lookup.z, lookup.alpha)).isZero())
        return error.InvalidLookupSum;
    var hybrid_sums: [N_COMPONENTS + 1]QM31 = undefined;
    @memcpy(hybrid_sums[0..N_COMPONENTS], &sums);
    hybrid_sums[N_COMPONENTS] = chip_sum;
    if (spec) |item| {
        var initial: [4]M31 = undefined;
        var final: [4]M31 = undefined;
        for (0..4) |i| {
            if (public_words[i] >= core.fields.m31.Modulus or
                public_words[4 + i] >= core.fields.m31.Modulus)
                return error.InvalidPublicStatement;
            initial[i] = M31.fromCanonical(public_words[i]);
            final[i] = M31.fromCanonical(public_words[4 + i]);
        }
        if (!(try chip.endpointSum(chip_sum, .init(lookup.z, lookup.alpha), item.rounds, initial, final)).isZero())
            return error.InvalidChipLookupSum;
        core.channel.lookup_transcript.mixInteractionClaim(&channel, &hybrid_sums);
    } else core.channel.lookup_transcript.mixInteractionClaim(&channel, &sums);
    try scheme.commit(allocator, roots[2], interaction_logs, &channel);

    var bound = try cpu.air.bind(allocator, template, component_logs, layout);
    defer bound.deinit();
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [N_COMPONENTS]cairo.proving.air.component.Component = undefined;
    var handles: [N_COMPONENTS + 1]core.air.components.Component = undefined;
    for (bound.components, &captured, handles[0..N_COMPONENTS], sums) |*source, *runtime, *handle, claimed| {
        runtime.* = .init(allocator, source, &pp_logs, lifting_bound, lookup.z, lookup.alpha, claimed);
        handle.* = runtime.asVerifierComponent();
    }
    var chip_component: chip.Component = undefined;
    var component_count: usize = N_COMPONENTS;
    if (spec) |item| {
        var main_offset: usize = 0;
        var interaction_offset: usize = 0;
        for (widths) |width| main_offset += width;
        for (interaction_widths) |width| interaction_offset += width;
        chip_component = .{
            .log_size = try chip.validateRounds(item.rounds),
            .constant = item.constant,
            .main_offset = main_offset,
            .interaction_offset = interaction_offset,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = chip_sum,
        };
        handles[N_COMPONENTS] = chip_component.asVerifierComponent();
        component_count += 1;
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        handles[0..component_count],
        &channel,
        &scheme,
        &stark,
        true,
        &capture,
    );
    defer capture.deinit(allocator);
    if (converted_out) |out| {
        if (spec != null) return error.UnsupportedRecursiveProfile;
        const config = try cpu.verifier_proof.proofConfig(stark.commitment_scheme_proof.sampled_values.items[0].len, pcs);
        out.* = try cpu.verifier_proof.fromVerifiedCapture(allocator, &stark, &capture, config, &sums, nonce, 0);
    }
}

fn logsFor(
    allocator: std.mem.Allocator,
    sizes: [N_COMPONENTS]u32,
    widths: [N_COMPONENTS]usize,
    chip_log: ?u32,
    chip_width: usize,
) ![]u32 {
    var count: usize = 0;
    for (widths) |width| count += width;
    const logs = try allocator.alloc(u32, count + if (chip_log != null) chip_width else @as(usize, 0));
    var cursor: usize = 0;
    for (sizes, widths) |log, width| {
        @memset(logs[cursor..][0..width], log);
        cursor += width;
    }
    if (chip_log) |log| @memset(logs[cursor..], log);
    return logs;
}

const SPARSE_GATE_MAGIC = "S31NAT3G";
const SPARSE_CHIP_MAGIC = "S31NAT3C";

pub fn serializeSparse(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof, has_chip: bool) ![]u8 {
    if ((proof.chip_claimed_sum != null) != has_chip) return error.WrongProofProfile;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, if (has_chip) SPARSE_CHIP_MAGIC else SPARSE_GATE_MAGIC);
    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, proof.interaction_pow_nonce, .little);
    try bytes.appendSlice(allocator, &nonce);
    const all_sums = proof.claimed_sums.toArray();
    for (circuit.common.sparse_arithmetic.active_component_indices) |index|
        try appendSum(allocator, &bytes, all_sums[index]);
    if (has_chip) try appendSum(allocator, &bytes, proof.chip_claimed_sum.?);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.stark_proof.proof);
    return bytes.toOwnedSlice(allocator);
}

fn appendSum(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), sum: QM31) !void {
    for (sum.toM31Array()) |limb| {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, limb.v, .little);
        try bytes.appendSlice(allocator, &encoded);
    }
}

pub fn verifySparse(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.sparse_arithmetic.Layout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    source_digest: [32]u8,
    chip_spec: ?HybridSpec,
) !void {
    const has_chip = chip_spec != null;
    const magic = if (has_chip) SPARSE_CHIP_MAGIC else SPARSE_GATE_MAGIC;
    const sum_count: usize = if (has_chip) 4 else 3;
    const header_len = magic.len + 8 + sum_count * 16;
    if (raw.len < header_len or raw.len > (16 << 20) or !std.mem.eql(u8, raw[0..magic.len], magic))
        return error.InvalidNativeProof;
    const nonce = std.mem.readInt(u64, raw[magic.len..][0..8], .little);
    var sums: [4]QM31 = undefined;
    for (sums[0..sum_count], 0..) |*sum, index| {
        const start = magic.len + 8 + index * 16;
        var limbs: [4]u32 = undefined;
        for (&limbs, 0..) |*limb, j| {
            limb.* = std.mem.readInt(u32, raw[start + 4 * j ..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.InvalidNativeProof;
        }
        sum.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    const decode_memory = try allocator.alloc(u8, 64 << 20);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(raw[header_len..]);
    var stark = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer stark.deinit(bounded.allocator());
    if (stream.pos != raw.len - header_len or
        stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidNativeProof;
    if (!std.meta.eql(stark.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidProofConfig;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &preprocessed_root, &roots[0]))
        return error.InvalidPreprocessedRoot;

    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs) |word, *output|
        output.* = QM31.fromU32Unchecked(word & 0xffff, word >> 16, 0, 0);
    var initial: [4]M31 = undefined;
    var final: [4]M31 = undefined;
    if (has_chip) for (0..4) |i| {
        if (public_words[i] >= core.fields.m31.Modulus or
            public_words[4 + i] >= core.fields.m31.Modulus)
            return error.InvalidPublicStatement;
        initial[i] = M31.fromCanonical(public_words[i]);
        final[i] = M31.fromCanonical(public_words[4 + i]);
    };
    const chip_request: ?cpu.prove.ChipRequest = if (chip_spec) |item| .{
        .source_digest = source_digest,
        .rounds = item.rounds,
        .constant = item.constant,
        .initial = initial,
        .final = final,
    } else null;
    const logs = [3]u32{
        layout.logSize("qm31_ops_in0_address") orelse return error.InvalidSparseLayout,
        layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidSparseLayout,
        16,
    };
    const expected_hash = cpu.sparse_arithmetic.identityHash(
        source_digest,
        preprocessed_root,
        logs,
        pcs.fri_config.log_blowup_factor,
        chip_request,
    );
    if (!std.mem.eql(u8, &expected_hash, &circuit_hash))
        return error.InvalidCircuitHash;
    var channel = MC.Channel{};
    cpu.sparse_arithmetic.mixProfile(&channel, .{
        .source_digest = source_digest,
        .chip_request = chip_request,
    });
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs: [circuit.common.sparse_arithmetic.N_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    MC.mixRoot(&channel, circuit_hash);
    channel.mixFelts(&outputs);
    const chip_log: ?u32 = if (chip_spec) |item| try chip.validateRounds(item.rounds) else null;
    const main_logs = try sparseLogs(allocator, logs, .{ 12, 4, 1 }, chip_log, chip.main_width);
    defer allocator.free(main_logs);
    const interaction_logs = try sparseLogs(allocator, logs, .{ 8, 12, 4 }, chip_log, chip.interaction_width);
    defer allocator.free(interaction_logs);
    try scheme.commit(allocator, roots[1], main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce))
        return error.InvalidInteractionNonce;
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    if (!(try circuit.witness.sparse_arithmetic.lookupSum(&outputs, .{ sums[0], sums[1], sums[2] }, lookup.z, lookup.alpha)).isZero())
        return error.InvalidLookupSum;
    if (chip_spec) |item| if (!(try chip.endpointSum(
        sums[3],
        .init(lookup.z, lookup.alpha),
        item.rounds,
        initial,
        final,
    )).isZero()) return error.InvalidChipLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, sums[0..sum_count]);
    try scheme.commit(allocator, roots[2], interaction_logs, &channel);
    var bound = try cpu.air.bindSparseArithmetic(allocator, template, logs, layout);
    defer bound.deinit();
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [3]cairo.proving.air.component.Component = undefined;
    var handles: [4]core.air.components.Component = undefined;
    for (bound.components, &captured, handles[0..3], sums[0..3]) |*source, *runtime, *handle, claimed| {
        runtime.* = .init(allocator, source, &pp_logs, lifting_bound, lookup.z, lookup.alpha, claimed);
        handle.* = runtime.asVerifierComponent();
    }
    var chip_component: chip.Component = undefined;
    var component_count: usize = 3;
    if (chip_spec) |item| {
        chip_component = .{
            .log_size = try chip.validateRounds(item.rounds),
            .constant = item.constant,
            .main_offset = circuit.witness.sparse_arithmetic.main_width,
            .interaction_offset = circuit.witness.sparse_arithmetic.interaction_width,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = sums[3],
        };
        handles[3] = chip_component.asVerifierComponent();
        component_count = 4;
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        handles[0..component_count],
        &channel,
        &scheme,
        &stark,
        true,
        &capture,
    );
    defer capture.deinit(allocator);
}

const SPARSE_WIDE_MAGIC = "S31NAT5W";

pub fn serializeSparseWide(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof) ![]u8 {
    if (proof.chip_claimed_sum != null) return error.WrongProofProfile;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, SPARSE_WIDE_MAGIC);
    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, proof.interaction_pow_nonce, .little);
    try bytes.appendSlice(allocator, &nonce);
    const all_sums = proof.claimed_sums.toArray();
    for (circuit.common.sparse_wide.active_component_indices) |index|
        try appendSum(allocator, &bytes, all_sums[index]);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.stark_proof.proof);
    return bytes.toOwnedSlice(allocator);
}

pub fn verifySparseWide(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.sparse_wide.Layout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    source_digest: [32]u8,
) !void {
    return verifySparseWideInternal(allocator, layout, template, pcs, preprocessed_root, circuit_hash, public_words, raw, source_digest, null);
}

/// Convert only after authenticating the entire native STARK, including its
/// sparse-wide profile prefix, lookup closure, Merkle openings, and FRI.
pub fn verifySparseWideAndCapture(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.sparse_wide.Layout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    source_digest: [32]u8,
) !cpu.verifier_proof.VerifierProof {
    var converted: cpu.verifier_proof.VerifierProof = undefined;
    try verifySparseWideInternal(allocator, layout, template, pcs, preprocessed_root, circuit_hash, public_words, raw, source_digest, &converted);
    return converted;
}

fn verifySparseWideInternal(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.sparse_wide.Layout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    source_digest: [32]u8,
    converted_out: ?*cpu.verifier_proof.VerifierProof,
) !void {
    const header_len = SPARSE_WIDE_MAGIC.len + 8 + 4 * 16;
    if (raw.len < header_len or raw.len > (16 << 20) or !std.mem.eql(u8, raw[0..SPARSE_WIDE_MAGIC.len], SPARSE_WIDE_MAGIC))
        return error.InvalidNativeProof;
    const nonce = std.mem.readInt(u64, raw[SPARSE_WIDE_MAGIC.len..][0..8], .little);
    var sums: [4]QM31 = undefined;
    for (&sums, 0..) |*sum, index| {
        const start = SPARSE_WIDE_MAGIC.len + 8 + index * 16;
        var limbs: [4]u32 = undefined;
        for (&limbs, 0..) |*limb, j| {
            limb.* = std.mem.readInt(u32, raw[start + 4 * j ..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.InvalidNativeProof;
        }
        sum.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    const decode_memory = try allocator.alloc(u8, 64 << 20);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(raw[header_len..]);
    var stark = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer stark.deinit(bounded.allocator());
    if (stream.pos != raw.len - header_len or stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidNativeProof;
    if (!std.meta.eql(stark.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidProofConfig;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &preprocessed_root, &roots[0])) return error.InvalidPreprocessedRoot;

    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs) |word, *output|
        output.* = QM31.fromU32Unchecked(word & 0xffff, word >> 16, 0, 0);
    const logs = [4]u32{
        layout.logSize("eq_in0_address") orelse return error.InvalidSparseLayout,
        layout.logSize("qm31_ops_in0_address") orelse return error.InvalidSparseLayout,
        layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidSparseLayout,
        16,
    };
    const expected_hash = cpu.sparse_wide.identityHash(source_digest, preprocessed_root, logs, pcs.fri_config.log_blowup_factor);
    if (!std.mem.eql(u8, &expected_hash, &circuit_hash)) return error.InvalidCircuitHash;
    var channel = MC.Channel{};
    cpu.sparse_wide.mixProfile(&channel, .{ .source_digest = source_digest });
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs: [circuit.common.sparse_wide.N_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    MC.mixRoot(&channel, circuit_hash);
    channel.mixFelts(&outputs);
    const main_logs = try sparseLogs(allocator, logs, .{ 4, 12, 4, 1 }, null, 0);
    defer allocator.free(main_logs);
    const interaction_logs = try sparseLogs(allocator, logs, .{ 4, 8, 12, 4 }, null, 0);
    defer allocator.free(interaction_logs);
    try scheme.commit(allocator, roots[1], main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce))
        return error.InvalidInteractionNonce;
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    if (!(try circuit.witness.sparse_wide.lookupSum(&outputs, sums, lookup.z, lookup.alpha)).isZero())
        return error.InvalidLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &sums);
    try scheme.commit(allocator, roots[2], interaction_logs, &channel);
    var bound = try cpu.air.bindSparseWide(allocator, template, logs, layout);
    defer bound.deinit();
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [4]cairo.proving.air.component.Component = undefined;
    var handles: [4]core.air.components.Component = undefined;
    for (bound.components, &captured, &handles, sums) |*source, *runtime, *handle, claimed| {
        runtime.* = .init(allocator, source, &pp_logs, lifting_bound, lookup.z, lookup.alpha, claimed);
        handle.* = runtime.asVerifierComponent();
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &scheme, &stark, true, &capture);
    defer capture.deinit(allocator);
    if (converted_out) |out| {
        const trace_log = std.math.sub(u32, pcs.trace_lifting_log_size, pcs.fri_config.log_blowup_factor) catch
            return error.InvalidProofConfig;
        const config: @import("stwo_circuit_recursion_wire").circuit_serialize.ProofConfig = .{
            .n_preprocessed_columns = layout.entries.len,
            .component_shapes = &circuit.statements.sparse_wide_statement.shapes,
            .log_trace_size = trace_log,
            .fri = pcs.fri_config,
        };
        out.* = try cpu.verifier_proof.fromVerifiedCapture(allocator, &stark, &capture, config, &sums, nonce, 0);
    }
}

const DIRECT_GATE_MAGIC = "S31NAT4G";
const DIRECT_CHIP_MAGIC = "S31NAT4C";

pub fn serializeDirect(allocator: std.mem.Allocator, proof: *const cpu.Internal.CircuitProof, has_chip: bool) ![]u8 {
    if ((proof.chip_claimed_sum != null) != has_chip) return error.WrongProofProfile;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, if (has_chip) DIRECT_CHIP_MAGIC else DIRECT_GATE_MAGIC);
    var nonce: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce, proof.interaction_pow_nonce, .little);
    try bytes.appendSlice(allocator, &nonce);
    try appendSum(allocator, &bytes, proof.claimed_sums.toArray()[1]);
    if (has_chip) try appendSum(allocator, &bytes, proof.chip_claimed_sum.?);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.stark_proof.proof);
    return bytes.toOwnedSlice(allocator);
}

pub fn verifyDirect(
    allocator: std.mem.Allocator,
    layout: *const circuit.common.direct_arithmetic.Layout,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    preprocessed_root: H.Hash,
    circuit_hash: H.Hash,
    public_words: [8]u32,
    raw: []const u8,
    source_digest: [32]u8,
    chip_spec: ?HybridSpec,
) !void {
    const has_chip = chip_spec != null;
    const magic = if (has_chip) DIRECT_CHIP_MAGIC else DIRECT_GATE_MAGIC;
    const sum_count: usize = if (has_chip) 2 else 1;
    const header_len = magic.len + 8 + sum_count * 16;
    if (raw.len < header_len or raw.len > (16 << 20) or !std.mem.eql(u8, raw[0..magic.len], magic))
        return error.InvalidNativeProof;
    const nonce = std.mem.readInt(u64, raw[magic.len..][0..8], .little);
    var sums: [2]QM31 = undefined;
    for (sums[0..sum_count], 0..) |*sum, index| {
        const start = magic.len + 8 + index * 16;
        var limbs: [4]u32 = undefined;
        for (&limbs, 0..) |*limb, j| {
            limb.* = std.mem.readInt(u32, raw[start + 4 * j ..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.InvalidNativeProof;
        }
        sum.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    const decode_memory = try allocator.alloc(u8, 64 << 20);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(raw[header_len..]);
    var stark = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer stark.deinit(bounded.allocator());
    if (stream.pos != raw.len - header_len or
        stark.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidNativeProof;
    if (!std.meta.eql(stark.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidProofConfig;
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &preprocessed_root, &roots[0])) return error.InvalidPreprocessedRoot;
    var outputs: [8]QM31 = undefined;
    for (public_words, &outputs) |word, *output| {
        if (word >= core.fields.m31.Modulus) return error.InvalidPublicStatement;
        output.* = QM31.fromBase(M31.fromCanonical(word));
    }
    var initial: [4]M31 = undefined;
    var final: [4]M31 = undefined;
    if (has_chip) for (0..4) |i| {
        initial[i] = M31.fromCanonical(public_words[i]);
        final[i] = M31.fromCanonical(public_words[4 + i]);
    };
    const chip_request: ?cpu.prove.ChipRequest = if (chip_spec) |item| .{
        .source_digest = source_digest,
        .rounds = item.rounds,
        .constant = item.constant,
        .initial = initial,
        .final = final,
    } else null;
    const log_size = layout.traceLogSize();
    const expected_hash = cpu.direct_arithmetic.identityHash(
        source_digest,
        preprocessed_root,
        log_size,
        pcs.fri_config.log_blowup_factor,
        chip_request,
    );
    if (!std.mem.eql(u8, &expected_hash, &circuit_hash)) return error.InvalidCircuitHash;
    var channel = MC.Channel{};
    cpu.direct_arithmetic.mixProfile(&channel, .{
        .source_digest = source_digest,
        .chip_request = chip_request,
    });
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer scheme.deinit(allocator);
    var pp_logs = [_]u32{log_size} ** circuit.common.direct_arithmetic.N_COLUMNS;
    try scheme.commit(allocator, roots[0], &pp_logs, &channel);
    MC.mixRoot(&channel, circuit_hash);
    channel.mixFelts(&outputs);
    const chip_log: ?u32 = if (chip_spec) |item| try chip.validateRounds(item.rounds) else null;
    const main_logs = try sparseLogs(allocator, .{ log_size, 0, 0 }, .{ 12, 0, 0 }, chip_log, chip.main_width);
    defer allocator.free(main_logs);
    const interaction_logs = try sparseLogs(allocator, .{ log_size, 0, 0 }, .{ 8, 0, 0 }, chip_log, chip.interaction_width);
    defer allocator.free(interaction_logs);
    try scheme.commit(allocator, roots[1], main_logs, &channel);
    if (!channel.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce))
        return error.InvalidInteractionNonce;
    channel.mixU64(nonce);
    const lookup = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    if (!(try circuit.witness.direct_arithmetic.lookupSum(&outputs, sums[0], lookup.z, lookup.alpha)).isZero())
        return error.InvalidLookupSum;
    if (chip_spec) |item| if (!(try chip.endpointSum(
        sums[1],
        .init(lookup.z, lookup.alpha),
        item.rounds,
        initial,
        final,
    )).isZero()) return error.InvalidChipLookupSum;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, sums[0..sum_count]);
    try scheme.commit(allocator, roots[2], interaction_logs, &channel);
    var bound = try cpu.air.bindDirectArithmetic(allocator, template, log_size, layout);
    defer bound.deinit();
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [1]cairo.proving.air.component.Component = undefined;
    captured[0] = .init(allocator, &bound.components[0], &pp_logs, lifting_bound, lookup.z, lookup.alpha, sums[0]);
    var handles: [2]core.air.components.Component = undefined;
    handles[0] = captured[0].asVerifierComponent();
    var chip_component: chip.Component = undefined;
    var component_count: usize = 1;
    if (chip_spec) |item| {
        chip_component = .{
            .log_size = try chip.validateRounds(item.rounds),
            .constant = item.constant,
            .main_offset = circuit.witness.direct_arithmetic.main_width,
            .interaction_offset = circuit.witness.direct_arithmetic.interaction_width,
            .elements = .init(lookup.z, lookup.alpha),
            .claimed_sum = sums[1],
        };
        handles[1] = chip_component.asVerifierComponent();
        component_count = 2;
    }
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(
        H,
        MC,
        allocator,
        handles[0..component_count],
        &channel,
        &scheme,
        &stark,
        true,
        &capture,
    );
    defer capture.deinit(allocator);
}

fn sparseLogs(
    allocator: std.mem.Allocator,
    sizes: anytype,
    widths: anytype,
    chip_log: ?u32,
    chip_width: usize,
) ![]u32 {
    var count: usize = 0;
    inline for (widths) |width| count += width;
    const out = try allocator.alloc(u32, count + if (chip_log != null) chip_width else @as(usize, 0));
    var at: usize = 0;
    inline for (widths, 0..) |width, index| {
        @memset(out[at..][0..width], sizes[index]);
        at += width;
    }
    if (chip_log) |size| @memset(out[at..], size);
    return out;
}
