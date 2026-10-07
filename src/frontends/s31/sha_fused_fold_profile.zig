//! Verifier-owned identity for one full 11-component recursive Bitcoin fold
//! circuit joined to the 10-component fused SHA256d AIR. The 56 private
//! header/digest Gate addresses come from the value-free fold topology.
//! The eight public outputs are packed raw u32 words of the chain-state
//! Blake2s digest. The header and its SHA digest are private trace values;
//! current unmasked openings do not provide zero knowledge.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const direct = @import("sha_fused_private_join_profile.zig");

pub const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
pub const pp = circuit.common.preprocessed;
pub const trace = circuit.witness.trace;
pub const component_list = circuit.common.component_list;
pub const QM31 = core.fields.qm31.QM31;
pub const circuit_components: usize = component_list.N_COMPONENTS;
pub const claim_count: usize = circuit_components + 1 + direct.word_claim_count;
pub const component_count: usize = circuit_components + direct.component_count;
pub const magic = "S31FCF01";
pub const claim_bytes: usize = claim_count * 16;
pub const prefix_bytes: usize = magic.len + 8 + claim_bytes + 32;
pub const max_proof_bytes: usize = 1 << 26;

/// Host-owned source domain for the hand-built fold relation. The canonical
/// fixed root separately commits the concrete checkpoint, child verifier
/// configuration, projection, step selector, and padding. A trusted verifier
/// passes this digest to `deriveKey`; proof bytes never supply it.
pub fn trustedFoldSourceDigest() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{
        "bitcoin_chain_fold.zig",
        "bitcoin_fold_step.zig",
        "bitcoin_fold_digest.zig",
        "bitcoin_chain_anchor.zig",
        "bitcoin_target.zig",
        "poseidon2.zig",
        "recursion_counter.zig",
        "recursion_gate.zig",
    }) |path| {
        hasher.update(path ++ "\x00");
        hasher.update(@embedFile(path));
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

comptime {
    std.debug.assert(circuit_components == 11);
    std.debug.assert(direct.component_count == 10);
    std.debug.assert(claim_count == 17);
    std.debug.assert(component_count == 21);
}

pub const Key = struct {
    source_digest: [32]u8,
    statement: direct.PublicStatement,
    n_vars: u32,
    circuit_logs: component_list.PerComponent(u32),
    circuit_layout: pp.ColumnLayout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    fixed_root: [32]u8,
    digest: [32]u8,

    pub fn validate(self: Key) !void {
        try self.statement.validate();
        if (!std.mem.eql(u8, &self.source_digest, &trustedFoldSourceDigest())) return error.UntrustedFusedFoldSourceDigest;
        if (self.statement.digest_visibility != .private) return error.PublicDigestForbiddenInFusedFold;
        if (self.n_vars <= 3 or self.n_vars >= core.fields.m31.Modulus) return error.InvalidFusedFoldVariableCount;
        const logs = self.circuit_logs;
        for (logs.toArray()) |log| if (log < 4 or log > 26) return error.InvalidFusedFoldComponentLogSize;
        const expected_layout = try pp.ColumnLayout.fromComponentSizes(.{
            .eq = @as(usize, 1) << @intCast(logs.eq),
            .qm31_ops = @as(usize, 1) << @intCast(logs.qm31_ops),
            .triple_xor = @as(usize, 1) << @intCast(logs.triple_xor),
            .m31_to_u32 = @as(usize, 1) << @intCast(logs.m_31_to_u_32),
            .blake_g_gate = @as(usize, 1) << @intCast(logs.blake_g_gate),
        });
        if (!self.circuit_layout.eql(&expected_layout)) return error.InvalidFusedFoldLayout;
        const derived_logs = try component_list.circuitComponentLogSizes(&self.circuit_layout);
        if (!std.meta.eql(logs, derived_logs)) return error.InvalidFusedFoldComponentLogs;
        for (self.statement.config.gate_addresses) |address| if (address <= 2 or address >= self.n_vars) return error.InvalidFusedFoldGateAddress;
        const canonical_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
            self.pcs.fri_config,
            @max(self.circuit_layout.traceLogSize(), 8),
        );
        if (!std.meta.eql(self.pcs, canonical_pcs)) return error.InvalidFusedFoldPcsConfig;
        if (!builtin.is_test) {
            const fri = self.pcs.fri_config;
            if (fri.pow_bits != 26 or fri.log_blowup_factor != 1 or
                fri.log_last_layer_degree_bound != 0 or fri.n_queries != 70 or
                fri.fold_step != 1) return error.InsecureFusedFoldPcsConfig;
        }
        if (!std.mem.eql(u8, &self.digest, &keyDigest(self))) return error.WrongFusedFoldKeyDigest;
    }

    pub fn identity(self: Key) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("S31-FUSED-FOLD-IDENTITY-V1\x00");
        hasher.update(&self.digest);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

pub fn mixProfile(channel: *MC.Channel, key: Key) void {
    channel.mixU64(0x5333_3146_4346_3031);
    mixBytes(channel, key.source_digest);
    mixBytes(channel, direct.semanticDigest());
    mixBytes(channel, circuitAirDigest());
    channel.mixU32s(&.{ key.n_vars, direct.component_count, component_count, claim_count });
    const logs = key.circuit_logs.toArray();
    channel.mixU32s(&logs);
    channel.mixU32s(&key.statement.config.gate_addresses);
    channel.mixU32s(&.{key.statement.config.first_call_id});
    channel.mixU32s(&.{
        key.pcs.fri_config.pow_bits,                    key.pcs.fri_config.log_blowup_factor,
        key.pcs.fri_config.log_last_layer_degree_bound, key.pcs.fri_config.n_queries,
        key.pcs.fri_config.fold_step,                   key.pcs.trace_lifting_log_size,
        key.pcs.preprocessed_lifting_log_size,
    });
    core.channel.lookup_transcript.mixChannelSalt(channel, 0);
    key.pcs.fri_config.mixInto(channel);
}

pub fn keyDigest(key: Key) [32]u8 {
    var channel = MC.Channel{};
    mixProfile(&channel, key);
    MC.mixRoot(&channel, key.fixed_root);
    return channel.digestBytes();
}

pub fn circuitAirDigest() [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, cpu.air.bundle_sha256) catch unreachable;
    return result;
}

fn mixBytes(channel: *MC.Channel, bytes: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

pub fn fixedLogs(allocator: std.mem.Allocator, key: Key) ![]u32 {
    const sha_logs = @import("sha_fused_private_join_native_verifier.zig").fixedLogSizes();
    const result = try allocator.alloc(u32, pp.N_PREPROCESSED_COLUMNS + sha_logs.len);
    for (key.circuit_layout.entries, result[0..pp.N_PREPROCESSED_COLUMNS]) |entry, *log| log.* = entry.log_size;
    @memcpy(result[pp.N_PREPROCESSED_COLUMNS..], &sha_logs);
    return result;
}

fn sumWidths(comptime widths: [circuit_components]usize) usize {
    var total: usize = 0;
    for (widths) |width| total += width;
    return total;
}

pub const main_width: usize = sumWidths(trace.traceWidths());
pub const interaction_width: usize = sumWidths(trace.interactionWidths());

pub fn mainLogs(allocator: std.mem.Allocator, key: Key) ![]u32 {
    const sha_logs = @import("sha_fused_private_join_native_verifier.zig").mainLogSizes();
    const result = try allocator.alloc(u32, main_width + sha_logs.len);
    var at: usize = 0;
    for (key.circuit_logs.toArray(), trace.traceWidths()) |log, width| {
        @memset(result[at..][0..width], log);
        at += width;
    }
    @memcpy(result[main_width..], &sha_logs);
    return result;
}

pub fn interactionLogs(allocator: std.mem.Allocator, key: Key) ![]u32 {
    const sha_logs = @import("sha_fused_private_join_native_verifier.zig").interactionLogSizes();
    const result = try allocator.alloc(u32, interaction_width + sha_logs.len);
    var at: usize = 0;
    for (key.circuit_logs.toArray(), trace.interactionWidths()) |log, width| {
        @memset(result[at..][0..width], log);
        at += width;
    }
    @memcpy(result[interaction_width..], &sha_logs);
    return result;
}

pub fn shaPrefix() direct.Prefix {
    return .{ .fixed = pp.N_PREPROCESSED_COLUMNS, .main = main_width, .interaction = interaction_width };
}

pub fn validateOfficialBundle(bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &circuitAirDigest())) return error.InvalidFusedFoldAirBundle;
}

pub fn validatePublicOutputs(outputs: []const QM31) !void {
    if (outputs.len != 8) return error.InvalidFusedFoldPublicOutputCount;
    for (outputs) |output| {
        const limbs = output.toM31Array();
        if (limbs[0].toU32() >= 1 << 16 or limbs[1].toU32() >= 1 << 16 or
            !limbs[2].isZero() or !limbs[3].isZero())
            return error.InvalidFusedFoldPublicOutputEncoding;
    }
}

pub fn debugWidths() [3]usize {
    return .{
        pp.N_PREPROCESSED_COLUMNS + direct.Layout.init(.{}).total_fixed,
        main_width + direct.Layout.init(.{}).total_main,
        interaction_width + direct.Layout.init(.{}).total_interaction,
    };
}

test "full fold profile has 11 circuit and 10 SHA components with canonical column offsets" {
    try std.testing.expectEqual(@as(usize, 11), circuit_components);
    try std.testing.expectEqual(@as(usize, 21), component_count);
    try std.testing.expectEqual(@as(usize, 17), claim_count);
    const prefix = shaPrefix();
    try std.testing.expectEqual(@as(usize, 45), prefix.fixed);
    try std.testing.expectEqual(main_width, prefix.main);
    try std.testing.expectEqual(interaction_width, prefix.interaction);
    const widths = debugWidths();
    try std.testing.expectEqual(prefix.fixed + 51, widths[0]);
    try std.testing.expectEqual(prefix.main + 270, widths[1]);
    try std.testing.expectEqual(prefix.interaction + 64, widths[2]);
}

test "fold outputs admit all packed raw u32 words and reject malformed QM31 encodings" {
    var values: [8]QM31 = @splat(QM31.fromU32Unchecked(65535, 65535, 0, 0));
    try validatePublicOutputs(&values);
    values[0] = QM31.fromU32Unchecked(65536, 0, 0, 0);
    try std.testing.expectError(error.InvalidFusedFoldPublicOutputEncoding, validatePublicOutputs(&values));
}

test "fold key rejects a self-consistent but untrusted source domain" {
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(100 + i);
    const layout = try pp.ColumnLayout.fromComponentSizes(.{
        .eq = 32768,
        .qm31_ops = 2097152,
        .m31_to_u32 = 262144,
        .triple_xor = 131072,
        .blake_g_gate = 2097152,
    });
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var key = Key{
        .source_digest = trustedFoldSourceDigest(),
        .statement = .{ .digest_visibility = .private, .config = .{ .gate_addresses = addresses, .first_call_id = 1 } },
        .n_vars = 5_606_320,
        .circuit_logs = try component_list.circuitComponentLogSizes(&layout),
        .circuit_layout = layout,
        .pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize()),
        .fixed_root = @splat(0x42),
        .digest = undefined,
    };
    key.digest = keyDigest(key);
    try key.validate();
    key.source_digest[0] ^= 1;
    key.digest = keyDigest(key);
    try std.testing.expectError(error.UntrustedFusedFoldSourceDigest, key.validate());
}

test "joined fold prover and verifier public entry points instantiate" {
    const prover = @import("sha_fused_fold_prover.zig");
    const native = @import("sha_fused_fold_native_verifier.zig");
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(100 + i);
    const invalid_statement = direct.PublicStatement{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = addresses, .first_call_id = 0 },
    };
    const allocator = std.testing.allocator;
    const invalid_request = prover.Request{
        .source_digest = trustedFoldSourceDigest(),
        .n_vars = 0,
        .statement = invalid_statement,
        .header = @splat(0),
    };
    try std.testing.expectError(error.InvalidShaCallId, prover.prove(allocator, &.{}, undefined, undefined, undefined, invalid_request));
    try std.testing.expectError(error.InvalidShaCallId, native.deriveKey(allocator, trustedFoldSourceDigest(), undefined, 0, invalid_statement, undefined));
    var invalid_key: Key = undefined;
    invalid_key.statement = invalid_statement;
    invalid_key.source_digest = trustedFoldSourceDigest();
    var invalid_proof: prover.Proof = undefined;
    invalid_proof.key = invalid_key;
    try std.testing.expectError(error.InvalidShaCallId, prover.serialize(allocator, &invalid_proof));
    try std.testing.expectError(error.InvalidShaCallId, native.verifyBytes(allocator, .{ .key = invalid_key, .public_outputs = &.{} }, &.{}));
}
