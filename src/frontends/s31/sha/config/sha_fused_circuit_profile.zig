//! Verifier-owned key and transcript for the sparse-wide circuit joined to
//! three SHA256 compression calls. The 80-byte header is absent from the
//! public statement; the circuit's Poseidon root is the sole public computed
//! output. The call namespace and Gate addresses are public metadata.
//! The SHA digest is a committed witness connected to the circuit through
//! the Gate lookup. A Key is derived from independently compiled,
//! value-free circuit topology. This unmasked STARK does not promise
//! zero-knowledge confidentiality for the header.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const direct = @import("sha_fused_private_join_profile.zig");

pub const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
pub const pp = circuit.common.sparse_wide;
pub const sparse_trace = circuit.witness.sparse_wide;
pub const QM31 = core.fields.qm31.QM31;
pub const circuit_components: usize = 4;
pub const claim_count: usize = circuit_components + 1 + direct.word_claim_count;
pub const component_count: usize = circuit_components + direct.component_count;
pub const magic = "S31FCJ04";
pub const claim_bytes: usize = claim_count * 16;
pub const prefix_bytes: usize = magic.len + 8 + claim_bytes + 32;
pub const max_proof_bytes: usize = 1 << 26;

pub const Key = struct {
    source_digest: [32]u8,
    statement: direct.PublicStatement,
    n_vars: u32,
    circuit_logs: [4]u32,
    circuit_layout: pp.Layout,
    pcs: core.pcs.config_v2.PcsConfigV2,
    fixed_root: [32]u8,
    digest: [32]u8,

    pub fn validate(self: Key) !void {
        try self.statement.validate();
        if (self.statement.digest_visibility != .private) return error.PublicDigestForbiddenInFusedCircuitV4;
        if (self.n_vars <= 3 or self.n_vars >= core.fields.m31.Modulus) return error.InvalidDirectCircuitVariableCount;
        const expected = try pp.Layout.fromSizes(
            @as(usize, 1) << @intCast(self.circuit_logs[0]),
            @as(usize, 1) << @intCast(self.circuit_logs[1]),
            @as(usize, 1) << @intCast(self.circuit_logs[2]),
        );
        if (self.circuit_logs[3] != 16) return error.InvalidDirectCircuitLayout;
        for (self.circuit_layout.entries, expected.entries) |actual, want| {
            if (actual.log_size != want.log_size or !std.mem.eql(u8, actual.id, want.id))
                return error.InvalidDirectCircuitLayout;
        }
        for (self.statement.config.gate_addresses) |address| if (address <= 2 or address >= self.n_vars) return error.InvalidDirectCircuitGateAddress;
        const canonical_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
            self.pcs.fri_config,
            @max(@max(self.circuit_logs[0], @max(self.circuit_logs[1], self.circuit_logs[2])), 16),
        );
        if (!std.meta.eql(self.pcs, canonical_pcs)) return error.InvalidDirectCircuitPcsConfig;
        if (!@import("builtin").is_test) {
            const fri = self.pcs.fri_config;
            if (fri.pow_bits != 26 or fri.log_blowup_factor != 1 or
                fri.log_last_layer_degree_bound != 0 or fri.n_queries != 70 or
                fri.fold_step != 1) return error.InsecureDirectCircuitPcsConfig;
        }
        const expected_digest = keyDigest(self);
        if (!std.mem.eql(u8, &self.digest, &expected_digest)) return error.WrongDirectCircuitKeyDigest;
    }

    pub fn identity(self: Key) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("S31-FUSED-CIRCUIT-IDENTITY-V4\x00");
        hasher.update(&self.digest);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};

pub fn mixProfile(channel: *MC.Channel, key: Key) void {
    channel.mixU64(0x5333_3146_434a_3034);
    mixBytes(channel, key.source_digest);
    mixBytes(channel, direct.semanticDigest());
    mixBytes(channel, circuitAirDigest());
    channel.mixU32s(&.{ key.n_vars, direct.component_count, component_count, claim_count });
    channel.mixU32s(&key.circuit_logs);
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
    const sha_logs = @import("../verification/sha_fused_private_join_native_verifier.zig").fixedLogSizes();
    const result = try allocator.alloc(u32, pp.N_COLUMNS + sha_logs.len);
    for (key.circuit_layout.entries, result[0..pp.N_COLUMNS]) |entry, *log| log.* = entry.log_size;
    @memcpy(result[pp.N_COLUMNS..], &sha_logs);
    return result;
}
pub fn mainLogs(allocator: std.mem.Allocator, key: Key) ![]u32 {
    const sha_logs = @import("../verification/sha_fused_private_join_native_verifier.zig").mainLogSizes();
    const result = try allocator.alloc(u32, sparse_trace.main_width + sha_logs.len);
    // The explicit widths below are the canonical sparse-wide-v5 ordering.
    var at: usize = 0;
    for (key.circuit_logs, [_]usize{ 4, 12, 4, 1 }) |log, width| {
        @memset(result[at..][0..width], log);
        at += width;
    }
    @memcpy(result[sparse_trace.main_width..], &sha_logs);
    return result;
}
pub fn interactionLogs(allocator: std.mem.Allocator, key: Key) ![]u32 {
    const sha_logs = @import("../verification/sha_fused_private_join_native_verifier.zig").interactionLogSizes();
    const result = try allocator.alloc(u32, sparse_trace.interaction_width + sha_logs.len);
    var at: usize = 0;
    for (key.circuit_logs, [_]usize{ 4, 8, 12, 4 }) |log, width| {
        @memset(result[at..][0..width], log);
        at += width;
    }
    @memcpy(result[sparse_trace.interaction_width..], &sha_logs);
    return result;
}

pub fn shaPrefix() direct.Prefix {
    return .{ .fixed = pp.N_COLUMNS, .main = sparse_trace.main_width, .interaction = sparse_trace.interaction_width };
}

pub fn validateOfficialBundle(bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &circuitAirDigest())) return error.InvalidDirectCircuitAirBundle;
}

pub fn validatePublicOutputs(outputs: []const QM31) !void {
    if (outputs.len != 8) return error.InvalidDirectCircuitPublicOutputCount;
    for (outputs) |output| {
        const limbs = output.toM31Array();
        if (limbs[0].toU32() >= 1 << 16 or limbs[1].toU32() >= 1 << 16 or
            limbs[2].toU32() != 0 or limbs[3].toU32() != 0 or
            (@as(u64, limbs[0].toU32()) + (@as(u64, limbs[1].toU32()) << 16)) >= core.fields.m31.Modulus)
            return error.InvalidDirectCircuitPublicOutputEncoding;
    }
}

pub fn debugWidths() [3]usize {
    return .{ pp.N_COLUMNS + direct.Layout.init(.{}).total_fixed, sparse_trace.main_width + direct.Layout.init(.{}).total_main, sparse_trace.interaction_width + direct.Layout.init(.{}).total_interaction };
}
