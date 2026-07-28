//! Public contracts and canonical field decoding shared by resident verification.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const proof_mod = @import("stwo_core").proof;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const cairo_adapter = @import("../adapter/mod.zig");
const composition_bundle = @import("composition_bundle.zig");
const proof_bundle = @import("proof_bundle.zig");

pub const M31 = m31.M31;
pub const QM31 = qm31.QM31;

pub const Hasher = blake2_merkle.Blake2sPlainMerkleHasher;
pub const Proof = proof_mod.StarkProof(Hasher);
pub const Channel = channel_blake2s.Blake2sChannel;
pub const MerkleChannel = blake2_merkle.Blake2sPlainMerkleChannel;

pub const sn2_pow_bits: u32 = 26;
pub const sn2_interaction_pow_bits: u32 = 24;
pub const sn2_query_count: usize = 70;
pub const sn2_fold_step: u32 = 3;
pub const sn2_trace_tree_count: usize = 4;
pub const sn2_fri_layer_count: usize = 8;
pub const sn2_max_log_degree_bound: u32 = 24;
pub const protocol_config_word_count: usize = 8;

/// Proof geometry whose PCS fields are encoded in transcript ordinal 2. The
/// verifier re-mixes those words before accepting the proof, so a successful
/// verification authenticates the geometry rather than trusting bundle sizes.
pub const ProtocolGeometry = struct {
    trace_tree_count: usize,
    fri_layer_count: usize,
    max_log_degree_bound: u32,
    query_pow_bits: u32,
    interaction_pow_bits: u32,
    log_blowup_factor: u32,
    query_count: usize,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    lifting_log_size: ?u32,

    /// Decodes canonical PCS words supplied by an authenticated statement or
    /// manifest. Parsing alone does not establish the caller's security policy.
    pub fn fromConfigWords(
        words: []const u32,
        interaction_pow_bits: u32,
        trace_tree_count: usize,
        max_log_degree_bound: u32,
    ) Error!ProtocolGeometry {
        if (words.len != protocol_config_word_count or words[6] != 0 or words[7] != 0)
            return Error.InvalidProtocolGeometry;
        const geometry = ProtocolGeometry{
            .trace_tree_count = trace_tree_count,
            .fri_layer_count = try friLayerCount(
                max_log_degree_bound,
                words[3],
                words[4],
            ),
            .max_log_degree_bound = max_log_degree_bound,
            .query_pow_bits = words[0],
            .interaction_pow_bits = interaction_pow_bits,
            .log_blowup_factor = words[1],
            .query_count = @intCast(words[2]),
            .log_last_layer_degree_bound = words[3],
            .fold_step = words[4],
            .lifting_log_size = if (words[5] == 0) null else words[5],
        };
        try geometry.validate();
        return geometry;
    }

    /// Exact compatibility geometry for the captured SN PIE 2 protocol.
    pub fn sn2() ProtocolGeometry {
        return .{
            .trace_tree_count = sn2_trace_tree_count,
            .fri_layer_count = sn2_fri_layer_count,
            .max_log_degree_bound = sn2_max_log_degree_bound,
            .query_pow_bits = sn2_pow_bits,
            .interaction_pow_bits = sn2_interaction_pow_bits,
            .log_blowup_factor = 1,
            .query_count = sn2_query_count,
            .log_last_layer_degree_bound = 0,
            .fold_step = sn2_fold_step,
            .lifting_log_size = null,
        };
    }

    pub fn validate(self: ProtocolGeometry) Error!void {
        if (self.trace_tree_count == 0 or self.trace_tree_count > 1 << 10 or
            self.fri_layer_count == 0 or
            self.query_count == 0 or self.query_count > 1 << 20 or
            self.query_pow_bits > 64 or self.interaction_pow_bits > 64 or
            self.max_log_degree_bound > 31 or
            self.fri_layer_count != try friLayerCount(
                self.max_log_degree_bound,
                self.log_last_layer_degree_bound,
                self.fold_step,
            ))
            return Error.InvalidProtocolGeometry;
        if (self.lifting_log_size) |log_size| {
            if (log_size == 0 or log_size > 31) return Error.InvalidProtocolGeometry;
        }
        var config = fri.FriConfig.init(
            self.log_last_layer_degree_bound,
            self.log_blowup_factor,
            self.query_count,
        ) catch return Error.InvalidProtocolGeometry;
        config.fold_step = self.fold_step;
    }

    pub fn friConfig(self: ProtocolGeometry) Error!fri.FriConfig {
        try self.validate();
        var config = fri.FriConfig.init(
            self.log_last_layer_degree_bound,
            self.log_blowup_factor,
            self.query_count,
        ) catch return Error.InvalidProtocolGeometry;
        config.fold_step = self.fold_step;
        return config;
    }

    pub fn matchesTranscript(self: ProtocolGeometry, words: []const u32) bool {
        if (words.len != protocol_config_word_count or self.query_count > std.math.maxInt(u32))
            return false;
        const expected = [protocol_config_word_count]u32{
            self.query_pow_bits,
            self.log_blowup_factor,
            @intCast(self.query_count),
            self.log_last_layer_degree_bound,
            self.fold_step,
            self.lifting_log_size orelse 0,
            0,
            0,
        };
        return std.mem.eql(u32, words, &expected);
    }
};

fn friLayerCount(max_log_degree_bound: u32, final_log: u32, fold_step: u32) Error!usize {
    if (fold_step == 0 or max_log_degree_bound <= final_log or
        fold_step > max_log_degree_bound - final_log)
        return Error.InvalidProtocolGeometry;
    const folds = max_log_degree_bound - final_log;
    return @intCast(1 + (folds - 1) / fold_step);
}

pub const Error = error{
    InvalidProofShape,
    InvalidSampleShape,
    InvalidTraceShape,
    InvalidFriShape,
    InvalidProtocolGeometry,
    InvalidComponentShape,
    InvalidGlobalLookupSum,
    InvalidProgram,
    InvalidStatementBinding,
    NonCanonicalM31,
    MissingMaskValue,
};

pub const SampleShape = struct {
    /// Per tree, per column, number of OODS samples in transcript order.
    trees: []const []const usize,
};

pub const TranscriptInput = struct {
    ordinal: u32,
    words: []const u32,
};

pub const VerifyInput = struct {
    bundle: proof_bundle.ProofBundle,
    composition: composition_bundle.Bundle,
    /// Degree logs for the preprocessed, base, and interaction trees.
    tree_logs: [3][]const u32,
    /// Direct-PIE statement transcript prefix. Roots and proof payloads are
    /// cross-checked against the resident bundle before they are absorbed.
    transcript_inputs: []const TranscriptInput,
    /// Source of the public Cairo data. The verifier rederives all statement
    /// ordinals before using its public memory values in global LogUp closure.
    statement: *const cairo_adapter.ProverInput,
};

pub fn m31FromWord(word: u32) Error!M31 {
    if (word >= m31.Modulus) return Error.NonCanonicalM31;
    return M31.fromCanonical(word);
}

pub fn qm31FromWords(words: []const u32) Error!QM31 {
    if (words.len != 4) return Error.InvalidProofShape;
    return QM31.fromM31(
        try m31FromWord(words[0]),
        try m31FromWord(words[1]),
        try m31FromWord(words[2]),
        try m31FromWord(words[3]),
    );
}

pub fn qm31Words(value: QM31) [4]u32 {
    const coordinates = value.toM31Array();
    return .{ coordinates[0].v, coordinates[1].v, coordinates[2].v, coordinates[3].v };
}

test "resident verifier rejects non-canonical field words" {
    try std.testing.expectError(Error.NonCanonicalM31, m31FromWord(m31.Modulus));
}

test "runtime protocol derives FRI layers from authenticated geometry" {
    const words = [_]u32{ 18, 2, 40, 1, 4, 0, 0, 0 };
    const geometry = try ProtocolGeometry.fromConfigWords(&words, 12, 5, 22);
    try std.testing.expectEqual(@as(usize, 5), geometry.trace_tree_count);
    try std.testing.expectEqual(@as(usize, 6), geometry.fri_layer_count);
    try std.testing.expect(geometry.matchesTranscript(&words));

    var malformed = words;
    malformed[7] = 1;
    try std.testing.expectError(
        Error.InvalidProtocolGeometry,
        ProtocolGeometry.fromConfigWords(&malformed, 12, 5, 22),
    );
}
