//! Canonical M31 preimage for the verifier-owned SegmentV2 transcript program.
//!
//! The native `Program.identity` is already a Poseidon field digest. Retaining
//! its exact words lets a recursive wrapper prove that digest from a fixed,
//! cold-recompiled program instead of importing an opaque native assertion.
//! This module does not publish a recursive proof or activate V3.

const std = @import("std");
const core = @import("stwo_core");
const transcript = @import("transcript_program_v2.zig");
const schedule = @import("air/verifier_schedule.zig");
const public_data = @import("../air/public_data_v2.zig");
const statement = @import("../air/statement.zig");
const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;
const PcsConfig = core.pcs.PcsConfig;

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const PROGRAM_DOMAIN = transcript.PROGRAM_ID_DOMAIN;

pub const AuthorityV1 = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    digest: channel.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        program: *const transcript.Program,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data.PublicDataV2,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
    ) !AuthorityV1 {
        try program.validateAgainst(plan, pcs_config, data, component_descs, infra_descs);
        const words = try canonicalWords(allocator, program);
        errdefer allocator.free(words);
        const digest = channel.hashCanonicalWords(words, PROGRAM_DOMAIN);
        if (!std.meta.eql(digest, program.identity))
            return error.ProgramFieldIdentityMismatch;
        return .{ .allocator = allocator, .words = words, .digest = digest };
    }

    pub fn deinit(self: *AuthorityV1) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const AuthorityV1,
        program: *const transcript.Program,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data.PublicDataV2,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
    ) !void {
        try program.validateAgainst(plan, pcs_config, data, component_descs, infra_descs);
        const expected = try canonicalWords(self.allocator, program);
        defer self.allocator.free(expected);
        if (!wordsEqual(self.words, expected) or
            !std.meta.eql(self.digest, program.identity) or
            !std.meta.eql(self.digest, channel.hashCanonicalWords(self.words, PROGRAM_DOMAIN)))
            return error.ProgramFieldIdentityMismatch;
    }
};

/// Exact `transcript_program_v2.programIdentity` input in canonical field order.
/// Every unrestricted u32 and every byte-array length is split into u16 limbs.
pub fn canonicalWords(allocator: std.mem.Allocator, program: *const transcript.Program) ![]M31 {
    var words: std.ArrayList(M31) = .empty;
    errdefer words.deinit(allocator);
    try scalar(&words, allocator, program.format_version);
    try scalar(&words, allocator, program.schema_version);
    try appendDigest(&words, allocator, program.plan_id);
    try appendDigest(&words, allocator, program.wire_id);
    try appendDigest(&words, allocator, program.statement_authority_id);
    try u32Value(&words, allocator, program.wire_word_count);
    try pcsWords(&words, allocator, program.pcs_config);
    if (program.lookup_activation) |activation| {
        try scalar(&words, allocator, @import("../air/lang/lookup_physical_manifest_v2.zig").FORMAT_VERSION);
        try scalar(&words, allocator, activation.format_version);
        try bytes(&words, allocator, &activation.manifest_identity);
        try bytes(&words, allocator, &activation.statement_identity);
        try bytes(&words, allocator, &activation.activation_identity);
        try u32Value(&words, allocator, activation.component_count);
        try u32Value(&words, allocator, activation.opcode_main_columns);
        try u32Value(&words, allocator, activation.opcode_interaction_columns);
        try u32Value(&words, allocator, activation.detailed_claim_count);
    }
    try u32Value(&words, allocator, std.math.cast(u32, program.instructions.len) orelse return error.ProgramFieldWordCountOverflow);
    for (program.instructions) |instruction| {
        try scalar(&words, allocator, @intFromEnum(instruction.kind));
        try u32Value(&words, allocator, instruction.verifier_sequence);
        try u32Value(&words, allocator, instruction.sub_index);
        for (instruction.args) |arg| try u32Value(&words, allocator, arg);
    }
    return words.toOwnedSlice(allocator);
}

fn pcsWords(words: *std.ArrayList(M31), allocator: std.mem.Allocator, config: PcsConfig) !void {
    try u32Value(words, allocator, config.pow_bits);
    try u32Value(words, allocator, config.fri_config.log_blowup_factor);
    try u32Value(words, allocator, std.math.cast(u32, config.fri_config.n_queries) orelse return error.ProgramFieldWordCountOverflow);
    try u32Value(words, allocator, config.fri_config.log_last_layer_degree_bound);
    try u32Value(words, allocator, config.fri_config.fold_step);
    try scalar(words, allocator, @intFromBool(config.lifting_log_size != null));
    try u32Value(words, allocator, config.lifting_log_size orelse 0);
}

fn scalar(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: anytype) !void {
    const raw = std.math.cast(u32, value) orelse return error.NonCanonicalProgramField;
    if (raw >= core.fields.m31.Modulus) return error.NonCanonicalProgramField;
    try words.append(allocator, M31.fromCanonical(raw));
}

fn u32Value(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: u32) !void {
    try scalar(words, allocator, value & 0xffff);
    try scalar(words, allocator, value >> 16);
}

fn appendDigest(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: channel.Digest) !void {
    for (value) |word| try scalar(words, allocator, word);
}

fn bytes(words: *std.ArrayList(M31), allocator: std.mem.Allocator, value: []const u8) !void {
    try u32Value(words, allocator, std.math.cast(u32, value.len) orelse return error.ProgramFieldWordCountOverflow);
    for (value) |byte| try scalar(words, allocator, byte);
}

fn wordsEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}
