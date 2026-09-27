//! Domain-separated full-width execution parent key. A verifier-owned pin is mandatory.
//! Explicit profile admission; this does not authorize existing production keys.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const registry = @import("air/universal_challenges.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const Hash = std.crypto.hash.Blake3;
pub const VERSION: u32 = 3;
pub const DOMAIN = "stwo-zig/blake3-execution-child-parent/v3\x00";
pub const Profile = enum(u32) {
    diagnostic_q8_pow0 = 1,
    csp_q70_pow26 = 2,
    pub fn config(self: Profile) core.pcs.PcsConfig {
        return switch (self) {
            .diagnostic_q8_pow0 => PCS_CONFIG,
            .csp_q70_pow26 => CSP_CONFIG,
        };
    }
};
pub const PCS_CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 8, .fold_step = 1 } };
pub const CSP_CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 70, .fold_step = 1 } };
pub const Context = @import("blake3_execution_parent_preparation.zig").Context;
pub const Key = struct {
    version: u32 = VERSION,
    profile: Profile = .diagnostic_q8_pow0,
    config: core.pcs.PcsConfig = PCS_CONFIG,
    context: Context,
    log_sizes: [native.Airs.len]u32,
    preprocessed_root: suite.Hasher.Hash,
    pub fn identity(self: *const Key) ![32]u8 {
        if (self.version != VERSION or !std.meta.eql(self.config, self.profile.config())) return error.InvalidBlake3ParentProfile;
        for (self.log_sizes) |log| if (log == 0 or log > 30) return error.InvalidBlake3ParentGeometry;
        if (std.mem.allEqual(u8, &self.preprocessed_root, 0)) return error.InvalidBlake3ParentRoot;
        var hash = Hash.init(.{});
        hash.update(DOMAIN);
        hash.update(core.channel.blake3.PROTOCOL_ID);
        word(&hash, self.version);
        word(&hash, @intFromEnum(self.profile));
        try configWords(&hash, self.config);
        try mixContext(&hash, self.context);
        hash.update(&registry.registryOrderDigest());
        word(&hash, native.Airs.len);
        inline for (native.Airs, 0..) |Air, i| {
            word(&hash, i);
            hash.update(&Air.SEMANTIC_DIGEST);
            word(&hash, self.log_sizes[i]);
            word(&hash, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            word(&hash, Air.PREPROCESSED_COLUMN_COUNT);
            word(&hash, Air.DIRECT_CONSTRAINT_COUNT);
            word(&hash, Air.INTERACTION_COLUMN_COUNT);
        }
        for (native.selectors) |value| word(&hash, value.v);
        for ([_]schema.Kind{ .bitwise, .range_check_8_8 }) |kind| {
            word(&hash, @intFromEnum(kind));
            word(&hash, schema.logSize(kind));
            word(&hash, @intCast(schema.arity(kind)));
        }
        hash.update(&self.preprocessed_root);
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        return digest;
    }
};
/// The expected identity must come from verifier configuration, never the proof.
pub const Admission = struct {
    key: Key,
    expected_id: [32]u8,
    pub fn init(key: Key, expected_id: [32]u8) !Admission {
        const self = Admission{ .key = key, .expected_id = expected_id };
        try self.validate();
        return self;
    }
    pub fn validate(self: *const Admission) !void {
        if (!std.mem.eql(u8, &try self.key.identity(), &self.expected_id)) return error.UntrustedBlake3ParentKey;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        // Full 32-bit words preserve all bits of the structural key identity.
        var words: [8]u32 = undefined;
        for (&words, 0..) |*value, i| value.* = std.mem.readInt(u32, self.expected_id[i * 4 ..][0..4], .little);
        channel.mixU32s(&.{ 0x42334550, VERSION, @intFromEnum(self.key.profile) });
        self.key.config.mixInto(channel);
        channel.mixU32s(&words);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
        try self.validate();
        if (claims.len != native.Airs.len + 2) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&.{ 0x42334543, VERSION, native.Airs.len + 2 });
        channel.mixFelts(claims);
    }
    pub fn admitRoot(self: *const Admission, root: suite.Hasher.Hash) !void {
        try self.validate();
        if (!std.mem.eql(u8, &root, &self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
    }
};
fn word(hash: *Hash, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hash.update(&encoded);
}
fn configWords(hash: *Hash, config: core.pcs.PcsConfig) !void {
    const fri = config.fri_config;
    if (config.pow_bits > core.channel.blake3.MAX_POW_BITS or fri.n_queries == 0 or fri.n_queries > std.math.maxInt(u32) or fri.log_blowup_factor == 0 or fri.log_blowup_factor > 30 or fri.log_last_layer_degree_bound > 30 or fri.fold_step == 0 or fri.fold_step > @import("air/fri_verifier_circuit.zig").MAX_FOLD_STEP) return error.InvalidBlake3ParentProfile;
    if (config.lifting_log_size) |lifting| if (lifting > 30) return error.InvalidBlake3ParentProfile;
    word(hash, @intFromBool(config.lifting_log_size != null));
    word(hash, config.lifting_log_size orelse 0);
    for ([_]u32{ config.pow_bits, fri.log_blowup_factor, fri.log_last_layer_degree_bound, @intCast(fri.n_queries), fri.fold_step }) |value| word(hash, value);
}

/// Stable context identity also used when admitting two child preparations.
pub fn contextIdentity(context: Context) ![32]u8 {
    var hash = Hash.init(.{});
    hash.update("stwo-zig/blake3-parent-context/v3\x00");
    try mixContext(&hash, context);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}
fn mixContext(hash: *Hash, context: Context) !void {
    try configWords(hash, context.child_config);
    hash.update(&context.child_key_id);
    for (context.graph_ids) |id| hash.update(&id);
    hash.update(&context.transcript_plan_id);
    if ((context.statement_identity == null) != (context.span_binding_id == null)) return error.InvalidBlake3ParentSpan;
    word(hash, @intFromBool(context.statement_identity != null));
    if (context.statement_identity) |id| {
        hash.update(&id);
        hash.update(&context.span_binding_id.?);
    }
    word(hash, @intFromBool(context.aggregation != null));
    if (context.aggregation) |aggregate| {
        if (context.statement_identity == null) return error.InvalidBlake3ParentSpan;
        hash.update(&aggregate.right_child_key_id);
        try configWords(hash, aggregate.right_config);
        for (aggregate.right_graph_ids) |id| hash.update(&id);
        hash.update(&aggregate.right_transcript_plan_id);
        for (aggregate.child_statement_ids) |id| hash.update(&id);
        for (aggregate.child_span_binding_ids) |id| hash.update(&id);
        for (aggregate.namespace_ids) |id| hash.update(&id);
    }
}
