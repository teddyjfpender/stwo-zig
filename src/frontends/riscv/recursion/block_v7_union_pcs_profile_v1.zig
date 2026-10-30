//! Borrowed compiler view of independently reconstructed union PCS geometry.
//! No proof capture or proposed verifier key participates in this view.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
pub const View = struct {
    original: *const Profile.Owned,
    claims: *const Multi.Claims,
    columns: []const []const u32,
    config: core.pcs.PcsConfig,
    widths: []const u32,
    lifting_log: u32,
    seal: [32]u8,
    relation_pairs: usize,
    initial_roots: usize,
    pub fn init(original: *const Profile.Owned, claims: *const Multi.Claims) !View {
        try original.validateAgainst(claims);
        return .{ .original = original, .claims = claims, .columns = original.shape.columns, .config = original.shape.config, .widths = original.shape.widths, .lifting_log = original.shape.lifting_log, .seal = original.seal, .relation_pairs = try @import("air/block_v7_union_caller_draws_v1.zig").pairCount(original.statement.input.callers.len), .initial_roots = try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(original) };
    }
    pub fn validate(self: *const View) !void {
        try self.original.validateAgainst(self.claims);
        if (!std.meta.eql(self.seal, self.original.seal) or !std.meta.eql(self.config, self.original.shape.config) or self.columns.len != self.original.shape.columns.len or self.lifting_log != self.original.shape.lifting_log or self.widths.len != self.original.shape.widths.len or self.initial_roots != try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(self.original) or self.relation_pairs != try @import("air/block_v7_union_caller_draws_v1.zig").pairCount(self.original.statement.input.callers.len)) return error.UntrustedUnionPcsProfile;
        for (self.columns, self.original.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedUnionPcsProfile;
        if (!std.mem.eql(u32, self.widths, self.original.shape.widths)) return error.UntrustedUnionPcsProfile;
    }
    pub fn deepProfile(self: *const View) @import("air/pcs_deep_circuit.zig").Profile {
        return self.original.shape.deepProfile();
    }
    pub fn friProfile(self: *const View) @import("air/fri_verifier_circuit.zig").Profile {
        return self.original.shape.friProfile();
    }
};

/// Borrowed geometry of an in-process immutable compiler. No serialized cache
/// or producer-selected key is admitted here. Canonical reconstruction happened
/// in Capsule.derive; source metadata remains privately owned there.
pub const FrozenView = struct {
    capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule,
    columns: []const []const u32,
    config: core.pcs.PcsConfig,
    widths: []const u32,
    lifting_log: u32,
    seal: [32]u8,
    relation_pairs: usize,
    initial_roots: usize,
    pub fn init(capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule) !FrozenView {
        const p = capsule.profile();
        return .{ .capsule = capsule, .columns = p.shape.columns, .config = p.shape.config, .widths = p.shape.widths, .lifting_log = p.shape.lifting_log, .seal = p.seal, .relation_pairs = try @import("air/block_v7_union_caller_draws_v1.zig").pairCount(p.statement.input.callers.len), .initial_roots = try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(p) };
    }
    pub fn validate(self: *const FrozenView) !void {
        const p = self.capsule.profile();
        if (!std.meta.eql(p.seal, try p.identity()) or !std.meta.eql(self.seal, p.seal) or !std.meta.eql(self.config, p.shape.config) or self.columns.len != p.shape.columns.len or self.lifting_log != p.shape.lifting_log or !std.mem.eql(u32, self.widths, p.shape.widths) or self.initial_roots != try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(p) or self.relation_pairs != try @import("air/block_v7_union_caller_draws_v1.zig").pairCount(p.statement.input.callers.len)) return error.UntrustedUnionPcsProfile;
        for (self.columns, p.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedUnionPcsProfile;
    }
    pub fn deepProfile(self: *const FrozenView) @import("air/pcs_deep_circuit.zig").Profile {
        return self.capsule.profile().shape.deepProfile();
    }
    pub fn friProfile(self: *const FrozenView) @import("air/fri_verifier_circuit.zig").Profile {
        return self.capsule.profile().shape.friProfile();
    }
};
