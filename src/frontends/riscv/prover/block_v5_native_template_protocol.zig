//! Versioned native-only execution template. Fixed columns contain typed
//! opcode/clock selectors and lookup constants, never per-leaf hash custody.
//! The current isActive selector still depends on exact row counts, so a
//! template may be reused only by instances with identical row geometry.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("../air/statement.zig");
const opcode = @import("../air/lookups/opcode_interaction.zig");
const profile_mod = @import("../isa/execution_profile.zig");
const admission = @import("blake3_commitment_plan.zig").Admission;
const sealed_mod = @import("block_v5_source_seal_v1.zig");

pub const VERSION: u32 = 2;
pub const TAG: u32 = 0x42354e54; // B5NT
pub const Digest = [32]u8;
pub const ColumnTree = enum { fixed, main, interaction };

pub const Template = struct {
    config: core.pcs.PcsConfig,
    execution_profile: profile_mod.ExecutionProfile,
    external_retirements: u32,
    geometry_digest: Digest,
    fixed_root: Digest,

    pub fn fromShape(shape: *const statement.Blake3ExecutionStatement, config: core.pcs.PcsConfig, execution_profile: profile_mod.ExecutionProfile, external_retirements: u32, fixed_root: Digest) !Template {
        try shape.validateBlake3ExecutionWithExternal(external_retirements);
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        return .{
            .config = config,
            .execution_profile = execution_profile,
            .external_retirements = external_retirements,
            .geometry_digest = try geometryDigest(shape, external_retirements),
            .fixed_root = fixed_root,
        };
    }

    pub fn identity(self: Template) !Digest {
        if (std.mem.allEqual(u8, &self.fixed_root, 0)) return error.InvalidNativeV5FixedRoot;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(self.execution_profile), self.external_retirements });
        self.config.mixInto(&channel);
        channel.mixRoot(self.geometry_digest);
        channel.mixRoot(self.fixed_root);
        return channel.digestBytes();
    }

    pub fn admit(self: Template, shape: *const statement.Blake3ExecutionStatement, expected_id: Digest) !void {
        if (!std.meta.eql(self.geometry_digest, try geometryDigest(shape, self.external_retirements)) or
            !std.meta.eql(try self.identity(), expected_id))
            return error.UntrustedNativeV5Template;
    }
};

pub fn geometryDigest(shape: *const statement.Blake3ExecutionStatement, external_retirements: u32) !Digest {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, shape.total_steps, external_retirements, shape.n_components, shape.n_infra });
    channel.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
    for (shape.component_descs[0..shape.n_components]) |desc| {
        channel.mixU32s(&.{ @intFromEnum(desc.family), desc.log_size, desc.n_rows, desc.n_columns });
        channel.mixRoot(@import("../air/lang/opcode_composition_manifest.zig").BY_FAMILY[@intFromEnum(desc.family)].authority_digest);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc|
        channel.mixU32s(&.{ @intFromEnum(desc.kind), desc.log_size, desc.n_rows, desc.n_columns });
    return channel.digestBytes();
}

/// The first-round main root is instance-specific. Neither it nor the public
/// machine endpoints are allowed to change the reusable fixed template ID.
pub fn instanceId(template_id: Digest, shape: *const statement.Blake3ExecutionStatement, pin: admission, roots: sealed_mod.Roots, index: u32) !Digest {
    try pin.validatePublic(&shape.public_data);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, index, shape.initial_pc, shape.final_pc });
    channel.mixRoot(template_id);
    channel.mixRoot(pin.expected_id);
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    shape.public_data.mixInto(&channel);
    shape.mixShardManifest(&channel);
    return channel.digestBytes();
}

/// One local PCS transcript, domain-separated from the global LogUp draw.
/// All families draw universal relations from sealed.sharedChannel() itself.
pub fn pcsChannel(a: std.mem.Allocator, sealed: sealed_mod.Sealed, template_id: Digest, instance_id: Digest, roots: sealed_mod.Roots, index: u32) !core.proof_suites.Blake3.Channel {
    var channel = sealed.sharedChannel();
    // V2 makes the verifier transcript linear for recursive replay. These
    // are the identical B5SS relation draws used by all global providers;
    // local PCS domain separation follows the frozen prefix.
    _ = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, index });
    channel.mixRoot(template_id);
    channel.mixRoot(instance_id);
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    return channel;
}

pub fn mixClaims(channel: anytype, shape: *const statement.Blake3ExecutionStatement, claims: *const statement.RiscVInteractionClaim) !void {
    if (claims.n_components != shape.n_components or claims.n_infra != shape.n_infra)
        return error.InvalidNativeV5Claims;
    channel.mixU32s(&.{ TAG, VERSION, shape.n_components, shape.n_infra });
    for (shape.component_descs[0..shape.n_components], 0..) |desc, index|
        channel.mixFelts(try claims.opcodeClaims(desc.family, index));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, index|
        channel.mixFelts(try claims.infraClaims(desc.kind, index));
}

pub fn columnLogs(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external_retirements: u32, tree: ColumnTree) ![]u32 {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    var logs: std.ArrayList(u32) = .empty;
    errdefer logs.deinit(a);
    for (shape.component_descs[0..shape.n_components]) |desc| {
        const count: usize = switch (tree) {
            .fixed => 2,
            .main => desc.n_columns,
            .interaction => opcode.nColumns(desc.family),
        };
        try logs.appendNTimes(a, desc.log_size, count);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        const count: usize = switch (tree) {
            .fixed => statement.nPreprocessedColumnsForInfra(desc.kind),
            .main => desc.n_columns,
            .interaction => statement.nInteractionColsForInfra(desc.kind),
        };
        try logs.appendNTimes(a, desc.log_size, count);
    }
    return logs.toOwnedSlice(a);
}
