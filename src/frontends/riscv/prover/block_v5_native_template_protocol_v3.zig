//! Versioned native-only execution template. Fixed columns contain typed
//! opcode/clock selectors and lookup constants, never per-leaf hash custody.
//! The current isActive selector still depends on exact row counts, so a
//! template may be reused only by instances with identical row geometry.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("../air/statement.zig");
const profile_mod = @import("../isa/execution_profile.zig");
const admission = @import("block_v5_native_public_admission_v1.zig").Admission;
const sealed_mod = @import("block_v5_source_seal_v1.zig");
const frame = @import("block_v5_native_frame_v1.zig");

pub const VERSION: u32 = 3;
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
    if (frame.required(shape)) {
        _ = try frame.expected(shape, external_retirements);
        frame.mixGeometry(&channel);
    }
    if (shape.localZeroCustody()) {
        channel.mixU32s(&.{ @import("../air/x0_local_custody_v1.zig").TAG, shape.x0_local_custody_version });
        channel.mixRoot(@import("../air/x0_local_custody_v1.zig").abiId());
    }
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
    if (pin.context.execution_index != index) return error.UntrustedNativeV5PublicAdmission;
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
    // V3 preserves linear replay and replaces per-leaf custody admission. These
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
    return (try @import("block_v5_native_column_log_layout_v1.zig").Cursor.init(shape, external_retirements, tree)).allocate(a);
}

/// Reconstruct exact masks from independent statement geometry without an
/// allocator. Stored arrays remain proposals and cannot select the layout.
pub fn requireColumnLogs(shape: *const statement.Blake3ExecutionStatement, external_retirements: u32, tree: ColumnTree, logs: []const u32) !void {
    try (try @import("block_v5_native_column_log_layout_v1.zig").Cursor.init(shape, external_retirements, tree)).require(logs);
}

/// Independent cap for all trace and composition columns in the native wire.
/// The local-zero degree-four recipe has bound N+2; the native protocol's
/// fixed composition split of one yields composition column log N+1.
pub fn maximumProofColumnLog(shape: *const statement.Blake3ExecutionStatement, external_retirements: u32) !u32 {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    if (frame.required(shape)) {
        _ = try frame.expected(shape, external_retirements);
        return frame.LOG_SIZE;
    }
    var result: u32 = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        const log = try std.math.add(u32, desc.log_size, @intFromBool(shape.localZeroCustody()));
        result = @max(result, log);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| result = @max(result, desc.log_size);
    return result;
}
