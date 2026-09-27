//! Experimental preparation cache for the existing Ethereum/SHA native AIR.
//! Only opcode/table and extension fixed columns are retained across plans.
//! Plan-dependent BLAKE3 custody columns and the full Tree0 root are rebuilt
//! for every instance. Neither Template nor Instance verifies a proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const native_mod = @import("../air/statement.zig");
const Native = native_mod.Blake3ExecutionStatement;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Extension = Profile.admission.Statement;
const Desc = Profile.Descriptor;
const plans = @import("blake3_commitment_plan.zig");
const Hashes = @import("blake3_commitment_columns.zig").Owner;
const base = @import("blake3_execution_protocol.zig");
const compact = @import("compact_extension_contract.zig").ForProfile(Profile);
const range = @import("../recursion/air/compact_range_geometry.zig");
const Column = engine.pcs.ColumnEvaluation;
const Digest = [32]u8;
const suite = core.proof_suites.Blake3;

pub const VERSION: u32 = 1;

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        config: core.pcs.PcsConfig,
        total_steps: u32,
        component_descs: []const native_mod.FamilyComponentDesc,
        infra_descs: []const native_mod.InfraComponentDesc,
        extension_descs: [Profile.component_count]Desc,
        keccak_calls: u32,
        signer_calls: u32,
        sha_calls: u32,
        native_columns: []const Column,
        extension_columns: []const Column,
        invariant_root: Digest,
        geometry_id: Digest,
        id: Digest,

        /// The first statement supplies geometry only. Its public state and
        /// commitment plan are deliberately not retained in the template.
        pub fn init(a: std.mem.Allocator, native: *const Native, extension: *const Extension, config: core.pcs.PcsConfig) !*Self {
            try base.validateConfig(config);
            try native.validateBlake3ExecutionWithExternal(Profile.externalCount(extension));
            try Profile.validateGeometry(extension, native.total_steps);
            const self = try a.create(Self);
            self.* = .{
                .allocator = a,
                .arena = .init(a),
                .config = config,
                .total_steps = native.total_steps,
                .component_descs = undefined,
                .infra_descs = undefined,
                .extension_descs = Profile.descriptors(extension),
                .keccak_calls = extension.ethereum.counts.keccak_calls,
                .signer_calls = extension.ethereum.counts.signer_calls,
                .sha_calls = extension.sha.call_count,
                .native_columns = undefined,
                .extension_columns = undefined,
                .invariant_root = undefined,
                .geometry_id = undefined,
                .id = undefined,
            };
            errdefer self.deinit();
            const owned = self.arena.allocator();
            self.component_descs = try owned.dupe(native_mod.FamilyComponentDesc, native.component_descs[0..native.n_components]);
            self.infra_descs = try owned.dupe(native_mod.InfraComponentDesc, native.infra_descs[0..native.n_infra]);
            var prefix: std.ArrayList(Column) = .empty;
            try base.nativePreprocessedWithExternal(owned, native, Profile.externalCount(extension), &prefix);
            self.native_columns = try prefix.toOwnedSlice(owned);
            self.extension_columns = try Profile.preprocessed(owned, extension);
            self.geometry_id = geometryId(self);
            self.invariant_root = try commitRoot(Backend, a, config, self.native_columns, &.{}, self.extension_columns);
            self.id = templateId(self);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.arena.deinit();
            self.allocator.destroy(self);
        }

        /// Re-derive the plan-dependent Tree0 columns and commit the *full*
        /// current-layout fixed tree. The returned current_key_id is B3CK and
        /// must still be checked by the existing fresh native verifier.
        pub fn prepareInstance(self: *const Self, a: std.mem.Allocator, native: *const Native, extension: *const Extension, pin: plans.Admission, config: core.pcs.PcsConfig, ranges: range.Plan) !Instance {
            if (!std.meta.eql(config, self.config)) return error.TemplateConfigMismatch;
            try native.validateBlake3ExecutionWithExternal(Profile.externalCount(extension));
            try self.validateGeometry(native, extension);
            try pin.validatePublic(&native.public_data);
            const hashes = try Hashes.initVerifier(a, pin);
            defer hashes.deinit();
            try extension.validate(a, native, pin, hashes.logs);
            const full_root = try commitRoot(Backend, a, config, self.native_columns, hashes.preprocessed(), self.extension_columns);
            const current_key_id = try (compact{
                .allocator = a,
                .native = native,
                .extension = extension,
                .ranges = ranges,
            }).identity(config, pin, hashes.logs, full_root);
            var public_channel = suite.Channel{};
            native.public_data.mixInto(&public_channel);
            const public_id = public_channel.digestBytes();
            const range_id = try ranges.identity();
            const instance_id = instanceId(self.id, pin.expected_id, public_id, range_id, full_root, current_key_id);
            return .{
                .template_id = self.id,
                .instance_id = instance_id,
                .plan_id = pin.expected_id,
                .public_id = public_id,
                .range_id = range_id,
                .full_fixed_root = full_root,
                .current_key_id = current_key_id,
            };
        }

        fn validateGeometry(self: *const Self, native: *const Native, extension: *const Extension) !void {
            if (native.total_steps != self.total_steps or
                !sameDescriptors(self.component_descs, native.component_descs[0..native.n_components]) or
                !sameDescriptors(self.infra_descs, native.infra_descs[0..native.n_infra]) or
                extension.ethereum.counts.keccak_calls != self.keccak_calls or
                extension.ethereum.counts.signer_calls != self.signer_calls or
                extension.sha.call_count != self.sha_calls or
                !std.meta.eql(Profile.descriptors(extension), self.extension_descs))
                return error.TemplateGeometryMismatch;
        }
    };
}

pub const Instance = struct {
    template_id: Digest,
    instance_id: Digest,
    plan_id: Digest,
    public_id: Digest,
    range_id: Digest,
    full_fixed_root: Digest,
    current_key_id: Digest,

    /// Versioned transcript suffix for a future native proof route. The
    /// current B3CK route does not call this; its own identity already binds
    /// plan, public statement, compact range plan, and complete fixed root.
    pub fn mixInto(self: Instance, channel: anytype) void {
        channel.mixU32s(&.{ 0x4e545049, VERSION }); // NTPI
        base.mixDigest(channel, self.template_id);
        base.mixDigest(channel, self.instance_id);
        base.mixDigest(channel, self.plan_id);
        base.mixDigest(channel, self.public_id);
        base.mixDigest(channel, self.range_id);
        base.mixDigest(channel, self.full_fixed_root);
        base.mixDigest(channel, self.current_key_id);
    }

    /// Structural comparison only. `expected` must come from an independently
    /// admitted policy and the actual proof still needs fresh verification.
    pub fn validateExpected(self: Instance, expected: Instance) !void {
        if (!std.meta.eql(self, expected)) return error.TemplateInstanceMismatch;
    }
};

fn commitRoot(comptime Backend: type, a: std.mem.Allocator, config: core.pcs.PcsConfig, prefix: []const Column, middle: []const Column, suffix: []const Column) !Digest {
    const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
    var scheme = try Scheme.init(a, config);
    scheme.setCoefficientRetentionPolicy(.never);
    defer scheme.deinit(a);
    var columns: std.ArrayList(Column) = .empty;
    defer columns.deinit(a);
    try columns.appendSlice(a, prefix);
    try columns.appendSlice(a, middle);
    try columns.appendSlice(a, suffix);
    var channel = suite.Channel{};
    try scheme.commitBorrowedStreaming(a, columns.items, @import("blake3_coefficient_retention.zig").streamingBatchColumns(), &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    return roots.items[0];
}

fn geometryId(self: anytype) Digest {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo.riscv.native-prepared-template-geometry.v1\x00");
    word(&hash, self.total_steps);
    word(&hash, @intCast(self.component_descs.len));
    for (self.component_descs) |desc| {
        word(&hash, @intFromEnum(desc.family));
        word(&hash, desc.log_size);
        word(&hash, desc.n_rows);
        word(&hash, desc.n_columns);
    }
    word(&hash, @intCast(self.infra_descs.len));
    for (self.infra_descs) |desc| {
        word(&hash, @intFromEnum(desc.kind));
        word(&hash, desc.log_size);
        word(&hash, desc.n_rows);
        word(&hash, desc.n_columns);
    }
    word(&hash, self.keccak_calls);
    word(&hash, self.signer_calls);
    word(&hash, self.sha_calls);
    for (self.extension_descs) |desc| {
        word(&hash, desc.log_size);
        word(&hash, desc.preprocessed_columns);
        word(&hash, desc.main_columns);
        word(&hash, desc.interaction_columns);
    }
    return finish(&hash);
}

fn templateId(self: anytype) Digest {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo.riscv.native-prepared-template.v1\x00");
    word(&hash, VERSION);
    const relation_digest = @import("../air/lang/relation.zig").registryOrderDigest();
    hash.update(&relation_digest);
    for (self.component_descs) |desc| hash.update(&@import("../air/lang/opcode_composition_manifest.zig").BY_FAMILY[@intFromEnum(desc.family)].authority_digest);
    inline for (@import("blake3_commitment_components.zig").Airs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
    hash.update(&@import("../isa/execution_profile.zig").ethereum_semantic_digest);
    inline for (@import("../air/guest_precompile/sha256_component_profile.zig").Airs) |Air| hash.update(&Air.SEMANTIC_DIGEST);
    word(&hash, self.config.pow_bits);
    word(&hash, self.config.fri_config.log_blowup_factor);
    word(&hash, @intCast(self.config.fri_config.n_queries));
    word(&hash, self.config.fri_config.log_last_layer_degree_bound);
    word(&hash, self.config.fri_config.fold_step);
    word(&hash, @intFromBool(self.config.lifting_log_size != null));
    word(&hash, self.config.lifting_log_size orelse 0);
    hash.update(&self.geometry_id);
    hash.update(&self.invariant_root);
    return finish(&hash);
}

fn instanceId(template_id: Digest, plan_id: Digest, public_id: Digest, range_id: Digest, root: Digest, current_key_id: Digest) Digest {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo.riscv.native-prepared-instance.v1\x00");
    hash.update(&template_id);
    hash.update(&plan_id);
    hash.update(&public_id);
    hash.update(&range_id);
    hash.update(&root);
    hash.update(&current_key_id);
    return finish(&hash);
}

fn sameDescriptors(left: anytype, right: @TypeOf(left)) bool {
    if (left.len != right.len) return false;
    for (left, right) |l, r| if (!std.meta.eql(l, r)) return false;
    return true;
}
fn word(hash: *std.crypto.hash.Blake3, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
fn finish(hash: *std.crypto.hash.Blake3) Digest {
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}
