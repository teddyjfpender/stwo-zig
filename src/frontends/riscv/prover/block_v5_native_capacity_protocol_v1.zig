//! Explicit capacity-native protocol. Public counts are instance authority;
//! capacity selectors are proved in the same main tree as native cells.
//! This is a distinct open family and is not accepted by NativeV3/fused code.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const statement = @import("../air/statement.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const admission = @import("block_v5_native_public_admission_v1.zig");
const old = @import("block_v5_native_template_protocol_v3.zig");
const profile = @import("../isa/execution_profile.zig");
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42354354; // B5CT, never B5NT
pub const Digest = [32]u8;
pub const MAX_SHARDS = statement.MAX_COMPONENTS + 1;
pub const Shard = struct { log_size: u32, rows: u32, first_index: usize, active_index: usize, main_index: usize };
pub const Plan = struct {
    shards: [MAX_SHARDS]Shard = [_]Shard{.{ .log_size = 0, .rows = 0, .first_index = 0, .active_index = 0, .main_index = 0 }} ** MAX_SHARDS,
    len: usize = 0,
    native_main_count: usize,
    fixed_count: usize,
    pub fn fromShape(shape: *const statement.Blake3ExecutionStatement, external: u32) !Plan {
        try shape.validateBlake3ExecutionWithExternal(external);
        var result = Plan{ .native_main_count = shape.nMainColumns(), .fixed_count = shape.nPreprocessedColumns() };
        for (shape.component_descs[0..shape.n_components]) |desc| try result.append(desc.log_size, desc.n_rows);
        for (shape.infra_descs[0..shape.n_infra]) |desc| {
            // Native-only capacity recipes never smuggle provider tables into
            // the reusable template. Providers retain their own authority.
            if (desc.kind != .clock_update) return error.UnsupportedNativeCapacityInfrastructure;
            try result.append(desc.log_size, desc.n_rows);
        }
        if (result.len == 0) {
            const frame = @import("block_v5_native_frame_v1.zig");
            _ = try frame.expected(shape, external);
            result.native_main_count = frame.MAIN_COLUMNS;
            result.fixed_count = frame.FIXED_COLUMNS;
        } else if (result.fixed_count != 2 * result.len) return error.InvalidNativeCapacityGeometry;
        return result;
    }
    fn append(self: *Plan, log: u32, rows: u32) !void {
        if (self.len == MAX_SHARDS or log == 0 or log > 24 or rows == 0 or rows > (@as(u32, 1) << @intCast(log))) return error.InvalidNativeCapacityGeometry;
        self.shards[self.len] = .{ .log_size = log, .rows = rows, .first_index = 2 * self.len, .active_index = 2 * self.len + 1, .main_index = self.native_main_count + 2 * self.len };
        self.len += 1;
    }
    pub fn mainCount(self: *const Plan) usize {
        return self.native_main_count + 2 * self.len;
    }
    pub fn active(self: *const Plan) []const Shard {
        return self.shards[0..self.len];
    }
};
pub const Template = struct {
    config: core.pcs.PcsConfig,
    execution_profile: profile.ExecutionProfile,
    capacity_digest: Digest,
    fixed_root: Digest,
    pub fn fromShape(shape: *const statement.Blake3ExecutionStatement, external: u32, config: core.pcs.PcsConfig, selected: profile.ExecutionProfile, fixed_root: Digest) !Template {
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        return .{ .config = config, .execution_profile = selected, .capacity_digest = try capacityDigest(shape, external), .fixed_root = fixed_root };
    }
    pub fn identity(self: Template) !Digest {
        if (std.mem.allEqual(u8, &self.fixed_root, 0)) return error.InvalidNativeCapacityFixedRoot;
        var c = core.proof_suites.Blake3.Channel{};
        c.mixU32s(&.{ TAG, VERSION, @intFromEnum(self.execution_profile), @import("block_v5_native_capacity_activity_v1.zig").N_CONSTRAINTS });
        self.config.mixInto(&c);
        c.mixRoot(self.capacity_digest);
        c.mixRoot(self.fixed_root);
        return c.digestBytes();
    }
    pub fn admit(self: Template, shape: *const statement.Blake3ExecutionStatement, external: u32, expected: Digest) !void {
        if (!std.meta.eql(self.capacity_digest, try capacityDigest(shape, external)) or !std.meta.eql(try self.identity(), expected)) return error.UntrustedNativeCapacityTemplate;
    }
};
pub fn capacityDigest(shape: *const statement.Blake3ExecutionStatement, external: u32) !Digest {
    const plan = try Plan.fromShape(shape, external);
    var c = core.proof_suites.Blake3.Channel{};
    c.mixU32s(&.{ TAG, VERSION, shape.n_components, shape.n_infra, shape.x0_local_custody_version });
    if (shape.localZeroCustody()) c.mixRoot(@import("../air/x0_local_custody_v1.zig").abiId());
    c.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
    for (shape.component_descs[0..shape.n_components]) |desc| {
        c.mixU32s(&.{ @intFromEnum(desc.family), desc.log_size, desc.n_columns });
        c.mixRoot(@import("../air/lang/opcode_composition_manifest.zig").BY_FAMILY[@intFromEnum(desc.family)].authority_digest);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| c.mixU32s(&.{ @intFromEnum(desc.kind), desc.log_size, desc.n_columns });
    // A genuinely empty ordinary native instance retains its existing typed
    // frame AIR and fixed recipe, rather than an invented empty STARK.
    if (plan.len == 0) @import("block_v5_native_frame_v1.zig").mixGeometry(&c);
    return c.digestBytes();
}
pub fn instanceId(template_id: Digest, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, roots: seal.Roots, index: u32) !Digest {
    _ = try Plan.fromShape(shape, external);
    try pin.validatePublic(&shape.public_data);
    if (pin.context.execution_index != index) return error.UntrustedNativeCapacityInstance;
    var c = core.proof_suites.Blake3.Channel{};
    c.mixU32s(&.{ TAG, VERSION, index, external, shape.total_steps });
    c.mixRoot(template_id);
    c.mixRoot(pin.expected_id);
    for (roots) |root| c.mixRoot(root);
    shape.public_data.mixInto(&c);
    shape.mixShardManifest(&c); // exact rows remain instance-bound
    return c.digestBytes();
}
pub fn pcsChannel(a: std.mem.Allocator, sealed: seal.Sealed, template: Digest, instance: Digest, roots: seal.Roots, index: u32) !core.proof_suites.Blake3.Channel {
    var c = sealed.sharedChannel();
    _ = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &c);
    c.mixU32s(&.{ TAG, VERSION, index });
    c.mixRoot(template);
    c.mixRoot(instance);
    for (roots) |root| c.mixRoot(root);
    return c;
}
pub fn mixClaims(c: anytype, shape: *const statement.Blake3ExecutionStatement, claims: *const statement.RiscVInteractionClaim) !void {
    c.mixU32s(&.{ TAG, VERSION });
    try old.mixClaims(c, shape, claims);
}
pub fn columnLogs(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, tree: old.ColumnTree) ![]u32 {
    const plan = try Plan.fromShape(shape, external);
    const cursor = try @import("block_v5_native_column_log_layout_v1.zig").Cursor.init(shape, external, tree);
    if (tree != .main or plan.len == 0) return cursor.allocate(a);
    if (try cursor.count() != plan.native_main_count) return error.InvalidNativeCapacityGeometry;
    const result = try a.alloc(u32, plan.mainCount());
    errdefer a.free(result);
    try cursor.write(result[0..plan.native_main_count]);
    for (plan.active()) |shard| @memset(result[shard.main_index..][0..2], shard.log_size);
    return result;
}

/// Native spans and the two constrained capacity-selector columns per shard
/// retain their original committed order, with no temporary geometry array.
pub fn requireColumnLogs(shape: *const statement.Blake3ExecutionStatement, external: u32, tree: old.ColumnTree, logs: []const u32) !void {
    const plan = try Plan.fromShape(shape, external);
    if (tree != .main or plan.len == 0) return old.requireColumnLogs(shape, external, tree, logs);
    if (logs.len != plan.mainCount()) return error.UntrustedNativeColumnGeometry;
    try old.requireColumnLogs(shape, external, tree, logs[0..plan.native_main_count]);
    for (plan.active()) |shard| if (!std.mem.allEqual(u32, logs[shard.main_index..][0..2], shard.log_size))
        return error.UntrustedNativeColumnGeometry;
}
/// Independently reconstructed fixed root depends only on capacity/roster.
pub fn fixedColumns(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32) ![]engine.pcs.ColumnEvaluation {
    const plan = try Plan.fromShape(shape, external);
    if (plan.len == 0) return @import("block_v5_native_frame_v1.zig").fixedColumns(a);
    const result = try a.alloc(engine.pcs.ColumnEvaluation, plan.fixed_count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column.values);
        a.free(result);
    }
    for (plan.active()) |shard| {
        result[initialized] = .{ .log_size = shard.log_size, .values = try @import("opcode_trace.zig").generateIsFirst(a, shard.log_size) };
        initialized += 1;
        const values = try a.alloc(core.fields.m31.M31, @as(usize, 1) << @intCast(shard.log_size));
        @memset(values, core.fields.m31.M31.one());
        result[initialized] = .{ .log_size = shard.log_size, .values = values };
        initialized += 1;
    }
    return result;
}
pub fn freeColumns(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation) void {
    for (columns) |column| a.free(column.values);
    a.free(columns);
}
