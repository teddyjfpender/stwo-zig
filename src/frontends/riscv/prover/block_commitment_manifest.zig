//! First-round transcript for independently sized block component instances.
//! This binds a census of PCS roots, not proof validity. Every receipt must
//! subsequently be checked against its actual proof by native AND recursive
//! verifiers. Not yet activated in the production block proof protocol.
const std = @import("std");
const core = @import("stwo_core");
const planning = @import("block_component_plan.zig");
const Channel = core.proof_suites.Blake3.Channel;
const Digest = [32]u8;
const family_count = @typeInfo(planning.Kind).@"enum".fields.len;
comptime {
    if (family_count != 7) @compileError("block manifest v1 component roster changed; bump its protocol version");
}
pub const Context = struct {
    /// Independently admitted program, input, output and execution statement.
    job_id: Digest,
    /// Versioned typed AIR relation registry, never the prover's chosen buses.
    relation_abi_id: Digest,
    config: core.pcs.PcsConfig,
    rows: [family_count]u64,
};
pub const Admission = struct {
    instance: planning.Instance,
    air_id: Digest,
    key_id: Digest,
    statement_id: Digest,
    /// Identity of all fixed/main/interaction column logs in declared order.
    geometry_id: Digest,
    fixed_root: Digest,
};
pub const Sealed = struct {
    digest: Digest,
    instance_count: u32,
    /// The new block protocol may draw shared relations only from this state.
    /// Existing leaf proofs still use their original local transcript.
    pub fn sharedChannel(self: Sealed) Channel {
        var channel = Channel{};
        channel.mixU32s(&.{ 0x42334348, 1, self.instance_count }); // B3CH v1
        channel.mixRoot(self.digest);
        return channel;
    }
};
/// Borrows immutable, independently admitted descriptors, not traces or PCS
/// schemes. The caller can discard each committed instance immediately after
/// append, then replay it under the sealed census with commitment equality.
pub const Builder = struct {
    admissions: []const Admission,
    channel: Channel,
    next: u32 = 0,
    sealed: bool = false,
    pub fn init(context: Context, admissions: []const Admission) !Builder {
        if (admissions.len == 0 or admissions.len > std.math.maxInt(u32)) return error.InvalidComponentCensus;
        // Only the currently qualified canonical security configuration.
        const canonical = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .n_queries = 70, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
        if (!std.meta.eql(context.config, canonical)) return error.InvalidBlockSecurity;
        var covered: [family_count]u64 = @splat(0);
        for (admissions, 0..) |admission, index| {
            const item = admission.instance;
            const kind = @intFromEnum(item.kind);
            if (item.index != index or item.log_rows == 0 or item.log_rows > 30 or item.rows == 0) return error.InvalidComponentCensus;
            if (item.first_row != covered[kind] or item.rows > item.capacity()) return error.InvalidComponentCoverage;
            covered[kind] = try std.math.add(u64, covered[kind], item.rows);
        }
        if (!std.meta.eql(covered, context.rows)) return error.InvalidComponentCoverage;
        var channel = Channel{};
        channel.mixU32s(&.{ 0x42334d46, 1, @intCast(admissions.len) }); // B3MF v1
        channel.mixRoot(context.job_id);
        channel.mixRoot(context.relation_abi_id);
        context.config.mixInto(&channel);
        for (context.rows) |rows| channel.mixU64(rows);
        // Freeze the entire admitted roster before accepting any main roots.
        for (admissions) |admission| {
            const item = admission.instance;
            channel.mixU32s(&.{ item.index, @intFromEnum(item.kind), item.log_rows });
            channel.mixU64(item.first_row);
            channel.mixU64(item.rows);
            channel.mixRoot(admission.air_id);
            channel.mixRoot(admission.key_id);
            channel.mixRoot(admission.statement_id);
            channel.mixRoot(admission.geometry_id);
            channel.mixRoot(admission.fixed_root);
        }
        return .{ .admissions = admissions, .channel = channel };
    }
    /// Roots must come from the actual PCS fixed/main trees. They are not
    /// witness-column hashes. Refused appends leave the builder unchanged.
    pub fn append(self: *Builder, index: u32, roots: [2]Digest) !void {
        if (self.sealed) return error.ManifestAlreadySealed;
        if (index != self.next or index >= self.admissions.len) return error.InvalidComponentOrder;
        if (!std.meta.eql(roots[0], self.admissions[index].fixed_root)) return error.UntrustedComponentRoot;
        self.channel.mixU32s(&.{index});
        self.channel.mixRoot(roots[0]);
        self.channel.mixRoot(roots[1]);
        self.next += 1;
    }
    pub fn seal(self: *Builder) !Sealed {
        if (self.sealed) return error.ManifestAlreadySealed;
        if (self.next != self.admissions.len) return error.IncompleteComponentManifest;
        self.sealed = true;
        self.channel.mixU32s(&.{ 0x42334d45, 1, self.next }); // B3ME v1
        return .{ .digest = self.channel.digestBytes(), .instance_count = self.next };
    }
};

test "block manifest binds exact three-instance coverage without dummy leaves" {
    const a = std.testing.allocator;
    var plan = try planning.create(a, &.{.{ .kind = .memory, .rows = 9, .columns = 8, .log_rows = &.{ 1, 2 } }}, .{ .source_bytes_per_instance = 128, .max_instances = 3 });
    defer plan.deinit();
    var admissions: [3]Admission = undefined;
    for (&admissions, plan.instances) |*admission, instance| admission.* = fixtureAdmission(instance);
    const context = fixtureContext();
    const reference = try fixtureManifest(context, &admissions, false);
    try std.testing.expectEqual(@as(u32, 3), reference.instance_count);
    const changed = try fixtureManifest(context, &admissions, true);
    try std.testing.expect(!std.meta.eql(reference.digest, changed.digest));
    try std.testing.expect(!std.meta.eql(reference.sharedChannel(), changed.sharedChannel()));
    var foreign_job = context;
    foreign_job.job_id[0] ^= 1;
    try std.testing.expect(!std.meta.eql(reference.digest, (try fixtureManifest(foreign_job, &admissions, false)).digest));
    inline for (.{ "air_id", "key_id", "statement_id", "geometry_id" }) |field| {
        var changed_admissions = admissions;
        @field(changed_admissions[1], field)[0] ^= 1;
        try std.testing.expect(!std.meta.eql(reference.digest, (try fixtureManifest(context, &changed_admissions, false)).digest));
    }
    var missing_work = context;
    missing_work.rows[@intFromEnum(planning.Kind.execution)] = 1;
    try std.testing.expectError(error.InvalidComponentCoverage, Builder.init(missing_work, &admissions));
    var insecure = context;
    insecure.config.pow_bits = 0;
    try std.testing.expectError(error.InvalidBlockSecurity, Builder.init(insecure, &admissions));
    var duplicate = admissions;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(error.InvalidComponentCensus, Builder.init(context, &duplicate));
}
test "block manifest refuses omissions reordering duplicate receipts and foreign fixed roots" {
    var admission = fixtureAdmission(.{ .index = 0, .kind = .memory, .first_row = 0, .rows = 9, .log_rows = 4, .source_bytes = 512 });
    var builder = try Builder.init(fixtureContext(), &.{admission});
    try std.testing.expectError(error.IncompleteComponentManifest, builder.seal());
    const before = builder.channel;
    try std.testing.expectError(error.InvalidComponentOrder, builder.append(1, .{ admission.fixed_root, @splat(7) }));
    admission.fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedComponentRoot, builder.append(0, .{ admission.fixed_root, @splat(7) }));
    try std.testing.expectEqualDeep(before, builder.channel);
    admission.fixed_root[0] ^= 1;
    try builder.append(0, .{ admission.fixed_root, @splat(7) });
    try std.testing.expectError(error.InvalidComponentOrder, builder.append(0, .{ admission.fixed_root, @splat(7) }));
    _ = try builder.seal();
    try std.testing.expectError(error.ManifestAlreadySealed, builder.seal());
    try std.testing.expectError(error.ManifestAlreadySealed, builder.append(1, .{ admission.fixed_root, @splat(7) }));
}
fn fixtureContext() Context {
    var rows: [family_count]u64 = @splat(0);
    rows[@intFromEnum(planning.Kind.memory)] = 9;
    return .{ .job_id = @splat(1), .relation_abi_id = @splat(2), .config = .{ .pow_bits = 26, .fri_config = .{ .n_queries = 70, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0 } }, .rows = rows };
}
fn fixtureAdmission(instance: planning.Instance) Admission {
    return .{ .instance = instance, .air_id = @splat(3), .key_id = @splat(4), .statement_id = @splat(5), .geometry_id = @splat(6), .fixed_root = @splat(7) };
}
fn fixtureManifest(context: Context, admissions: []const Admission, change_main: bool) !Sealed {
    var builder = try Builder.init(context, admissions);
    for (admissions) |admission| try builder.append(admission.instance.index, .{ admission.fixed_root, @splat(if (change_main) 9 else 8) });
    return builder.seal();
}
