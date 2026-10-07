//! Sealed two-header circuit + packed SHA proof profile.
//!
//! This is verifier-owned metadata, never parsed from the proof. Its exact
//! component order is four sparse-wide circuit AIRs, four packed SHA AIRs,
//! two private SHA callers, and two lookup tables. Each caller has separate
//! circuit Gate and SHA wire lookup claims.
const std = @import("std");
const core = @import("stwo_core");
const provider = @import("s31_sha_provider");
const sha = @import("sha_chip_profile.zig");
const caller = @import("sha_caller_equations.zig");

pub const format_version: u32 = 1;
pub const transcript_domain: u32 = 0x53335332; // S3S2
pub const first_call_id: u32 = 1;
pub const call_count: u32 = 6;
pub const header_count: usize = 2;
pub const public_output_count: u32 = 8;
pub const circuit_component_count: usize = 4;
pub const sha_component_count: usize = 4;
pub const caller_component_index: usize = 8;
pub const caller_component_count: usize = header_count;
pub const table_component_count: usize = 2;
pub const component_count: usize = circuit_component_count + sha_component_count + caller_component_count + table_component_count;
pub const claimed_sum_count: usize = component_count + caller_component_count; // each caller has Gate and SHA sums
pub const gate_address_count: usize = caller.gate_limb_count;
pub const component_names = [_][]const u8{
    "circuit_eq",       "circuit_qm31",     "circuit_m31_to_u32", "circuit_range16",
    "sha_source",       "sha_schedule",     "sha_round",          "sha_feed_forward",
    "s31_sha_caller_0", "s31_sha_caller_1", "table_bitwise",      "table_range_8_8",
};

pub const Table = struct { kind: u8, log_size: u32, arity: u32 };
pub const tables: [table_component_count]Table = blk: {
    var descriptors: [table_component_count]Table = undefined;
    for (provider.joint_lookup_kinds, &descriptors) |kind, *descriptor| descriptor.* = .{
        .kind = @intFromEnum(kind),
        .log_size = provider.schema.logSize(kind),
        .arity = @intCast(provider.schema.arity(kind)),
    };
    break :blk descriptors;
};

/// The committed caller AIR's sealed widths and degree.
pub const CallerShape = struct {
    log_size: u32 = 4,
    main_columns: u32 = 440,
    interaction_columns: u32 = 304,
    direct_constraints: u32 = caller.constraint_count,
    logup_constraints: u32 = 76,
    maximum_degree: u32 = 3,
};

pub const Profile = struct {
    source_digest: [32]u8,
    circuit_logs: [4]u32,
    n_vars: u32,
    gate_addresses: [header_count][gate_address_count]u32,
    pcs: core.pcs.config_v2.PcsConfigV2,
    sha_components: [sha_component_count]sha.Descriptor,
    caller_shape: CallerShape,
    table_roster: [table_component_count]Table,

    pub fn canonical(
        source_digest: [32]u8,
        circuit_logs: [4]u32,
        n_vars: u32,
        gate_addresses: [header_count][gate_address_count]u32,
        pcs: core.pcs.config_v2.PcsConfigV2,
    ) !Profile {
        try validateInputs(circuit_logs, n_vars, gate_addresses, pcs);
        const sha_profile = try sha.Profile.canonical(call_count);
        return .{
            .source_digest = source_digest,
            .circuit_logs = circuit_logs,
            .n_vars = n_vars,
            .gate_addresses = gate_addresses,
            .pcs = pcs,
            .sha_components = sha_profile.descriptors[0..sha_component_count].*,
            .caller_shape = .{},
            .table_roster = tables,
        };
    }

    pub fn validate(self: Profile) !void {
        const expected = try canonical(self.source_digest, self.circuit_logs, self.n_vars, self.gate_addresses, self.pcs);
        if (!std.meta.eql(self, expected)) return error.InvalidS31ShaJointProfile;
    }

    /// Mix before the fixed-tree commitment. The prover and native verifier
    /// call this exact method, then mix the FRI config using its native API.
    pub fn mixInto(self: Profile, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ transcript_domain, format_version, component_count, claimed_sum_count, call_count, header_count, first_call_id, public_output_count, self.n_vars });
        try mixBytes(channel, self.source_digest);
        channel.mixU32s(&self.circuit_logs);
        for (self.gate_addresses) |addresses| channel.mixU32s(&addresses);
        channel.mixU32s(&.{
            self.pcs.fri_config.pow_bits,
            self.pcs.fri_config.log_blowup_factor,
            self.pcs.fri_config.log_last_layer_degree_bound,
            self.pcs.fri_config.n_queries,
            self.pcs.fri_config.fold_step,
            self.pcs.trace_lifting_log_size,
            self.pcs.preprocessed_lifting_log_size,
        });
        try mixBytes(channel, circuitAirDigest());
        for (self.sha_components, 0..) |descriptor, index| {
            channel.mixU32s(&.{ @intCast(index + circuit_component_count), descriptor.live_rows, descriptor.log_size, descriptor.preprocessed_columns, descriptor.main_columns, descriptor.interaction_columns, descriptor.direct_constraints, descriptor.interaction_batches, descriptor.maximum_degree });
            try mixBytes(channel, descriptor.semantic_digest);
        }
        for (0..header_count) |index| channel.mixU32s(&.{
            @intCast(caller_component_index + index),
            @intCast(first_call_id + 3 * index),
            self.caller_shape.log_size,
            self.caller_shape.main_columns,
            self.caller_shape.interaction_columns,
            self.caller_shape.direct_constraints,
            self.caller_shape.logup_constraints,
            self.caller_shape.maximum_degree,
        });
        // The caller component publishes the same digest over these two
        // source files; its equations and quotient evaluator are key-bound.
        try mixBytes(channel, callerAirDigest());
        try mixBytes(channel, provider.tableSchemaSourceDigest());
        try mixBytes(channel, provider.tableInteractionSourceDigest());
        for (self.table_roster, 0..) |table, index|
            channel.mixU32s(&.{ @intCast(caller_component_index + caller_component_count + index), table.kind, table.log_size, table.arity });
    }

    /// A relying party pins this digest together with the preprocessed root.
    /// It cannot substitute for verifying the one-proof AIR and LogUp claims.
    pub fn keyDigest(self: Profile, preprocessed_root: [32]u8) ![32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("S31-SHA-JOINT-BATCH2-SEALED-KEY-V1\x00");
        const Sink = struct {
            hasher: *std.crypto.hash.sha2.Sha256,
            pub fn mixU32s(ctx: *@This(), values: []const u32) void {
                var bytes: [4]u8 = undefined;
                for (values) |value| {
                    std.mem.writeInt(u32, &bytes, value, .little);
                    ctx.hasher.update(&bytes);
                }
            }
        };
        var sink = Sink{ .hasher = &hasher };
        try self.mixInto(&sink);
        hasher.update(&preprocessed_root);
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return digest;
    }

    /// Domain-separated circuit identity mixed after the canonical fixed
    /// commitment and before the public ABI. A generic sparse-wide proof
    /// cannot replay as a circuit+SHA proof even with the same source and root.
    pub fn circuitIdentity(self: Profile, preprocessed_root: [32]u8) ![32]u8 {
        const key = try self.keyDigest(preprocessed_root);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("S31-SHA-JOINT-BATCH2-CIRCUIT-ID-V1\x00");
        hasher.update(&key);
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return digest;
    }
};

fn validateInputs(logs: [4]u32, n_vars: u32, addresses: [header_count][gate_address_count]u32, pcs: core.pcs.config_v2.PcsConfigV2) !void {
    if (n_vars <= 3 or n_vars >= core.fields.m31.Modulus) return error.InvalidShaJointVariableCount;
    for (logs[0..3]) |log| if (log < 4 or log > 30) return error.InvalidShaJointCircuitShape;
    if (logs[3] != 16) return error.InvalidShaJointCircuitShape;
    for (addresses, 0..) |group, group_index| for (group, 0..) |address, i| {
        if (address <= 2 or address >= n_vars) return error.InvalidShaJointGateAddress;
        for (group[0..i]) |earlier| if (earlier == address) return error.InvalidShaJointGateAddress;
        for (addresses[0..group_index]) |earlier_group| for (earlier_group) |earlier|
            if (earlier == address) return error.InvalidShaJointGateAddress;
    };
    const fri = pcs.fri_config;
    if (fri.pow_bits != 26 or fri.log_blowup_factor != 1 or fri.log_last_layer_degree_bound != 0 or fri.n_queries != 70 or fri.fold_step != 1)
        return error.InvalidShaJointPcsConfig;
    var max_log: u32 = 18; // bitwise table; SHA emits no 20-bit table requests
    for (logs) |log| max_log = @max(max_log, log);
    const expected = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, max_log);
    if (!std.meta.eql(pcs, expected)) return error.InvalidShaJointPcsConfig;
}

fn callerAirDigest() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("sha_caller_air.zig"));
    hasher.update(@embedFile("sha_caller_equations.zig"));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

pub fn circuitAirDigest() [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2") catch unreachable;
    return result;
}

fn mixBytes(channel: anytype, bytes: [32]u8) !void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

test "two-header SHA key rejects changed addresses, roster, PCS and root replay" {
    var addresses: [header_count][gate_address_count]u32 = undefined;
    for (&addresses, 0..) |*group, group_index| {
        for (group, 0..) |*address, i|
            address.* = @intCast(3 + group_index * gate_address_count + i);
    }
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, 18);
    const profile = try Profile.canonical(@splat(7), .{ 8, 9, 8, 16 }, 120, addresses, pcs);
    try profile.validate();
    const digest = try profile.keyDigest(@splat(11));
    const identity = try profile.circuitIdentity(@splat(11));
    try std.testing.expect(!std.meta.eql(digest, try profile.keyDigest(@splat(12))));
    try std.testing.expect(!std.meta.eql(identity, try profile.circuitIdentity(@splat(12))));
    var changed = profile;
    changed.gate_addresses[0][0] = 119;
    try std.testing.expect(!std.meta.eql(digest, try changed.keyDigest(@splat(11))));
    changed = profile;
    changed.sha_components[0].semantic_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidS31ShaJointProfile, changed.keyDigest(@splat(11)));
    changed = profile;
    changed.table_roster[0].arity += 1;
    try std.testing.expectError(error.InvalidS31ShaJointProfile, changed.keyDigest(@splat(11)));
    changed = profile;
    changed.pcs.fri_config.n_queries = 1;
    try std.testing.expectError(error.InvalidShaJointPcsConfig, changed.keyDigest(@splat(11)));
    addresses[1][0] = addresses[0][0];
    try std.testing.expectError(error.InvalidShaJointGateAddress, Profile.canonical(@splat(7), .{ 8, 9, 8, 16 }, 120, addresses, pcs));
}
