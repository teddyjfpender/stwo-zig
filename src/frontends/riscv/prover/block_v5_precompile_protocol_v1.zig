//! Independent typed SHA/Keccak/signer family under the shared B5SS VM buses.
//! Caller roots contain extension columns only. They do not alias native
//! opcode roots or authorize a complete block until global providers close.
const std = @import("std");
const core = @import("stwo_core");
const profile = @import("blake3_ethereum_sha_profile.zig");
const Statement = profile.admission.Statement;
const seal = @import("block_v5_source_seal_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");

pub const TAG: u32 = 0x42355046; // B5PF
pub const execution_recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
pub const VERSION: u32 = execution_recipe.callerProtocolVersion();
pub const circuit_profile: @import("ethereum_circuit_profile_v1.zig").CircuitProfileV1 = execution_recipe.callerProfile();
pub const Digest = [32]u8;
pub const CallerBinding = struct {
    execution_index: u32,
    execution_instance_id: Digest,
    caller_entry_index: u32,
    caller_instance_id: Digest,
    caller_key_id: Digest,
    first_roots: seal.Roots,
    sealed_digest: Digest,
};

pub fn validate(statement: *const Statement, total_steps: u32, config: core.pcs.PcsConfig) !void {
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    try validateGeometry(statement, total_steps);
    if (profile.externalCount(statement) == 0) return error.EmptyBlockV5PrecompileFamily;
}

pub fn validateGeometry(statement: *const Statement, total_steps: u32) !void {
    try circuit_profile.requireCallerExecution(profile.execution_profile);
    try execution_recipe.requireCaller(statement, total_steps);
}

pub fn keyId(statement: *const Statement, total_steps: u32, config: core.pcs.PcsConfig, fixed_root: Digest) !Digest {
    try validate(statement, total_steps, config);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, total_steps, @intFromEnum(profile.execution_profile), @intFromEnum(circuit_profile) });
    config.mixInto(&channel);
    channel.mixRoot(@import("../air/lang/relation.zig").registryOrderDigest());
    statement.ethereum.mixValidatedInto(&channel);
    try statement.sha.mixIntoForRecipe(&channel, circuit_profile.localZeroCustody());
    channel.mixRoot(fixed_root);
    return channel.digestBytes();
}

pub fn instanceId(key_id: Digest, execution_instance_id: Digest, index: u32, roots: seal.Roots) Digest {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, index });
    channel.mixRoot(key_id);
    channel.mixRoot(execution_instance_id);
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    return channel.digestBytes();
}

pub fn drawRelations(a: std.mem.Allocator, sealed: seal.Sealed) !profile.Relations {
    var channel = sealed.sharedChannel();
    const vm = try universal.UniversalRelations.draw(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(circuit_profile) });
    return profile.Relations.drawAfterVm(a, &channel, vm);
}

pub fn pcsChannel(a: std.mem.Allocator, sealed: seal.Sealed, binding: CallerBinding) !core.proof_suites.Blake3.Channel {
    var channel = sealed.sharedChannel();
    // Replay the shared prefix and extension suffix linearly. Future recursive
    // verification can use the same transcript machine without branch/reset.
    const vm = try universal.UniversalRelations.draw(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(circuit_profile) });
    _ = try profile.Relations.drawAfterVm(a, &channel, vm);
    channel.mixU32s(&.{ TAG, VERSION, binding.execution_index });
    channel.mixRoot(binding.execution_instance_id);
    channel.mixRoot(binding.caller_key_id);
    channel.mixRoot(binding.caller_instance_id);
    channel.mixRoot(binding.first_roots[0]);
    channel.mixRoot(binding.first_roots[1]);
    return channel;
}

pub fn admit(binding: CallerBinding, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    try sealed.require(pins, entries);
    try execution_recipe.requireMode(sealed.register_custody_mode);
    if (binding.execution_index >= sealed.execution_instance_count or
        binding.caller_entry_index != binding.execution_index or
        !std.meta.eql(binding.sealed_digest, sealed.digest) or
        !std.meta.eql(binding.caller_instance_id, instanceId(binding.caller_key_id, binding.execution_instance_id, binding.execution_index, binding.first_roots)))
        return error.UntrustedBlockV5PrecompileInstance;
    var execution_found = false;
    var precompile_found = false;
    for (entries) |entry| {
        if (entry.family == .execution and entry.index == binding.execution_index) {
            if (!std.meta.eql(entry.instance_id, binding.execution_instance_id))
                return error.UntrustedBlockV5PrecompileExecution;
            execution_found = true;
        }
        if (entry.family == .precompile and entry.index == binding.caller_entry_index) {
            if (!std.meta.eql(entry.instance_id, binding.caller_instance_id) or
                !std.meta.eql(entry.roots, binding.first_roots))
                return error.UntrustedBlockV5PrecompileRoots;
            precompile_found = true;
        }
    }
    if (!execution_found or !precompile_found) return error.MissingBlockV5PrecompileInstance;
}

pub const Tree = enum { fixed, main, interaction };
pub fn columnLogs(a: std.mem.Allocator, statement: *const Statement, tree: Tree) ![]u32 {
    try validateGeometry(statement, profile.externalCount(statement));
    var logs: std.ArrayList(u32) = .empty;
    errdefer logs.deinit(a);
    for (profile.descriptors(statement)) |desc| {
        const width = switch (tree) {
            .fixed => desc.preprocessed_columns,
            .main => desc.main_columns,
            .interaction => desc.interaction_columns,
        };
        try logs.appendNTimes(a, desc.log_size, width);
    }
    return logs.toOwnedSlice(a);
}
