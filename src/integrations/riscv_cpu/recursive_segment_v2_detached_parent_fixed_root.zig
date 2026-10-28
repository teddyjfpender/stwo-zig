//! Commit a proof-free parent Tree 0 using only child keys and a proposed
//! manifest. Admission must independently derive and check that manifest and
//! compare the returned root with the pinned parent key before proof loading.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const cohort = recursion.detached_parent_prepared_v1;
const protocol = recursion.detached_parent_protocol_v1;
const storage = recursion.transaction_storage_v2;
const M31 = @import("stwo_core").fields.m31.M31;
const Digest = recursion.poseidon2_channel.Digest;

/// Admit a two-segment parent without opening either child proof or the parent
/// proof. The key bytes and their hashes are supplied independently of any
/// candidate bundle. The child native Tree0 roots are checked first, then the
/// entire parent Tree0 is rebuilt from those admitted child keys.
pub fn admitSegmentParentFromPinnedKeys(comptime Engine: type, allocator: std.mem.Allocator, parent_bytes: []const u8, parent_pin: [32]u8, child_bytes: [2][]const u8, child_pins: [2][32]u8) !Digest {
    const parent = try recursion.detached_parent_command_v1.OwnedKeyV1.admit(allocator, parent_bytes, parent_pin);
    defer parent.deinit();
    for (child_pins, parent.key().child_key_sha256) |pin, committed| {
        if (!std.meta.eql(pin, committed)) return error.DetachedParentChildKeyPinMismatch;
    }
    const ChildKey = recursion.detached_segment_command_v1.OwnedKeyV1;
    var children: [2]*ChildKey = undefined;
    var initialized: usize = 0;
    defer for (children[0..initialized]) |child| child.deinit();
    for (child_bytes, child_pins, &children) |bytes, pin, *child| {
        child.* = try ChildKey.admitWithNativeRoot(Engine, allocator, bytes, pin);
        initialized += 1;
        const leaf_root = try @import("recursive_segment_v2_detached_proof.zig").rebuildFixedRootFromKey(allocator, child.*.key());
        if (!std.meta.eql(leaf_root, child.*.key().preprocessed_root))
            return error.DetachedParentChildRootMismatch;
    }
    try parent.key().fixed_recipe.validateAgainstChildKeys(.segment, allocator, .{ children[0].key(), children[1].key() });
    const rebuilt = try rootFromKeysAgainstManifest(Engine, .segment, allocator, .{ children[0].key(), children[1].key() }, parent.key().publication_mode, &parent.key().manifest, &parent.key().parameters, parent.key().profile);
    if (!std.meta.eql(rebuilt, parent.key().preprocessed_root))
        return error.DetachedParentPreprocessedCommitmentMismatch;
    return rebuilt;
}

pub fn rootFromKeysAgainstManifest(comptime Engine: type, comptime family: recursion.detached_child_capture_v1.Family, allocator: std.mem.Allocator, keys: anytype, mode: protocol.PublicationMode, manifest: *const cohort.manifest_mod.Manifest, parameters: *const cohort.ParametersV1, profile: protocol.ProfileV1) !Digest {
    try recursion.detached_parent_key_manifest_v1.assertMatches(family, allocator, keys, mode, manifest, parameters);
    const TreeStorage = storage.TreeStorageForManifest(Engine, cohort.manifest_mod);
    var scheme = try Engine.init(allocator, profile.pcsConfig());
    defer Engine.deinit(&scheme, allocator);
    var channel: Engine.Channel = .{};
    var tree = try TreeStorage.init(allocator, manifest, 0);
    defer tree.deinit();
    try recursion.detached_parent_fixed_tree0_rebuild_v1.fillFromChildKeys(family, allocator, keys, mode, manifest, tree.columns);
    try tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.DetachedParentPreprocessedCommitmentMismatch;
    return roots.items[0];
}

pub fn testAgainstPreparedColumns(comptime family: recursion.detached_child_capture_v1.Family, allocator: std.mem.Allocator, keys: anytype, mode: protocol.PublicationMode, manifest: *const cohort.manifest_mod.Manifest, parameters: *const cohort.ParametersV1, prepared_columns: [][]M31) !void {
    const recipe_family: recursion.detached_parent_fixed_recipe_v1.ChildFamily = if (family == .segment) .segment else .parent;
    var recipe = try recursion.detached_parent_fixed_recipe_v1.FixedRecipeV1.fromChildKeys(recipe_family, allocator, keys);
    try recipe.validateAgainstChildKeys(recipe_family, allocator, keys);
    recipe.children[0].sampled_value_count += 1;
    try std.testing.expectError(error.DetachedParentFixedRecipeMismatch, recipe.validateAgainstChildKeys(recipe_family, allocator, keys));
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const TreeStorage = storage.TreeStorageForManifest(Engine, cohort.manifest_mod);
    const profile: protocol.ProfileV1 = .recursive_q193_v1;
    var scheme = try Engine.init(allocator, profile.pcsConfig());
    defer Engine.deinit(&scheme, allocator);
    var channel: Engine.Channel = .{};
    var tree = try TreeStorage.init(allocator, manifest, 0);
    defer tree.deinit();
    if (tree.columns.len != prepared_columns.len) return error.DetachedParentDestinationMismatch;
    for (tree.columns, prepared_columns) |destination, source| {
        if (destination.len != source.len) return error.DetachedParentDestinationMismatch;
        @memcpy(destination, source);
    }
    try tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.DetachedParentPreprocessedCommitmentMismatch;
    const rebuilt = try rootFromKeysAgainstManifest(Engine, family, allocator, keys, mode, manifest, parameters, profile);
    try std.testing.expectEqualDeep(roots.items[0], rebuilt);
    if (comptime family == .parent) {
        var wrong_count = parameters.*;
        if (wrong_count.poseidon_active_rows == 0) return error.DetachedParentParameterMismatch;
        wrong_count.poseidon_active_rows -= 1;
        try std.testing.expectError(
            error.DetachedParentParameterMismatch,
            rootFromKeysAgainstManifest(Engine, family, allocator, keys, mode, manifest, &wrong_count, profile),
        );
        var changed_words: [2]M31 = .{ parameters.words[0][0], parameters.words[0][1] };
        changed_words[0] = if (changed_words[0].eql(M31.zero())) M31.one() else M31.zero();
        var wrong_parameter = parameters.*;
        wrong_parameter.words[0] = &changed_words;
        try std.testing.expectError(
            error.DetachedParentParameterMismatch,
            rootFromKeysAgainstManifest(Engine, family, allocator, keys, mode, manifest, &wrong_parameter, profile),
        );
    }
}

test "SegmentV2 distinct segment keys reproduce parent graph fixed rows through proof-free admission" {
    const allocator = std.testing.allocator;
    const parent_dir = std.process.getEnvVarOwned(allocator, "STWO_DETACHED_PARENT_BUNDLE") catch return error.SkipZigTest;
    defer allocator.free(parent_dir);
    const left_dir = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_BUNDLE") catch return error.SkipZigTest;
    defer allocator.free(left_dir);
    const right_dir = std.process.getEnvVarOwned(allocator, "STWO_DETACHED_OTHER_SEGMENT_BUNDLE") catch return error.SkipZigTest;
    defer allocator.free(right_dir);
    const parent_pin_hex = std.process.getEnvVarOwned(allocator, "STWO_DETACHED_PARENT_KEY_SHA256") catch return error.SkipZigTest;
    defer allocator.free(parent_pin_hex);
    const left_pin_hex = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_KEY_SHA256") catch return error.SkipZigTest;
    defer allocator.free(left_pin_hex);
    const right_pin_hex = std.process.getEnvVarOwned(allocator, "STWO_DETACHED_OTHER_SEGMENT_KEY_SHA256") catch return error.SkipZigTest;
    defer allocator.free(right_pin_hex);
    var parent_pin: [32]u8 = undefined;
    var child_pins: [2][32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&parent_pin, parent_pin_hex);
    _ = try std.fmt.hexToBytes(&child_pins[0], left_pin_hex);
    _ = try std.fmt.hexToBytes(&child_pins[1], right_pin_hex);
    const parent_path = std.process.getEnvVarOwned(allocator, "STWO_DETACHED_PARENT_KEY_PATH") catch try std.fs.path.join(allocator, &.{ parent_dir, "key.json" });
    defer allocator.free(parent_path);
    const left_path = try std.fs.path.join(allocator, &.{ left_dir, "key.json" });
    defer allocator.free(left_path);
    const right_path = try std.fs.path.join(allocator, &.{ right_dir, "key.json" });
    defer allocator.free(right_path);
    const parent_bytes = try std.fs.cwd().readFileAlloc(allocator, parent_path, recursion.detached_parent_command_v1.MAX_KEY_BYTES);
    defer allocator.free(parent_bytes);
    const left_bytes = try std.fs.cwd().readFileAlloc(allocator, left_path, recursion.detached_segment_command_v1.MAX_KEY_BYTES);
    defer allocator.free(left_bytes);
    const right_bytes = try std.fs.cwd().readFileAlloc(allocator, right_path, recursion.detached_segment_command_v1.MAX_KEY_BYTES);
    defer allocator.free(right_bytes);
    const child_bytes = [2][]const u8{ left_bytes, right_bytes };
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    _ = try admitSegmentParentFromPinnedKeys(Engine, allocator, parent_bytes, parent_pin, child_bytes, child_pins);

    var wrong_child_pin = child_pins;
    wrong_child_pin[0][0] ^= 1;
    try std.testing.expectError(error.DetachedParentChildKeyPinMismatch, admitSegmentParentFromPinnedKeys(Engine, allocator, parent_bytes, parent_pin, child_bytes, wrong_child_pin));

    var parsed = try std.json.parseFromSlice(protocol.KeyV1, allocator, parent_bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const modulus = @import("stwo_core").fields.m31.Modulus;
    parsed.value.preprocessed_root[0] = (parsed.value.preprocessed_root[0] + 1) % modulus;
    const hostile_bytes = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(hostile_bytes);
    const hostile_pin = recursion.detached_parent_command_v1.hash(hostile_bytes);
    try std.testing.expectError(error.DetachedParentPreprocessedCommitmentMismatch, admitSegmentParentFromPinnedKeys(Engine, allocator, hostile_bytes, hostile_pin, child_bytes, child_pins));
}
