//! Metadata parity checks do not admit a key, instantiate an original policy,
//! verify a capture or invoke any commitment. Original production bodies are
//! retained separately; full fixed/live/root parity remains a proof obligation.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("block_v5_recursive_provider_definition_v1.zig");
const Stores = @import("block_v5_recursive_provider_store_v1.zig");
const Derive = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const FixedKey = @import("../recursion/blake3_parent_fixed_key_v1.zig");
fn metadata(comptime family: @import("block_v5_recursive_provider_family_v1.zig").Family) !void {
    const Bus = D.ForFamily(family).Bus;
    const Protocol = D.ForFamily(family).Protocol;
    const Template = Stores.ForFamily(family).TemplatePolicy;
    const profile = Base.Profile.csp_q70_pow26;
    const wires = [_]Bus.Wire{.{ .circuit = 1500, .wire = 2, .uses = 1, .source = .main_root, .coordinate = 0 }};
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    var rows: [3]Storage.FixedRow(Storage.Airs[3]) = @splat(@splat(core.fields.m31.M31.zero()));
    fixed[3] = &rows;
    const context = Base.Context{ .child_key_id = @splat(3), .child_config = profile.config(), .graph_ids = .{ @splat(4), @splat(5), @splat(6) }, .transcript_plan_id = @splat(7) };
    const geometry = Base.Key{ .profile = profile, .config = profile.config(), .context = context, .log_sizes = try FixedKey.rowLogs(fixed), .preprocessed_root = @splat(8) };
    const key = try Protocol.Key.fromGeometry(geometry, &wires);
    const template = Template{ .key = key, .key_id = try key.identity(), .schedule = &wires };
    // Untrusted metadata proposals only; no original Prepared, MAIN or
    // successful source/policy constructor is synthesized.
    var live_context = context;
    var live_fixed = fixed;
    var live_wires: []const Bus.Wire = &wires;
    try Derive.requirePolicyMetadata(family, template, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile);
    live_context.child_key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, template, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile));
    live_context = context;
    live_fixed[3] = rows[0..2];
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, template, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile));
    live_fixed[3] = &rows;
    var changed = template;
    changed.key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, changed, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile));
    var other_wires = wires;
    other_wires[0].uses += 1;
    live_wires = &other_wires;
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, template, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile));
    // Changing both proposed schedules cannot preserve the key-bound schedule.
    changed = template;
    changed.schedule = &other_wires;
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, changed, live_context, try FixedKey.rowLogs(live_fixed), live_wires, profile));
    live_wires = &wires;
    try std.testing.expectError(error.UntrustedIndependentWordTemplate, Derive.requirePolicyMetadata(family, template, live_context, try FixedKey.rowLogs(live_fixed), live_wires, .diagnostic_q8_pow0));
}
test "word expected setup: RAM live metadata rejects changed context key row geometry and schedule" {
    try metadata(.ram_lanes);
}
test "word expected setup: range live metadata retains canonical security and exact routing" {
    try metadata(.range16);
}
test "word expected setup: original driver options independently bound retained setup metadata" {
    const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
    var options = Publication.Options{};
    try options.validate();
    options.max_word_template_metadata_bytes = 0;
    try std.testing.expectError(error.InvalidCpuRecursivePublicationOptions, options.validate());
    const Forest = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
    var limits = Forest.Limits{};
    try limits.validate();
    limits.max_word_template_metadata_bytes = 0;
    try std.testing.expectError(error.InvalidRamForestOwnerLimits, limits.validate());
}
test {
    _ = @import("block_v5_word_expected_setup_cache_v1.zig");
}
