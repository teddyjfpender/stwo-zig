//! Nonproving pre-proof semantic-policy, exact routing and custody tests.
//! Structural metadata never enters native admission, PCS or a positive proof
//! receiver. Complete factories/stages are retained as addresses separately.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Expected = @import("block_v5_page_recursive_expected_setup_v1.zig");
const Algebra = @import("../recursion/block_v5_memory_source_page_forest_algebra_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

test "PAGE expected setup: absent and legacy semantic policies never nominate expected constants" {
    inline for (.{ Semantic.Kind.raw, .fold }) |kind| try std.testing.expectError(error.MissingIndependentPageSemanticClaims, Policy.expectedClaims(kind, null));
    var raw = [_]Policy.RawRecord{.{ .pin = undefined, .artifact = undefined }};
    var fold = [_]Policy.FoldRecord{.{ .pin = undefined, .operands = undefined, .artifact = undefined }};
    var wire: Policy.Wire = undefined;
    wire.raw = &raw;
    wire.fold = &fold;
    wire.version = Policy.LEGACY_VERSION;
    try Policy.requireClaimVersion(wire); // Read-only, never fixed admission.
    wire.version = Policy.VERSION;
    try std.testing.expectError(error.MissingIndependentPageSemanticClaims, Policy.requireClaimVersion(wire));
    raw[0].expected_claims = Semantic.Claims.zero();
    try std.testing.expectError(error.MissingIndependentPageSemanticClaims, Policy.requireClaimVersion(wire));
    fold[0].expected_claims = Semantic.Claims.zero();
    try Policy.requireClaimVersion(wire);
    wire.version = Policy.LEGACY_VERSION;
    try std.testing.expectError(error.UnsupportedSourcePagePolicy, Policy.requireClaimVersion(wire));
    wire.version = Policy.VERSION + 1;
    try std.testing.expectError(error.UnsupportedSourcePagePolicy, Policy.requireClaimVersion(wire));
}
test "PAGE expected setup: exact independently proposed semantic cells reject every changed coordinate" {
    const original = Semantic.Claims.zero();
    inline for (.{ Semantic.Kind.raw, .fold }) |kind| {
        try Expected.requireClaims(kind, original, original);
        for (0..Algebra.CLAIM_COUNT) |index| {
            var flat = Algebra.flatten(original);
            flat[index] = Q.one();
            const decoded = Algebra.decode(Q, flat);
            const changed = Semantic.Claims{ .source = decoded.source, .indexed = decoded.indexed, .fold = decoded.fold };
            try std.testing.expectError(error.UntrustedPagePolicySemanticClaims, Expected.requireClaims(kind, original, changed));
        }
    }
    var noncanonical = original;
    noncanonical.indexed = Q.fromBase(.{ .v = core.fields.m31.Modulus });
    try std.testing.expectError(error.NoncanonicalPageForestClaims, Policy.expectedClaims(.raw, noncanonical));
}
fn claimsFault(a: std.mem.Allocator) !void {
    var proposal = Semantic.Claims.zero();
    proposal.source.bytes = Q.one();
    const bytes = try std.json.Stringify.valueAlloc(a, proposal, .{});
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(Semantic.Claims, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
    defer parsed.deinit();
    try Expected.requireClaims(.raw, proposal, parsed.value);
    parsed.value.source.bytes = Q.zero();
    try std.testing.expectError(error.UntrustedPagePolicySemanticClaims, Expected.requireClaims(.raw, proposal, parsed.value));
}
test "PAGE expected setup: semantic policy JSON owns exact canonical coordinates under all allocation faults" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, claimsFault, .{});
}
fn routing(comptime kind: Semantic.Kind) !void {
    const Bus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("../recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const Checks = Expected.ForKind(kind);
    const wires = [_]Bus.Wire{.{ .circuit = 1500, .wire = 2, .uses = 1, .source = .first_root, .coordinate = 0 }};
    const profile = Base.Profile.csp_q70_pow26;
    const context = Base.Context{ .child_key_id = @splat(3), .child_config = profile.config(), .graph_ids = .{ @splat(4), @splat(5), @splat(6) }, .transcript_plan_id = @splat(7) };
    const logs: [Storage.Airs.len]u32 = @splat(1);
    const key = try Protocol.Key.fromGeometry(.{ .profile = profile, .config = profile.config(), .context = context, .log_sizes = logs, .preprocessed_root = @splat(8) }, &wires);
    try Checks.requireMetadata(key, context, logs, &wires);
    inline for (.{ "child_key_id", "child_config", "graph_ids", "transcript_plan_id" }) |field| {
        var changed = context;
        if (comptime std.mem.eql(u8, field, "child_key_id")) changed.child_key_id[0] ^= 1 else if (comptime std.mem.eql(u8, field, "child_config")) changed.child_config.pow_bits -= 1 else if (comptime std.mem.eql(u8, field, "graph_ids")) changed.graph_ids[2][0] ^= 1 else changed.transcript_plan_id[0] ^= 1;
        try std.testing.expectError(error.UntrustedPageExpectedSetup, Checks.requireMetadata(key, changed, logs, &wires));
    }
    for (0..logs.len) |slot| {
        var changed = logs;
        changed[slot] += 1;
        try std.testing.expectError(error.UntrustedPageExpectedSetup, Checks.requireMetadata(key, context, changed, &wires));
    }
    inline for (.{ "circuit", "wire", "uses", "source", "coordinate" }) |field| {
        var changed = wires;
        if (comptime std.mem.eql(u8, field, "source")) changed[0].source = .word else @field(changed[0], field) += 1;
        try std.testing.expectError(error.UntrustedPageExpectedSetup, Checks.requireMetadata(key, context, logs, &changed));
    }
}
test "PAGE expected setup: raw and fold retain exact original contexts cohort logs and supply schedules" {
    try routing(.raw);
    try routing(.fold);
}
fn custody(a: std.mem.Allocator) !void {
    const Bus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(.raw);
    const Protocol = @import("../recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(.raw);
    const Returned = @import("../recursion/block_v5_memory_source_page_recursive_fixed_roster_v1.zig").ForKind(.raw).ForBackend(Cpu).KeyAndSchedule;
    const owner = try Budget.create(a, 64 << 10);
    var owns_budget = true;
    defer if (owns_budget) owner.destroy();
    const wires = try owner.allocator().dupe(Bus.Wire, &.{.{ .circuit = 1500, .wire = 2, .uses = 1, .source = .first_root, .coordinate = 0 }});
    var owns_wires = true;
    errdefer if (owns_wires) owner.allocator().free(wires);
    const profile = Base.Profile.csp_q70_pow26;
    const context = Base.Context{ .child_key_id = @splat(3), .child_config = profile.config(), .graph_ids = .{ @splat(4), @splat(5), @splat(6) }, .transcript_plan_id = @splat(7) };
    const key = try Protocol.Key.fromGeometry(.{ .profile = profile, .config = profile.config(), .context = context, .log_sizes = @splat(1), .preprocessed_root = @splat(8) }, wires);
    var metadata = Returned{ .allocator = owner.allocator(), .key = key, .wires = wires, .allocation_owner = owner.retain() };
    owns_wires = false;
    defer metadata.deinit();
    owner.destroy();
    owns_budget = false;
    try Expected.ForKind(.raw).requireMetadata(metadata.key, context, @splat(1), metadata.wires);
}
test "PAGE expected setup: returned routing metadata retains its allocator after caller release and faults" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, custody, .{});
}
test "PAGE expected setup: stage missing claims reject before capture or allocation with original security defaults" {
    inline for (.{ Semantic.Kind.raw, .fold }) |kind| {
        const Options = @import("block_v5_memory_source_page_recursive_stage_v1.zig").ForKind(kind).ForBackend(Cpu).Options;
        var options = Options{ .profile = .csp_q70_pow26 };
        try std.testing.expectError(error.MissingIndependentPageSemanticClaims, options.validate(options.profile.config()));
        options.expected_claims = Semantic.Claims.zero();
        try options.validate(options.profile.config());
        options.transcript_capacity = 0;
        try std.testing.expectError(error.PageFixedRosterResourceLimit, options.validate(options.profile.config()));
        options.transcript_capacity = 2;
        options.profile = .diagnostic_q8_pow0;
        try std.testing.expectError(error.SourcePageRecursiveSecurityMismatch, options.validate(Base.Profile.csp_q70_pow26.config()));
    }
}
test "PAGE expected setup: closed node metadata preserves every original context and cohort with no external terms" {
    const profile = Base.Profile.csp_q70_pow26;
    const context = Base.Context{ .child_key_id = @splat(3), .child_config = profile.config(), .graph_ids = .{ @splat(4), @splat(5), @splat(6) }, .transcript_plan_id = @splat(7) };
    const logs: [Storage.Airs.len]u32 = @splat(1);
    const geometry = Base.Key{ .profile = profile, .config = profile.config(), .context = context, .log_sizes = logs, .preprocessed_root = @splat(8) };
    try Expected.requireNodeMetadata(geometry, context, logs, &.{});
    var changed = context;
    changed.graph_ids[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedPageExpectedSetup, Expected.requireNodeMetadata(geometry, changed, logs, &.{}));
    for (0..logs.len) |index| {
        var other = logs;
        other[index] += 1;
        try std.testing.expectError(error.UntrustedPageExpectedSetup, Expected.requireNodeMetadata(geometry, context, other, &.{}));
    }
    const Wire = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig").Wire;
    const nonempty: [1]Wire = undefined; // Only length is read by the guard.
    try std.testing.expectError(error.UntrustedPageExpectedSetup, Expected.requireNodeMetadata(geometry, context, logs, &nonempty));
    var limits = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig").Limits{};
    try limits.validate();
    limits.fixed.max_bytes = 0;
    try std.testing.expectError(error.InvalidPageForestPolicyLimits, limits.validate());
    limits.fixed.max_bytes = 2 << 30;
    limits.node_fixed.max_live_bytes = 0;
    try std.testing.expectError(error.PageForestFixedResourceLimit, limits.validate());
}
