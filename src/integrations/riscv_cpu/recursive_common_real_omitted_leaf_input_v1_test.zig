const std = @import("std");

const leaf_support = @import("ethereum_block_leaf_support.zig");
const bundle = @import("ethereum_provider_omitted_leaf_bundle_v1.zig");
const subject = @import("recursive_common_real_omitted_leaf_input_v1.zig");

const Engine = leaf_support.RecursiveEngine;

test "real omitted wrapper cold-open API type instantiates" {
    _ = &instantiateColdOpen;
}

fn instantiateColdOpen(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    authority: bundle.Authority(Engine),
    limits: bundle.Limits,
) !void {
    var opened = try subject.FreshInputV1(Engine).coldOpen(
        allocator,
        bytes,
        authority,
        limits,
    );
    defer opened.deinit();
    try opened.validate(authority, bytes);
    const view: subject.LiveViewV1(Engine) = opened.liveView();
    try view.ordinary_h1.validateCaptureCustody(authority);
    try view.node_authority.validate();
    try view.node_public.validate();
}

test "real omitted wrapper remains unavailable before q193 cold proof" {
    const status = subject.currentStatus();
    try status.validate();
    try std.testing.expect(status.native_bundle_cold_verify_available);
    try std.testing.expect(status.fixed_node_public_derived);
    try std.testing.expect(!status.wrapper_proof_available);
    try std.testing.expect(!status.wrapper_transport_available);
    try std.testing.expect(!status.wrapper_cold_geometry_available);
    try std.testing.expect(!status.production_activation);
    try std.testing.expectEqual(
        subject.MissingAuthorityV1.common_wrapper_one_leaf_cohort,
        status.first_missing,
    );

    var mutation = status;
    mutation.wrapper_proof_available = true;
    try std.testing.expectError(
        error.InvalidRealOmittedLeafWrapperStatus,
        mutation.validate(),
    );
}
