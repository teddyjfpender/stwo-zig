const std = @import("std");
const command = @import("recursive_segment_v2_detached_leaf_options.zig");
const pin = "ab" ** 32;
const valid = [_][]const u8{ "--memory-addresses", "16", "--segment-count", "1", "--segments-output", "new-output", "--child-0-key", "key.json", "--child-0-key-sha256", pin };

test "detached leaf command selects only canonical output and admitted keys" {
    const options = try command.parse(&valid);
    try std.testing.expectEqual(command.Profile.recursive_q193_v1, options.proof_profile);
    try std.testing.expectEqual(command.Backend.cpu, options.native_backend);
    try std.testing.expectEqual(command.Backend.cpu, options.recursive_backend);
    try std.testing.expectEqual(@as(usize, 1), options.segment_count);
    try std.testing.expectEqual(@as(usize, 16), options.address_count);
    try std.testing.expectEqualStrings("new-output", options.directory);
    try std.testing.expectEqualStrings(pin, options.child_key_pins[0].?);
    try std.testing.expectError(error.InvalidArguments, command.parse(&.{}));
    try std.testing.expectError(error.SegmentOutputRequired, command.parse(&.{ "--memory-addresses", "1" }));
    try std.testing.expectError(error.MissingDetachedKeyAdmission, command.parse(&.{ "--memory-addresses", "1", "--segments-output", "new-output" }));
}

test "detached leaf command rejects retired routes duplicates and malformed pins" {
    inline for (.{ "--native-steps", "--native-ingress-profile", "--initial-register7", "--two-segment-output", "--check-workload" }) |flag|
        try std.testing.expectError(error.InvalidArguments, command.parse(&(valid ++ .{ flag, "1" })));
    try std.testing.expectError(error.DuplicateArgument, command.parse(&(valid ++ .{ "--memory-addresses", "4" })));
    try std.testing.expectError(error.InvalidArguments, command.parse(&(valid ++ .{"--memory-addresses"})));
    try std.testing.expectError(error.InvalidSha256, command.parse(&.{ "--child-0-key-sha256", "zz" ** 32 }));
    try std.testing.expectError(error.InvalidArguments, command.parse(&(valid ++ .{ "--child-1-key", "extra.json" })));
}

test "detached leaf Metal requires authenticated AOT and coherent backend selection" {
    try std.testing.expectError(error.RecursiveMetalRequiresNativeMetal, command.parse(&(valid ++ .{ "--recursive-backend", "metal" })));
    try std.testing.expectError(error.MissingAuthenticatedAot, command.parse(&(valid ++ .{ "--native-backend", "metal" })));
    try std.testing.expectError(error.UnexpectedAotArguments, command.parse(&(valid ++ .{ "--aot-bundle", "bundle" })));
    const metal = try command.parse(&(valid ++ .{ "--native-backend", "metal", "--aot-bundle", "bundle", "--aot-manifest-sha256", pin }));
    try std.testing.expectEqual(command.Backend.metal, metal.recursive_backend);
    const hybrid = try command.parse(&(valid ++ .{ "--native-backend", "metal", "--recursive-backend", "cpu", "--aot-bundle", "bundle", "--aot-manifest-sha256", pin }));
    try std.testing.expectEqual(command.Backend.cpu, hybrid.recursive_backend);
}
