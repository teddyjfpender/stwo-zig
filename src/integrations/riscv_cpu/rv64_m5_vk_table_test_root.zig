//! M5 canon-vk: recursion/native VK tables, in-circuit membership, and the
//! canonical outer profile / shape policy.
const std = @import("std");
test {
    _ = @import("rv64_recursion/vk_table.zig");
    _ = @import("rv64_recursion/node_summary.zig");
    _ = @import("rv64_recursion/om31_native/canon_hash.zig");
    _ = @import("rv64_recursion/om31_native/node_summary_v3.zig");
    _ = @import("rv64_recursion/om31_native/typed_root.zig");
    _ = @import("rv64_recursion/om31_native/typed_fold.zig");
}
const P = @import("stwo_circuit_cpu_integration").om31.protocol;
test "canon-vk canonical outer profiles: registry domains, base PCS configs, fail-closed parse" {
    const r = P.Profile.m5_outer_canonical_r1_b2_q108_p20_fold4_v1;
    const m = P.Profile.m5_outer_canonical_m3_b4_q51_p26_fold4_v1;
    try std.testing.expect(std.meta.eql(r.config(), P.Profile.r1_b2_q108_p20_fold4.config()));
    try std.testing.expect(std.meta.eql(m.config(), P.Profile.m3_b4_q51_p26_fold4.config()));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m5-canonical-q108-p20-fold4/lens-v1", r.domainName());
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m5-canonical-m3-b4-q51-p26-fold4/lens-v1", m.domainName());
    try std.testing.expect(r.canonical() and m.canonical() and !P.Profile.r1_b2_q108_p20_fold4.canonical());
    try std.testing.expectEqual(@as(u32, 128), r.conjecturedBits());
    try std.testing.expectEqual(@as(u32, 128), m.conjecturedBits());
    try std.testing.expectEqual(r, try P.Profile.parse(r.name()));
    // P03: an unknown name is an error value (entry points exit cleanly), never a panic.
    try std.testing.expectError(error.UnknownOm31OuterProfile, P.Profile.parse("m5_outer_canonical_r1"));
}
test "canon-vk review: r1_domain names r1 only; the active profile's domain comes from domainName()" {
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/q108-p20-fold4/lens-v1", P.r1_domain);
    try std.testing.expectEqualStrings(P.r1_domain, P.Profile.r1_b2_q108_p20_fold4.domainName());
    try std.testing.expect(!std.mem.eql(u8, P.r1_domain, P.Profile.m5_outer_canonical_r1_b2_q108_p20_fold4_v1.domainName()));
}
