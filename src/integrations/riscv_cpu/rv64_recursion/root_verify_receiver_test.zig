//! receiver contract cases for root_verify.
//! Root-only receiver (stream rootverify, M5 plan "verifier" column, binding
//! note rv64-m5-binding.md §5). The receiver derives a VK table ONCE from its
//! own pinned binary (never from producer stores), then verifies a block by:
//!   1. checking the table header against its own profile/binary/image;
//!   2. recomputing every leaf statement digest from the receiver-admitted
//!      bundle metadata (no native proof is verified: leaves do that in-circuit);
//!   3. recomputing every fold digest bottom-up from table VKs (no child
//!      recursion proof is read: folds verify children in-circuit);
//!   4. verifying ONLY the root proof, under a verifier-only authority rebuilt
//!      from the table VK, against the recomputed root digest.
//!
//! Table profiles (named; unknown ids are refused):
//! - `rv64-m4-fold-v2-compat/v0`: today's proof format. Fold VKs are keyed by
//!   the fold v2 geometry class (`om31_outer.classKey`, binding argued in
//!   rv64-m3-topo-binding.md). Leaf VKs are keyed by the native leaf class
//!   (native FIXED binding + declaration + PCS config); see `leafKey` for the
//!   determinism premise and how derive checks it.
//! - `rv64-m5-vk-table/v1`: reserved for canon-vk's canonical leaves/folds
//!   (T_rec/T_nat in the root statement); refused until that format exists.
const std = @import("std");
const Om31 = @import("stwo_circuit_cpu_integration").om31;
const Bridge = @import("om31_outer.zig");
const Owner = @import("root_verify.zig");
const SCHEMA = Owner.SCHEMA;
const Profile = Owner.Profile;
const foldClassKey = Owner.foldClassKey;
const foldClassKeyK = Owner.foldClassKeyK;
const foldDigest = Owner.foldDigest;
const foldDigestK = Owner.foldDigestK;
const Table = Owner.Table;
const hexAlloc = Owner.hexAlloc;
const requireHeader = Owner.requireHeader;
const requirePinnedRoot = Owner.requirePinnedRoot;
const requireReceiverLocal = Owner.requireReceiverLocal;
const LeafInput = Owner.LeafInput;
const expectedRootArity = Owner.expectedRootArity;
const expectedRoot = Owner.expectedRoot;

test "root_verify: profile ids are named and unknown ids refused" {
    try std.testing.expectEqual(Profile.m4_fold_v2_compat, try Profile.parse("rv64-m4-fold-v2-compat/v0"));
    try std.testing.expectError(error.VkTableProfileNotImplemented, Profile.parse("rv64-m5-vk-table/v1"));
    try std.testing.expectError(error.UnknownVkTableProfile, Profile.parse("rv64-m4-fold-v2-compat/v1"));
    try std.testing.expectError(error.UnknownVkTableProfile, Profile.parse(""));
}

test "root_verify: producer-directory tables are refused" {
    try std.testing.expectError(error.StoreSuppliedVkRefused, requireReceiverLocal("/run/case/proof/vk.json", "/run/case/proof"));
    try std.testing.expectError(error.StoreSuppliedVkRefused, requireReceiverLocal("/run/case/proof", "/run/case/proof"));
    try requireReceiverLocal("/run/case/proof-vk.json", "/run/case/proof");
    try requireReceiverLocal("/home/r/vk.json", "/run/case/proof");
}

test "root_verify: table JSON round trip, root binding and header policy" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    _ = try table.put(.leaf, @splat(1), testKey(1), "leaf-a");
    _ = try table.put(.fold, @splat(2), testKey(2), "fold-a");
    try std.testing.expect(!try table.put(.leaf, @splat(1), testKey(1), "dup"));
    try std.testing.expectError(error.VkLeafClassMismatch, table.put(.leaf, @splat(1), testKey(3), "clash"));
    const bytes = try table.toJson(a);
    defer a.free(bytes);
    var back = try Table.fromJson(a, bytes);
    defer back.deinit();
    try std.testing.expectEqualDeep(table.root(), back.root());
    try std.testing.expect(std.meta.eql(back.find(.fold, @splat(2)).?.*, testKey(2)));
    try requireHeader(&back, table.header);
    var other = table.header;
    other.receiver_sha256 = "x";
    try std.testing.expectError(error.VkTableNotDerivedByThisReceiver, requireHeader(&back, other));
    other = table.header;
    other.image = "j";
    try std.testing.expectError(error.VkTableImageMismatch, requireHeader(&back, other));
    other = table.header;
    other.native_profile = "m";
    try std.testing.expectError(error.VkTableNativeProfileMismatch, requireHeader(&back, other));
    // Tampering with an entry breaks the recomputed table root.
    const tampered = try a.dupe(u8, bytes);
    defer a.free(tampered);
    const at = std.mem.indexOf(u8, tampered, "\"total_constraints\": 101").?;
    tampered[at + "\"total_constraints\": 10".len] = '9';
    try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, tampered));
    // Every header field is bound: relabelling the deriving receiver (review A1)
    // or the fold version without a reseal breaks the root.
    for ([_][]const u8{ "\"receiver_sha256\": \"r\"", "\"source_commit\": \"c\"" }) |needle| {
        const relabel = try a.dupe(u8, bytes);
        defer a.free(relabel);
        const at_field = std.mem.indexOf(u8, relabel, needle).?;
        relabel[at_field + needle.len - 2] = 'z';
        try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, relabel));
    }
    var plain = try testTable(a);
    defer plain.deinit();
    var relabelled = try testTable(a);
    defer relabelled.deinit();
    relabelled.header.fold_version +%= 1;
    try std.testing.expect(!std.mem.eql(u8, &relabelled.root(), &plain.root()));
    // Operator pin.
    const pin = try hexAlloc(a, &back.root());
    defer a.free(pin);
    try requirePinnedRoot(&back, pin);
    pin[0] = if (pin[0] == '0') '1' else '0';
    try std.testing.expectError(error.VkTableRootPinMismatch, requirePinnedRoot(&back, pin));
    try std.testing.expectError(error.InvalidVkTableRootPin, requirePinnedRoot(&back, "00"));
}

test "root_verify: tree shape, adjacency and missing classes" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const leaf = testKey(7);
    _ = try table.put(.leaf, @splat(7), leaf, "");
    var leaves: [3]LeafInput = undefined;
    for (&leaves, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
    var folds: usize = 0;
    try std.testing.expectError(error.VkTableMissingFoldClass, expectedRoot(&table, &leaves, &folds));
    const fold = testKey(9);
    _ = try table.put(.fold, foldClassKey(&leaf, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &fold), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &leaf), fold, "");
    folds = 0;
    const root = try expectedRoot(&table, &leaves, &folds);
    try std.testing.expectEqual(@as(usize, 2), folds);
    // [0,1) + [1,2) first, then ([0,2) + [2,3)).
    const d01 = try foldDigest(.{ .{ .key = &leaf, .digest = leaves[0].digest }, .{ .key = &leaf, .digest = leaves[1].digest } });
    const d = try foldDigest(.{ .{ .key = &fold, .digest = d01 }, .{ .key = &leaf, .digest = leaves[2].digest } });
    try std.testing.expectEqualDeep(d, root.digest);
    // Permuting two leaves changes the root digest (order is bound).
    std.mem.swap(LeafInput, &leaves[0], &leaves[1]);
    folds = 0;
    try std.testing.expect(!std.mem.eql(u8, &d, &(try expectedRoot(&table, &leaves, &folds)).digest));
    // Unknown leaf class.
    leaves[2].key = @splat(8);
    folds = 0;
    try std.testing.expectError(error.VkTableMissingLeafClass, expectedRoot(&table, &leaves, &folds));
}

test "root_verify: native VK section is root-bound, deduplicated and refused when altered" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const empty_root = table.root();
    try std.testing.expect(try table.putNative(@splat(3), "artifact-three"));
    try std.testing.expect(!try table.putNative(@splat(3), "artifact-three"));
    try std.testing.expectError(error.VkNativeClassMismatch, table.putNative(@splat(3), "artifact-other"));
    try std.testing.expectError(error.InvalidNativeVkArtifact, table.putNative(@splat(4), ""));
    try std.testing.expect(try table.putNative(@splat(1), "artifact-one"));
    try std.testing.expect(!std.mem.eql(u8, &empty_root, &table.root()));
    const bytes = try table.toJson(a);
    defer a.free(bytes);
    var back = try Table.fromJson(a, bytes);
    defer back.deinit();
    try std.testing.expectEqualDeep(table.root(), back.root());
    try std.testing.expectEqualStrings("artifact-three", back.findNative(@splat(3)).?);
    try std.testing.expect(back.findNative(@splat(9)) == null);
    // One flipped artifact byte (hex) breaks the recomputed root.
    const tampered = try a.dupe(u8, bytes);
    defer a.free(tampered);
    const hex_one = "61727469666163742d6f6e65"; // "artifact-one"
    const at = std.mem.indexOf(u8, tampered, hex_one).?;
    tampered[at + 1] = '2';
    try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, tampered));
    // The v0 schema (M5 tables without the native section) is refused.
    const old = try std.mem.replaceOwned(u8, a, bytes, SCHEMA, "rv64-vk-receiver-table/v0");
    defer a.free(old);
    try std.testing.expectError(error.UnknownVkTableSchema, Table.fromJson(a, old));
}

test "root_verify: plan-driven tree equals the binary carry; k-ary keys bind the arity" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const leaf = testKey(7);
    const fold = testKey(9);
    _ = try table.put(.leaf, @splat(7), leaf, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &fold), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &fold), fold, "");
    for ([_]usize{ 1, 2, 3, 5, 7, 11, 17 }) |n| {
        const leaves = try a.alloc(LeafInput, n);
        defer a.free(leaves);
        for (leaves, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
        var f1: usize = 0;
        var f2: usize = 0;
        const carry = try expectedRoot(&table, leaves, &f1);
        const planned = try expectedRootArity(a, &table, leaves, 2, &f2);
        try std.testing.expectEqualDeep(carry.digest, planned.digest);
        try std.testing.expectEqual(f1, f2);
        try std.testing.expectEqual(n - 1, f2);
    }
    // k = 2 keeps the historical class key; k = 3 differs (version word).
    const k2 = try foldClassKeyK(&.{ &leaf, &leaf });
    try std.testing.expectEqualDeep(foldClassKey(&leaf, &leaf), k2);
    const k3 = try foldClassKeyK(&.{ &leaf, &leaf, &leaf });
    try std.testing.expect(!std.mem.eql(u8, &k2, &k3));
    try std.testing.expectError(error.InvalidRecursiveFoldArity, foldClassKeyK(&.{&leaf}));
    // 4-ary: 5 leaves -> one 4-fold + a binary finalisation over the carry.
    _ = try table.put(.fold, try foldClassKeyK(&.{ &leaf, &leaf, &leaf, &leaf }), fold, "");
    var leaves5: [5]LeafInput = undefined;
    for (&leaves5, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
    var f4: usize = 0;
    const r4 = try expectedRootArity(a, &table, &leaves5, 4, &f4);
    try std.testing.expectEqual(@as(usize, 2), f4);
    const d4 = try foldDigestK(&.{ .{ .key = &leaf, .digest = leaves5[0].digest }, .{ .key = &leaf, .digest = leaves5[1].digest }, .{ .key = &leaf, .digest = leaves5[2].digest }, .{ .key = &leaf, .digest = leaves5[3].digest } });
    const d = try foldDigestK(&.{ .{ .key = &fold, .digest = d4 }, .{ .key = &leaf, .digest = leaves5[4].digest } });
    try std.testing.expectEqualDeep(d, r4.digest);
}

fn testKey(seed: u8) VerifierKey {
    var vk: VerifierKey = undefined;
    for (&vk.column, 0..) |*c, i| c.* = @intCast(i);
    for (&vk.log_size, 0..) |*l, i| l.* = 10 + @as(u32, @intCast(i % 7));
    for (&vk.logs, 0..) |*l, i| l.* = 12 + @as(u32, @intCast(i % 5));
    vk.n_outputs = 8;
    vk.total_constraints = 100 + seed;
    vk.max_evaluation_log_size = 20;
    vk.fixed_root = @splat(seed);
    vk.identity = @splat(seed +% 1);
    return vk;
}
fn testTable(a: std.mem.Allocator) !Table {
    return Table.init(a, .{ .profile = Profile.m4_fold_v2_compat.id(), .native_profile = "n", .outer_domain = Om31.protocol.domainName(), .fold_version = Bridge.version, .source_commit = "c", .receiver_sha256 = "r", .image = "i" });
}
