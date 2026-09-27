//! Nonproving durable policy/operand/ownership contracts. No PCS, proof,
//! recursion, guest or device code is invoked by any behavioral fixture.
const std = @import("std");
const Policy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Durable = @import("block_v5_memory_source_page_durable_loader_v1.zig");
const Export = @import("block_v5_memory_source_page_policy_export_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Inventory = @import("block_v5_memory_source_fold_inventory_owner_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Premix = @import("block_v5_memory_source_fold_premix_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const BUNDLE_LIMITS = Bundle.Limits{ .max_files = 1, .max_file_bytes = 128, .max_total_bytes = 128, .max_metadata_bytes = 4096, .max_manifest_bytes = 4096, .max_claims = 1, .max_proof_bytes = 64 };
test "source PAGE durable: policy pin format count and arithmetic caps reject before independent Globals or allocation" {
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSourcePagePolicyLimits, Policy.read(deny.allocator(), undefined, undefined, undefined, .{ .max_file_bytes = 0 }));
    try std.testing.expectError(error.UntrustedSourcePagePolicyPin, Policy.read(deny.allocator(), undefined, .{ .byte_len = 1, .sha256 = @splat(0) }, undefined, .{}));
    var wire: Policy.Wire = undefined;
    wire.format = Policy.FORMAT;
    wire.version = Policy.VERSION + 1;
    try std.testing.expectError(error.UnsupportedSourcePagePolicy, Policy.reconstruct(deny.allocator(), undefined, wire, .{}));
    wire.version = Policy.VERSION;
    wire.page_abi = Protocol.abiId();
    const raws: [2]Policy.RawRecord = undefined;
    wire.raw = &raws;
    wire.fold = &.{};
    try std.testing.expectError(error.SourcePagePolicyResourceLimit, Policy.reconstruct(deny.allocator(), undefined, wire, .{ .max_pages = 1 }));
    try std.testing.expectError(error.Overflow, Policy.metadataBytes(std.math.maxInt(usize), 0));
    try std.testing.expectError(error.InvalidSourcePagePolicyLimits, Export.write(deny.allocator(), undefined, undefined, undefined, undefined, .{ .max_owned_bytes = 0 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
const UNKNOWN_JSON = "{\"unknown\":0}";
fn policyFault(a: std.mem.Allocator, dir: std.fs.Dir, pin: Policy.Pin) !void {
    _ = Policy.read(a, dir, pin, undefined, .{}) catch |failure| {
        if (failure == error.OutOfMemory) return failure;
        try std.testing.expectEqual(error.UnknownField, failure);
        return;
    };
    return error.TestExpectedError;
}
test "source PAGE durable: exact hash framing strict unknown fields and every parser allocation fault" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try Files.publish(temp.dir, Policy.FILE, UNKNOWN_JSON);
    const pin = Policy.Pin{ .byte_len = UNKNOWN_JSON.len, .sha256 = Files.hash(UNKNOWN_JSON) };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, policyFault, .{ temp.dir, pin });
    var changed = pin;
    changed.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Policy.read(std.testing.allocator, temp.dir, changed, undefined, .{}));
    changed = pin;
    changed.byte_len += 1;
    try std.testing.expectError(error.TamperedV5BundleFileLength, Policy.read(std.testing.allocator, temp.dir, changed, undefined, .{}));
    try std.testing.expectError(error.UntrustedSourcePagePolicyPin, Policy.read(std.testing.allocator, temp.dir, pin, undefined, .{ .max_file_bytes = UNKNOWN_JSON.len - 1 }));
    try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(temp.dir, Policy.FILE, UNKNOWN_JSON));
}
const Fixture = struct {
    operations: [1]Fold.Operation,
    pin: Protocol.FoldPin,
    fn init() !Fixture {
        const before = (Hash.Frame{ .leaf = 7 }).nativeDigest();
        const after = (Hash.Frame{ .leaf = 9 }).nativeDigest();
        const operation = Fold.Operation{ .ordinal = 0, .kind = .leaf, .coordinate = .{ .height = 0, .index = 16 }, .value = .{ .before = before, .after = after }, .leaf = .{ .address = 64, .before = 7, .after = 9, .clock = 0xfedcba9876543210, .image = .input, .image_ordinal = 1, .touch_ordinal = 2, .touched = true } };
        const page = Protocol.Page{ .index = 0, .first = 0, .count = 1, .row_log = 1 };
        const geometry = try Blake.Geometry.fromOperations(&.{operation}, 1, .{});
        const recipes = [_]@import("block_v5_memory_source_blake_semantics_v1.zig").Recipe{
            .{ .slot = 0, .multiplicity = 1, .default_height = null, .compression_count = 1, .first_compression = 0 },
            .{ .slot = 1, .multiplicity = 1, .default_height = null, .compression_count = 1, .first_compression = 1 },
        };
        const rows = [_]Semantic.FoldRow{.{ .descriptor = .{ .kind = .leaf, .height = 0 }, .recipes = &recipes, .first_compression = 0, .compressions = 2 }};
        return .{ .operations = .{operation}, .pin = .{ .page = page, .plan_id = @splat(7), .inventory_id = try Premix.inventoryId(page, 1, &rows), .geometry = geometry, .roots = @splat(@splat(9)) } };
    }
};
fn inventoryFault(a: std.mem.Allocator, dir: std.fs.Dir, pin: Protocol.FoldPin, stored: Store.Pin) !void {
    var inventory = try Inventory.load(a, dir, "operand", pin, stored, .{});
    defer inventory.deinit();
    try std.testing.expectEqual(@as(usize, 1), inventory.rows.len);
    try std.testing.expectEqual(@as(usize, 2), inventory.recipes.len);
    try std.testing.expectEqual(@as(u32, 2), inventory.rows[0].compressions);
    try std.testing.expectEqual(@as(u32, 1), inventory.recipes[1].first_compression);
    inventory.requireRelease(a, inventory.rows);
}
test "source PAGE durable: original mutable input fold recipes full clocks and every descriptor allocation fault" {
    const fixture = try Fixture.init();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const stored = try Store.publish(std.testing.allocator, temp.dir, "operand", fixture.pin.page, fixture.pin.plan_id, @splat(11), &fixture.operations, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, inventoryFault, .{ temp.dir, fixture.pin, stored });
    var changed = fixture.pin;
    changed.inventory_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageLoaderInventory, Inventory.load(std.testing.allocator, temp.dir, "operand", changed, stored, .{}));
    changed = fixture.pin;
    changed.geometry.frames += 1;
    try std.testing.expectError(error.UntrustedSourcePageLoaderInventory, Inventory.load(std.testing.allocator, temp.dir, "operand", changed, stored, .{}));
    var bad_file = stored;
    bad_file.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Inventory.load(std.testing.allocator, temp.dir, "operand", fixture.pin, bad_file, .{}));
    var loaded = try Store.load(std.testing.allocator, temp.dir, "operand", fixture.pin.page, fixture.pin.plan_id, stored.page_identity, stored, .{});
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u64, 0xfedcba9876543210), loaded.operations[0].leaf.clock);
    try std.testing.expectEqual(Fold.ImageKind.input, loaded.operations[0].leaf.image);
    try std.testing.expectEqual(@as(u32, 9), loaded.operations[0].leaf.after);
}
test "source PAGE durable: failed session and live descriptors cannot satisfy exact consumption or retry" {
    var loader: Durable.Loader = undefined;
    loader.failed = true;
    try std.testing.expectError(error.IncompleteSourcePageLoader, loader.requireConsumed());
    try std.testing.expectError(error.IncompleteSourcePageLoader, loader.pageLoader().raw(&loader, std.testing.allocator, 0));
    loader.failed = false;
    loader.pending = null;
    loader.pending_index = null;
    var raw_taken = [_]bool{false};
    var fold_taken = [_]bool{true};
    loader.raw_taken = &raw_taken;
    loader.fold_taken = &fold_taken;
    try std.testing.expectError(error.IncompleteSourcePageLoader, loader.requireConsumed());
    raw_taken[0] = true;
    loader.pending_index = 0;
    try std.testing.expectError(error.IncompleteSourcePageLoader, loader.requireConsumed());
    // No synthetic Open/VerifiedPage is ever used in these consumption checks.
}
test "source PAGE durable: owned loader caps reject before any metadata or file capability is read" {
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.SourcePageLoaderResourceLimit, Durable.Loader.init(deny.allocator(), undefined, undefined, undefined, undefined, .{ .store = BUNDLE_LIMITS, .max_owned_bytes = 0 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
