//! No proofs/PCS/guest: source reader, exact durable descriptor ownership and
//! policy mutations. Proposed metadata here is never a verified PAGE receipt.
const std = @import("std");
const core = @import("stwo_core");
const SourcePages = @import("block_v5_cpu_source_pages_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Reader = @import("block_v5_memory_source_page_reader_v1.zig").Reader;
const Loader = @import("block_v5_memory_source_page_job_loader_v1.zig").Loader;
const JobModule = @import("block_v5_memory_source_page_job_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const FoldStage = @import("block_v5_memory_source_fold_premix_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
fn source(input: []const u8) !Source.Admitted {
    const empty = Initial.sha256("");
    const root = Defaults.get().defaults[0].bytes;
    return Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
        .initial_rw_root = root,
        .initial_registers = @splat(0),
        .public_input_sha256 = Initial.sha256(input),
        .public_input_len = input.len,
        .input_words = .{ .records = 0, .sha256 = empty },
        .rw_words = .{ .records = 0, .sha256 = empty },
        .first_touches = .{ .records = 0, .sha256 = empty },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = root, .endpoints = .{ .records = 0, .sha256 = empty } }, @splat(8), .{});
}
test "CPU source PAGE path: options fail before source files or allocator are touched" {
    try (SourcePages.Options{}).validate();
    var changed = SourcePages.Options{};
    changed.join.pages.max_receiver_heap_bytes += 1;
    try std.testing.expectError(error.InvalidV5CpuSourcePageOptions, changed.validate());
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSourcePageJobLimits, SourcePages.collect(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, .{ .job = .{ .max_job_heap_bytes = 0 } }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    try std.testing.expect(!SourcePages.Report.recursive_global_authority);
}
test "CPU source PAGE path: durable producer and independent receiver policies agree before collection" {
    const original = SourcePages.Options{};
    var changes: [6]SourcePages.Options = @splat(original);
    changes[0].policy.source.max_records -= 1;
    changes[1].policy.fold.max_leaves -= 1;
    changes[2].policy.pages.max_receiver_heap_bytes -= 1;
    changes[3].policy.codec.max_artifact_bytes -= 1;
    changes[4].loader_owned_bytes = 0;
    changes[5].verification_heap_bytes = 0;
    for (changes) |options| {
        var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.InvalidV5CpuSourcePageOptions, SourcePages.collect(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, options));
        try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    }
}
test "CPU source PAGE path: positional private reader enforces all lengths offsets and overflow" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var files: [4]std.fs.File = undefined;
    var initialized: usize = 0;
    defer for (files[0..initialized]) |file| file.close();
    for (&files, 0..) |*file, index| {
        var path: [32]u8 = undefined;
        file.* = try temporary.dir.createFile(try std.fmt.bufPrint(&path, "source-{d}", .{index}), .{ .read = true });
        initialized += 1;
    }
    const streams = @import("block_v5_rw_endpoint_sources_v1.zig").Sources{ .initial = .{ .input_words = files[0], .rw_words = files[1], .first_touches = files[2] }, .endpoints = files[3] };
    const input = [_]u8{ 3, 5, 7 };
    const admitted = try source(&input);
    var reader = try Reader.init(admitted, streams, &input);
    const provider = reader.provider();
    var out: [2]u8 = undefined;
    try provider.read(provider.context, .public_input, 1, &out);
    try std.testing.expectEqualSlices(u8, &.{ 5, 7 }, &out);
    try std.testing.expectError(error.InvalidSourcePageReaderOffset, provider.read(provider.context, .public_input, 2, &out));
    try std.testing.expectError(error.Overflow, provider.read(provider.context, .public_input, std.math.maxInt(u64), &out));
    try std.testing.expectError(error.InvalidSourcePageReaderLength, Reader.init(admitted, streams, &.{}));
    try files[3].writeAll(&.{0});
    try std.testing.expectError(error.InvalidSourcePageReaderLength, Reader.init(admitted, streams, &input));
}
fn operations() [2]Fold.Operation {
    const root = Defaults.get().defaults[0].bytes;
    return .{
        .{ .ordinal = 0, .kind = .leaf, .coordinate = .{ .height = 0, .index = 8 }, .value = .{ .before = root, .after = root }, .leaf = .{ .address = 32, .before = 3, .after = 5, .clock = 9, .image = .input, .touched = true } },
        .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
    };
}
fn fixture(dir: std.fs.Dir) !JobModule.FoldRecord {
    const ops = operations();
    const page = Protocol.Page{ .index = 0, .first = 0, .count = 2, .row_log = 1 };
    const recipes = [_]@import("block_v5_memory_source_blake_semantics_v1.zig").Recipe{
        .{ .slot = 0, .multiplicity = 1, .default_height = null, .compression_count = 1, .first_compression = 0 },
        .{ .slot = 1, .multiplicity = 1, .default_height = null, .compression_count = 1, .first_compression = 1 },
    };
    // Descriptor/file fixture only; this truncated inventory is never offered
    // to a PAGE proof or accepted as a complete tree/source witness.
    const rows = [_]Semantic.FoldRow{
        .{ .descriptor = .{ .kind = .leaf, .height = 0 }, .recipes = &recipes, .first_compression = 0, .compressions = 2 },
        .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 2, .compressions = 0 },
    };
    const pin = Protocol.FoldPin{ .page = page, .plan_id = @splat(7), .inventory_id = try FoldStage.inventoryId(page, 1, &rows), .geometry = try Blake.Geometry.fromOperations(&ops, 1, .{}), .roots = @splat(@splat(9)) };
    var path: [96]u8 = undefined;
    const stored = try Store.publish(std.testing.allocator, dir, try JobModule.name(&path, .fold, 0, false), page, pin.plan_id, @splat(6), &ops, .{});
    return .{ .pin = pin, .stored = stored };
}
fn inventoryFault(a: std.mem.Allocator, dir: std.fs.Dir, record: JobModule.FoldRecord) !void {
    var records = [_]JobModule.FoldRecord{record};
    // Only immutable file/descriptor policy fields are used in this fixture;
    // no context/proof/VerifiedPage is fabricated or accepted.
    var job: SourcePages.Job = undefined;
    job.dir = dir;
    job.folds = &records;
    job.limits = .{};
    var loader = Loader{ .job = &job, .reader = undefined };
    const callbacks = loader.pageLoader();
    const rows = try callbacks.fold_rows(callbacks.context, a, 0, 2);
    defer callbacks.release_fold_rows.?(callbacks.context, a, rows);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(Fold.Kind.root, rows[1].descriptor.kind);
    try std.testing.expectEqual(@as(usize, 2), rows[0].recipes.len);
    try std.testing.expectEqual(@as(u32, 1), rows[0].recipes[1].first_compression);
    try std.testing.expectError(error.SourcePageLoaderDescriptorLive, loader.requireReleased());
    try std.testing.expectError(error.UntrustedSourcePageLoaderInventory, callbacks.fold_rows(callbacks.context, a, 0, 2));
}
test "CPU source PAGE path: durable exact fold inventory releases nested ownership on every allocation failure" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const record = try fixture(temporary.dir);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, inventoryFault, .{ temporary.dir, record });
}
test "CPU source PAGE path: independent fold census inventory and compact file corruption fail closed" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const record = try fixture(temporary.dir);
    var changed = record;
    changed.pin.inventory_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageLoaderInventory, inventoryFault(std.testing.allocator, temporary.dir, changed));
    changed = record;
    changed.pin.geometry.compressions += 1;
    try std.testing.expectError(error.UntrustedSourcePageLoaderInventory, inventoryFault(std.testing.allocator, temporary.dir, changed));
    var path: [96]u8 = undefined;
    const file = try temporary.dir.openFile(try JobModule.name(&path, .fold, 0, false), .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(&.{0xff}, Store.HEADER_BYTES);
    try std.testing.expectError(error.TamperedV5BundleFileHash, inventoryFault(std.testing.allocator, temporary.dir, record));
}
