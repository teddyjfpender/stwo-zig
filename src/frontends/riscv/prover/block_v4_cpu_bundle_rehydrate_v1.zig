//! Detached, file-backed block-v4 receiver adapter. The bundle is transport
//! metadata only; caller-supplied SHA pins and recursion policy remain outside
//! it, and `streaming_file_receiver.verifyCanonical` issues authority only
//! after fresh proof verification.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const bundle_mod = @import("block_v4_cpu_bundle_manifest_v1.zig");
const trusted_mod = @import("block_v4_cpu_trusted_manifest_v1.zig");
const rebind = @import("block_v4_cpu_complete_pin_rebind_v1.zig");
const receiver = @import("block_v4_cpu_streaming_file_receiver_v1.zig");
const runner = @import("block_v4_cpu_runner_source.zig");
const first_mod = @import("block_v4_cpu_streaming_first_round.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const public_mod = @import("block_v4_public_source_assembly.zig");
const capture_mod = @import("block_v4_cpu_staged_capture.zig");
const execution_mod = @import("block_v4_cpu_staged_execution.zig");
const tables_mod = @import("block_v4_cpu_streaming_tables.zig");
const leaf_mod = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_mod = @import("block_v4_cpu_incremental_forest_stage.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const pins_mod = @import("block_memory_complete_receiver_v3.zig");

pub const Inputs = struct {
    elf: []const u8,
    input: []const u8,
    oracle: []const u8,
    schedule_json: []const u8,
    max_segment_cycles: u32,
};

/// `recursion_pins` must be independent receiver policy, not copied from the
/// bundle. The final trusted manifest currently pins the outer key and forest
/// digest; the caller additionally pins the exact leaf/dyadic key/edge roster.
pub fn verifyCanonical(
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    expected_bundle_sha256: bundle_mod.Digest,
    candidate_file: receiver.ManifestFile,
    final_file: receiver.ManifestFile,
    inputs: Inputs,
    recursion_pins: pins_mod.RecursionPins,
) !batch.CompleteBlock {
    var bundle = try bundle_mod.read(a, dir, expected_bundle_sha256);
    defer bundle.deinit();
    const wire = bundle.view();
    if (!std.meta.eql(wire.candidate_manifest_sha256, candidate_file.expected_sha256) or
        !std.meta.eql(wire.final_manifest_sha256, final_file.expected_sha256))
        return error.UntrustedBlockV4BundlePolicyHashes;
    var candidate = try trusted_mod.read(a, candidate_file.dir, candidate_file.path, candidate_file.expected_sha256);
    defer candidate.deinit();
    var final = try trusted_mod.read(a, final_file.dir, final_file.path, final_file.expected_sha256);
    defer final.deinit();
    try candidate.admitInputs(inputs.elf, inputs.input, inputs.oracle, inputs.schedule_json);
    try final.admitInputs(inputs.elf, inputs.input, inputs.oracle, inputs.schedule_json);
    try rebind.admitPolicyTransition(candidate.trusted(), candidate.sourcePins(), final.trusted(), final.sourcePins());
    if (!std.meta.eql(wire.statement.seal.base, candidate.trusted().base_seal) or
        !std.meta.eql(wire.statement.complete_pins.?.expected_job, final.trusted().job) or
        !std.meta.eql(wire.statement.complete_pins.?.forest_roster_digest, final.trusted().forest_roster_digest) or
        !std.meta.eql(wire.statement.complete_pins.?.outer_recursive_key_id, final.trusted().outer_key_id))
        return error.UntrustedBlockV4BundleStatement;
    // The persisted statement has final recursive pins. The core receiver
    // must first verify against the candidate policy used when SourceSeal was
    // drawn, then the canonical file receiver rebinds these two fields only.
    var candidate_statement = wire.statement;
    var candidate_complete = candidate_statement.complete_pins.?;
    candidate_complete.outer_recursive_key_id = candidate.trusted().outer_key_id;
    candidate_complete.forest_roster_digest = candidate.trusted().forest_roster_digest;
    candidate_statement.complete_pins = candidate_complete;
    if (!std.meta.eql(try candidate_statement.firstRoundDigest(a), wire.statement.seal.first_round_roster_digest) or
        !std.meta.eql(candidate_statement.seal, wire.statement.seal))
        return error.ChangedBlockV4BundleFirstRound;
    if (inputs.max_segment_cycles == 0 or inputs.max_segment_cycles > 1 << 22)
        return error.InvalidBlockV4SegmentBudget;
    var retained_table_bytes: u64 = 0;
    for (wire.opcode_tables) |pin| retained_table_bytes = try std.math.add(u64, retained_table_bytes, pin.file.len);
    for (wire.external_tables) |pin| retained_table_bytes = try std.math.add(u64, retained_table_bytes, pin.file.len);
    if (retained_table_bytes > 256 * 1024 * 1024)
        return error.BlockV4RetainedTableBudgetExceeded;

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    // Runner passes return an owned segment at a time. Use the freeing host
    // allocator, not `scratch`: ArenaAllocator.free is a no-op and would
    // otherwise retain every mainnet segment until verification finishes.
    var source = try runner.Source.initWithSchedule(a, inputs.elf, inputs.input, inputs.oracle, inputs.max_segment_cycles, parent.Profile.csp_q70_pow26.config(), candidate.sourcePins(), inputs.schedule_json);
    defer source.deinit();
    if (!std.meta.eql(source.job, candidate.trusted().job))
        return error.UntrustedBlockV4BundleRunnerJob;
    // These files enter the public image admission before any proof file is
    // opened. Their bundle hashes are transport checks only.
    try bundle_mod.checkPinnedFile(dir, .public_image, wire.public_image);
    try bundle_mod.checkPinnedFile(dir, .public_touches, wire.public_touches);
    const image = try dir.openFile("initial-nonzero.bin", .{});
    defer image.close();
    const touches = try dir.openFile("first-touch.bin", .{});
    defer touches.close();

    var first = first_mod.FirstRound{
        .a = scratch,
        .replay = undefined,
        .entries = @constCast(wire.first_entries),
        .event_count = wire.event_count,
        .opcode_events = wire.opcode_events,
        .external_events = wire.external_events,
        .opcode_plan = undefined,
        .external_plan = undefined,
        .opcode_counters = .empty,
        .external_counters = .empty,
    };
    var public = public_mod.Prepared{
        .a = scratch,
        .image = image,
        .touches = touches,
        .pin = wire.public_pin,
        .registers = wire.public_registers,
        .register_mask = wire.statement.seal.register_mask,
        .entries = @constCast(wire.public_entries),
        .digest = wire.statement.seal.roster_digest,
    };
    var memories = capture_mod.Capture{
        // Proof bytes are opened and released one at a time by the receiver.
        .a = a,
        .dir = dir,
        .memory = @constCast(wire.memories),
        .tables = @constCast(wire.memory_tables),
        .next_memory = wire.memories.len,
        .next_table = wire.memory_tables.len,
    };
    var executions = execution_mod.Sink{
        .a = a,
        .dir = dir,
        .entries = @constCast(wire.executions),
        .next = wire.executions.len,
    };
    var opcode_tables = tables_mod.Tables{
        .a = scratch,
        .plan = undefined,
        .counters = &.{},
        .first = &.{},
        .roots = @constCast(wire.statement.execution_range_table_roots),
        .wires = try openTables(scratch, dir, wire.opcode_tables, .opcode_table),
    };
    var external_tables = tables_mod.Tables{
        .a = scratch,
        .plan = undefined,
        .counters = &.{},
        .first = &.{},
        .roots = @constCast(wire.statement.execution_extension_range_table_roots),
        .wires = try openTables(scratch, dir, wire.external_tables, .external_table),
    };
    const product = product_mod.Product{
        .statement = candidate_statement,
        .source = &source,
        .first = &first,
        .public = &public,
        .memories = &memories,
        .opcode_tables = &opcode_tables,
        .external_tables = if (wire.statement.seal.extension_rosters_bound) &external_tables else null,
        .executions = &executions,
        .elapsed_ns = 0,
    };
    const leaves = try makeLeaves(a, dir, wire.leaves);
    defer {
        leaves.deinit();
        a.destroy(leaves);
    }
    const forest = try makeForest(a, dir, wire.parents, wire.roots, wire.outer.forest_digest);
    defer {
        forest.deinit();
        a.destroy(forest);
    }
    const outer = receiver.OuterFile{
        .dir = dir,
        .path = @import("block_v4_cpu_incremental_outer_stage.zig").OUTER_FILE,
        .byte_len = @intCast(wire.outer.file.len),
        .sha256 = wire.outer.file.sha256,
    };
    return receiver.verifyCanonical(a, product, candidate_file, final_file, inputs.schedule_json, recursion_pins, .{ .leaves = leaves, .forest = forest, .outer = outer });
}

fn openTables(a: std.mem.Allocator, dir: std.fs.Dir, pins: []const bundle_mod.TablePin, kind: std.meta.Tag(bundle_mod.Locator)) ![]batch.SerializedTableProof {
    const wires = try a.alloc(batch.SerializedTableProof, pins.len);
    for (pins, wires, 0..) |pin, *wire, index| {
        const locator: bundle_mod.Locator = switch (kind) {
            .opcode_table => .{ .opcode_table = @intCast(index) },
            .external_table => .{ .external_table = @intCast(index) },
            else => unreachable,
        };
        wire.* = .{ .stark_bytes = try bundle_mod.openPinned(a, dir, locator, pin.file), .claim = pin.claim };
    }
    return wires;
}

fn makeLeaves(a: std.mem.Allocator, dir: std.fs.Dir, pins: []const bundle_mod.LeafPin) !*leaf_mod.Capture {
    const stage = try a.create(leaf_mod.Capture);
    errdefer a.destroy(stage);
    const entries = try a.alloc(leaf_mod.Entry, pins.len);
    errdefer a.free(entries);
    for (pins, entries) |pin, *entry| entry.* = .{
        .byte_len = @intCast(pin.file.len),
        .sha256 = pin.file.sha256,
        .admission = pin.admission,
        .descriptor = pin.descriptor,
    };
    stage.* = .{ .a = a, .dir = dir, .profile = .csp_q70_pow26, .entries = entries, .next = entries.len };
    return stage;
}

fn makeForest(a: std.mem.Allocator, dir: std.fs.Dir, parents: []const bundle_mod.ParentPin, roots: []const bundle_mod.RootPin, digest: bundle_mod.Digest) !*forest_mod.Stage {
    const stage = try a.create(forest_mod.Stage);
    errdefer a.destroy(stage);
    const parent_pins = try a.alloc(forest_mod.ParentPin, parents.len);
    errdefer a.free(parent_pins);
    const root_pins = try a.alloc(forest_mod.RootPin, roots.len);
    errdefer a.free(root_pins);
    for (parents, parent_pins) |pin, *entry| entry.* = .{
        .statement = pin.statement,
        .admission = pin.admission,
        .left = pin.left,
        .right = pin.right,
        .byte_len = @intCast(pin.file.len),
        .sha256 = pin.file.sha256,
    };
    for (roots, root_pins) |pin, *entry| entry.* = .{
        .statement = pin.statement,
        .admission = pin.admission,
        .file = if (pin.parent_file) .{ .parent = pin.file_index } else .{ .leaf = pin.file_index },
    };
    stage.* = .{ .a = a, .dir = dir, .parents = parent_pins, .roots = root_pins, .digest = digest };
    return stage;
}

test "detached bundle rejects an unpinned transport before proof files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = bundle_mod.FILE, .data = "{}" });
    try std.testing.expectError(error.ChangedBlockV4BundleManifest, verifyCanonical(
        std.testing.allocator, tmp.dir, @splat(0), undefined, undefined, undefined, undefined,
    ));
}
