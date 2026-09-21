//! Separate CPU key-setup process over independently pinned expected inputs.
//! Native proofs establish recursive preparation; no outer proof is created.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const command = frontend.recursion.detached_segment_command_v1;
const proof = @import("recursive_segment_v2_detached_proof.zig");
const ingress = @import("recursive_segment_v2_native_ingress.zig");
const model = @import("recursive_segment_v2_memory_workload.zig");
const workload = @import("recursive_segment_v2_workload.zig");
const M31 = core.fields.m31.M31;

const ExpectedInput = struct { path: []const u8, sha256: []const u8 };
const SetupV1 = struct {
    version: u32,
    memory_addresses: usize,
    initial_memory_word: u32,
    proof_profile: proof.Profile,
    expected: []const ExpectedInput,
};
const KeyReceipt = struct {
    key_sha256: [32]u8,
    circuit_identity: [32]u8,
    preprocessed_root: [8]u32,
    expected_wire_sha256: [32]u8,
};

fn digest(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidSetupPin;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 5 and std.mem.eql(u8, args[1], "--export-workload")) {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, args[2], command.MAX_INPUT_BYTES);
        defer allocator.free(bytes);
        const pin = try digest(args[3]);
        if (!std.meta.eql(command.hash(bytes), pin)) return error.SetupManifestPinMismatch;
        const parsed = try std.json.parseFromSlice(WorkloadV1, allocator, bytes, .{});
        defer parsed.deinit();
        const selected = parsed.value;
        if (selected.version != 1) return error.UnsupportedSetupVersion;
        switch (selected.memory_addresses) {
            1, 4, 16 => {},
            else => return error.InvalidMemoryAddressCount,
        }
        switch (selected.segment_count) {
            inline 1, 2, 4, 8 => |count| try exportWorkload(count, allocator, selected, pin, args[4]),
            else => return error.InvalidSegmentCount,
        }
        return;
    }
    if (args.len != 4) return error.ExpectedSetupManifestPinAndNewDirectory;
    const pin = try digest(args[2]);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], command.MAX_INPUT_BYTES);
    defer allocator.free(bytes);
    if (!std.meta.eql(command.hash(bytes), pin)) return error.SetupManifestPinMismatch;
    const parsed = try std.json.parseFromSlice(SetupV1, allocator, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const setup = parsed.value;
    if (setup.version != 1) return error.UnsupportedSetupVersion;
    switch (setup.memory_addresses) {
        1, 4, 16 => {},
        else => return error.InvalidMemoryAddressCount,
    }
    switch (setup.expected.len) {
        inline 1, 2, 4, 8 => |count| try derive(count, allocator, setup, std.fs.path.dirname(args[1]) orelse ".", pin, args[3]),
        else => return error.InvalidSegmentCount,
    }
}

fn requireWords(wanted: []const M31, actual: []const M31) !void {
    if (wanted.len != actual.len) return error.SetupExpectedStatementMismatch;
    for (wanted, actual) |left, right| if (!left.eql(right)) return error.SetupExpectedStatementMismatch;
}

fn derive(comptime count: usize, allocator: std.mem.Allocator, setup: SetupV1, base: []const u8, setup_pin: [32]u8, output: []const u8) !void {
    var expected: [count]command.OwnedExpectedV1 = undefined;
    var pins: [count][32]u8 = undefined;
    var initialized: usize = 0;
    defer for (expected[0..initialized]) |*value| value.deinit();
    for (setup.expected, 0..) |input, index| {
        pins[index] = try digest(input.sha256);
        const path = try std.fs.path.resolve(allocator, &.{ base, input.path });
        defer allocator.free(path);
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, command.MAX_INPUT_BYTES);
        defer allocator.free(bytes);
        if (!std.meta.eql(command.hash(bytes), pins[index])) return error.SetupExpectedPinMismatch;
        expected[index] = try command.OwnedExpectedV1.decode(allocator, bytes);
        initialized += 1;
    }
    var segments = try model.materialize(count, allocator, setup.memory_addresses, setup.initial_memory_word);
    defer for (&segments) |*segment| segment.deinit();
    var results: [count]*const frontend.runner.SegmentResult = undefined;
    for (&segments, 0..) |*segment, index| results[index] = &segment.base;
    try workload.validateSegments(count, results, setup.memory_addresses, setup.initial_memory_word);
    const statements = try workload.fixtureStatementsForSegments(count, allocator, results);
    const admitted = try workload.admitSegments(count, results, ingress.digest("recursive-v2-session"), statements);
    // Authenticate every expected statement before native proving or output writes.
    for (admitted.sources, 0..) |source, index| {
        const words = try allocator.alloc(M31, try source.canonicalWordCount());
        defer allocator.free(words);
        _ = try source.encodeCanonical(words);
        try requireWords(expected[index].data.words(), words);
    }
    try std.fs.cwd().makeDir(output);
    var directory = try std.fs.cwd().openDir(output, .{});
    defer directory.close();
    const native_keys = try frontend.recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(ingress.digest("recursive-v2-segment-vk"), ingress.digest("recursive-v2-parent-vk"));
    var receipts: [count]KeyReceipt = undefined;
    for (results, statements, 0..) |result, statement, index| {
        var prepared = try ingress.prepareWithProfile(@import("recursive_segment_v2_leaf_outer.zig").Engine, allocator, result, statement, native_keys, if (setup.proof_profile == .recursive_q193_v1) .protocol_v1 else .development_q1);
        defer prepared.deinit();
        try requireWords(expected[index].data.words(), prepared.capture.public_data.data.words());
        const bytes = try proof.deriveKey(allocator, &prepared, setup.proof_profile);
        defer allocator.free(bytes);
        const key_pin = command.hash(bytes);
        const key = try command.OwnedKeyV1.admit(allocator, bytes, key_pin);
        defer key.deinit();
        receipts[index] = .{ .key_sha256 = key_pin, .circuit_identity = try key.key().identity(), .preprocessed_root = key.key().preprocessed_root, .expected_wire_sha256 = pins[index] };
        var name: [48]u8 = undefined;
        var file = try directory.createFile(try std.fmt.bufPrint(&name, "child-{d}-key.json", .{index}), .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
    }
    const report = try std.json.Stringify.valueAlloc(allocator, .{ .version = @as(u32, 1), .setup_manifest_sha256 = setup_pin, .profile = setup.proof_profile, .segments = count, .native_proofs_created = count, .outer_proofs_created = @as(u32, 0), .keys = receipts }, .{});
    defer allocator.free(report);
    var file = try directory.createFile("setup.json", .{ .exclusive = true });
    defer file.close();
    try file.writeAll(report);
    std.debug.print("SEGMENT_V2_KEY_SETUP segments={d} outer_proofs_created=0 directory={s}\n", .{ count, output });
}

const WorkloadV1 = struct {
    version: u32,
    memory_addresses: usize,
    initial_memory_word: u32,
    segment_count: usize,
    proof_profile: proof.Profile,
};

/// Export expected statements from execution checked against the separate
/// instruction/memory model. This process creates neither keys nor proofs.
fn exportWorkload(comptime count: usize, allocator: std.mem.Allocator, selected: WorkloadV1, pin: [32]u8, output: []const u8) !void {
    var segments = try model.materialize(count, allocator, selected.memory_addresses, selected.initial_memory_word);
    defer for (&segments) |*segment| segment.deinit();
    var results: [count]*const frontend.runner.SegmentResult = undefined;
    for (&segments, 0..) |*segment, index| results[index] = &segment.base;
    try workload.validateSegments(count, results, selected.memory_addresses, selected.initial_memory_word);
    const statements = try workload.fixtureStatementsForSegments(count, allocator, results);
    const admitted = try workload.admitSegments(count, results, ingress.digest("recursive-v2-session"), statements);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    var expected: [count]ExpectedInput = undefined;
    var encoded: [count][]const u8 = undefined;
    const recursion = frontend.recursion;
    const ParentProfile = recursion.detached_parent_preparation_v1.ProfileV1;
    var profiles: [count]ParentProfile = undefined;
    var level: [count]recursion.span_continuation_v1.Words = undefined;
    const Artifact = struct { path: []const u8, bytes: []const u8 };
    var parent_artifacts: std.ArrayList(Artifact) = .empty;
    const ParentInput = struct { expected: ExpectedInput, boundary_profile: ?ExpectedInput };
    var parents: std.ArrayList([]const ParentInput) = .empty;
    // Materialize all authenticated statements before creating the output.
    for (admitted.sources, 0..) |source, index| {
        const words = try temporary.alloc(M31, try source.canonicalWordCount());
        _ = try source.encodeCanonical(words);
        const public = try frontend.air.public_data_v2.PublicDataV2.authenticate(words);
        encoded[index] = try command.encodeExpected(temporary, &public);
        const view = try public.authenticatedView();
        level[index] = try recursion.span_continuation_v1.fromSegment(&view.statement);
        const section = recursion.detached_section_profile_v1.SectionProfileV1{ .counts = .{
            view.entry_snapshot.count, view.exit_snapshot.count, view.entry_memory_clocks.count, view.exit_memory_clocks.count,
        } };
        const entry_addresses = try temporary.alloc(u32, view.entry_snapshot.count);
        const exit_addresses = try temporary.alloc(u32, view.exit_snapshot.count);
        for (entry_addresses, 0..) |*address, at| address.* = view.sparseEntry(view.entry_snapshot, at).address;
        for (exit_addresses, 0..) |*address, at| address.* = view.sparseEntry(view.exit_snapshot, at).address;
        const memory = recursion.detached_memory_profile_v1.MemoryProfileV1{ .entry_addresses = entry_addresses, .exit_addresses = exit_addresses };
        try section.validateView(&view);
        try memory.validate(section);
        profiles[index] = .{ .sections = .{ section, section }, .memory = .{ memory, memory } };
        expected[index] = .{
            .path = try std.fmt.allocPrint(temporary, "child-{d}-expected.json", .{index}),
            .sha256 = try std.fmt.allocPrint(temporary, "{s}", .{std.fmt.bytesToHex(command.hash(encoded[index]), .lower)}),
        };
    }
    var width: usize = count;
    var depth: usize = 0;
    while (width > 1) : (depth += 1) {
        const parent_inputs = try temporary.alloc(ParentInput, width / 2);
        for (parent_inputs, 0..) |*node, index| {
            level[index] = try recursion.span_continuation_v1.fold(&level[index * 2], &level[index * 2 + 1], if (width == 2) .root else .intermediate);
            const bytes = try recursion.detached_parent_command_v1.encodeExpected(temporary, &level[index]);
            const name = try std.fmt.allocPrint(temporary, "parent-{d}-{d}-expected.json", .{ depth + 1, index });
            node.* = .{ .expected = try artifactInput(temporary, name, bytes), .boundary_profile = null };
            try parent_artifacts.append(temporary, .{ .path = name, .bytes = bytes });
            if (depth == 0) {
                const profile = ParentProfile{ .sections = .{ profiles[index * 2].sections[0], profiles[index * 2 + 1].sections[0] }, .memory = .{ profiles[index * 2].memory[0], profiles[index * 2 + 1].memory[0] } };
                const topology = try std.json.Stringify.valueAlloc(temporary, profile, .{});
                const topology_name = try std.fmt.allocPrint(temporary, "parent-1-{d}-boundary.json", .{index});
                node.boundary_profile = try artifactInput(temporary, topology_name, topology);
                try parent_artifacts.append(temporary, .{ .path = topology_name, .bytes = topology });
            }
        }
        try parents.append(temporary, parent_inputs);
        width /= 2;
    }
    const template = try std.json.Stringify.valueAlloc(temporary, .{
        .version = @as(u32, 1),
        .profile = selected.proof_profile,
        .memory_addresses = selected.memory_addresses,
        .initial_memory_word = selected.initial_memory_word,
        .leaf_expected = expected,
        .parents = parents.items,
    }, .{});
    const setup = SetupV1{ .version = 1, .memory_addresses = selected.memory_addresses, .initial_memory_word = selected.initial_memory_word, .proof_profile = selected.proof_profile, .expected = &expected };
    const setup_json = try std.json.Stringify.valueAlloc(temporary, setup, .{});
    try std.fs.cwd().makeDir(output);
    var directory = try std.fs.cwd().openDir(output, .{});
    defer directory.close();
    for (expected, encoded) |input, bytes| try directory.writeFile(.{ .sub_path = input.path, .data = bytes });
    try directory.writeFile(.{ .sub_path = "setup-manifest.json", .data = setup_json });
    for (parent_artifacts.items) |artifact| try directory.writeFile(.{ .sub_path = artifact.path, .data = artifact.bytes });
    try directory.writeFile(.{ .sub_path = "tree-inputs.json", .data = template });
    const receipt = try std.json.Stringify.valueAlloc(temporary, .{
        .version = @as(u32, 1),
        .workload_sha256 = std.fmt.bytesToHex(pin, .lower),
        .setup_manifest_sha256 = std.fmt.bytesToHex(command.hash(setup_json), .lower),
        .segments = count,
        .memory_addresses = selected.memory_addresses,
        .retired_instructions = 2 + 3 * model.updatesForSegments(count),
        .keys_created = @as(u32, 0),
        .proofs_created = @as(u32, 0),
    }, .{});
    try directory.writeFile(.{ .sub_path = "workload.json", .data = receipt });
    std.debug.print("SEGMENT_V2_WORKLOAD_ADMISSION segments={d} addresses={d} keys_created=0 proofs_created=0\n", .{ count, selected.memory_addresses });
}

fn artifactInput(allocator: std.mem.Allocator, path: []const u8, bytes: []const u8) !ExpectedInput {
    return .{ .path = path, .sha256 = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.bytesToHex(command.hash(bytes), .lower)}) };
}
