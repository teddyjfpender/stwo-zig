//! Export canonical hostile inputs for an existing root candidate. This checks
//! transport custody only; the independent verifier must reject every fixture.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const transport = @import("ethereum_wrapper_root_command_v1.zig");
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const fixed = @import("ethereum_wrapper_fixed_circuit_v1.zig");
const public = @import("recursive_field_node_public_v2.zig");
const span = recursion.span_statement;
const M31 = core.fields.m31.M31;

const Mutation = enum { statement, boundary, position, protocol, circuit_parameter };
const Case = struct {
    name: []const u8,
    inputs_file: []const u8,
    inputs_sha256: []const u8,
    key_file: []const u8,
    expected_key_sha256: []const u8,
    test_only_alternate_key: bool,
};
const Manifest = struct {
    version: u16 = 1,
    initial_profile: bool,
    original_key_sha256: []const u8,
    original_inputs_sha256: []const u8,
    proof_sha256: []const u8,
    proof_bytes: usize,
    proof_verified: bool = false,
    cases: []const Case,
};

fn increment(word: u32) u32 {
    return (word + 1) % core.fields.m31.Modulus;
}

fn changedNode(original: public.NodePublicV2, mutation: Mutation) !?public.NodePublicV2 {
    try original.validate();
    if (original.coordinate.height != 0 or original.node_kind != .real)
        return error.ExpectedRealLeafRejectionSource;
    var words: span.StatementWords = undefined;
    for (original.statement_words, &words) |word, *out| out.* = M31.fromCanonical(word);
    var statement = try span.SpanStatement.fromCanonicalWords(&words);
    if (std.meta.activeTag(statement.body) != .executed)
        return error.ExpectedRealLeafRejectionSource;
    var coordinate = original.coordinate;
    switch (mutation) {
        .statement => statement.job.complete.program[0] = increment(statement.job.complete.program[0]),
        .boundary => {
            statement.body.executed.entry.rw_memory[0] = increment(statement.body.executed.entry.rw_memory[0]);
            if (statement.body.executed.first_segment == 0)
                statement.job.complete.initial_state = statement.body.executed.entry;
        },
        .position => {
            // Move an interior leaf to another interior slot, retaining cycles,
            // states and absent edge claims. A one-segment job has no such case.
            const executed = &statement.body.executed;
            if (executed.first_segment == 0 or executed.endSegment() == statement.job.segment_count)
                return null;
            const index = if (executed.first_segment > 1)
                executed.first_segment - 1
            else if (@as(u64, executed.first_segment) + 2 < statement.job.segment_count)
                executed.first_segment + 1
            else
                return null;
            executed.first_segment = index;
            statement.slots = try span.SlotSpan.init(index, 0);
            coordinate = try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, index);
        },
        else => unreachable,
    }
    const canonical = try statement.canonicalWords();
    var encoded: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (canonical, &encoded) |word, *out| out.* = word.toU32();
    const changed = try public.NodePublicV2.initLeaf(coordinate, encoded, original.source_digest);
    if (std.meta.eql(changed, original)) return error.UnchangedEthereumRejectionFixture;
    return changed;
}

fn changedKey(original: anytype, mutation: Mutation) !@TypeOf(original) {
    try original.validate();
    var changed = original;
    switch (mutation) {
        .protocol => {
            // Deliberately invalid, not an invented supported security profile.
            changed.session_fields.protocol.fri_query_count -= 1;
            if (changed.validate()) |_| return error.UnchangedEthereumRejectionFixture else |err| {
                if (err != error.InvalidTemporalParentProtocolAuthority) return err;
            }
        },
        .circuit_parameter => {
            changed.parameters.poseidon_active_rows = if (original.parameters.poseidon_active_rows > 0)
                original.parameters.poseidon_active_rows - 1
            else
                1;
            changed.session_fields = try fixed.sessionFields(&changed);
            try changed.validate();
            if (std.meta.eql(changed.session_fields, original.session_fields))
                return error.UnchangedEthereumRejectionFixture;
        },
        else => unreachable,
    }
    return changed;
}

fn writeExclusive(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
}

fn fileHash(dir: std.fs.Dir, name: []const u8, expected_bytes: usize) ![32]u8 {
    var file = try dir.openFile(name, .{});
    defer file.close();
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        total = try std.math.add(usize, total, count);
        if (total > expected_bytes) return error.EthereumRootProofIdentityMismatch;
        digest.update(buffer[0..count]);
    }
    if (total != expected_bytes) return error.EthereumRootProofIdentityMismatch;
    return digest.finalResult();
}

pub fn exportDirectory(allocator: std.mem.Allocator, initial: bool, source_path: []const u8, expected_key: [32]u8, output_path: []const u8) !void {
    if (initial)
        return exportSelected(transport.Initial38, allocator, true, source_path, expected_key, output_path);
    return exportSelected(transport.Ordinary, allocator, false, source_path, expected_key, output_path);
}

fn exportSelected(comptime Command: type, allocator: std.mem.Allocator, initial: bool, source_path: []const u8, expected_key: [32]u8, output_path: []const u8) !void {
    var source = try std.fs.cwd().openDir(source_path, .{});
    defer source.close();
    const key_json = try source.readFileAlloc(allocator, "key.json", 64 * 1024 * 1024);
    defer allocator.free(key_json);
    const admitted = try Command.OwnedKeyV1.admit(allocator, key_json, expected_key);
    defer admitted.deinit();
    const input_json = try source.readFileAlloc(allocator, "inputs.json", 128 * 1024);
    defer allocator.free(input_json);
    const original = try Command.decodeInputs(allocator, input_json);
    _ = try original.claims.vector(&admitted.key().manifest);
    // The complete checker requires all five cases. Initial/terminal leaves
    // cannot use this interior-slot mutation; reject that unsupported source
    // before creating any output rather than publishing a partial manifest.
    const position_node = (try changedNode(original.node, .position)) orelse
        return error.UnsupportedEthereumRejectionPosition;
    if (!std.meta.eql(try fileHash(source, "proof.bin", original.proof_bytes), original.proof_sha256))
        return error.EthereumRootProofIdentityMismatch;

    // Never reuse an output directory. The manifest is published last, so a
    // partial export cannot be mistaken for a complete rejection fixture set.
    try std.fs.cwd().makeDir(output_path);
    var output = try std.fs.cwd().openDir(output_path, .{});
    defer output.close();
    try writeExclusive(output, "original-key.json", key_json);
    var cases: [5]Case = undefined;
    var count: usize = 0;
    var input_hashes: [5][64]u8 = undefined;
    var key_hashes: [5][64]u8 = undefined;
    inline for (.{
        .{ Mutation.statement, "changed-statement" },
        .{ Mutation.boundary, "changed-boundary" },
        .{ Mutation.position, "changed-position" },
        .{ Mutation.protocol, "changed-protocol" },
        .{ Mutation.circuit_parameter, "changed-circuit-parameter" },
    }) |entry| {
        const mutation = entry[0];
        const alternate_key = mutation == .protocol or mutation == .circuit_parameter;
        var inputs = original;
        var key_pin = expected_key;
        const key_file = if (alternate_key) entry[1] ++ "-key.json" else "original-key.json";
        if (alternate_key) {
            const changed = try changedKey(admitted.key().*, mutation);
            const bytes = try std.json.Stringify.valueAlloc(allocator, changed, .{});
            defer allocator.free(bytes);
            key_pin = transport.hash(bytes);
            if (std.meta.eql(key_pin, expected_key)) return error.UnchangedEthereumRejectionFixture;
            try writeExclusive(output, key_file, bytes);
        } else {
            inputs.node = if (mutation == .position) position_node else (try changedNode(original.node, mutation)).?;
        }
        // Key-only cases retain the exact original input bytes, not merely an
        // equivalent JSON rendering. Node-only cases use the shared public ABI.
        const changed_json: ?[]u8 = if (!alternate_key) try std.json.Stringify.valueAlloc(allocator, inputs, .{}) else null;
        defer if (changed_json) |bytes| allocator.free(bytes);
        const bytes = changed_json orelse input_json;
        const inputs_file = entry[1] ++ "-inputs.json";
        try writeExclusive(output, inputs_file, bytes);
        input_hashes[count] = std.fmt.bytesToHex(transport.hash(bytes), .lower);
        key_hashes[count] = std.fmt.bytesToHex(key_pin, .lower);
        cases[count] = .{ .name = entry[1], .inputs_file = inputs_file, .inputs_sha256 = &input_hashes[count], .key_file = key_file, .expected_key_sha256 = &key_hashes[count], .test_only_alternate_key = alternate_key };
        count += 1;
    }
    if (!std.meta.eql(try fileHash(source, "key.json", key_json.len), expected_key) or
        !std.meta.eql(try fileHash(source, "inputs.json", input_json.len), transport.hash(input_json)) or
        !std.meta.eql(try fileHash(source, "proof.bin", original.proof_bytes), original.proof_sha256))
        return error.EthereumRejectionSourceChanged;
    const original_key_hex = std.fmt.bytesToHex(expected_key, .lower);
    const original_inputs_hex = std.fmt.bytesToHex(transport.hash(input_json), .lower);
    const proof_hex = std.fmt.bytesToHex(original.proof_sha256, .lower);
    const manifest = Manifest{ .initial_profile = initial, .original_key_sha256 = &original_key_hex, .original_inputs_sha256 = &original_inputs_hex, .proof_sha256 = &proof_hex, .proof_bytes = original.proof_bytes, .cases = cases[0..count] };
    const manifest_json = try std.json.Stringify.valueAlloc(allocator, manifest, .{ .whitespace = .indent_2 });
    defer allocator.free(manifest_json);
    try writeExclusive(output, "manifest.json", manifest_json);
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 4) return error.ExpectedRootDirectoryIndependentKeySha256AndOutput;
    const selected = try transport.parseArguments(args[1 .. args.len - 1]);
    try exportDirectory(allocator, selected.initial, selected.directory, selected.expected_key_sha256, args[args.len - 1]);
}

test "Ethereum root rejection fixtures preserve canonical statements and exact candidate custody" {
    try exerciseFixtures(false);
    try exerciseFixtures(true);
}

fn exerciseFixtures(comptime initial: bool) !void {
    const allocator = std.testing.allocator;
    const fixtures = @import("ethereum_wrapper_root_verifier_v1_test.zig");
    const Command = if (initial) transport.Initial38 else transport.Ordinary;
    const Verifier = if (initial) verifier.Initial38 else verifier.Ordinary;
    const key = if (initial) try fixtures.testInitialKey() else try fixtures.testKey();
    const session = try fixtures.testSession(null);
    var first_words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (session.parent_statement_words, &first_words) |word, *out| out.* = word.toU32();
    const first_node = try public.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0), first_words, [_]u32{1} ** 8);
    const first_boundary = (try changedNode(first_node, .boundary)).?;
    try first_boundary.validate();
    try std.testing.expect((try changedNode(first_node, .position)) == null);
    var statement = try span.SpanStatement.fromCanonicalWords(&session.parent_statement_words);
    statement.job = try span.JobContext.init(statement.job.complete, 5);
    statement.job.complete.total_cycles = 40;
    statement.slots = try span.SlotSpan.init(2, 0);
    statement.body.executed.first_segment = 2;
    statement.body.executed.first_cycle = 16;
    statement.body.executed.input = span.EdgeClaim.absent();
    statement.body.executed.output = span.EdgeClaim.absent();
    const canonical = try statement.canonicalWords();
    var words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (canonical, &words) |word, *out| out.* = word.toU32();
    const node = try public.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 2), words, [_]u32{1} ** 8);
    const proof = "transport fixture only, not a verified STARK";
    const inputs = Command.PublicInputsV1{ .version = Verifier.VERSION, .node = node, .claims = .{ .values = @splat(core.fields.qm31.QM31.zero()), .poseidon_partials = @splat(core.fields.qm31.QM31.zero()) }, .interaction_pow_nonce = 17, .proof_bytes = proof.len, .proof_sha256 = transport.hash(proof) };
    const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(key_json);
    const input_json = try std.json.Stringify.valueAlloc(allocator, inputs, .{});
    defer allocator.free(input_json);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.makeDir("source");
    var source = try temporary.dir.openDir("source", .{});
    defer source.close();
    try writeExclusive(source, "key.json", key_json);
    try writeExclusive(source, "inputs.json", input_json);
    try writeExclusive(source, "proof.bin", proof);
    const source_path = try source.realpathAlloc(allocator, ".");
    defer allocator.free(source_path);
    const temporary_path = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(temporary_path);
    const output_path = try std.fs.path.join(allocator, &.{ temporary_path, "rejections" });
    defer allocator.free(output_path);
    const pin = transport.hash(key_json);
    var wrong_pin = pin;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.EthereumRootKeyHashMismatch, exportDirectory(allocator, initial, source_path, wrong_pin, output_path));
    try exportDirectory(allocator, initial, source_path, pin, output_path);
    try std.testing.expectError(error.PathAlreadyExists, exportDirectory(allocator, initial, source_path, pin, output_path));
    var output = try std.fs.cwd().openDir(output_path, .{});
    defer output.close();
    const manifest_json = try output.readFileAlloc(allocator, "manifest.json", 128 * 1024);
    defer allocator.free(manifest_json);
    const parsed = try std.json.parseFromSlice(Manifest, allocator, manifest_json, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 5), parsed.value.cases.len);
    try std.testing.expect(!parsed.value.proof_verified);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(pin, .lower), parsed.value.original_key_sha256);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(transport.hash(input_json), .lower), parsed.value.original_inputs_sha256);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(inputs.proof_sha256, .lower), parsed.value.proof_sha256);
    try std.testing.expectEqual(inputs.proof_bytes, parsed.value.proof_bytes);
    for (parsed.value.cases) |case| {
        const bytes = try output.readFileAlloc(allocator, case.inputs_file, 128 * 1024);
        defer allocator.free(bytes);
        try std.testing.expectEqualStrings(case.inputs_sha256, &std.fmt.bytesToHex(transport.hash(bytes), .lower));
        const changed = try Command.decodeInputs(allocator, bytes);
        var restored = changed;
        restored.node = inputs.node;
        try std.testing.expectEqualDeep(inputs, restored);
        const changed_key_json = try output.readFileAlloc(allocator, case.key_file, 64 * 1024 * 1024);
        defer allocator.free(changed_key_json);
        const changed_pin = transport.hash(changed_key_json);
        try std.testing.expectEqualStrings(case.expected_key_sha256, &std.fmt.bytesToHex(changed_pin, .lower));
        if (case.test_only_alternate_key) {
            try std.testing.expectEqualStrings(input_json, bytes);
            try std.testing.expect(!std.meta.eql(pin, changed_pin));
            if (std.mem.eql(u8, case.name, "changed-protocol")) {
                try std.testing.expectError(error.InvalidTemporalParentProtocolAuthority, Command.OwnedKeyV1.admit(allocator, changed_key_json, changed_pin));
            } else {
                const admitted = try Command.OwnedKeyV1.admit(allocator, changed_key_json, changed_pin);
                defer admitted.deinit();
                try std.testing.expect(!std.meta.eql(admitted.key().session_fields, key.session_fields));
            }
        } else {
            try std.testing.expect(!std.meta.eql(node, changed.node));
            try std.testing.expectEqualDeep(pin, changed_pin);
            try std.testing.expectEqualDeep(node.source_digest, changed.node.source_digest);
            var decoded_words: span.StatementWords = undefined;
            for (changed.node.statement_words, &decoded_words) |word, *out| out.* = M31.fromCanonical(word);
            const changed_statement = try span.SpanStatement.fromCanonicalWords(&decoded_words);
            if (std.mem.eql(u8, case.name, "changed-statement")) {
                try std.testing.expectEqual(increment(statement.job.complete.program[0]), changed_statement.job.complete.program[0]);
                try std.testing.expectEqualDeep(statement.body, changed_statement.body);
            } else if (std.mem.eql(u8, case.name, "changed-boundary")) {
                try std.testing.expectEqual(increment(statement.body.executed.entry.rw_memory[0]), changed_statement.body.executed.entry.rw_memory[0]);
                try std.testing.expectEqualDeep(statement.job, changed_statement.job);
            } else {
                try std.testing.expectEqual(@as(u32, 1), changed.node.coordinate.index);
                try std.testing.expectEqual(@as(u32, 1), changed_statement.body.executed.first_segment);
                try std.testing.expectEqualDeep(statement.body.executed.entry, changed_statement.body.executed.entry);
            }
        }
    }
    const unsupported_path = try std.fs.path.join(allocator, &.{ temporary_path, "unsupported" });
    defer allocator.free(unsupported_path);
    var last_statement = statement;
    last_statement.slots = try span.SlotSpan.init(4, 0);
    last_statement.body.executed.first_segment = 4;
    last_statement.body.executed.first_cycle = 32;
    last_statement.body.executed.exit = last_statement.job.complete.final_state;
    last_statement.body.executed.output = try span.EdgeClaim.present(last_statement.job.complete.public_output);
    var last_words: [public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (try last_statement.canonicalWords(), &last_words) |word, *out| out.* = word.toU32();
    const last_node = try public.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 4), last_words, node.source_digest);
    for ([_]public.NodePublicV2{ first_node, last_node }) |boundary_node| {
        var unsupported = inputs;
        unsupported.node = boundary_node;
        const bytes = try std.json.Stringify.valueAlloc(allocator, unsupported, .{});
        defer allocator.free(bytes);
        try source.writeFile(.{ .sub_path = "inputs.json", .data = bytes });
        try std.testing.expectError(error.UnsupportedEthereumRejectionPosition, exportDirectory(allocator, initial, source_path, pin, unsupported_path));
        try std.testing.expectError(error.FileNotFound, temporary.dir.access("unsupported", .{}));
    }
    try source.writeFile(.{ .sub_path = "inputs.json", .data = input_json });
    var corrupt = try source.openFile("proof.bin", .{ .mode = .write_only });
    defer corrupt.close();
    try corrupt.writeAll("X");
    try std.testing.expectError(error.EthereumRootProofIdentityMismatch, exportDirectory(allocator, initial, source_path, pin, output_path));
}
