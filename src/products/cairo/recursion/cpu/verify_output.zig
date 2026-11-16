const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");

// This scoped diagnostic is optional and never changes a primary verdict.
pub fn write(out: *std.Io.Writer, entry: @import("stwo_core").error_codes.Entry) void {
    if (entry.code != 0x5001 and entry.code != 0x5002 and entry.code != 0x5501 and entry.code != 0x5503) return;
    const known = wire.error_codes.lookup(entry.code) orelse return;
    if (known.class != entry.class or !std.mem.eql(u8, known.tag, entry.tag) or !std.mem.eql(u8, known.since, entry.since)) return;
    std.json.Stringify.value(.{ .schema = "circuit_decode_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = "circuit_serialize.deserializeProof", .code = entry.code, .class = entry.class }, .{}, out) catch return;
    out.writeByte('\n') catch return;
    out.flush() catch {};
}

// Closed product-private input admission. No caller-supplied parser or callback
// can reach this origin classifier; the real command selects a concrete format.
const Parsers = struct {
    pub const registry = wire.registry.parseRegistry;
    pub const request = wire.verify_request.parseVerifyRequest;
    pub const leaf = wire.leaf_proof_json.parseLeafInput;
    pub const manifest = wire.leaf_proof_json.parseLeavesManifest;
    pub const definition = wire.registry_definition.parseRegistryDefinition;
    pub const parameters = wire.registry.parseProverParameters;
    pub const fri = wire.registry.parseFriConfig;
    pub const checkpoint = wire.checkpoint.parse;
};
pub const InputFormat = std.meta.DeclEnum(Parsers);

fn ParseResult(comptime format: InputFormat) type {
    return @typeInfo(@TypeOf(@field(Parsers, @tagName(format)))).@"fn".return_type.?;
}

pub fn parseInput(comptime format: InputFormat, allocator: std.mem.Allocator, text: []const u8) ParseResult(format) {
    var buffer: [320]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&buffer);
    return parseInputTo(format, &stderr.interface, allocator, text);
}

fn parseInputTo(comptime format: InputFormat, out: *std.Io.Writer, allocator: std.mem.Allocator, text: []const u8) ParseResult(format) {
    return @field(Parsers, @tagName(format))(allocator, text) catch |err| {
        const entry = if (comptime format == .definition)
            wire.error_codes.fromRegistryDefinition(err)
        else if (comptime format == .checkpoint)
            wire.error_codes.fromPacked(err)
        else
            wire.error_codes.fromJsonRead(err);
        // Failure of this optional side channel never replaces the parser cause.
        std.json.Stringify.value(.{ .schema = "recursion_input_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = @tagName(format), .code = entry.code, .class = entry.class }, .{}, out) catch return err;
        out.writeByte('\n') catch return err;
        out.flush() catch {};
        return err;
    };
}

test "decoder rejection JSON is exact and unknown metadata emits no fabricated code" {
    const entry = wire.error_codes.fromCircuitDecode(error.NotEnoughData);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    write(&output.writer, entry);
    try std.testing.expectEqualStrings("{\"schema\":\"circuit_decode_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"circuit_serialize.deserializeProof\",\"code\":20481,\"class\":\"invalid_input\"}\n", output.written());
    for (0..4) |fault| {
        var bad = entry;
        switch (fault) {
            0 => bad.code = 65535,
            1 => bad.class = .internal,
            2 => bad.tag = "ForeignOrigin",
            3 => bad.since = "1.0.0",
            else => unreachable,
        }
        const before = output.written().len;
        write(&output.writer, bad);
        try std.testing.expectEqual(before, output.written().len);
    }
}

test "optional decoder diagnostic write failure cannot replace primary rejection" {
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    write(&failing, wire.error_codes.fromCircuitDecode(error.ValueOutOfRange));
    try std.testing.expectEqual(@as(usize, 0), failing.end);
}

test "recursion JSON admission executes all seven owned origins and rejects physical invalid inputs" {
    const a = std.testing.allocator;
    inline for (std.meta.fields(InputFormat)) |field| {
        const format: InputFormat = @enumFromInt(field.value);
        var output: std.Io.Writer.Allocating = .init(a);
        defer output.deinit();
        for ([_][]const u8{ "{", "{}", "[]" }, [_]wire.json_text.ReadError{ error.InvalidJson, error.MissingField, error.InvalidValue }) |text, expected| {
            try std.testing.expectError(expected, parseInputTo(format, &output.writer, a, text));
            var buffer: [320]u8 = undefined;
            const entry = wire.error_codes.fromJsonRead(expected);
            const exact = try std.fmt.bufPrint(&buffer, "{{\"schema\":\"recursion_input_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"{s}\",\"code\":{d},\"class\":\"invalid_input\"}}\n", .{ @tagName(format), entry.code });
            try std.testing.expectEqualStrings(exact, output.written());
            output.clearRetainingCapacity();
        }
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, parseInputTo(format, &output.writer, failing.allocator(), "{}"));
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
        try std.testing.expect(std.mem.indexOf(u8, output.written(), "resource_exhausted") != null);
    }
}

test "recursion JSON admission preserves parser error when diagnostic writer fails" {
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.InvalidJson, parseInputTo(.registry, &failing, std.testing.allocator, "{"));
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    write(&output.writer, wire.error_codes.fromPostcard(error.EndOfStream));
    write(&output.writer, wire.error_codes.fromJsonRead(error.InvalidJson));
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

const InputCases = struct {
    fn fixture(comptime format: InputFormat, a: std.mem.Allocator) ![]u8 {
        return switch (format) {
            .registry => std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registries/recursive_tree_test.json", 1 << 20),
            .parameters => std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registry_definitions/canonical_small/cairo_prover_params.json", 1 << 20),
            .fri => std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registry_definitions/canonical_small/circuit_fri_config.json", 1 << 20),
            .definition => std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registry_definitions/canonical_small/definition.json", 1 << 20),
            .checkpoint => blk: {
                var out: std.Io.Writer.Allocating = .init(a);
                defer out.deinit();
                try wire.checkpoint.write(&out.writer, .{ .proof = "abc", .preprocessed_root = @splat(1), .output_digest = @splat(2), .packed_output = .{ .composite = .{ .circuit_hash = @splat(3), .subtasks = &.{} } } });
                break :blk a.dupe(u8, out.written());
            },
            .manifest => a.dupe(u8, "{\"leaves\":[\"b.json\",\"a.json\"]}"),
            .request => a.dupe(u8,
                \\{"pcs_config":{"fri_config":{"pow_bits":10,"log_blowup_factor":1,"log_last_layer_degree_bound":0,"n_queries":3,"fold_step":1},"trace_lifting_log_size":21,"preprocessed_lifting_log_size":21},"preprocessed_column_log_sizes":[["eq_in0_address",4]],"preprocessed_root":[1,2,3,4,5,6,7,8],"output_digest":[0,0,0,0,0,0,0,9]}
            ),
            .leaf => blk: {
                var out: std.Io.Writer.Allocating = .init(a);
                defer out.deinit();
                try wire.leaf_proof_json.writeLeafInput(&out.writer, .{
                    .proof = .{ .circuit_preprocessed_root = .{ .words = @splat(0) }, .circuit_hash = .{ .words = @splat(1) }, .proof = "abc" },
                    .output_preimage = &.{ "3", "4" },
                });
                break :blk a.dupe(u8, out.written());
            },
        };
    }
    fn cleanup(value: anytype) void {
        if (@hasDecl(@TypeOf(value.*), "deinit")) value.deinit();
    }
    fn encode(comptime format: InputFormat, out: *std.Io.Writer, value: anytype) !void {
        switch (format) {
            .registry => try wire.registry.writeRegistry(out, value.registry),
            .request => try wire.verify_request.writeVerifyRequest(out, value.request),
            .leaf => try wire.leaf_proof_json.writeLeafInput(out, value.value),
            .checkpoint => try wire.checkpoint.write(out, value.node),
            .fri => {
                var writer = wire.json_text.Writer.init(out, false);
                try wire.registry.writeFriConfig(&writer, value);
            },
            else => @compileError("this format has no public writer"),
        }
    }
};

test "recursion JSON actual admissions preserve public codec bytes and every allocation cleanup" {
    const a = std.testing.allocator;
    inline for (std.meta.fields(InputFormat)) |field| {
        const format: InputFormat = @enumFromInt(field.value);
        const text = try InputCases.fixture(format, a);
        defer a.free(text);
        const before = std.hash.Wyhash.hash(0, text);
        var out: std.Io.Writer.Allocating = .init(a);
        defer out.deinit();
        var parsed = try parseInputTo(format, &out.writer, a, text);
        defer InputCases.cleanup(&parsed);
        try std.testing.expectEqual(@as(usize, 0), out.written().len);
        try std.testing.expectEqual(before, std.hash.Wyhash.hash(0, text));
        if (comptime format == .registry or format == .request or format == .leaf or format == .fri or format == .checkpoint) {
            try InputCases.encode(format, &out.writer, parsed);
            var silence: [0]u8 = .{};
            var sink = std.Io.Writer.fixed(&silence);
            var redecoded = try parseInputTo(format, &sink, a, out.written());
            defer InputCases.cleanup(&redecoded);
            var reencoded: std.Io.Writer.Allocating = .init(a);
            defer reencoded.deinit();
            try InputCases.encode(format, &reencoded.writer, redecoded);
            try std.testing.expectEqualStrings(out.written(), reencoded.written());
        }
        const Runner = struct {
            fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
                var none: [0]u8 = .{};
                var sink = std.Io.Writer.fixed(&none);
                var value = try parseInputTo(format, &sink, allocator, bytes);
                defer InputCases.cleanup(&value);
            }
        };
        try std.testing.checkAllAllocationFailures(a, Runner.run, .{text});
    }
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    try std.testing.expectError(error.EmptyTraceRange, parseInputTo(.definition, &output.writer, a,
        \\{"cairo_prover_params_json":"a","circuit_fri_config_json":"b","program":"p","min_trace_log_size":21,"max_trace_log_size":20,"add_zk_blinding":false}
    ));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_input_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"definition\",\"code\":20997,\"class\":\"invalid_input\"}\n", output.written());
}
