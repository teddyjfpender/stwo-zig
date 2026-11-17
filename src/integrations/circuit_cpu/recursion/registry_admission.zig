//! Closed registry lookups at the real leaf/fold admission boundary.
const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");
const Queries = struct {
    pub const config = wire.registry.CircuitRegistry.config;
    pub const leaf = wire.registry.CircuitRegistry.leafVerifier;
    pub const multiverifier = wire.registry.CircuitRegistry.multiverifier;
};
pub const Kind = std.meta.DeclEnum(Queries);
fn Result(comptime kind: Kind) type {
    return @typeInfo(@TypeOf(@field(Queries, @tagName(kind)))).@"fn".return_type.?;
}
pub fn query(comptime kind: Kind, registry: wire.registry.CircuitRegistry, argument: anytype) Result(kind) {
    var bytes: [320]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&bytes);
    return queryTo(kind, &stderr.interface, registry, argument);
}
fn queryTo(comptime kind: Kind, out: *std.Io.Writer, registry: wire.registry.CircuitRegistry, argument: anytype) Result(kind) {
    const operation = @field(Queries, @tagName(kind));
    return (if (comptime kind == .multiverifier) operation(registry) else operation(registry, argument)) catch |err| {
        const entry = wire.error_codes.fromRegistryQuery(err);
        std.json.Stringify.value(.{ .schema = "recursion_registry_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = @tagName(kind), .code = entry.code, .class = entry.class }, .{}, out) catch return err;
        out.writeByte('\n') catch return err;
        out.flush() catch {};
        return err;
    };
}

test "registry admission executes actual query origins and preserves writer failure" {
    const a = std.testing.allocator;
    const text = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registries/recursive_tree_test.json", 1 << 20);
    defer a.free(text);
    var parsed = try wire.registry.parseRegistry(a, text);
    defer parsed.deinit();
    const registry = parsed.registry;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    _ = try queryTo(.config, &out.writer, registry, registry.circuit_proof_configs[0].name);
    _ = try queryTo(.leaf, &out.writer, registry, registry.leaf_verifiers[0].trace_log_size);
    _ = try queryTo(.multiverifier, &out.writer, registry, {});
    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    try std.testing.expectError(error.UnknownConfig, queryTo(.config, &out.writer, registry, "absent"));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_registry_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"config\",\"code\":21249,\"class\":\"invalid_input\"}\n", out.written());
    out.clearRetainingCapacity();
    try std.testing.expectError(error.UnsupportedLeaf, queryTo(.leaf, &out.writer, registry, std.math.maxInt(u32)));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "21250") != null);
    var missing = registry;
    missing.multiverifiers = &.{};
    out.clearRetainingCapacity();
    try std.testing.expectError(error.NotExactlyOneMultiverifier, queryTo(.multiverifier, &out.writer, missing, {}));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "21252") != null);
    missing.leaf_verifiers = &.{};
    try std.testing.expectError(error.NoLeafVerifiers, missing.maxLeafTraceLogSize());
    try std.testing.expectEqual(@as(u16, 0x5303), wire.error_codes.fromRegistryQuery(error.NoLeafVerifiers).code);
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.UnknownConfig, queryTo(.config, &failing, registry, "absent"));
}
