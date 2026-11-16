//! Explicit asset paths for the proof-independent resident product.
const std = @import("std");
const stwo = @import("stwo_cairo_cuda");

pub const Paths = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    source: stwo.integration.canonical_source.Paths,
    preprocessed: []const u8,

    pub fn init(parent: std.mem.Allocator, input: []const u8, circuit_registry: ?[]const u8) !Paths {
        const arena = try parent.create(std.heap.ArenaAllocator);
        errdefer parent.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(parent);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const asset_root = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_ARTIFACT_DIR") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try std.fs.cwd().realpathAlloc(allocator, "vectors/cairo"),
            else => return err,
        };
        const preprocessed = try std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS");
        if (!std.fs.path.isAbsolute(asset_root) or !std.fs.path.isAbsolute(preprocessed)) return error.ArtifactPathNotAbsolute;
        const variant_name = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_PREPROCESSED_VARIANT") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => "canonical_small",
            else => return err,
        };
        const variant = std.meta.stringToEnum(stwo.frontend.preprocessed.trace.Variant, variant_name) orelse return error.InvalidPreprocessedVariant;
        const leaf_lane = if (circuit_registry) |registry_path| blk: {
            const bytes = try std.fs.cwd().readFileAlloc(allocator, registry_path, 16 << 20);
            var registry = try admitRegistry(allocator, bytes);
            defer registry.deinit();
            break :blk try stwo.frontend.proving.leaf_lane.Lane.fromParameters(registry.registry.cairo_prover_params);
        } else null;
        return .{ .allocator = parent, .arena = arena, .source = .{
            .input = input,
            .leaf_lane = leaf_lane,
            .variant = variant,
            .automatic_variant = !std.process.hasEnvVarConstant("STWO_CAIRO_CUDA_PREPROCESSED_VARIANT"),
            .library = try std.fs.path.join(allocator, &.{ asset_root, "official/air_template_library_v1.json" }),
            .witnesses = try std.fs.path.join(allocator, &.{ asset_root, "official/witness_programs_v1.bin" }),
            .topology = try std.fs.path.join(allocator, &.{ asset_root, "official/witness_feed_topology_v1.json" }),
            .fixed = try std.fs.path.join(allocator, &.{ asset_root, "cairo_fixed_tables.bin" }),
            .relations = try std.fs.path.join(allocator, &.{ asset_root, "cairo_relation_templates.bin" }),
        }, .preprocessed = preprocessed };
    }

    pub fn deinit(self: *Paths) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

fn admitRegistry(allocator: std.mem.Allocator, text: []const u8) @import("stwo_circuit_recursion_wire").registry.ReadError!@import("stwo_circuit_recursion_wire").registry.OwnedRegistry {
    var bytes: [320]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&bytes);
    return admitRegistryTo(&stderr.interface, allocator, text);
}
fn admitRegistryTo(out: *std.Io.Writer, allocator: std.mem.Allocator, text: []const u8) @import("stwo_circuit_recursion_wire").registry.ReadError!@import("stwo_circuit_recursion_wire").registry.OwnedRegistry {
    const wire = @import("stwo_circuit_recursion_wire");
    return wire.registry.parseRegistry(allocator, text) catch |err| {
        const entry = wire.error_codes.fromJsonRead(err);
        std.json.Stringify.value(.{ .schema = "recursion_input_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = "registry", .code = entry.code, .class = entry.class }, .{}, out) catch return err;
        out.writeByte('\n') catch return err;
        out.flush() catch {};
        return err;
    };
}

test "CUDA canonical registry admission executes actual JSON origin without GPU" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/registries/recursive_tree_test.json", 1 << 20);
    defer a.free(bytes);
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    var parsed = try admitRegistryTo(&output.writer, a, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
    try std.testing.expectError(error.InvalidJson, admitRegistryTo(&output.writer, a, "{"));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_input_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"registry\",\"code\":20993,\"class\":\"invalid_input\"}\n", output.written());
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.InvalidValue, admitRegistryTo(&failing, a, "[]"));
}
