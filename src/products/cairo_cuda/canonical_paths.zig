//! Explicit asset paths for the proof-independent resident product.
const std = @import("std");
const stwo = @import("stwo_cairo_cuda");

pub const Paths = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    source: stwo.integration.canonical_source.Paths,
    preprocessed: []const u8,

    pub fn init(parent: std.mem.Allocator, input: []const u8) !Paths {
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
        return .{ .allocator = parent, .arena = arena, .source = .{
            .input = input,
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
