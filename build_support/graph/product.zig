//! Release and target policy for logical build products.

const std = @import("std");
const modules = @import("modules.zig");

pub const SCHEMA_VERSION: u32 = 1;

pub const State = enum {
    released,
    staged,
    parity_gated,
    experimental,
    disabled,
    unavailable,
};

pub const TargetSupport = enum {
    any,
    linux,
    macos,

    pub fn accepts(self: TargetSupport, os: std.Target.Os.Tag) bool {
        return switch (self) {
            .any => true,
            .linux => os == .linux,
            .macos => os == .macos,
        };
    }
};

pub const DependencyManifest = struct {
    module_roots: []const []const u8 = &.{},
    external_dependencies: []const []const u8 = &.{},
};

pub const NamedImport = struct {
    name: []const u8,
    source: []const u8,
};

pub const SourceClosure = struct {
    entry_roots: []const []const u8,
    named_imports: []const NamedImport = &.{},
    generated_imports: []const []const u8 = &.{},
    allowed_files: []const []const u8 = &.{},
    allowed_prefixes: []const []const u8 = &.{},
    required_dynamic_dependencies: []const []const u8 = &.{},
    forbidden_dynamic_dependencies: []const []const u8 = &.{},

    pub fn validate(self: SourceClosure) !void {
        if (self.entry_roots.len == 0) return error.MissingClosureEntryRoot;
        if (self.allowed_files.len == 0 and self.allowed_prefixes.len == 0)
            return error.MissingClosureSourceOwner;
        for (self.entry_roots) |path| if (path.len == 0) return error.EmptyClosurePath;
        for (self.allowed_files) |path| if (path.len == 0) return error.EmptyClosurePath;
        for (self.allowed_prefixes) |path| if (path.len == 0) return error.EmptyClosurePath;
        for (self.named_imports, 0..) |named, index| {
            if (named.name.len == 0 or named.source.len == 0) return error.InvalidNamedImport;
            for (self.named_imports[index + 1 ..]) |other| {
                if (std.mem.eql(u8, named.name, other.name)) return error.DuplicateNamedImport;
            }
        }
    }
};

pub const Descriptor = struct {
    schema_version: u32 = SCHEMA_VERSION,
    product: modules.Product,
    state: State,
    target_support: TargetSupport,
    unsupported_target_reason: ?[]const u8 = null,
    unavailable_reason: ?[]const u8 = null,
    build_step: []const u8,
    test_step: ?[]const u8,
    executable: ?[]const u8,
    installed_artifacts: []const []const u8 = &.{},
    compatibility_aliases: []const []const u8 = &.{},
    release_gates: []const []const u8 = &.{},
    benchmark_step: ?[]const u8 = null,
    profiler_step: ?[]const u8 = null,
    dependencies: DependencyManifest = .{},
    source_closure: ?SourceClosure = null,

    pub fn validate(self: Descriptor) !void {
        if (self.schema_version != SCHEMA_VERSION) return error.UnsupportedProductSchema;
        try self.product.validate();
        if (self.build_step.len == 0) return error.MissingBuildStep;
        if (self.test_step) |name| if (name.len == 0) return error.MissingTestStep;
        if (self.executable) |name| if (name.len == 0) return error.MissingExecutable;
        if (self.target_support != .any and empty(self.unsupported_target_reason))
            return error.MissingUnsupportedTargetReason;
        if (!self.isConstructible() and empty(self.unavailable_reason))
            return error.MissingUnavailableReason;
        if (self.isConstructible() and self.executable == null and self.product.role == .cli)
            return error.MissingExecutable;
        if (!self.isConstructible() and self.executable != null)
            return error.UnavailableProductInstallsExecutable;
        if (!self.isConstructible() and self.installed_artifacts.len != 0)
            return error.UnavailableProductInstallsArtifact;
        if (self.isConstructible() and self.product.role == .cli and
            self.installed_artifacts.len == 0)
            return error.MissingInstalledArtifact;
        if (self.isConstructible() and self.dependencies.module_roots.len == 0)
            return error.MissingDependencyManifest;
        if (self.isConstructible()) {
            const closure = self.source_closure orelse return error.MissingSourceClosure;
            try closure.validate();
        }
    }

    pub fn isConstructible(self: Descriptor) bool {
        return switch (self.state) {
            .released, .staged, .parity_gated => true,
            .experimental, .disabled, .unavailable => false,
        };
    }

    pub fn isAvailableOn(self: Descriptor, os: std.Target.Os.Tag) bool {
        return self.isConstructible() and self.target_support.accepts(os);
    }

    pub fn unavailableMessage(self: Descriptor, os: std.Target.Os.Tag) ?[]const u8 {
        if (!self.target_support.accepts(os)) return self.unsupported_target_reason;
        if (!self.isConstructible()) return self.unavailable_reason;
        return null;
    }
};

pub fn registerUnavailable(
    b: *std.Build,
    descriptor: Descriptor,
    os: std.Target.Os.Tag,
) void {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid product descriptor {s}: {s}",
        .{ descriptor.product.name, @errorName(err) },
    );
    const reason = descriptor.unavailableMessage(os) orelse std.debug.panic(
        "product {s} is available on {s}",
        .{ descriptor.product.name, @tagName(os) },
    );
    const failure = b.addFail(b.fmt("{s} is unavailable: {s}", .{
        descriptor.product.name,
        reason,
    }));
    const build_step = b.step(descriptor.build_step, reason);
    build_step.dependOn(&failure.step);
    if (descriptor.test_step) |name| {
        const test_step = b.step(name, reason);
        test_step.dependOn(&failure.step);
    }
    // The platform-blind catalog closure asserts benchmark step names on
    // every host; unavailable products register them fail-closed too.
    if (descriptor.benchmark_step) |name| {
        const benchmark_step = b.step(name, reason);
        benchmark_step.dependOn(&failure.step);
    }
}

fn empty(value: ?[]const u8) bool {
    return value == null or value.?.len == 0;
}

test "disabled products require a reason and cannot install" {
    const invalid = Descriptor{
        .product = .{
            .name = "stwo-cairo-metal",
            .frontend = .cairo,
            .backend = .metal,
            .role = .cli,
        },
        .state = .disabled,
        .target_support = .macos,
        .unsupported_target_reason = "Metal requires macOS",
        .build_step = "stwo-cairo-metal",
        .test_step = null,
        .executable = null,
    };
    try std.testing.expectError(error.MissingUnavailableReason, invalid.validate());
}

test "target support is compatibility policy, not product selection" {
    const descriptor = Descriptor{
        .product = .{
            .name = "stwo-native-metal",
            .frontend = .native,
            .backend = .metal,
            .role = .cli,
        },
        .state = .parity_gated,
        .target_support = .macos,
        .unsupported_target_reason = "Metal requires macOS",
        .build_step = "stwo-native-metal",
        .test_step = "test-native-metal",
        .executable = "stwo-zig-native-metal",
        .installed_artifacts = &.{"stwo-zig-native-metal"},
        .dependencies = .{
            .module_roots = &.{"src/products/native_metal/main.zig"},
        },
        .source_closure = .{
            .entry_roots = &.{"src/products/native_metal/main.zig"},
            .allowed_prefixes = &.{"src/products/native_metal"},
        },
    };
    try descriptor.validate();
    try std.testing.expect(descriptor.isAvailableOn(.macos));
    try std.testing.expect(!descriptor.isAvailableOn(.linux));
}
