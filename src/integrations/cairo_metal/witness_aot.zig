//! Admission contract for generated Cairo witness metallibs.

const std = @import("std");
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const witness_codegen = @import("witness_codegen.zig");

pub const codegen_version: u64 = 7;

comptime {
    if (witness_codegen.codegen_version != codegen_version)
        @compileError("authenticated witness metallib codegen version drift");
}

pub const Epoch = enum {
    base,
    interaction,
};

pub const RequiredExports = struct {
    allocator: std.mem.Allocator,
    names: [][]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        bundle: witness_bundle.Bundle,
    ) !RequiredExports {
        const count = std.math.mul(usize, bundle.entries.len, 2) catch
            return error.ExportCountOverflow;
        const names = try allocator.alloc([]u8, count);
        var initialized: usize = 0;
        errdefer {
            for (names[0..initialized]) |name| allocator.free(name);
            allocator.free(names);
        }
        for (bundle.entries) |entry| inline for (.{ Epoch.base, Epoch.interaction }) |epoch| {
            names[initialized] = try witness_codegen.kernelNameForMode(
                allocator,
                entry.program.semanticIdentity(),
                kernelMode(entry.label, epoch),
            );
            initialized += 1;
        };
        return .{ .allocator = allocator, .names = names };
    }

    pub fn deinit(self: *RequiredExports) void {
        for (self.names) |name| self.allocator.free(name);
        self.allocator.free(self.names);
        self.* = undefined;
    }
};

pub const AuthenticatedMetallib = struct {
    path: []const u8,
    expected_sha256: [32]u8,
    expected_length: u64,
    codegen_version: u64,
    /// Canonical witness-family exports from the AOT build manifest. The order
    /// is base then interaction for every witness-bundle entry.
    witness_exports: []const []const u8,

    pub fn authenticate(
        self: AuthenticatedMetallib,
        allocator: std.mem.Allocator,
        bundle: witness_bundle.Bundle,
    ) !void {
        if (self.codegen_version != codegen_version)
            return error.WitnessCodegenVersionMismatch;
        try validateRequiredExports(allocator, bundle, self.witness_exports);
        const measurement = try measureFile(self.path);
        if (measurement.length != self.expected_length)
            return error.WitnessMetallibLengthMismatch;
        if (!std.mem.eql(u8, &measurement.sha256, &self.expected_sha256))
            return error.WitnessMetallibDigestMismatch;
    }
};

/// Emits exactly the witness-family translation unit described by
/// `RequiredExports`. This is the offline compiler input for this contract.
pub fn generateSource(
    allocator: std.mem.Allocator,
    bundle: witness_bundle.Bundle,
) ![]u8 {
    if (bundle.entries.len == 0) return error.EmptyWitnessBatch;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    for (witness_codegen.preambleParts()) |part| try source.appendSlice(allocator, part);
    for (bundle.entries) |entry| inline for (.{ Epoch.base, Epoch.interaction }) |epoch| {
        const kernel = try witness_codegen.generateKernelForMode(
            allocator,
            entry.program,
            kernelMode(entry.label, epoch),
        );
        defer allocator.free(kernel);
        try source.appendSlice(allocator, kernel);
    };
    return source.toOwnedSlice(allocator);
}

pub fn kernelMode(component: []const u8, epoch: Epoch) witness_codegen.KernelMode {
    return switch (epoch) {
        .base => if (cairo_proof_plan.retainsLookupInputs(component))
            .base_lookup
        else
            .base,
        .interaction => if (cairo_proof_plan.retainedLookupReplaysSubwords(component))
            .interaction_subwords
        else
            .interaction,
    };
}

pub fn validateRequiredExports(
    allocator: std.mem.Allocator,
    bundle: witness_bundle.Bundle,
    actual: []const []const u8,
) !void {
    var required = try RequiredExports.init(allocator, bundle);
    defer required.deinit();
    if (actual.len != required.names.len) return error.WitnessExportCountMismatch;
    for (required.names, actual) |expected, found| {
        if (!std.mem.eql(u8, expected, found)) return error.WitnessExportMismatch;
    }
}

const Measurement = struct {
    length: u64,
    sha256: [32]u8,
};

fn measureFile(path: []const u8) !Measurement {
    if (path.len == 0) return error.InvalidWitnessMetallib;
    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0) return error.InvalidWitnessMetallib;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var length: u64 = 0;
    while (true) {
        const read = try file.read(&buffer);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        length = std.math.add(u64, length, read) catch return error.WitnessMetallibLengthOverflow;
    }
    const after = try file.stat();
    if (length != before.size or !sameFile(before, after))
        return error.WitnessMetallibChangedDuringAuthentication;
    return .{ .length = length, .sha256 = hasher.finalResult() };
}

fn sameFile(left: std.fs.File.Stat, right: std.fs.File.Stat) bool {
    return left.inode == right.inode and
        left.size == right.size and
        left.mtime == right.mtime and
        left.ctime == right.ctime and
        left.mode == right.mode;
}

test "witness AOT manifest covers the active base and interaction kernels exactly" {
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    var exports = try RequiredExports.init(std.testing.allocator, bundle);
    defer exports.deinit();

    try std.testing.expectEqual(bundle.entries.len * 2, exports.names.len);
    for (bundle.entries, 0..) |entry, index| {
        const base = try witness_codegen.kernelNameForMode(
            std.testing.allocator,
            entry.program.semanticIdentity(),
            kernelMode(entry.label, .base),
        );
        defer std.testing.allocator.free(base);
        const interaction = try witness_codegen.kernelNameForMode(
            std.testing.allocator,
            entry.program.semanticIdentity(),
            kernelMode(entry.label, .interaction),
        );
        defer std.testing.allocator.free(interaction);
        try std.testing.expectEqualStrings(base, exports.names[index * 2]);
        try std.testing.expectEqualStrings(interaction, exports.names[index * 2 + 1]);
    }

    const source = try generateSource(std.testing.allocator, bundle);
    defer std.testing.allocator.free(source);
    for (exports.names) |name| {
        const declaration = try std.fmt.allocPrint(std.testing.allocator, "kernel void {s}(", .{name});
        defer std.testing.allocator.free(declaration);
        try std.testing.expect(std.mem.indexOf(u8, source, declaration) != null);
    }
}

test "witness AOT authentication binds identity version and exact exports" {
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    var exports = try RequiredExports.init(std.testing.allocator, bundle);
    defer exports.deinit();

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const contents = "authenticated fake metallib for pure admission tests";
    try temporary.dir.writeFile(.{ .sub_path = "witness.metallib", .data = contents });
    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "witness.metallib");
    defer std.testing.allocator.free(path);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(contents, &digest, .{});

    const approved = AuthenticatedMetallib{
        .path = path,
        .expected_sha256 = digest,
        .expected_length = contents.len,
        .codegen_version = codegen_version,
        .witness_exports = exports.names,
    };
    try approved.authenticate(std.testing.allocator, bundle);

    var invalid = approved;
    invalid.codegen_version -= 1;
    try std.testing.expectError(
        error.WitnessCodegenVersionMismatch,
        invalid.authenticate(std.testing.allocator, bundle),
    );
    invalid = approved;
    invalid.witness_exports = invalid.witness_exports[0 .. invalid.witness_exports.len - 1];
    try std.testing.expectError(
        error.WitnessExportCountMismatch,
        invalid.authenticate(std.testing.allocator, bundle),
    );
    const reordered = try std.testing.allocator.dupe([]u8, exports.names);
    defer std.testing.allocator.free(reordered);
    std.mem.swap([]u8, &reordered[0], &reordered[1]);
    invalid = approved;
    invalid.witness_exports = reordered;
    try std.testing.expectError(
        error.WitnessExportMismatch,
        invalid.authenticate(std.testing.allocator, bundle),
    );
    invalid = approved;
    invalid.expected_length += 1;
    try std.testing.expectError(
        error.WitnessMetallibLengthMismatch,
        invalid.authenticate(std.testing.allocator, bundle),
    );
    invalid = approved;
    invalid.expected_sha256[0] ^= 1;
    try std.testing.expectError(
        error.WitnessMetallibDigestMismatch,
        invalid.authenticate(std.testing.allocator, bundle),
    );
}

test "legacy unsuffixed SN2 witness exports fail the v7 AOT contract" {
    var bundle = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    const legacy = try std.testing.allocator.alloc([]u8, bundle.entries.len);
    var initialized: usize = 0;
    defer {
        for (legacy[0..initialized]) |name| std.testing.allocator.free(name);
        std.testing.allocator.free(legacy);
    }
    for (bundle.entries, legacy) |entry, *name| {
        name.* = try witness_codegen.kernelName(
            std.testing.allocator,
            entry.program.semanticIdentity(),
        );
        initialized += 1;
    }

    try std.testing.expectError(
        error.WitnessExportCountMismatch,
        validateRequiredExports(std.testing.allocator, bundle, legacy),
    );
}
