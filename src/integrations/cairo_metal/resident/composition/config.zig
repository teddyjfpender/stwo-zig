//! Process configuration for resident Cairo composition preparation.

const std = @import("std");
const eval_codegen = @import("../../eval_codegen.zig");
const composition_aot = @import("../../composition_aot.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const Error = @import("../errors.zig").Error;

const enable_fusion_env = "STWO_ZIG_SN2_ENABLE_COMPOSITION_PART_FUSION";
const fusion_cap_env = "STWO_ZIG_SN2_COMPOSITION_FUSION_CAP";
const fusion_mode_env = "STWO_ZIG_SN2_COMPOSITION_FUSION_MODE";
const source_env = "STWO_ZIG_SN2_COMPOSITION_SOURCE";
const component_limit_env = "STWO_ZIG_SN2_COMPOSITION_COMPONENT_LIMIT";
const diagnostic_component_env = "STWO_ZIG_SN2_LOG_COMPOSITION_PART_COMPONENT";

pub const LibrarySelection = union(enum) {
    metallib,
    source: []u8,
};

pub const FusionMode = enum {
    capped,
    experimental_hybrid_source_diagnostic,
};

/// Configuration resolved before selecting and loading the evaluator library.
pub const LibraryConfig = struct {
    fusion_requested: bool,
    fusion_instruction_cap: usize,
    fusion_mode: FusionMode,
    library: LibrarySelection,

    pub fn fromProcess(allocator: std.mem.Allocator) !LibraryConfig {
        const fusion_requested = std.process.hasEnvVarConstant(enable_fusion_env);
        const source_artifact_present = std.process.hasEnvVarConstant(source_env);
        try validateFusionSource(fusion_requested, source_artifact_present);

        const encoded_mode = std.process.getEnvVarOwned(
            allocator,
            fusion_mode_env,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded_mode) |value| allocator.free(value);
        const fusion_mode = try parseFusionMode(encoded_mode);
        const encoded_cap = std.process.getEnvVarOwned(
            allocator,
            fusion_cap_env,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded_cap) |value| allocator.free(value);
        try validateFusionMode(
            fusion_requested,
            fusion_mode,
            encoded_cap != null,
        );
        const fusion_instruction_cap = try fusionInstructionCap(
            fusion_requested,
            encoded_cap,
        );
        const library: LibrarySelection = if (std.process.getEnvVarOwned(
            allocator,
            source_env,
        )) |source_path|
            .{ .source = source_path }
        else |err| switch (err) {
            error.EnvironmentVariableNotFound => .metallib,
            else => return err,
        };
        return .{
            .fusion_requested = fusion_requested,
            .fusion_instruction_cap = fusion_instruction_cap,
            .fusion_mode = fusion_mode,
            .library = library,
        };
    }

    pub fn deinit(self: *LibraryConfig, allocator: std.mem.Allocator) void {
        switch (self.library) {
            .metallib => {},
            .source => |source_path| allocator.free(source_path),
        }
        self.* = undefined;
    }
};

/// Configuration resolved after the evaluator library has been loaded.
pub const ExecutionConfig = struct {
    component_limit: usize,
    diagnostic_component: ?usize,
    fusion_enabled: bool,

    pub fn fromProcess(
        allocator: std.mem.Allocator,
        component_count: usize,
        fusion_requested: bool,
    ) !ExecutionConfig {
        const component_limit = if (std.process.getEnvVarOwned(
            allocator,
            component_limit_env,
        )) |encoded_limit| limit: {
            defer allocator.free(encoded_limit);
            break :limit try componentLimit(component_count, encoded_limit);
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => try componentLimit(component_count, null),
            else => return err,
        };
        const diagnostic_component = if (std.process.getEnvVarOwned(
            allocator,
            diagnostic_component_env,
        )) |encoded_component| component: {
            defer allocator.free(encoded_component);
            break :component try parseDiagnosticComponent(encoded_component);
        } else |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        return .{
            .component_limit = component_limit,
            .diagnostic_component = diagnostic_component,
            .fusion_enabled = fusionEnabled(fusion_requested, diagnostic_component),
        };
    }
};

fn validateFusionSource(fusion_requested: bool, source_artifact_present: bool) !void {
    if (fusion_requested and !source_artifact_present)
        return error.FusedCompositionRequiresSourceArtifact;
}

fn parseFusionMode(encoded: ?[]const u8) !FusionMode {
    const text = encoded orelse return .capped;
    if (std.mem.eql(u8, text, "experimental-hybrid-source-diagnostic"))
        return .experimental_hybrid_source_diagnostic;
    return error.InvalidFusionMode;
}

fn validateFusionMode(
    fusion_requested: bool,
    fusion_mode: FusionMode,
    fusion_cap_present: bool,
) !void {
    if (fusion_mode != .experimental_hybrid_source_diagnostic) return;
    if (!fusion_requested) return error.HybridFusionRequiresFusedComposition;
    if (fusion_cap_present) return error.HybridFusionConflictsWithCap;
}

fn fusionInstructionCap(fusion_requested: bool, encoded: ?[]const u8) !usize {
    const text = encoded orelse return eval_codegen.default_fused_instruction_cap;
    if (!fusion_requested) return error.FusionCapRequiresFusedComposition;
    const value = try std.fmt.parseUnsigned(usize, text, 10);
    if (value == 0 or value > eval_codegen.max_fused_instruction_cap)
        return error.InvalidFusionInstructionCap;
    return value;
}

fn componentLimit(total: usize, encoded: ?[]const u8) !usize {
    if (total == 0) return Error.InvalidCardinality;
    const text = encoded orelse return total;
    const value = std.fmt.parseInt(usize, text, 10) catch return Error.InvalidCardinality;
    if (value == 0 or value > total) return Error.InvalidCardinality;
    return value;
}

fn parseDiagnosticComponent(encoded: []const u8) !usize {
    return std.fmt.parseUnsigned(usize, encoded, 10);
}

fn fusionEnabled(fusion_requested: bool, diagnostic_component: ?usize) bool {
    return fusion_requested and diagnostic_component == null;
}

test "composition config keeps production environment names stable" {
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_ENABLE_COMPOSITION_PART_FUSION", enable_fusion_env);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_COMPOSITION_FUSION_CAP", fusion_cap_env);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_COMPOSITION_FUSION_MODE", fusion_mode_env);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_COMPOSITION_SOURCE", source_env);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_COMPOSITION_COMPONENT_LIMIT", component_limit_env);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_LOG_COMPOSITION_PART_COMPONENT", diagnostic_component_env);
}

test "composition config keeps hybrid fusion explicit and unambiguous" {
    try std.testing.expectEqual(FusionMode.capped, try parseFusionMode(null));
    try std.testing.expectEqual(
        FusionMode.experimental_hybrid_source_diagnostic,
        try parseFusionMode("experimental-hybrid-source-diagnostic"),
    );
    try std.testing.expectError(error.InvalidFusionMode, parseFusionMode("hybrid"));
    try validateFusionMode(true, .capped, false);
    try validateFusionMode(true, .capped, true);
    try validateFusionMode(true, .experimental_hybrid_source_diagnostic, false);
    try std.testing.expectError(
        error.HybridFusionRequiresFusedComposition,
        validateFusionMode(false, .experimental_hybrid_source_diagnostic, false),
    );
    try std.testing.expectError(
        error.HybridFusionConflictsWithCap,
        validateFusionMode(true, .experimental_hybrid_source_diagnostic, true),
    );
}

test "composition config validates fusion source and cap" {
    try validateFusionSource(false, false);
    try validateFusionSource(false, true);
    try validateFusionSource(true, true);
    try std.testing.expectError(
        error.FusedCompositionRequiresSourceArtifact,
        validateFusionSource(true, false),
    );
    try std.testing.expectError(
        error.FusionCapRequiresFusedComposition,
        fusionInstructionCap(false, "1"),
    );
    try std.testing.expectEqual(
        eval_codegen.default_fused_instruction_cap,
        try fusionInstructionCap(false, null),
    );
    try std.testing.expectEqual(
        eval_codegen.max_fused_instruction_cap,
        try fusionInstructionCap(true, "4096"),
    );
    try std.testing.expectError(
        error.InvalidFusionInstructionCap,
        fusionInstructionCap(true, "0"),
    );
    var buffer: [32]u8 = undefined;
    const above_max = try std.fmt.bufPrint(&buffer, "{}", .{eval_codegen.max_fused_instruction_cap + 1});
    try std.testing.expectError(
        error.InvalidFusionInstructionCap,
        fusionInstructionCap(true, above_max),
    );
    try std.testing.expectError(
        error.InvalidCharacter,
        fusionInstructionCap(true, "not-a-number"),
    );
}

test "composition config component limit is bounded" {
    try std.testing.expectEqual(@as(usize, 58), try componentLimit(58, null));
    try std.testing.expectEqual(@as(usize, 7), try componentLimit(58, "7"));
    try std.testing.expectEqual(@as(usize, 58), try componentLimit(58, "58"));
    try std.testing.expectError(Error.InvalidCardinality, componentLimit(0, null));
    try std.testing.expectError(Error.InvalidCardinality, componentLimit(58, ""));
    try std.testing.expectError(Error.InvalidCardinality, componentLimit(58, "0"));
    try std.testing.expectError(Error.InvalidCardinality, componentLimit(58, "59"));
    try std.testing.expectError(Error.InvalidCardinality, componentLimit(58, "not-a-number"));
}

test "composition config diagnostics disable part fusion" {
    try std.testing.expectEqual(@as(usize, 0), try parseDiagnosticComponent("0"));
    try std.testing.expectEqual(@as(usize, 57), try parseDiagnosticComponent("57"));
    try std.testing.expectError(error.InvalidCharacter, parseDiagnosticComponent(""));
    try std.testing.expect(fusionEnabled(true, null));
    try std.testing.expect(!fusionEnabled(true, 0));
    try std.testing.expect(!fusionEnabled(false, null));
}

/// Loads an AOT composition metallib only after it authenticates.
///
/// Library selection already lives here, so integrity belongs here too: there
/// is then exactly one place a `.metallib` can enter a resident composition,
/// and it cannot be reached without a digest check. Failures propagate; the
/// caller must fall back to the host evaluator, never to an unchecked load.
pub fn loadAuthenticated(
    metal: *metal_runtime.Runtime,
    metallib_path: []const u8,
) !metal_runtime.EvalLibrary {
    _ = try composition_aot.authenticateFromProcess(std.heap.page_allocator, metallib_path);
    return metal.loadEvalLibrary(metallib_path);
}
