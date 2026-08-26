//! Reviewed P-002 machine and human projections.
//!
//! Generation first compares every shared native profile coordinate with the
//! existing production-shadow protocol report. That comparison is structural
//! compatibility evidence only; it neither observes nor changes production
//! activation.

const std = @import("std");
const protocol_report = @import("protocol_report.zig");
const registry = @import("static_profile_registry.zig");

pub const machine_filename = "profiles-v1.tsv";
pub const readable_filename = "profiles-v1.md";

pub const Artifact = struct {
    allocator: std.mem.Allocator,
    machine: []u8,
    readable: []u8,

    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.readable);
        self.allocator.free(self.machine);
        self.* = undefined;
    }
};

pub const AuthorityError = error{AuthorityMismatch};
pub const ProjectionError = error{ArtifactMismatch};

/// Collects both independent static authorities before rendering reviewed
/// bytes. No runtime trace, proof, timing, or memory telemetry is imported.
pub fn generate(allocator: std.mem.Allocator) !Artifact {
    const native = try registry.collect(allocator);
    try crossCheckAuditedProtocol(allocator, &native);
    return render(allocator, &native);
}

/// Renders an already validated native report. This split makes every owned
/// allocation introduced by artifact projection exhaustively testable.
pub fn render(
    allocator: std.mem.Allocator,
    report: *const registry.Report,
) !Artifact {
    try report.validate();
    var machine = std.Io.Writer.Allocating.init(allocator);
    defer machine.deinit();
    registry.writeTsv(&machine.writer, report) catch |err| switch (err) {
        error.InvalidReport => return error.InvalidReport,
        error.WriteFailed => return error.OutOfMemory,
    };
    const owned_machine = try machine.toOwnedSlice();
    errdefer allocator.free(owned_machine);

    var readable = std.Io.Writer.Allocating.init(allocator);
    defer readable.deinit();
    registry.writeMarkdown(&readable.writer, report) catch |err| switch (err) {
        error.InvalidReport => return error.InvalidReport,
        error.WriteFailed => return error.OutOfMemory,
    };
    const owned_readable = try readable.toOwnedSlice();
    return .{
        .allocator = allocator,
        .machine = owned_machine,
        .readable = owned_readable,
    };
}

/// Exact shared-coordinate comparison with the A-005 production-shadow
/// authority. Native-only DAG/closure facts deliberately remain native facts.
pub fn crossCheckAuditedProtocol(
    allocator: std.mem.Allocator,
    native: *const registry.Report,
) !void {
    try native.validate();
    const audited = try protocol_report.collect(allocator);
    audited.validate() catch return error.AuthorityMismatch;

    if (audited.families.len != native.families.len)
        return error.AuthorityMismatch;
    for (native.families, audited.families) |actual, expected| {
        const profile = actual.profile;
        if (expected.family != actual.family or
            profile.physical_main_columns != expected.main_columns or
            profile.constraint_roots != expected.direct_constraints or
            profile.lookup_events != expected.lookups or
            profile.lookup_batch_size != expected.batch_size or
            profile.lookup_batches != expected.interaction_constraints or
            profile.interaction_columns != expected.interaction_columns or
            profile.maximum_logical_constraint_degree !=
                expected.maximum_direct_degree or
            profile.maximum_lookup_numerator_degree !=
                expected.maximum_numerator_degree or
            profile.maximum_lookup_denominator_degree !=
                expected.maximum_denominator_degree or
            profile.maximum_modeled_interaction_degree !=
                expected.maximum_interaction_degree)
        {
            return error.AuthorityMismatch;
        }
    }
}

/// Shared fail-closed byte comparison used by the command and corruption tests.
pub fn checkProjection(expected: []const u8, actual: []const u8) ProjectionError!void {
    if (!std.mem.eql(u8, expected, actual)) return error.ArtifactMismatch;
}
