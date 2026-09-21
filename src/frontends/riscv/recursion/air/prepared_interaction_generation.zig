//! Shared cold preparation of typed interactions and their exact domain audit.
//! Callers own destination staging and publish it only after this returns.
//! Diagnostic or tuple-ledger failures may occur after staging columns were
//! written; no audit result is returned on those failures.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const interaction = @import("relation_interaction.zig");
const universal = @import("universal_challenges.zig");

pub const AuditRequest = struct {
    verify_domains: bool = false,
    tuples: ?struct {
        ledger: *interaction.TupleLedger,
        component: u8,
    } = null,
};

/// Arithmetic output, not an admission or publication capability.
pub const Generated = struct {
    claimed_sum: QM31,
    audit: ?interaction.DomainAudit,
};

/// Reuse the framework's inverse plane for domain decomposition. The optional
/// cold reference independently checks those sums and never supplies authority.
pub fn generateInto(
    comptime Framework: type,
    allocator: std.mem.Allocator,
    plan: *const Framework.Plan,
    rows: []const Framework.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
    destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31,
    audit_request: ?AuditRequest,
) !Generated {
    const generator = @import("interaction_generator.zig").Host{};
    return generateIntoWithGenerator(Framework, allocator, plan, rows, log_size, relations, destination, audit_request, &generator);
}

pub fn generateIntoWithGenerator(
    comptime Framework: type,
    allocator: std.mem.Allocator,
    plan: *const Framework.Plan,
    rows: []const Framework.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
    destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31,
    audit_request: ?AuditRequest,
    generator: anytype,
) !Generated {
    var workspace = try Framework.Workspace.init(allocator, log_size);
    defer workspace.deinit();
    const request = audit_request orelse return .{
        .claimed_sum = try generator.generatePreparedInto(Framework, &workspace, plan, rows, log_size, relations, destination),
        .audit = null,
    };
    const event_terms = try std.math.mul(usize, rows.len, plan.events.len);
    const generated = try generator.generatePreparedIntoWithDomainSums(Framework, &workspace, plan, rows, log_size, relations, destination);
    const audit = interaction.DomainAudit{
        .values = generated.by_domain,
        .total = generated.claimed_sum,
        .logical_rows = rows.len,
        .event_terms = event_terms,
    };
    if (request.verify_domains) {
        const reference = try plan.auditPreparedDomainSums(allocator, rows, relations, generated.claimed_sum);
        if (!std.meta.eql(reference, audit)) return error.NativeInteractionDomainMismatch;
    }
    if (request.tuples) |tuples|
        try plan.appendPreparedTupleContributions(tuples.ledger, tuples.component, rows, interaction.allDomainMask());
    return .{ .claimed_sum = generated.claimed_sum, .audit = audit };
}
