//! Explicit interaction generation policy. Callers retain workspace and staging
//! ownership; no callback or backend context is installed in retained state.
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const universal = @import("universal_challenges.zig");

pub const Host = struct {
    pub fn generatePreparedInto(_: *const Host, comptime Framework: type, workspace: *Framework.Workspace, plan: *const Framework.Plan, rows: []const Framework.Row, log: u32, relations: *const universal.UniversalRelations, destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31) !QM31 {
        return Framework.generatePreparedInto(workspace, plan, rows, log, relations, destination);
    }

    pub fn generatePreparedIntoWithDomainSums(_: *const Host, comptime Framework: type, workspace: *Framework.Workspace, plan: *const Framework.Plan, rows: []const Framework.Row, log: u32, relations: *const universal.UniversalRelations, destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31) !Framework.DomainClaims {
        return Framework.generatePreparedIntoWithDomainSums(workspace, plan, rows, log, relations, destination);
    }
};
