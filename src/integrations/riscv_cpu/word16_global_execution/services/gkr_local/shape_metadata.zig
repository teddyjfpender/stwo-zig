//! Claim-free CPU role descriptors from the same component authorities used by
//! proving/verification. No witness, pending GKR artifact or key is constructed.
const A = @import("stwo_riscv_frontend").rv64_air;
const Frame = @import("frame.zig");
const Role = @import("role.zig");
const Table = @import("table_role.zig");
const Boundary = @import("boundary_role.zig");
const Service = @import("service_role.zig");
const Global = @import("global_cpu.zig");
const Roster = @import("roster.zig");
const binding_columns = @import("binding.zig").INTERACTION_COLUMNS;
pub const Descriptor = struct {
    widths: [3]usize,
    constraints: usize,
    degree: u8,
    max_samples: usize,
    local_terms: u32,
};
pub fn forOrigin(origin: Frame.Origin) !Descriptor {
    const global = Global.layout(origin);
    const max_samples = @import("role_geometry.zig").MAX_SAMPLES_PER_COLUMN;
    switch (origin) {
        .bulk => |kind| {
            const Bulk = @import("bulk_role.zig");
            const shape = Bulk.mainShapeFor(kind);
            return .{ .widths = .{ shape.fixed, shape.main, binding_columns + global.width() }, .constraints = Bulk.constraintCount(kind), .degree = Bulk.MAX_DEGREE, .max_samples = max_samples, .local_terms = @import("bulk_projection.zig").localTerms(kind) };
        },
        .bridge => |family| {
            const shape = Service.mainShapeFor(family);
            return .{ .widths = .{ shape.fixed, shape.main, binding_columns + global.width() }, .constraints = Service.constraintCount(family), .degree = Service.MAX_DEGREE, .max_samples = max_samples, .local_terms = Roster.bridgeTerms(family) };
        },
        .core => |kind| {
            if (kind == .initial or kind == .terminal) {
                const shape = Boundary.MAIN_SHAPE;
                return .{ .widths = .{ shape.fixed, shape.main, global.width() }, .constraints = Boundary.CONSTRAINTS, .degree = Boundary.MAX_DEGREE, .max_samples = max_samples, .local_terms = 0 };
            }
            if (Table.kindForRole(kind)) |table_kind| {
                const shape = Table.mainShapeFor(table_kind);
                return .{ .widths = .{ shape.fixed, shape.main, binding_columns }, .constraints = Table.constraintCount(table_kind), .degree = Table.MAX_DEGREE, .max_samples = max_samples, .local_terms = Roster.terms(kind) };
            } else |_| {}
            const main_role = try Role.mainRole(kind);
            const shape = A.main_only.authority.shape(main_role);
            return .{ .widths = .{ shape.fixed, shape.main, binding_columns + global.width() }, .constraints = Role.constraintCount(main_role, origin), .degree = Role.MAX_DEGREE, .max_samples = max_samples, .local_terms = Roster.terms(kind) };
        },
    }
}
