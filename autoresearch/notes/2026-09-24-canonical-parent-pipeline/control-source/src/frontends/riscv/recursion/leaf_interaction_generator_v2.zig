//! Admitted leaf interaction policy. Device generation replaces host column
//! generation; exact domain evidence remains an independent host audit.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const catalog = @import("air/segment_leaf_catalog_v2.zig");
const binding = @import("air/universal_relation_binding.zig");
const universal = @import("air/universal_challenges.zig");
const host = @import("air/interaction_generator.zig").Host;
const parameters_mod = @import("segment_leaf_parameters_v2.zig");
const Admission = @import("detached_segment_admission_v1.zig").AdmissionParametersV1;
const Manifest = @import("air/segment_outer_manifest_contract_v2.zig").Manifest;

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const capable = Backend != void and @hasDecl(Backend, "supportsFrameworkInteractions");
        allocator: std.mem.Allocator,
        parameters: Admission,
        device: bool,

        pub fn init(allocator: std.mem.Allocator, parameters: Admission, manifest: *const Manifest) !Self {
            _ = try parameters.validate(manifest);
            return .{ .allocator = allocator, .parameters = parameters, .device = if (capable) try Backend.supportsFrameworkInteractions() else false };
        }

        fn generateDevice(self: *const Self, comptime Framework: type, plan: *const Framework.Plan, rows: []const Framework.Row, log: u32, relations: *const universal.UniversalRelations, destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31) !QM31 {
            inline for (catalog.LOGICAL_ROWS) |entry| {
                if (comptime Framework.Plan == binding.Binding(entry.Air).Plan) {
                    if (std.mem.eql(u8, &plan.semantic_digest, &entry.Air.SEMANTIC_DIGEST)) {
                        const Air = entry.Air;
                        var definition = if (entry.requires_location) try Air.build(self.allocator, .generated) else try Air.build(self.allocator);
                        defer definition.deinit();
                        const direct = try @import("air/direct_constraint_program.zig").authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
                        const parameters = try parameters_mod.parametersFor(entry, self.parameters);
                        return @import("air/framework_device_interaction.zig").generateInto(Backend, Air, self.allocator, &direct, plan, rows, &parameters, log, relations, destination);
                    }
                }
            }
            return error.UnsupportedLeafInteractionProgram;
        }

        pub fn generatePreparedInto(self: *const Self, comptime Framework: type, workspace: *Framework.Workspace, plan: *const Framework.Plan, rows: []const Framework.Row, log: u32, relations: *const universal.UniversalRelations, destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31) !QM31 {
            if (comptime capable) {
                if (self.device) {
                    _ = try Framework.preflightPreparedInto(workspace, plan, rows, log, relations, destination);
                    return self.generateDevice(Framework, plan, rows, log, relations, destination);
                }
            }
            return (host{}).generatePreparedInto(Framework, workspace, plan, rows, log, relations, destination);
        }

        pub fn generatePreparedIntoWithDomainSums(self: *const Self, comptime Framework: type, workspace: *Framework.Workspace, plan: *const Framework.Plan, rows: []const Framework.Row, log: u32, relations: *const universal.UniversalRelations, destination: *[Framework.INTERACTION_COLUMN_COUNT][]M31) !Framework.DomainClaims {
            if (comptime capable) {
                if (self.device) {
                    const size = try Framework.preflightPreparedInto(workspace, plan, rows, log, relations, destination);
                    // The existing inversion workspace has three QM31 planes,
                    // more than enough for one complete M31 output slab. Stage
                    // there until the fallible independent audit also succeeds.
                    const scratch: []M31 = @alignCast(std.mem.bytesAsSlice(M31, std.mem.sliceAsBytes(workspace.scratch)));
                    var staged: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
                    for (&staged, 0..) |*column, index| column.* = scratch[index * size ..][0..size];
                    const claim = try self.generateDevice(Framework, plan, rows, log, relations, &staged);
                    const audit = try plan.auditPreparedDomainSums(self.allocator, rows, relations, claim);
                    for (staged, destination) |source, target| @memcpy(target, source);
                    return .{ .claimed_sum = claim, .by_domain = audit.values };
                }
            }
            return (host{}).generatePreparedIntoWithDomainSums(Framework, workspace, plan, rows, log, relations, destination);
        }
    };
}
