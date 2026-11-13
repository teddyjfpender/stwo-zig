//! Authority-owned source gathering and fresh parameters for shared GPU roles.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const S = @import("outer_source.zig");
const R = @import("resident_composition.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
pub fn evaluate(owner: *S.Owner, a: std.mem.Allocator, randomness: Outer.protocol.O, log: u32, split: u32, total: usize, trace: *const anyopaque) !D.Tree {
    if (total != owner.key.bound.total_constraints or log != owner.key.bound.max_evaluation_log_size or split != 1) return error.InvalidOuterCompositionAuthority;
    const entries = owner.backend.entries.items;
    const roles = try a.alloc(R.RuntimeRole, entries.len);
    defer a.free(roles);
    var made: usize = 0;
    defer for (roles[0..made]) |role| a.free(role.parameters);
    const claims = owner.claims.toArray();
    for (roles, entries, 0..) |*role, *entry, id| {
        const component = &owner.key.bound.components[entry.group.component];
        const original = try Outer.program.parameters(a, component, owner.z, owner.alpha, claims[entry.group.component]);
        defer a.free(original);
        const parameters = try a.alloc(Outer.protocol.O, entry.metadata.parameter_slots.len);
        for (parameters, entry.metadata.parameter_slots) |*value, slot| value.* = original[slot];
        const main = try Outer.geometry.span(component.*, 1);
        const inter = try Outer.geometry.span(component.*, 2);
        role.* = .{ .id = @intCast(id), .artifact = &entry.metadata, .evaluate = owner.backend.role, .trace_log = component.trace_log_size, .eval_log = component.evaluation_log_size, .widths = .{ component.preprocessed_indices.len, main.end - main.start, inter.end - inter.start }, .offsets = .{ 0, main.start, inter.start }, .fixed_indices = component.preprocessed_indices, .parameters = parameters };
        made += 1;
    }
    const beta = (try Outer.protocol.targetConfig()).fri_config.log_blowup_factor;
    return owner.backend.composition.evaluateOuterRolesAtBlowup(a, roles, randomness, log, split, total, trace, owner.scope, beta);
}
