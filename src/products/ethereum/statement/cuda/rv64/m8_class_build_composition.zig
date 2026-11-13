//! The composition half of the M8 GPU-native install-time class builder
//! (stream gn-shape; jobs/native_class_build.zig `Composition`): the hybrid's
//! composition roles (m8_native_composition_roles.zig fromItemsWith with
//! device claims) and the composition artifacts' parameter slots. Lives
//! outside rv64/jobs/ for the same reason m8_native_composition_roles.zig
//! does: it reads the legacy composition Context's kernel metadata (owner-
//! path imports are forbidden under jobs/ by the sync lint). Pure host.
//!
//! Binding (service root, outside jobs/): `var host = try HostArtifacts.init(a);
//! env.composition = of(&host.context);` (no GPU service needed), or
//! `of(&pool.devices[i].composition)` next to a resident pool.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const RC = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const CompRoles = @import("stwo_riscv_cuda_integration").rv64.execution.composition.roles;
const NCB = @import("jobs/native_class_build.zig");
const Items = CPU.rv64_gkr_cpu_components;

/// Executable-root install hook. Legacy class construction never enters the
/// job module dependency closure; native_node_class.zig is its runtime adapter.
pub fn installRecursion(a: std.mem.Allocator, libs: *@import("stwo_riscv_cuda_integration").rv64.execution.jobs.ops.Libraries, library: []const u8, manifest: []const u8, spool: []const u8) !@import("stwo_riscv_cuda_integration").rv64.execution.jobs.recursion_classes.Classes {
    return (try @import("native_recursion_install.zig").Owner.init(a, libs, library, manifest, spool)).interface();
}

/// Host composition artifacts (the resident composition context's
/// `artifacts` table, which CompRoles.fromItemsWith reads) WITHOUT a GPU
/// service: the same `joined_codegen.record` of every oracle descriptor that
/// RC.Context.init runs. Only `artifacts` / `artifact_count` are defined.
pub const HostArtifacts = struct {
    context: RC.Context,
    pub fn init(a: std.mem.Allocator) !*HostArtifacts {
        const Oracle = @import("stwo_riscv_cuda_integration").rv64.execution.composition.sources;
        const Gen = @import("stwo_riscv_cuda_integration").rv64.execution.composition.joined_codegen;
        const self = try a.create(HostArtifacts);
        errdefer a.destroy(self);
        self.context = undefined;
        self.context.allocator = a;
        self.context.artifact_count = 0;
        errdefer for (self.context.artifacts[0..self.context.artifact_count]) |*m| m.deinit();
        for (Oracle.descriptors(), self.context.artifacts[0..Oracle.count]) |d, *artifact| {
            var wide = try Gen.record(a, d);
            defer wide.deinit();
            artifact.* = .{ .allocator = wide.a, .program = .{ .identity = wide.program.identity, .inputs = wide.program.inputs, .roots = wide.program.roots }, .parameter_slots = wide.parameter_slots };
            wide.program.inputs = &.{};
            wide.program.roots = &.{};
            wide.parameter_slots = &.{};
            self.context.artifact_count += 1;
        }
        return self;
    }
    pub fn deinit(self: *HostArtifacts, a: std.mem.Allocator) void {
        for (self.context.artifacts[0..self.context.artifact_count]) |*m| m.deinit();
        a.destroy(self);
    }
};

pub fn of(context: *const RC.Context) NCB.Composition {
    return .{ .ctx = context, .roles = roles, .parameter_slots = slots, .oods = buildOods };
}
fn buildOods(raw: *const anyopaque, a: std.mem.Allocator, plan: *const @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_composition.Plan, sample_counts: []const []const u32, global_log: u32) anyerror![]u32 {
    const NO = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode_oods;
    const Gen = @import("stwo_riscv_cuda_integration").rv64.execution.composition.joined_codegen;
    const Oracle = @import("stwo_riscv_cuda_integration").rv64.execution.composition.sources;
    const context: *const RC.Context = @ptrCast(@alignCast(raw));
    const artifacts = try a.alloc(Gen.Artifact, plan.roles.len);
    defer a.free(artifacts);
    var count: usize = 0;
    defer for (artifacts[0..count]) |*artifact| artifact.deinit();
    const ids = try a.alloc(u32, plan.roles.len);
    defer a.free(ids);
    const programs = try a.alloc(*const NO.Program, plan.roles.len);
    defer a.free(programs);
    for (plan.roles, programs) |role, *program| {
        const id = role.spec.id;
        if (id >= Oracle.count or id >= context.artifact_count) return error.NativeStage2OodsProgramMissing;
        const index = for (ids[0..count], 0..) |known, i| {
            if (known == id) break i;
        } else blk: {
            artifacts[count] = try Gen.record(a, Oracle.descriptors()[id]);
            ids[count] = id;
            count += 1;
            break :blk count - 1;
        };
        const recorded = &artifacts[index].program;
        if (!std.mem.eql(u8, &recorded.identity, &context.artifacts[id].program.identity)) return error.NativeStage2OodsAuthorityMismatch;
        program.* = recorded;
    }
    // Cold symbolic recording is install-only. The returned descriptor owns
    // its encoded nodes/constants; no temporary DAG enters request execution.
    return NO.fromPlan(a, plan, programs, sample_counts, global_log);
}
fn roles(raw: *const anyopaque, a: std.mem.Allocator, items: []const Items.Item) anyerror!NCB.RolesOut {
    const context: *const RC.Context = @ptrCast(@alignCast(raw));
    const r = try a.create(CompRoles.Roles);
    errdefer a.destroy(r);
    r.* = try CompRoles.Roles.fromItemsWith(a, context, items, true);
    return .{ .specs = r.specs, .claim_count = r.claim_count, .ctx = r, .release = release };
}
fn release(raw: *anyopaque) void {
    const r: *CompRoles.Roles = @ptrCast(@alignCast(raw));
    const a = r.a;
    r.deinit();
    a.destroy(r);
}
fn slots(raw: *const anyopaque, id: u32) []const u32 {
    const context: *const RC.Context = @ptrCast(@alignCast(raw));
    return context.artifacts[id].parameter_slots;
}
