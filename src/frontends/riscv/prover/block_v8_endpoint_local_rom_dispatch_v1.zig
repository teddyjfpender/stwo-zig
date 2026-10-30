//! Shared Local implementation selects explicit program flavor. Both branches
//! expose the same immutable context interface; their identities stay distinct.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Legacy = @import("block_v7_complete_union_program_v1.zig");
const Sparse = @import("block_v8_sparse_rom_provider_v1.zig");
const Carrier = @import("block_v7_program_provider_v1.zig").ForBackend(Cpu).FirstRound;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Context = struct {
    allocator: std.mem.Allocator,
    legacy: ?*Legacy.Context = null,
    sparse: ?*Sparse.Context = null,
    claims: Q,
    logs: [3][]u32,
    fixed_columns: []Column,
    interaction: []Column,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    pub fn recordAfterChallenges(self: *const Context, ch: anytype) !void {
        if (self.legacy) |v| try v.recordAfterChallenges(ch) else try self.sparse.?.recordAfterChallenges(ch);
    }
    pub fn deinit(self: *Context) void {
        if (self.legacy) |v| v.deinit();
        if (self.sparse) |v| v.deinit();
        self.allocator.destroy(self);
    }
};
fn wrap(a: std.mem.Allocator, context: anytype) !*Context {
    errdefer context.deinit();
    const self = try a.create(Context);
    self.* = .{ .allocator = a, .claims = context.claims, .logs = context.logs, .fixed_columns = context.fixed_columns, .interaction = context.interaction, .provers = context.provers, .verifiers = context.verifiers };
    if (@TypeOf(context) == *Legacy.Context) self.legacy = context else self.sparse = context;
    return self;
}
pub fn prepare(a: std.mem.Allocator, first: *const Carrier, scope: *const Scope.Owned, input: Scope.Input) !*Context {
    return switch (input.rom_flavor) {
        .legacy_complete => wrap(a, try Legacy.prepare(Cpu, a, first, scope.programPolicy(input))),
        .sparse_elf => wrap(a, try Sparse.prepare(Cpu, a, first, scope.sparseProgramPolicy(input))),
    };
}
pub fn verifier(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input, claim: Q) !*Context {
    return switch (input.rom_flavor) {
        .legacy_complete => wrap(a, try Legacy.verifier(Cpu, a, scope.programPolicy(input), claim)),
        .sparse_elf => wrap(a, try Sparse.verifier(Cpu, a, scope.sparseProgramPolicy(input), claim)),
    };
}
