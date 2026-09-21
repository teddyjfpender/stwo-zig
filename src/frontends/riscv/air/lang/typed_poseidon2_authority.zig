//! Production authenticated authority for the canonical typed Poseidon2 provider.
//!
//! Construction is backend-neutral. The owned arena, materialization plan,
//! physical binding, executor, and relation plan share one authenticated
//! lifetime, and the resulting program identity is sealed before a backend
//! observes any committed column.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat = @import("typed_poseidon2_compat.zig");
const identity = @import("typed_poseidon2_identity.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const relations = @import("typed_poseidon2_relations.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");

pub const ProgramIdentityError =
    witness.ConstructionError ||
    relations.AuthenticationError ||
    identity.IdentityError;

pub const Authority = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,
    plan: materializer.Plan,
    binding: compat.OwnedBinding,
    executor: witness.Executor,
    relation_plan: relations.Plan,
    program_identity: identity.ProgramIdentity,

    pub fn init(allocator: std.mem.Allocator) !Authority {
        var program = try @import("typed_poseidon2_bound_program.zig").Program.init(allocator);
        errdefer program.deinit();
        var executor = try witness.Executor.init(allocator, &program.arena, program.definition, program.spans, &program.plan, &program.binding);
        errdefer executor.deinit();
        const relation_plan = try relations.authenticate(allocator, .{
            .arena = &program.arena,
            .definition = program.definition,
            .spans = program.spans,
            .materialization_plan = &program.plan,
            .binding = &program.binding,
        });
        const program_identity = try identity.ProgramIdentity.fromAuthenticated(&program.binding, &executor, &relation_plan);
        return .{
            .allocator = allocator,
            .arena = program.arena,
            .gate = program.gate,
            .spans = program.spans,
            .definition = program.definition,
            .plan = program.plan,
            .binding = program.binding,
            .executor = executor,
            .relation_plan = relation_plan,
            .program_identity = program_identity,
        };
    }

    pub fn deinit(self: *Authority) void {
        self.executor.deinit();
        self.binding.deinit(self.allocator);
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn relationAuthority(self: *const Authority) relations.Authority {
        return .{
            .arena = &self.arena,
            .definition = self.definition,
            .spans = self.spans,
            .materialization_plan = &self.plan,
            .binding = &self.binding,
        };
    }

    pub fn programIdentity(
        self: *const Authority,
    ) ProgramIdentityError!identity.ProgramIdentity {
        // Receipt creation is a fresh ownership boundary. Recompile H-005 from
        // the owned H-003 graph and H-004 binding, then reauthenticate H-006
        // against the same authority before trusting any locally sealed child.
        // Both operations deliberately reconstruct H-004 against the arena and
        // materialization plan rather than accepting a mutually consistent set
        // of copied component digests.
        try self.executor.reauthenticate(
            self.allocator,
            &self.arena,
            self.definition,
            self.spans,
            &self.plan,
            &self.binding,
        );
        try self.relation_plan.validateAgainst(
            self.allocator,
            self.relationAuthority(),
        );
        return identity.ProgramIdentity.fromAuthenticated(
            &self.binding,
            &self.executor,
            &self.relation_plan,
        );
    }

    /// Executes the pinned production specialization only after reconstructing
    /// the complete typed program identity. H-004/H-005 randomized parity
    /// tests require this kernel to remain byte-identical to the interpreter
    /// in every mode and at every committed row, so specialization changes
    /// performance without acquiring a second semantic authority.
    pub fn generateCanonicalMainInto(
        self: *Authority,
        columns: *[production.N_MAIN_COLUMNS][]M31,
        calls: []const production.Call,
        log_size: u32,
    ) !void {
        const authenticated = try self.programIdentity();
        if (!authenticated.isCanonical())
            return error.ProgramIdentityMismatch;
        return production.generateMainInto(
            self.allocator,
            columns,
            calls,
            log_size,
        );
    }
};

test "typed Poseidon2 authority admits byte-exact specialized execution" {
    const allocator = std.testing.allocator;
    var authority = try Authority.init(allocator);
    defer authority.deinit();
    const calls = [_]production.Call{
        .{ .input = .{3} ** production.WIDTH, .io = true },
        .{ .input = .{5} ** production.WIDTH, .wide = true },
        production.Call.narrow(7, 11),
    };
    const log_size: u32 = 2;
    const size: usize = 1 << log_size;
    const interpreted_storage = try allocator.alloc(
        M31,
        production.N_MAIN_COLUMNS * size,
    );
    defer allocator.free(interpreted_storage);
    const specialized_storage = try allocator.alloc(
        M31,
        production.N_MAIN_COLUMNS * size,
    );
    defer allocator.free(specialized_storage);
    var interpreted: [production.N_MAIN_COLUMNS][]M31 = undefined;
    var specialized: [production.N_MAIN_COLUMNS][]M31 = undefined;
    for (&interpreted, &specialized, 0..) |*lhs, *rhs, column| {
        lhs.* = interpreted_storage[column * size ..][0..size];
        rhs.* = specialized_storage[column * size ..][0..size];
    }
    try authority.executor.generateMainInto(&interpreted, &calls, log_size);
    try authority.generateCanonicalMainInto(&specialized, &calls, log_size);
    try std.testing.expectEqualSlices(
        u8,
        std.mem.sliceAsBytes(interpreted_storage),
        std.mem.sliceAsBytes(specialized_storage),
    );
}
