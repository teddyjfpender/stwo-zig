//! Test-only authenticated typed Poseidon authority for backend proof evidence.
//!
//! Construction is backend-neutral. The resulting program identity is sealed
//! before a CPU or Metal engine observes any committed column or telemetry.

const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const identity = @import("typed_poseidon2_identity.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const relations = @import("typed_poseidon2_relations.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");

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
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource(
            "air/components/poseidon2_m31.proof-harness.zig",
        );
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        const roots = poseidon.values(definition.outputs);
        var plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        errdefer plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        var binding = try compat.bindPlan(
            allocator,
            &arena,
            definition,
            spans,
            schedule,
            &plan,
        );
        errdefer binding.deinit(allocator);
        var executor = try witness.Executor.init(
            allocator,
            &arena,
            definition,
            spans,
            &plan,
            &binding,
        );
        errdefer executor.deinit();
        var result = Authority{
            .allocator = allocator,
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
            .plan = plan,
            .binding = binding,
            .executor = executor,
            .relation_plan = undefined,
            .program_identity = undefined,
        };
        result.relation_plan = try relations.authenticate(
            allocator,
            result.relationAuthority(),
        );
        result.program_identity = try identity.ProgramIdentity.fromAuthenticated(
            &result.binding,
            &result.executor,
            &result.relation_plan,
        );
        return result;
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
};

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var line: u32 = 2;
    const declaration = try spanAt(source_id, line);
    line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, line);
        line += 1;
    }
    const initial_linear = try spanAt(source_id, line);
    line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, line),
            .sbox = try spanAt(source_id, line + 1),
            .linear = try spanAt(source_id, line + 2),
        };
        line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, line),
            .sbox = try spanAt(source_id, line + 1),
            .linear = try spanAt(source_id, line + 2),
        };
        line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
