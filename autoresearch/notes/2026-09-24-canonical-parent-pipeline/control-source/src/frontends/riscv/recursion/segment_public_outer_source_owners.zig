//! Internal shard of segment_public_outer_source.zig; use the public facade.

pub const std = @import("std");

pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_mod = @import("../air/public_data.zig");

pub const native_relation_challenges = @import("../air/relation_challenges.zig");

pub const leaf_authority = @import("segment_leaf_authority.zig");

pub const semantics = @import("vm_public_semantics_circuit.zig");

pub const arithmetic = @import("arithmetic_circuit.zig");

pub const span_statement = @import("span_statement.zig");

pub const air = @import("air/mod.zig");

pub const adapter = air.universal_typed_component;

pub const binding = air.universal_relation_binding;

pub const framework = air.framework_interaction;

pub const relation_interaction = air.relation_interaction;

pub const manifest_mod = air.universal_adapter_manifest;

pub const roster = air.universal_roster;

pub const schedule = air.verifier_schedule;

pub const universal = air.universal_challenges;

pub const universal_manifest = air.universal_manifest;

pub const lowering = air.verifier_arithmetic_lowering;

pub const graph_mod = air.composition_circuit;

pub const claim_input_air = air.vm_public_claim_input;

pub const claim_input_witness = air.vm_public_claim_input_witness;

pub const claim_hash_air = air.vm_public_claim_hash;

pub const claim_hash_witness = air.vm_public_claim_hash_witness;

pub const io_hash_air = air.vm_public_io_hash;

pub const io_hash_witness = air.vm_public_io_hash_witness;

pub const claim_semantics_air = air.vm_public_claim_semantics_input;

pub const claim_semantics_witness = air.vm_public_claim_semantics_input_witness;

pub const public_logup_air = air.vm_public_logup_input;

pub const public_logup_witness = air.vm_public_logup_input_witness;

pub const public_logup_control_air = air.vm_public_logup_control.Air;

pub const control_witness = air.control_slice_witness;

pub const statement_input_air = air.statement_input;

pub const transcript_payload_air = air.transcript_payload;

pub const relation_challenge_witness = air.relation_challenge_witness;

pub const prepared_init = @import("segment_public_outer_source_prepared_init.zig");

pub const domain_audit = @import("segment_public_outer_source_domain_audit.zig");

pub const FORMAT_VERSION: u16 = 1;

pub const FIRST_ROW: usize = @intFromEnum(roster.Component.vm_public_claim_input);

pub const ROW_COUNT: usize = 6;

pub const LAST_ROW: usize = FIRST_ROW + ROW_COUNT - 1;

pub const CLAIM_CIRCUIT_ID: u32 = 40;

pub const PUBLIC_LOGUP_CIRCUIT_ID: u32 = 41;

pub const ClaimInputRelation = binding.Binding(claim_input_air);

pub const ClaimHashRelation = binding.Binding(claim_hash_air);

pub const IoHashRelation = binding.Binding(io_hash_air);

pub const ClaimSemanticsRelation = binding.Binding(claim_semantics_air);

pub const PublicLogupRelation = binding.Binding(public_logup_air);

pub const PublicLogupControlRelation = binding.Binding(public_logup_control_air);

pub const ClaimInputFramework = framework.Runtime(ClaimInputRelation.Runtime);

pub const ClaimHashFramework = framework.Runtime(ClaimHashRelation.Runtime);

pub const IoHashFramework = framework.Runtime(IoHashRelation.Runtime);

pub const ClaimSemanticsFramework = framework.Runtime(ClaimSemanticsRelation.Runtime);

pub const PublicLogupFramework = framework.Runtime(PublicLogupRelation.Runtime);

pub const PublicLogupControlFramework = framework.Runtime(PublicLogupControlRelation.Runtime);

pub const ClaimInputAdapter = adapter.Component(claim_input_air, ClaimInputRelation);

pub const ClaimHashAdapter = adapter.Component(claim_hash_air, ClaimHashRelation);

pub const IoHashAdapter = adapter.Component(io_hash_air, IoHashRelation);

pub const ClaimSemanticsAdapter = adapter.Component(
    claim_semantics_air,
    ClaimSemanticsRelation,
);

pub const PublicLogupAdapter = adapter.Component(public_logup_air, PublicLogupRelation);

pub const PublicLogupControlAdapter = adapter.Component(
    public_logup_control_air,
    PublicLogupControlRelation,
);

pub const LogSizes = [ROW_COUNT]u32;

pub const DomainAudits = [ROW_COUNT]relation_interaction.DomainAudit;

pub const Parameters = struct {
    claim_input: [ClaimInputAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_hash: [ClaimHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    io_hash: [IoHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_semantics: [ClaimSemanticsAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup: [PublicLogupAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup_control: [PublicLogupControlAdapter.PARAMETER_COLUMN_COUNT]M31,

    pub fn segmentLeaf() Parameters {
        const selectors = control_witness.ProofKind.segment_leaf.selectors();
        return .{
            .claim_input = .{
                selectors[0],
                M31.fromCanonical(claim_input_air.VM_CLAIM_SEMANTICS_SCOPE),
                M31.fromCanonical(claim_input_air.VM_CLAIM_HASH_SCOPE),
                M31.fromCanonical(claim_input_air.VM_PUBLIC_LOGUP_SCOPE),
                M31.fromCanonical(claim_input_air.VM_PUBLIC_INPUT_KIND),
                M31.fromCanonical(claim_input_air.VM_PUBLIC_OUTPUT_KIND),
                M31.fromCanonical(claim_input_air.LOW_BYTE_INDEX),
                M31.fromCanonical(claim_input_air.HIGH_BYTE_INDEX),
            },
            .claim_hash = .{
                selectors[0],
                M31.fromCanonical(claim_hash_air.VM_PUBLIC_CLAIM_HASH_DOMAIN),
                M31.fromCanonical(claim_hash_air.VM_CLAIM_HASH_SCOPE),
                M31.fromCanonical(claim_hash_air.SEGMENT_VERIFIER_ID),
                M31.fromCanonical(claim_hash_air.VM_PUBLIC_CLAIM_DIGEST_INPUT_KIND),
            },
            .io_hash = .{selectors[0]},
            .claim_semantics = .{
                selectors[0],
                M31.fromCanonical(claim_input_air.VM_CLAIM_SEMANTICS_SCOPE),
                M31.fromCanonical(statement_input_air.VM_CLAIM_STATEMENT_SCOPE),
            },
            .public_logup = .{
                selectors[0],
                M31.fromCanonical(claim_input_air.VM_PUBLIC_LOGUP_SCOPE),
                M31.fromCanonical(control_witness.SEGMENT_VERIFIER_ID),
                M31.fromCanonical(
                    relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                ),
                M31.fromCanonical(@intFromEnum(
                    transcript_payload_air.VerifierInputKind.claimed_sum,
                )),
            },
            .public_logup_control = .{ selectors[0], selectors[1] },
        };
    }
};

pub const Claims = struct {
    claim_input: QM31,
    claim_hash: QM31,
    io_hash: QM31,
    claim_semantics: QM31,
    public_logup: QM31,
    public_logup_control: QM31,

    pub fn asArray(self: Claims) [ROW_COUNT]QM31 {
        return .{
            self.claim_input,
            self.claim_hash,
            self.io_hash,
            self.claim_semantics,
            self.public_logup,
            self.public_logup_control,
        };
    }
};

pub const Components = struct {
    claim_input: ClaimInputAdapter,
    claim_hash: ClaimHashAdapter,
    io_hash: IoHashAdapter,
    claim_semantics: ClaimSemanticsAdapter,
    public_logup: PublicLogupAdapter,
    public_logup_control: PublicLogupControlAdapter,

    /// Appends precisely universal rows 12--17. The caller owns rows 0--11
    /// and 18--35 and seals the proof gate only after all are appended.
    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.claim_input.binding(manifest));
        try gate.append(manifest, try self.claim_hash.binding(manifest));
        try gate.append(manifest, try self.io_hash.binding(manifest));
        try gate.append(manifest, try self.claim_semantics.binding(manifest));
        try gate.append(manifest, try self.public_logup.binding(manifest));
        try gate.append(manifest, try self.public_logup_control.binding(manifest));
    }
};

pub fn AirOwner(comptime Air: type, comptime Relation: type) type {
    return struct {
        definition: Air.Definition,
        relation: Relation.Plan,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation = try Relation.authenticate(&definition),
                .definition = definition,
            };
        }

        fn validate(self: *const @This()) !void {
            try self.definition.validate();
            try self.relation.validateAgainst(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Relation.events(&self.definition),
            );
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const Owners = struct {
    claim_input: AirOwner(claim_input_air, ClaimInputRelation),
    claim_hash: AirOwner(claim_hash_air, ClaimHashRelation),
    io_hash: AirOwner(io_hash_air, IoHashRelation),
    claim_semantics: AirOwner(claim_semantics_air, ClaimSemanticsRelation),
    public_logup: AirOwner(public_logup_air, PublicLogupRelation),
    public_logup_control: AirOwner(
        public_logup_control_air,
        PublicLogupControlRelation,
    ),

    pub fn init(allocator: std.mem.Allocator) !Owners {
        var claim_input = try AirOwner(claim_input_air, ClaimInputRelation).init(allocator);
        errdefer claim_input.deinit();
        var claim_hash = try AirOwner(claim_hash_air, ClaimHashRelation).init(allocator);
        errdefer claim_hash.deinit();
        var io_hash = try AirOwner(io_hash_air, IoHashRelation).init(allocator);
        errdefer io_hash.deinit();
        var claim_semantics = try AirOwner(
            claim_semantics_air,
            ClaimSemanticsRelation,
        ).init(allocator);
        errdefer claim_semantics.deinit();
        var public_logup = try AirOwner(public_logup_air, PublicLogupRelation).init(allocator);
        errdefer public_logup.deinit();
        var public_logup_control = try AirOwner(
            public_logup_control_air,
            PublicLogupControlRelation,
        ).init(allocator);
        errdefer public_logup_control.deinit();
        return .{
            .claim_input = claim_input,
            .claim_hash = claim_hash,
            .io_hash = io_hash,
            .claim_semantics = claim_semantics,
            .public_logup = public_logup,
            .public_logup_control = public_logup_control,
        };
    }

    pub fn validate(self: *const Owners) !void {
        try self.claim_input.validate();
        try self.claim_hash.validate();
        try self.io_hash.validate();
        try self.claim_semantics.validate();
        try self.public_logup.validate();
        try self.public_logup_control.validate();
    }

    pub fn deinit(self: *Owners) void {
        self.public_logup_control.deinit();
        self.public_logup.deinit();
        self.claim_semantics.deinit();
        self.io_hash.deinit();
        self.claim_hash.deinit();
        self.claim_input.deinit();
        self.* = undefined;
    }
};

pub const Executors = struct {
    claim_input: claim_input_witness.Executor,
    claim_hash: claim_hash_witness.Executor,
    io_hash: io_hash_witness.Executor,

    pub fn init(owners: *const Owners) !Executors {
        const claim_input_binding = try claim_input_witness.Binding.canonical(
            &owners.claim_input.definition,
        );
        const claim_hash_binding = try claim_hash_witness.Binding.canonical(
            &owners.claim_hash.definition,
        );
        const io_hash_binding = try io_hash_witness.Binding.canonical(
            &owners.io_hash.definition,
        );
        return .{
            .claim_input = try claim_input_witness.Executor.init(
                &owners.claim_input.definition,
                &claim_input_binding,
            ),
            .claim_hash = try claim_hash_witness.Executor.init(
                &owners.claim_hash.definition,
                &claim_hash_binding,
            ),
            .io_hash = try io_hash_witness.Executor.init(
                &owners.io_hash.definition,
                &io_hash_binding,
            ),
        };
    }

    pub fn validate(self: *const Executors, owners: *const Owners) !void {
        const claim_input_binding = try claim_input_witness.Binding.canonical(
            &owners.claim_input.definition,
        );
        if (!std.meta.eql(self.claim_input.binding, claim_input_binding) or
            !std.mem.eql(
                u8,
                &self.claim_input.binding_digest,
                &claim_input_binding.identityDigest(),
            ))
        {
            return error.PreparedAuthorityMismatch;
        }
        try self.claim_hash.validate();
        try self.io_hash.validate();
    }
};

pub const OwnedGraph = struct {
    allocator: std.mem.Allocator,
    nodes: []graph_mod.Node,
    outputs: []u32,
    graph: graph_mod.CircuitGraph,

    pub fn init(allocator: std.mem.Allocator, circuit: *const arithmetic.Circuit) !OwnedGraph {
        const nodes = try allocator.alloc(graph_mod.Node, circuit.nodes().len);
        errdefer allocator.free(nodes);
        for (nodes, circuit.nodes()) |*destination, source| destination.* = .{
            .op = switch (source.op) {
                .input => .input,
                .constant => |words| .{ .constant = words },
                .add => |operands| .{ .add = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
                .sub => |operands| .{ .sub = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
                .mul => |operands| .{ .mul = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
                .neg => |operand| .{ .neg = operand },
                .inverse => |operand| .{ .inverse = operand },
            },
        };
        const outputs = try allocator.dupe(u32, circuit.outputs());
        errdefer allocator.free(outputs);
        const identity = graph_mod.computeGraphDigest(nodes, outputs);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .outputs = outputs,
            .graph = try graph_mod.CircuitGraph.authenticate(nodes, outputs, identity),
        };
    }

    pub fn validate(self: *const OwnedGraph) !void {
        if (self.graph.nodes.ptr != self.nodes.ptr or
            self.graph.outputs.ptr != self.outputs.ptr)
        {
            return error.ArithmeticGraphAuthorityMismatch;
        }
        try self.graph.validate();
    }

    pub fn deinit(self: *OwnedGraph) void {
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
};
