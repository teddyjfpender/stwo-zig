//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_1 = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const air_digest = dependency_0.air_digest;
const relation = dependency_0.relation;
const binary_authority = dependency_0.binary_authority;
const fixed_wire = dependency_0.fixed_wire;
const pair_node = dependency_0.pair_node;
const protocol = dependency_0.protocol;
const composition = dependency_0.composition;
const multiply_air = dependency_0.multiply_air;
const multiply_witness = dependency_0.multiply_witness;
const inverse_air = dependency_0.inverse_air;
const inverse_witness = dependency_0.inverse_witness;
const linear_air = dependency_0.linear_air;
const linear_witness = dependency_0.linear_witness;
const lowering = dependency_0.lowering;
const merkle_path_air = dependency_0.merkle_path_air;
const merkle_path_relation = dependency_0.merkle_path_relation;
const merkle_path_witness = dependency_0.merkle_path_witness;
const MultiplyRelation = dependency_0.MultiplyRelation;
const InverseRelation = dependency_0.InverseRelation;
const LinearRelation = dependency_0.LinearRelation;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_FRI_CIRCUIT_ID = dependency_0.LEFT_FRI_CIRCUIT_ID;
const RIGHT_FRI_CIRCUIT_ID = dependency_0.RIGHT_FRI_CIRCUIT_ID;
const LEFT_PCS_CIRCUIT_ID = dependency_0.LEFT_PCS_CIRCUIT_ID;
const RIGHT_PCS_CIRCUIT_ID = dependency_0.RIGHT_PCS_CIRCUIT_ID;
const SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID = dependency_0.SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID;
const ARITHMETIC_ROW_COUNT = dependency_0.ARITHMETIC_ROW_COUNT;
const ChildInput = dependency_1.ChildInput;
const SharedArithmeticInput = dependency_1.SharedArithmeticInput;
const traceLogSize = dependency_9.traceLogSize;
const hashInt = dependency_9.hashInt;

pub const ArithmeticRowsAuthority = struct {
    allocator: std.mem.Allocator,
    lanes: []lowering.Lane,
    reference: lowering.Reference,
    plan: lowering.Plan,
    multiply_definition: multiply_air.Definition,
    inverse_definition: inverse_air.Definition,
    linear_definition: linear_air.Definition,
    multiply_executor: multiply_witness.Executor,
    inverse_executor: inverse_witness.Executor,
    linear_executor: linear_witness.Executor,
    multiply_relation: MultiplyRelation.Plan,
    inverse_relation: InverseRelation.Plan,
    linear_relation: LinearRelation.Plan,
    log_sizes: [ARITHMETIC_ROW_COUNT]u32,
    authority_digest: air_digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        children: anytype,
        shared: ?SharedArithmeticInput,
    ) !ArithmeticRowsAuthority {
        const left = children[LEFT_CHILD].capture;
        const right = children[RIGHT_CHILD].capture;
        const left_composition = children[LEFT_CHILD].composition orelse
            return error.MissingCompositionAuthority;
        const right_composition = children[RIGHT_CHILD].composition orelse
            return error.MissingCompositionAuthority;
        if (shared) |input| try input.validate();
        const lanes = try allocator.alloc(
            lowering.Lane,
            7 + @as(usize, @intFromBool(shared != null)),
        );
        errdefer allocator.free(lanes);
        lanes[0] = .{
            .circuit_id = SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = left_composition.circuit_identity,
            .graph = left_composition.graph,
        };
        lanes[1] = .{
            .circuit_id = left_composition.circuit_id,
            .active_in = .binary,
            .circuit_identity = left_composition.circuit_identity,
            .graph = left_composition.graph,
        };
        lanes[2] = .{
            .circuit_id = LEFT_PCS_CIRCUIT_ID,
            .active_in = .binary,
            .circuit_identity = left.pcs_circuit.identity_digest,
            .graph = left.pcs_circuit.graph(),
        };
        lanes[3] = .{
            .circuit_id = LEFT_FRI_CIRCUIT_ID,
            .active_in = .binary,
            .circuit_identity = left.circuit.identity_digest,
            .graph = left.circuit.graph(),
        };
        lanes[4] = .{
            .circuit_id = right_composition.circuit_id,
            .active_in = .binary,
            .circuit_identity = right_composition.circuit_identity,
            .graph = right_composition.graph,
        };
        lanes[5] = .{
            .circuit_id = RIGHT_PCS_CIRCUIT_ID,
            .active_in = .binary,
            .circuit_identity = right.pcs_circuit.identity_digest,
            .graph = right.pcs_circuit.graph(),
        };
        lanes[6] = .{
            .circuit_id = RIGHT_FRI_CIRCUIT_ID,
            .active_in = .binary,
            .circuit_identity = right.circuit.identity_digest,
            .graph = right.circuit.graph(),
        };
        if (shared) |input| lanes[7] = input.lane;
        const reference = try lowering.Reference.seal(lanes);
        var plan = try lowering.Plan.init(allocator, reference);
        errdefer plan.deinit();

        var multiply_definition = try multiply_air.build(allocator, .generated);
        errdefer multiply_definition.deinit();
        var inverse_definition = try inverse_air.build(allocator, .generated);
        errdefer inverse_definition.deinit();
        var linear_definition = try linear_air.build(allocator, .generated);
        errdefer linear_definition.deinit();
        const multiply_binding = try multiply_witness.Binding.canonical(
            &multiply_definition,
        );
        const inverse_binding = try inverse_witness.Binding.canonical(
            &inverse_definition,
        );
        const linear_binding = try linear_witness.Binding.canonical(&linear_definition);

        var result = ArithmeticRowsAuthority{
            .allocator = allocator,
            .lanes = lanes,
            .reference = reference,
            .plan = plan,
            .multiply_definition = multiply_definition,
            .inverse_definition = inverse_definition,
            .linear_definition = linear_definition,
            .multiply_executor = try multiply_witness.Executor.init(
                &multiply_definition,
                &multiply_binding,
            ),
            .inverse_executor = try inverse_witness.Executor.init(
                &inverse_definition,
                &inverse_binding,
            ),
            .linear_executor = try linear_witness.Executor.init(
                &linear_definition,
                &linear_binding,
            ),
            .multiply_relation = try MultiplyRelation.authenticate(
                &multiply_definition,
            ),
            .inverse_relation = try InverseRelation.authenticate(
                &inverse_definition,
            ),
            .linear_relation = try LinearRelation.authenticate(
                &linear_definition,
            ),
            .log_sizes = .{
                try traceLogSize(plan.multiply_rows.len),
                try traceLogSize(plan.inverse_rows.len),
                try traceLogSize(plan.linear_rows.len),
            },
            .authority_digest = undefined,
        };
        result.authority_digest = arithmeticRowsAuthorityDigest(&result);
        try result.validate(children, shared);
        return result;
    }

    pub fn deinit(self: *ArithmeticRowsAuthority) void {
        self.linear_definition.deinit();
        self.inverse_definition.deinit();
        self.multiply_definition.deinit();
        self.plan.deinit();
        self.allocator.free(self.lanes);
        self.* = undefined;
    }

    pub fn validate(
        self: *const ArithmeticRowsAuthority,
        children: anytype,
        shared: ?SharedArithmeticInput,
    ) !void {
        if (shared) |input| try input.validate();
        try self.reference.validateAuthority();
        try self.plan.validateAgainst(self.reference);
        try self.multiply_relation.validateAgainst(
            &self.multiply_definition.arena,
            multiply_air.SEMANTIC_DIGEST,
            MultiplyRelation.events(&self.multiply_definition),
        );
        try self.inverse_relation.validateAgainst(
            &self.inverse_definition.arena,
            inverse_air.SEMANTIC_DIGEST,
            InverseRelation.events(&self.inverse_definition),
        );
        try self.linear_relation.validateAgainst(
            &self.linear_definition.arena,
            linear_air.SEMANTIC_DIGEST,
            LinearRelation.events(&self.linear_definition),
        );
        const left_composition = children[LEFT_CHILD].composition orelse
            return error.MissingCompositionAuthority;
        const right_composition = children[RIGHT_CHILD].composition orelse
            return error.MissingCompositionAuthority;
        if (self.lanes.len != 7 + @as(usize, @intFromBool(shared != null)) or
            !std.mem.eql(
                u8,
                &self.lanes[1].circuit_identity,
                &left_composition.circuit_identity,
            ) or !std.mem.eql(
            u8,
            &self.lanes[4].circuit_identity,
            &right_composition.circuit_identity,
        ) or (shared != null and !std.meta.eql(self.lanes[7], shared.?.lane)) or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &arithmeticRowsAuthorityDigest(self),
            )) return error.SourceAuthorityMismatch;
    }
};

pub const MerkleRowsAuthority = struct {
    definition: merkle_path_air.Definition,
    relation: merkle_path_relation.Plan,
    executor: merkle_path_witness.Executor,
    authority_digest: air_digest.Digest,

    pub fn init(allocator: std.mem.Allocator) !MerkleRowsAuthority {
        var definition = try merkle_path_air.build(allocator);
        errdefer definition.deinit();
        const binding = try merkle_path_witness.Binding.canonical(&definition);
        var result = MerkleRowsAuthority{
            .definition = definition,
            .relation = try merkle_path_relation.authenticate(&definition),
            .executor = try merkle_path_witness.Executor.init(
                &definition,
                &binding,
            ),
            .authority_digest = undefined,
        };
        result.authority_digest = merkleRowsAuthorityDigest(&result);
        try result.validate();
        return result;
    }

    pub fn deinit(self: *MerkleRowsAuthority) void {
        self.definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const MerkleRowsAuthority) !void {
        try self.definition.validate();
        const expected_binding = try merkle_path_witness.Binding.canonical(
            &self.definition,
        );
        if (!std.meta.eql(self.executor.binding, expected_binding) or
            !std.mem.eql(
                u8,
                &self.executor.binding_digest,
                &expected_binding.identityDigest(),
            ) or !std.mem.eql(
            u8,
            &self.authority_digest,
            &merkleRowsAuthorityDigest(self),
        )) {
            return error.SourceAuthorityMismatch;
        }
        try self.relation.validateAgainst(
            &self.definition.arena,
            merkle_path_air.SEMANTIC_DIGEST,
            self.definition.events,
        );
    }
};

/// Frozen-V1 boundary contract. Keeping the legacy types and validation path
/// behind a comptime contract lets newer, independently authenticated proof
/// profiles reuse the exact row writers without weakening or branching the V1
/// protocol at runtime.
pub fn FrozenV1Boundary(comptime dimensions: fixed_wire.Dimensions) type {
    return struct {
        pub const IS_LEGACY = true;
        pub const INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS = true;
        pub const PairPrepared = binary_authority.Prepared(dimensions);
        pub const RootPin = pair_node.RootVkPinV1;
        pub const Wire = fixed_wire.FixedStarkProofWire(dimensions);
        pub const Child = ChildInput(dimensions);
    };
}

pub fn arithmeticRowsAuthorityDigest(
    rows: *const ArithmeticRowsAuthority,
) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-rows-30-32/v1\x00");
    hash.update(&rows.reference.authority_digest);
    hash.update(&rows.plan.authority_digest);
    hash.update(&rows.multiply_executor.binding_digest);
    hash.update(&rows.inverse_executor.binding_digest);
    hash.update(&rows.linear_executor.binding_digest);
    inline for (.{
        rows.multiply_relation,
        rows.inverse_relation,
        rows.linear_relation,
    }) |plan| {
        hashInt(&hash, u16, plan.format_version);
        hash.update(&plan.semantic_digest);
        hash.update(&plan.registry_order_digest);
        hashInt(&hash, u16, plan.compiled_node_count);
    }
    for (rows.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

pub fn merkleRowsAuthorityDigest(rows: *const MerkleRowsAuthority) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-rows-33-34/v1\x00");
    hash.update(&merkle_path_air.SEMANTIC_DIGEST);
    hash.update(&rows.executor.binding_digest);
    hashInt(&hash, u16, rows.relation.format_version);
    hashInt(&hash, u16, rows.relation.semantic_format_version);
    hash.update(&rows.relation.semantic_digest);
    hash.update(&rows.relation.registry_order_digest);
    hashInt(&hash, u16, rows.relation.compiled_node_count);
    return hash.finalResult();
}
