//! Internal shard of vm_air_composition_circuit.zig; use the public facade.

const dependency_0 = @import("vm_air_composition_circuit_error.zig");
const dependency_2 = @import("vm_air_composition_circuit_validate_sample_geometry.zig");

const std = dependency_0.std;
const graph_build = dependency_0.graph_build;
const vm_air_composition_circuit = @This();
const M31 = dependency_0.M31;
const m31 = dependency_0.m31;
const QM31 = dependency_0.QM31;
const graph_mod = dependency_0.graph_mod;
const row18_witness = dependency_0.row18_witness;
const vm_leaf_context = dependency_0.vm_leaf_context;
const Sha256 = dependency_0.Sha256;
const CIRCUIT_ID = dependency_0.CIRCUIT_ID;
const TREE_COUNT = dependency_0.TREE_COUNT;
const Error = dependency_0.Error;
const Evaluation = dependency_2.Evaluation;
const Handle = dependency_2.Handle;
const OpKey = dependency_2.OpKey;
const validateSampleGeometry = dependency_2.validateSampleGeometry;
const inputWord = dependency_2.inputWord;
const constantPair = dependency_2.constantPair;
const handleIsZero = dependency_2.handleIsZero;
const isOne = dependency_2.isOne;
const canonicalPair = dependency_2.canonicalPair;
const qm31Words = dependency_2.qm31Words;
const indexU32 = dependency_2.indexU32;
const countInputNodes = dependency_2.countInputNodes;
const circuitDigest = dependency_2.circuitDigest;
const transcriptComponentForInfra = dependency_2.transcriptComponentForInfra;

pub const Circuit = struct {
    allocator: std.mem.Allocator,
    nodes: []graph_mod.Node,
    outputs: []u32,
    bindings: []graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    air_profile_digest: [Sha256.digest_length]u8,
    graph_digest: [Sha256.digest_length]u8,
    reference_digest: [Sha256.digest_length]u8,
    schedule_digest: [Sha256.digest_length]u8,
    identity_digest: [Sha256.digest_length]u8,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graph(self: *const Circuit) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.graph_digest,
        };
    }

    pub fn lane(self: *const Circuit) graph_mod.VmLane {
        return .{
            .circuit_id = CIRCUIT_ID,
            .graph = self.graph(),
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }

    pub fn reference(self: *const Circuit) Error!graph_mod.Reference {
        const lane_value = self.lane();
        return graph_mod.Reference.authenticate(
            lane_value,
            &.{},
            &.{},
            self.reference_digest,
        );
    }

    pub fn validate(self: *const Circuit) Error!void {
        try self.graph().validate();
        const lane_value = self.lane();
        const reference_digest = graph_mod.computeReferenceDigest(lane_value, &.{}, &.{});
        if (!std.mem.eql(u8, &reference_digest, &self.reference_digest))
            return error.CircuitIdentityMismatch;
        _ = try self.reference();
        const expected = circuitDigest(
            self.air_profile_digest,
            self.graph_digest,
            self.reference_digest,
            self.schedule_digest,
            self.input_profile,
            self.bindings,
        );
        if (!std.mem.eql(u8, &expected, &self.identity_digest))
            return error.CircuitIdentityMismatch;
    }

    /// Concrete replay against the exact successful verifier capture. This is
    /// both witness construction and a native-composition differential check:
    /// the final selected output must be zero for an authenticated proof.
    pub fn evaluate(
        self: *const Circuit,
        allocator: std.mem.Allocator,
        context: *const vm_leaf_context.Context,
        capture: anytype,
        active: bool,
    ) Error!Evaluation {
        try self.validate();
        try context.validate();
        if (!std.mem.eql(u8, &context.profile.manifest_digest, &self.air_profile_digest))
            return error.CircuitIdentityMismatch;
        const values = try allocator.alloc(QM31, self.nodes.len);
        errdefer allocator.free(values);
        @memset(values, QM31.zero());

        if (self.bindings.len != countInputNodes(self.nodes))
            return error.BindingCountMismatch;
        for (self.bindings) |binding| {
            if (binding.node_id >= values.len) return error.BindingCountMismatch;
            values[binding.node_id] = QM31.fromBase(try inputWord(
                binding.source,
                context,
                capture,
                active,
            ));
        }
        for (self.nodes, 0..) |node, node_id| {
            values[node_id] = switch (node.op) {
                .input => values[node_id],
                .constant => |words| QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                ),
                .add => |operands| values[operands.lhs].add(values[operands.rhs]),
                .sub => |operands| values[operands.lhs].sub(values[operands.rhs]),
                .mul => |operands| values[operands.lhs].mul(values[operands.rhs]),
                .neg => |operand| values[operand].neg(),
                .inverse => |operand| try values[operand].inv(),
            };
        }
        for (self.outputs) |output| {
            if (output >= values.len or !values[output].isZero())
                return error.UnsatisfiedCircuit;
        }
        return .{
            .allocator = allocator,
            .values = values,
            .circuit_identity = self.identity_digest,
        };
    }

    /// Replays every derived node without allocating. Input nodes are checked
    /// separately against the authenticated row-18 schedule by `Prepared`;
    /// this pass prevents a mutated intermediate or output value from being
    /// admitted merely because the circuit identity itself is still valid.
    pub fn validateEvaluation(
        self: *const Circuit,
        evaluation: *const Evaluation,
    ) Error!void {
        try self.validate();
        if (evaluation.values.len != self.nodes.len or
            !std.mem.eql(
                u8,
                &evaluation.circuit_identity,
                &self.identity_digest,
            ))
        {
            return error.CircuitIdentityMismatch;
        }
        for (self.nodes, 0..) |node, node_id| {
            const expected = switch (node.op) {
                .input => continue,
                .constant => |words| QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                ),
                .add => |operands| evaluation.values[operands.lhs].add(
                    evaluation.values[operands.rhs],
                ),
                .sub => |operands| evaluation.values[operands.lhs].sub(
                    evaluation.values[operands.rhs],
                ),
                .mul => |operands| evaluation.values[operands.lhs].mul(
                    evaluation.values[operands.rhs],
                ),
                .neg => |operand| evaluation.values[operand].neg(),
                .inverse => |operand| evaluation.values[operand].inv() catch
                    return error.CircuitIdentityMismatch,
            };
            if (!expected.eql(evaluation.values[node_id]))
                return error.CircuitIdentityMismatch;
        }
        for (self.outputs) |output| {
            if (output >= evaluation.values.len or
                !evaluation.values[output].isZero())
            {
                return error.UnsatisfiedCircuit;
            }
        }
    }

    /// Materialize the exact row-18 main values from verifier-owned inputs.
    /// Admission and all input reads complete before the first destination
    /// write, so shape or authority failures leave the caller's buffer intact.
    pub fn writeScheduleValues(
        self: *const Circuit,
        destination: []M31,
        preprocessing: *const row18_witness.Preprocessed,
        context: *const vm_leaf_context.Context,
        capture: anytype,
        active: bool,
    ) Error!void {
        try self.validate();
        try context.validate();
        try validateSampleGeometry(context, capture);
        try preprocessing.validate();
        if (preprocessing.source != .authenticated_graph or
            preprocessing.reference_digest == null or
            !std.mem.eql(
                u8,
                &preprocessing.reference_digest.?,
                &self.reference_digest,
            ) or
            !std.mem.eql(
                u8,
                &preprocessing.authority_digest,
                &self.schedule_digest,
            ) or
            destination.len != preprocessing.rows.len)
        {
            return error.CircuitIdentityMismatch;
        }

        // Preflight every classification and bounds check. The second pass is
        // deliberately infallible and contiguous.
        for (preprocessing.rows) |row| {
            if (row.circuit_id != CIRCUIT_ID) return error.CircuitIdentityMismatch;
            switch (row.classification) {
                .vm_input => |source| _ = try inputWord(source, context, capture, active),
                .constant_anchor, .output_anchor => |modes| {
                    if (!std.meta.eql(modes, graph_mod.ModeSet.SEGMENT))
                        return error.CircuitIdentityMismatch;
                },
                .recursion_input => return error.CircuitIdentityMismatch,
            }
        }
        for (preprocessing.rows, destination) |row, *value| {
            value.* = switch (row.classification) {
                .vm_input => |source| inputWord(source, context, capture, active) catch unreachable,
                .constant_anchor, .output_anchor => M31.zero(),
                .recursion_input => unreachable,
            };
        }
    }
};

/// Fully admitted row-18 authority and witness derived from one successful
/// native verification. This is the stable, non-generic handoff consumed by
/// backend outer provers: no statement pointer or decoded proof storage is
/// retained, and every owned layer revalidates its independent seal.
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: Circuit,
    evaluation: Evaluation,
    preprocessing: row18_witness.Preprocessed,
    schedule_values: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        context: *const vm_leaf_context.Context,
        capture: anytype,
    ) Error!Prepared {
        var circuit = try build(allocator, context, capture);
        errdefer circuit.deinit();
        var evaluation = try circuit.evaluate(allocator, context, capture, true);
        errdefer evaluation.deinit();
        const reference = try circuit.reference();
        var preprocessing = try row18_witness.Preprocessed.initFromReference(
            allocator,
            &reference,
        );
        errdefer preprocessing.deinit();
        const schedule_values = try allocator.alloc(M31, preprocessing.rows.len);
        errdefer allocator.free(schedule_values);
        try circuit.writeScheduleValues(
            schedule_values,
            &preprocessing,
            context,
            capture,
            true,
        );
        var result = Prepared{
            .allocator = allocator,
            .circuit = circuit,
            .evaluation = evaluation,
            .preprocessing = preprocessing,
            .schedule_values = schedule_values,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.schedule_values);
        self.preprocessing.deinit();
        self.evaluation.deinit();
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Prepared) Error!void {
        try self.circuit.validate();
        try self.preprocessing.validate();
        try self.circuit.validateEvaluation(&self.evaluation);
        if (self.schedule_values.len != self.preprocessing.rows.len or
            self.evaluation.values.len != self.circuit.nodes.len or
            !std.mem.eql(
                u8,
                &self.evaluation.circuit_identity,
                &self.circuit.identity_digest,
            ) or self.preprocessing.reference_digest == null or
            !std.mem.eql(
                u8,
                &self.preprocessing.reference_digest.?,
                &self.circuit.reference_digest,
            ) or !std.mem.eql(
            u8,
            &self.preprocessing.authority_digest,
            &self.circuit.schedule_digest,
        )) {
            return error.CircuitIdentityMismatch;
        }
        for (self.preprocessing.rows, self.schedule_values) |row, value| {
            if (row.circuit_id != CIRCUIT_ID) return error.CircuitIdentityMismatch;
            switch (row.classification) {
                .vm_input => {
                    const node_id: usize = row.node_id;
                    if (node_id >= self.evaluation.values.len)
                        return error.CircuitIdentityMismatch;
                    const expected = self.evaluation.values[node_id].tryIntoM31() catch
                        return error.CircuitIdentityMismatch;
                    if (!expected.eql(value)) return error.CircuitIdentityMismatch;
                },
                .constant_anchor, .output_anchor => |modes| {
                    if (!std.meta.eql(modes, graph_mod.ModeSet.SEGMENT) or
                        !value.isZero())
                    {
                        return error.CircuitIdentityMismatch;
                    }
                },
                .recursion_input => return error.CircuitIdentityMismatch,
            }
        }
    }
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(graph_mod.Node),
    outputs: std.ArrayList(u32),
    bindings: std.ArrayList(graph_mod.VmInputBinding),
    interned: std.AutoHashMap(OpKey, u32),
    failure: ?anyerror = null,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .nodes = .empty,
            .outputs = .empty,
            .bindings = .empty,
            .interned = std.AutoHashMap(OpKey, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        self.interned.deinit();
        self.bindings.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reserve(self: *Builder, inputs: usize, instructions: usize) Error!void {
        const operation_capacity = std.math.mul(usize, instructions, 24) catch
            return error.ArithmeticOverflow;
        const capacity = std.math.add(usize, inputs, operation_capacity) catch
            return error.ArithmeticOverflow;
        if (capacity >= m31.Modulus) return error.CircuitTooLarge;
        try self.nodes.ensureTotalCapacity(self.allocator, capacity);
        try self.bindings.ensureTotalCapacity(self.allocator, inputs);
        try self.outputs.ensureTotalCapacity(self.allocator, 1);
        try self.interned.ensureTotalCapacity(@intCast(capacity));
    }

    pub fn input(self: *Builder, source: graph_mod.VmSource) Error!Scalar {
        try self.check();
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = .input });
        try self.bindings.append(self.allocator, .{ .node_id = node_id, .source = source });
        return .{ .handle = .{ .node = node_id } };
    }

    pub fn constrainZero(self: *Builder, value: Scalar) Error!void {
        try self.check();
        try self.outputs.append(self.allocator, try self.nodeId(value.handle));
    }

    fn add(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.addFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn addFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.check();
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].add(pair[1]) };
        if (handleIsZero(lhs)) return rhs;
        if (handleIsZero(rhs)) return lhs;
        const a = try self.nodeId(lhs);
        const b = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .add = canonicalPair(a, b) },
            .{ .add = .{ .lhs = a, .rhs = b } },
        ) };
    }

    fn sub(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.subFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn subFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.check();
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].sub(pair[1]) };
        if (handleIsZero(rhs)) return lhs;
        if (std.meta.eql(lhs, rhs)) return .{ .constant = QM31.zero() };
        const a = try self.nodeId(lhs);
        const b = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .sub = .{ .lhs = a, .rhs = b } },
            .{ .sub = .{ .lhs = a, .rhs = b } },
        ) };
    }

    fn mul(self: *Builder, lhs: Handle, rhs: Handle) Handle {
        return self.mulFallible(lhs, rhs) catch |err| self.poison(err);
    }

    fn mulFallible(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        try self.check();
        if (constantPair(lhs, rhs)) |pair| return .{ .constant = pair[0].mul(pair[1]) };
        if (handleIsZero(lhs) or handleIsZero(rhs)) return .{ .constant = QM31.zero() };
        if (isOne(lhs)) return rhs;
        if (isOne(rhs)) return lhs;
        const a = try self.nodeId(lhs);
        const b = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .mul = canonicalPair(a, b) },
            .{ .mul = .{ .lhs = a, .rhs = b } },
        ) };
    }

    fn neg(self: *Builder, value: Handle) Handle {
        return self.negFallible(value) catch |err| self.poison(err);
    }

    fn negFallible(self: *Builder, value: Handle) Error!Handle {
        try self.check();
        return switch (value) {
            .constant => |constant| .{ .constant = constant.neg() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .neg = node_id },
                .{ .neg = node_id },
            ) },
        };
    }

    fn inverse(self: *Builder, value: Handle) Handle {
        return self.inverseFallible(value) catch |err| self.poison(err);
    }

    fn inverseFallible(self: *Builder, value: Handle) Error!Handle {
        try self.check();
        return switch (value) {
            .constant => |constant| .{ .constant = try constant.inv() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .inverse = node_id },
                .{ .inverse = node_id },
            ) },
        };
    }

    fn nodeId(self: *Builder, value: Handle) Error!u32 {
        try self.check();
        return switch (value) {
            .node => |node_id| node_id,
            .constant => |constant| blk: {
                const words = qm31Words(constant);
                break :blk try self.intern(
                    .{ .constant = words },
                    .{ .constant = words },
                );
            },
        };
    }

    fn intern(self: *Builder, key: OpKey, op: graph_mod.Op) Error!u32 {
        try self.check();
        if (self.interned.get(key)) |node_id| return node_id;
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = op });
        try self.interned.put(key, node_id);
        return node_id;
    }

    fn poison(self: *Builder, failure: anyerror) Handle {
        if (self.failure == null) self.failure = failure;
        return .{ .constant = QM31.zero() };
    }

    pub fn check(self: *const Builder) Error!void {
        if (self.failure) |_| return error.GraphConstructionFailed;
    }
};

pub threadlocal var installed_builder: ?*Builder = null;

pub const Scalar = struct {
    handle: Handle,

    pub fn zero() Scalar {
        return .{ .handle = .{ .constant = QM31.zero() } };
    }

    pub fn one() Scalar {
        return .{ .handle = .{ .constant = QM31.one() } };
    }

    pub fn fromBase(value: M31) Scalar {
        return .{ .handle = .{ .constant = QM31.fromBase(value) } };
    }

    pub fn fromSecure(value: QM31) Scalar {
        return .{ .handle = .{ .constant = value } };
    }

    pub fn add(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().add(lhs.handle, rhs.handle) };
    }

    pub fn sub(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().sub(lhs.handle, rhs.handle) };
    }

    pub fn mul(lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .handle = currentBuilder().mul(lhs.handle, rhs.handle) };
    }

    pub fn neg(self: Scalar) Scalar {
        return .{ .handle = currentBuilder().neg(self.handle) };
    }

    pub fn square(self: Scalar) Scalar {
        return self.mul(self);
    }

    pub fn inverse(self: Scalar) Scalar {
        return .{ .handle = currentBuilder().inverse(self.handle) };
    }

    pub fn isZero(self: Scalar) bool {
        return handleIsZero(self.handle);
    }
};

pub const GraphRelation = struct {
    z: Scalar,
    alpha_powers: [32]Scalar,
    arity: usize,

    fn init(z: Scalar, alpha: Scalar, arity: usize) GraphRelation {
        var result = GraphRelation{ .z = z, .alpha_powers = undefined, .arity = arity };
        var power = Scalar.one();
        for (&result.alpha_powers) |*slot| {
            slot.* = power;
            power = power.mul(alpha);
        }
        return result;
    }

    pub fn combine(self: GraphRelation, values: anytype) Scalar {
        std.debug.assert(values.len == self.arity);
        var result = Scalar.zero();
        for (values, self.alpha_powers[0..values.len]) |value, power| {
            result = result.add(power.mul(value));
        }
        return result.sub(self.z);
    }
};

pub const GraphRelations = struct {
    registers_state: GraphRelation,
    memory_access: GraphRelation,
    program_access: GraphRelation,
    merkle: GraphRelation,
    poseidon2: GraphRelation,
    poseidon2_io: GraphRelation,
    bitwise: GraphRelation,
    range_check_20: GraphRelation,
    range_check_8_11: GraphRelation,
    range_check_8_8_4: GraphRelation,
    range_check_8_8: GraphRelation,
    range_check_m31: GraphRelation,

    pub fn init(draws: [12][2]Scalar) GraphRelations {
        return .{
            .registers_state = .init(draws[0][0], draws[0][1], 2),
            .memory_access = .init(draws[1][0], draws[1][1], 7),
            .program_access = .init(draws[2][0], draws[2][1], 5),
            .merkle = .init(draws[3][0], draws[3][1], 4),
            .poseidon2 = .init(draws[4][0], draws[4][1], 16),
            .poseidon2_io = .init(draws[5][0], draws[5][1], 32),
            .bitwise = .init(draws[6][0], draws[6][1], 4),
            .range_check_20 = .init(draws[7][0], draws[7][1], 1),
            .range_check_8_11 = .init(draws[8][0], draws[8][1], 2),
            .range_check_8_8_4 = .init(draws[9][0], draws[9][1], 3),
            .range_check_8_8 = .init(draws[10][0], draws[10][1], 2),
            .range_check_m31 = .init(draws[11][0], draws[11][1], 2),
        };
    }
};

pub const SampleLayout = struct {
    allocator: std.mem.Allocator,
    offsets: [][]usize,
    values: []const Scalar,

    pub fn init(allocator: std.mem.Allocator, points: anytype, values: []const Scalar) Error!SampleLayout {
        if (points.len != TREE_COUNT) return error.InvalidSampleGeometry;
        const offsets = try allocator.alloc([]usize, points.len);
        errdefer allocator.free(offsets);
        var initialized: usize = 0;
        errdefer for (offsets[0..initialized]) |tree| allocator.free(tree);
        var cursor: usize = 0;
        for (points, offsets) |tree, *tree_offsets| {
            tree_offsets.* = try allocator.alloc(usize, tree.len + 1);
            initialized += 1;
            for (tree, 0..) |column, index| {
                tree_offsets.*[index] = cursor;
                cursor = std.math.add(usize, cursor, column.len) catch
                    return error.ArithmeticOverflow;
            }
            tree_offsets.*[tree.len] = cursor;
        }
        if (cursor != values.len) return error.InvalidSampleGeometry;
        return .{ .allocator = allocator, .offsets = offsets, .values = values };
    }

    pub fn deinit(self: *SampleLayout) void {
        for (self.offsets) |tree| self.allocator.free(tree);
        self.allocator.free(self.offsets);
        self.* = undefined;
    }

    pub fn at(self: *const SampleLayout, tree: usize, column: usize, sample: usize) Error!Scalar {
        if (tree >= self.offsets.len or column + 1 >= self.offsets[tree].len)
            return error.InvalidSampleGeometry;
        const start = self.offsets[tree][column];
        const end = self.offsets[tree][column + 1];
        if (sample >= end - start) return error.InvalidSampleGeometry;
        return self.values[start + sample];
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    context: *const vm_leaf_context.Context,
    capture: anytype,
) Error!Circuit {
    const Context = struct {
        pub const ErrorSet = Error;
        pub const CircuitType = Circuit;
        pub const Builder = vm_air_composition_circuit.Builder;
        pub const Scalar = vm_air_composition_circuit.Scalar;
        pub const GraphRelations = vm_air_composition_circuit.GraphRelations;
        pub const SampleLayout = vm_air_composition_circuit.SampleLayout;
        pub const CIRCUIT_ID = vm_air_composition_circuit.CIRCUIT_ID;
        pub const validateSampleGeometry = vm_air_composition_circuit.validateSampleGeometry;
        pub const transcriptComponentForInfra =
            vm_air_composition_circuit.transcriptComponentForInfra;
        pub const circuitDigest = vm_air_composition_circuit.circuitDigest;
        pub const installBuilder = vm_air_composition_circuit.installBuilder;
        pub const uninstallBuilder = vm_air_composition_circuit.uninstallBuilder;
    };
    return graph_build.Build(Context).build(allocator, context, capture);
}

pub fn currentBuilder() *Builder {
    return installed_builder orelse @panic("VM AIR recording scalar used outside build");
}

pub fn installBuilder(builder: *Builder) void {
    std.debug.assert(installed_builder == null);
    installed_builder = builder;
}

pub fn uninstallBuilder() void {
    std.debug.assert(installed_builder != null);
    installed_builder = null;
}
