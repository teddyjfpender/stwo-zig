//! Composition ownership boundary. Compilation and witness admission are
//! separate stages; neither stage exposes mutable graph or witness storage.
//! Ethereum V4 remains statement-specialized (including bridge roots). This
//! owner establishes memory custody, not admission of a universal circuit key.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("vm_air_composition_circuit.zig");
const graph_mod = @import("air/composition_circuit.zig");
const rows = @import("air/vm_air_composition_input_witness.zig");
const ethereum = @import("incremental_ethereum_vm_composition_program_v4.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const CompiledHandle = opaque {};
const OwnedHandle = opaque {};
const Storage = struct {
    allocator: std.mem.Allocator,
    program: ethereum.ProgramV4,
    schedule: ?graph_mod.CompiledSchedule,
    prepared: ?vm.Prepared = null,

    fn deinit(self: *Storage) void {
        if (self.prepared) |*value| value.deinit();
        if (self.schedule) |*value| value.deinit();
        self.program.deinit();
        self.allocator.destroy(self);
    }
};

/// Shape and identity data are copies; every buffer is deeply read-only.
pub const ProgramView = struct {
    nodes: []const graph_mod.Node,
    outputs: []const u32,
    bindings: []const graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    claim_routing: ?@import("incremental_ethereum_composition_profile_v4.zig").ClaimRoutingPlan = null,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,

    pub fn logicalClaimCount(self: ProgramView) u32 {
        return if (self.claim_routing) |routing| routing.logical_count else self.input_profile.claimed_sum_count;
    }

    pub fn logicalClaimIndex(self: ProgramView, physical: u32) !u32 {
        if (self.claim_routing) |routing| return routing.logicalForPhysical(physical);
        if (physical >= self.input_profile.claimed_sum_count) return error.InvalidEthereumClaimRouting;
        return physical;
    }

    pub fn lane(self: ProgramView) graph_mod.VmLane {
        return .{
            .circuit_id = vm.CIRCUIT_ID,
            .graph = .{ .nodes = self.nodes, .outputs = self.outputs, .identity_digest = self.graph_sha256 },
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }
};

fn programView(value: *const ethereum.ProgramV4) ProgramView {
    var result: ProgramView = undefined;
    inline for (std.meta.fields(ProgramView)) |field|
        @field(result, field.name) = @field(value, field.name);
    return result;
}

pub const Compiled = struct {
    handle: *CompiledHandle,

    /// The compiler constructs all retained buffers inside this boundary.
    /// No caller-owned mutable Program or retained schedule can be adopted.
    pub fn initEthereum(allocator: std.mem.Allocator, input: ethereum.CompilerInputV4) !Compiled {
        var schedule: graph_mod.CompiledSchedule = undefined;
        var compiled_program = try ethereum.compileRetainingSchedule(allocator, input, &schedule);
        errdefer compiled_program.deinit();
        errdefer schedule.deinit();
        const backing = try allocator.create(Storage);
        backing.* = .{ .allocator = allocator, .program = compiled_program, .schedule = schedule };
        return .{ .handle = @ptrCast(backing) };
    }

    /// Opt-in circuit profile whose bridge roots are statement inputs. This
    /// establishes graph/witness custody only; the outer provider cohort must
    /// independently close the added statement-word lookups before promotion.
    pub fn initEthereumWithStatementRoots(allocator: std.mem.Allocator, input: ethereum.StatementRootCompilerInput) !Compiled {
        var schedule: graph_mod.CompiledSchedule = undefined;
        var compiled_program = try ethereum.compileWithStatementRootsRetainingSchedule(allocator, input, &schedule);
        errdefer compiled_program.deinit();
        errdefer schedule.deinit();
        const backing = try allocator.create(Storage);
        backing.* = .{ .allocator = allocator, .program = compiled_program, .schedule = schedule };
        return .{ .handle = @ptrCast(backing) };
    }

    /// Separate admitted profile: native singleton claims reuse their
    /// canonical graph nodes, with one retained mapping for every consumer.
    pub fn initEthereumWithClaimAliases(allocator: std.mem.Allocator, input: ethereum.StatementRootCompilerInput) !Compiled {
        var schedule: graph_mod.CompiledSchedule = undefined;
        var compiled_program = try ethereum.compileWithClaimAliasesRetainingSchedule(allocator, input, &schedule);
        errdefer compiled_program.deinit();
        errdefer schedule.deinit();
        const backing = try allocator.create(Storage);
        backing.* = .{ .allocator = allocator, .program = compiled_program, .schedule = schedule };
        return .{ .handle = @ptrCast(backing) };
    }

    pub fn deinit(self: *Compiled) void {
        storage(self.handle).deinit();
        self.* = undefined;
    }

    pub fn program(self: Compiled) ProgramView {
        return programView(&storage(self.handle).program);
    }

    pub fn scheduleRows(self: Compiled) []const graph_mod.Row {
        return storage(self.handle).schedule.?.rows;
    }

    /// Consumes compilation on success AND failure. Inputs are read only
    /// during this call; all derived nodes, zero outputs and schedule values
    /// are checked before an immutable preparation is returned.
    pub fn finalize(self: *Compiled, inputs: []const M31, worker_count: usize) !Owned {
        const backing = storage(self.handle);
        const handle = self.handle;
        self.* = undefined;
        errdefer backing.deinit();
        if (worker_count == 0 or worker_count > @import("vm_air_composition_circuit_parallel_v4.zig").MAX_WORKER_COUNT)
            return error.InvalidWorkerCount;
        var schedule = backing.schedule.?;
        backing.schedule = null;
        backing.prepared = try vm.Prepared.initFromAuthenticatedLaneBorrowedParallelV4(
            backing.allocator,
            backing.program.lane(),
            backing.program.air_program_identity,
            inputs,
            &schedule,
            worker_count,
        );
        try backing.prepared.?.validate();
        return .{ .handle = @ptrCast(handle) };
    }
};

pub const Owned = struct {
    handle: *OwnedHandle,

    pub fn deinit(self: *Owned) void {
        storage(self.handle).deinit();
        self.* = undefined;
    }

    pub fn program(self: Owned) ProgramView {
        return programView(&storage(self.handle).program);
    }

    /// Borrowed read capability. The owner must outlive every consumer.
    pub fn source(self: Owned) Source {
        return .{ .immutable = self.handle };
    }

    pub fn auditAgainst(self: Owned, input: ethereum.CompilerInputV4) !void {
        const backing = storage(self.handle);
        try backing.program.validateAgainst(input);
        try backing.prepared.?.validate();
    }
};

/// One downstream contract for legacy mutable preparation and immutable
/// ownership. Legacy validation remains mutation-sensitive. Immutable reads
/// are cheap because construction retained no mutable aliases, not because
/// a flag suppresses validation of caller-owned buffers.
pub const Source = union(enum) {
    borrowed: *const vm.Prepared,
    immutable: *OwnedHandle,

    pub fn validate(self: Source) vm.Error!void {
        switch (self) {
            .borrowed => |value| try value.validate(),
            .immutable => |handle| std.debug.assert(storage(handle).prepared != null),
        }
    }

    pub fn audit(self: Source) vm.Error!void {
        try self.raw().validate();
    }

    pub fn view(self: Source) View {
        const value = self.raw();
        return .{
            .circuit = CircuitView.init(&value.circuit),
            .evaluation = .{ .values = value.evaluation.values, .circuit_identity = value.evaluation.circuit_identity },
            .preprocessing = .{ .rows = value.preprocessing.rows, .log_size = value.preprocessing.log_size, .authority_digest = value.preprocessing.authority_digest },
            .schedule_values = value.schedule_values,
        };
    }

    pub fn generatePreprocessedInto(self: Source, executor: *const rows.Executor, columns: *[rows.PREPROCESSED_COLUMN_COUNT][]M31) !void {
        try self.validate();
        try executor.generatePreprocessedInto(&self.raw().preprocessing, columns);
    }

    pub fn generateMainInto(self: Source, executor: *const rows.Executor, columns: *[rows.MAIN_COLUMN_COUNT][]M31, kind: rows.ProofKind) !void {
        try self.validate();
        const value = self.raw();
        try executor.generateMainInto(&value.preprocessing, columns, value.schedule_values, kind);
    }

    fn raw(self: Source) *const vm.Prepared {
        return switch (self) {
            .borrowed => |value| value,
            .immutable => |handle| &storage(handle).prepared.?,
        };
    }
};

pub const CircuitView = struct {
    nodes: []const graph_mod.Node,
    outputs: []const u32,
    bindings: []const graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    air_profile_digest: [32]u8,
    graph_digest: [32]u8,
    reference_digest: [32]u8,
    schedule_digest: [32]u8,
    identity_digest: [32]u8,

    fn init(value: *const vm.Circuit) CircuitView {
        var result: CircuitView = undefined;
        inline for (std.meta.fields(CircuitView)) |field|
            @field(result, field.name) = @field(value, field.name);
        return result;
    }

    pub fn graph(self: CircuitView) graph_mod.CircuitGraph {
        return .{ .nodes = self.nodes, .outputs = self.outputs, .identity_digest = self.graph_digest };
    }
};

pub const View = struct {
    circuit: CircuitView,
    evaluation: struct { values: []const QM31, circuit_identity: [32]u8 },
    preprocessing: struct { rows: []const graph_mod.Row, log_size: u32, authority_digest: [32]u8 },
    schedule_values: []const M31,
};

fn storage(handle: anytype) *Storage {
    return @ptrCast(@alignCast(handle));
}

// A tiny compiled graph exercises the same finalization and consumer boundary
// as Ethereum without instantiating the outer prover. No public constructor
// accepts this raw, externally mutable representation.
fn testCompiled(allocator: std.mem.Allocator) !Compiled {
    const profile = graph_mod.InputProfile{ .sampled_value_count = 0, .claimed_sum_count = 0, .relation_challenge_count = 0 };
    const nodes = try allocator.alloc(graph_mod.Node, 10);
    errdefer allocator.free(nodes);
    const bindings = try allocator.alloc(graph_mod.VmInputBinding, 9);
    errdefer allocator.free(bindings);
    const outputs = try allocator.dupe(u32, &.{9});
    errdefer allocator.free(outputs);
    for (bindings, 0..) |*binding, index| {
        nodes[index] = .{ .op = .input };
        binding.* = .{ .node_id = @intCast(index), .source = graph_mod.expectedVmSource(profile, index).? };
    }
    nodes[9] = .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 1 } } };
    var program: ethereum.ProgramV4 = undefined;
    inline for (std.meta.fields(ethereum.ProgramV4)) |field| {
        if (field.type == [32]u8) @field(program, field.name) = .{1} ** 32;
        if (field.type == u16 or field.type == u32) @field(program, field.name) = 0;
    }
    program.allocator = allocator;
    program.nodes = nodes;
    program.outputs = outputs;
    program.bindings = bindings;
    program.input_profile = profile;
    program.claim_routing = null;
    program.air_program_identity = .{1} ** 32;
    program.graph_sha256 = graph_mod.computeGraphDigest(nodes, outputs);
    program.reference_sha256 = graph_mod.computeReferenceDigest(program.lane(), &.{}, &.{});
    const reference = try graph_mod.Reference.authenticate(program.lane(), &.{}, &.{}, program.reference_sha256);
    var schedule = try graph_mod.compile(allocator, &reference);
    errdefer schedule.deinit();
    program.schedule_sha256 = schedule.authority_digest;
    const backing = try allocator.create(Storage);
    backing.* = .{ .allocator = allocator, .program = program, .schedule = schedule };
    return .{ .handle = @ptrCast(backing) };
}

test "composition ownership separates immutable structure inputs and consumer views" {
    var compiled = try testCompiled(std.testing.allocator);
    const structure = compiled.program();
    const schedule_ptr = compiled.scheduleRows().ptr;
    var inputs = [_]M31{M31.zero()} ** 9;
    var owned = try compiled.finalize(&inputs, 1);
    defer owned.deinit();
    inputs[0] = M31.one();
    const source = owned.source();
    try source.validate();
    try source.audit();
    const view = source.view();
    try std.testing.expect(structure.nodes.ptr == view.circuit.nodes.ptr);
    try std.testing.expect(schedule_ptr == view.preprocessing.rows.ptr);
    try std.testing.expect(view.evaluation.values[0].isZero());
    inline for (.{ @TypeOf(view.circuit.nodes), @TypeOf(view.circuit.outputs), @TypeOf(view.circuit.bindings), @TypeOf(view.evaluation.values), @TypeOf(view.preprocessing.rows), @TypeOf(view.schedule_values) }) |Slice|
        try std.testing.expect(@typeInfo(Slice).pointer.is_const);
    // A consumer may edit its metadata copy; that cannot alter the owner.
    var copy = view;
    copy.circuit.identity_digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(copy.circuit.identity_digest, source.view().circuit.identity_digest));
    try source.audit();
}

test "composition finalization frees every allocation on rejection and OOM" {
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var compiled = try testCompiled(allocator);
            var owned = try compiled.finalize(&([_]M31{M31.zero()} ** 9), 1);
            defer owned.deinit();
            try owned.source().audit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
    var invalid_worker = try testCompiled(std.testing.allocator);
    try std.testing.expectError(error.InvalidWorkerCount, invalid_worker.finalize(&.{}, 0));
    var invalid_shape = try testCompiled(std.testing.allocator);
    try std.testing.expectError(error.BindingCountMismatch, invalid_shape.finalize(&.{}, 1));
    var invalid_witness = try testCompiled(std.testing.allocator);
    var inputs = [_]M31{M31.zero()} ** 9;
    inputs[0] = M31.one();
    try std.testing.expectError(error.UnsatisfiedCircuit, invalid_witness.finalize(&inputs, 1));
}

test "composition borrowed admission retains mutation checks and matches frozen data" {
    var compiled = try testCompiled(std.testing.allocator);
    const program = compiled.program();
    var inputs = [_]M31{M31.zero()} ** 9;
    inputs[0] = M31.one();
    inputs[1] = M31.one();
    var raw = try vm.Prepared.initFromAuthenticatedLaneV2(std.testing.allocator, .{
        .circuit_id = vm.CIRCUIT_ID,
        .graph = .{ .nodes = program.nodes, .outputs = program.outputs, .identity_digest = program.graph_sha256 },
        .profile = program.input_profile,
        .bindings = program.bindings,
    }, program.air_program_identity, &inputs);
    defer raw.deinit();
    var owned = try compiled.finalize(&inputs, 1);
    defer owned.deinit();
    const borrowed = Source{ .borrowed = &raw };
    try borrowed.validate();
    try std.testing.expectEqualSlices(M31, borrowed.view().schedule_values, owned.source().view().schedule_values);
    try std.testing.expectEqualDeep(borrowed.view().circuit, owned.source().view().circuit);
    var definition = try @import("air/vm_air_composition_input.zig").build(std.testing.allocator);
    defer definition.deinit();
    const binding = try rows.Binding.canonical(&definition);
    const executor = try rows.Executor.init(&definition, &binding);
    // The adapter must emit the exact same physical columns for both owners.
    inline for (.{ rows.PREPROCESSED_COLUMN_COUNT, rows.MAIN_COLUMN_COUNT }) |count| {
        var expected: [count][16]M31 = undefined;
        var actual: [count][16]M31 = undefined;
        var expected_columns: [count][]M31 = undefined;
        var actual_columns: [count][]M31 = undefined;
        for (&expected_columns, &expected) |*column, *buffer| column.* = buffer;
        for (&actual_columns, &actual) |*column, *buffer| column.* = buffer;
        if (count == rows.PREPROCESSED_COLUMN_COUNT) {
            try borrowed.generatePreprocessedInto(&executor, &expected_columns);
            try owned.source().generatePreprocessedInto(&executor, &actual_columns);
        } else {
            try borrowed.generateMainInto(&executor, &expected_columns, .segment_leaf);
            try owned.source().generateMainInto(&executor, &actual_columns, .segment_leaf);
        }
        try std.testing.expectEqualDeep(expected, actual);
    }
    raw.evaluation.values[9] = QM31.one();
    try std.testing.expectError(error.CircuitIdentityMismatch, borrowed.validate());
    try owned.source().audit();
}
