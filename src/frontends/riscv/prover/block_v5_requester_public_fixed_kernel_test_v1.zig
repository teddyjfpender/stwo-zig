//! Pure ORIGINAL shared tuple/B5SS emitter parity. The fixture only models
//! ordinary source bytes/transcript seeds; it cannot manufacture a PUBLIC21
//! Owner, Fresh, expected proof key or accepted recursive equation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const RealBus = @import("../recursion/block_v5_requester_public_bus_v1.zig");
const Source = @import("../recursion/air/block_v5_requester_public_composition_v1.zig").Source;
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Seed = struct {
    digest: [32]u8,
    pub fn sharedChannel(self: @This()) core.proof_suites.Blake3.Channel {
        return @import("block_v5_universal_channel_v1.zig").init(self.digest);
    }
};
const PureOwner = struct {
    const NativeView = struct { admitted: struct { sealed: Seed } };
    const Policy = struct {
        digest: [32]u8,
        pub fn native(self: @This(), index: u32) !NativeView {
            if (index != 0) return error.InvalidPurePublicIndex;
            return .{ .admitted = .{ .sealed = .{ .digest = self.digest } } };
        }
    };
    policy: Policy = .{ .digest = @splat(0x42) },
    word: u32 = 17,
    pub fn validate(self: *const @This()) !void {
        if (self.word != 17) return error.InvalidPurePublicWord;
    }
    pub fn sealedCells(_: *const @This()) !struct { child: u32, first: u32 } {
        return .{ .child = 1, .first = 0 };
    }
};
const PublicModule = struct {
    pub const Owner = PureOwner;
};
const BusModule = struct {
    pub const Wire = RealBus.Wire;
    pub const Values = struct {
        public: *const PureOwner,
        pub fn at(self: @This(), wire: Wire) ![4]M {
            if (wire.source != .public_word or wire.source.public_word.window != 0 or wire.source.public_word.word != 0) return error.InvalidPurePublicSource;
            return Q.fromBase(M.fromCanonical(self.public.word)).toM31Array();
        }
    };
};
const CompositionModule = struct {
    pub const VERSION = @import("../recursion/air/block_v5_requester_public_composition_v1.zig").VERSION;
    pub const Prepared = struct {
        circuit: R.Circuit,
        inputs: []Q,
        values: []Q,
        sources: []Source,
        relations: U.UniversalRelations,
        semantic_identity: [32]u8,
    };
};
const Kernel = @import("../recursion/air/block_v5_global_public_export_rows_v1.zig").ForModules(PublicModule, CompositionModule, BusModule);
const Fixture = struct {
    a: std.mem.Allocator,
    owner: PureOwner = .{},
    graph: CompositionModule.Prepared,
    fn init(a: std.mem.Allocator) !Fixture {
        const owner = PureOwner{};
        var channel = (try owner.policy.native(0)).admitted.sealed.sharedChannel();
        const relations = try U.UniversalRelations.draw(a, &channel);
        const inputs = try a.alloc(Q, 1 + U.DRAW_COUNT);
        errdefer a.free(inputs);
        const sources = try a.alloc(Source, inputs.len);
        errdefer a.free(sources);
        var builder = R.Builder.init(a);
        defer builder.deinit();
        const symbols = try a.alloc(R.Scalar, inputs.len);
        defer a.free(symbols);
        for (symbols) |*symbol| symbol.* = (try builder.input()).value;
        inputs[0] = Q.fromU32Unchecked(17, 0, 0, 0);
        sources[0] = .{ .public = .{ .public_word = .{ .window = 0, .word = 0 } } };
        for (1..inputs.len) |i| {
            const index = i - 1;
            const element = relations.elements[index / 2];
            inputs[i] = if (index % 2 == 0) element.z else element.alpha_powers[1];
            sources[i] = .{ .challenge = @intCast(index) };
        }
        try builder.activate();
        defer if (builder.active) builder.deactivate();
        try builder.constrainZero(symbols[0].inverse().mul(symbols[0]).sub(R.Scalar.one()));
        try builder.constrainZero(symbols[0].sub(R.Scalar.fromSecure(inputs[0])));
        for (symbols[1..]) |symbol| try builder.constrainZero(symbol.sub(symbol));
        builder.deactivate();
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        const values = try a.alloc(Q, circuit.nodes.len);
        errdefer a.free(values);
        try circuit.evaluateInto(inputs, values);
        return .{ .a = a, .graph = .{ .circuit = circuit, .inputs = inputs, .values = values, .sources = sources, .relations = relations, .semantic_identity = @splat(0x31) } };
    }
    fn deinit(self: *Fixture) void {
        self.a.free(self.graph.inputs);
        self.a.free(self.graph.values);
        self.a.free(self.graph.sources);
        self.graph.circuit.deinit();
    }
};
test "requester fixed ports: shared tuple B5SS live and fixed exact row identity and source schedule parity" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var live = try Kernel.prepare(std.testing.allocator, &fixture.owner, &fixture.graph, 2);
    defer live.deinit();
    var fixed = try Kernel.prepareFixed(std.testing.allocator, &fixture.owner, &fixture.graph, 2);
    defer fixed.deinit();
    try std.testing.expectEqualDeep(live.identity, fixed.identity);
    try std.testing.expectEqual(live.wires.len, fixed.wires.len);
    for (live.wires, fixed.wires) |actual, expected| try std.testing.expectEqualDeep(actual, expected);
    inline for (0..Storage.Airs.len) |slot| {
        const expected = try fixed.rows.metadata(slot);
        try std.testing.expectEqual(live.rows.fixed[slot].len, expected.len);
        for (live.rows.fixed[slot], expected) |actual, tail| try std.testing.expectEqualDeep(actual, tail);
    }
    try std.testing.expect(!@hasField(Kernel.FixedPrepared, "main"));
    try std.testing.expect(!Kernel.FixedPrepared.complete_fixed_setup);
}
test "requester fixed ports: shared tuple source challenge relation and evaluation mutations reject identically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    fixture.graph.sources[0].public.public_word.word = 1;
    inline for (.{ Kernel.prepare, Kernel.prepareFixed }) |emit| try std.testing.expectError(error.InvalidPurePublicSource, emit(std.testing.allocator, &fixture.owner, &fixture.graph, 2));
    fixture.graph.sources[0].public.public_word.word = 0;
    fixture.graph.inputs[1] = fixture.graph.inputs[1].add(Q.one());
    inline for (.{ Kernel.prepare, Kernel.prepareFixed }) |emit| try std.testing.expectError(error.UntrustedGlobalPublicChallenge, emit(std.testing.allocator, &fixture.owner, &fixture.graph, 2));
    fixture.graph.inputs[1] = fixture.graph.inputs[1].sub(Q.one());
    fixture.graph.relations.elements[0].z = fixture.graph.relations.elements[0].z.add(Q.one());
    inline for (.{ Kernel.prepare, Kernel.prepareFixed }) |emit| try std.testing.expectError(error.UntrustedGlobalPublicChallenge, emit(std.testing.allocator, &fixture.owner, &fixture.graph, 2));
    fixture.graph.relations.elements[0].z = fixture.graph.relations.elements[0].z.sub(Q.one());
    fixture.graph.values[0] = fixture.graph.values[0].add(Q.one());
    inline for (.{ Kernel.prepare, Kernel.prepareFixed }) |emit| try std.testing.expectError(error.MutatedGlobalPublicGraph, emit(std.testing.allocator, &fixture.owner, &fixture.graph, 2));
}
test "requester fixed ports: fixed tuple metadata retains allocation budget after creator release" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const budget = try Budget.create(std.testing.allocator, 256 << 20);
    var budget_live = true;
    defer if (budget_live) budget.destroy();
    var fixed = try Kernel.prepareFixed(budget.allocator(), &fixture.owner, &fixture.graph, 2);
    defer fixed.deinit();
    budget.destroy();
    budget_live = false;
    try std.testing.expect((try fixed.rows.metadata(0)).len != 0);
    try std.testing.expect(fixed.wires.len != 0);
}
test "requester fixed ports: original validation and initial fixed allocation failures release before emission" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.expectError(error.InvalidGlobalPublicGraph, Kernel.prepareFixed(std.testing.failing_allocator, &fixture.owner, &fixture.graph, 0));
    for (0..2) |offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = offset });
        try std.testing.expectError(error.OutOfMemory, Kernel.prepareFixed(failing.allocator(), &fixture.owner, &fixture.graph, 2));
        try std.testing.expect(failing.has_induced_failure);
    }
    try std.testing.expectError(error.RequesterPublicFixedResourceLimit, @import("../recursion/air/block_v5_requester_public_fixed_rows_v1.zig").Owned.init(std.testing.failing_allocator, undefined, 0, .{}));
}
