//! Request-local, independently constructed native verifier programs. The opaque
//! handle has no deserialization/unchecked constructor. Captures and evaluations
//! are never cached; each live consumer owns fresh graph copies and operands.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
const Native = @import("../prover/block_v7_native_proof_v1.zig");
const Composition = @import("air/block_v7_native_composition_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Shared = @import("air/blake3_execution_composition.zig");
pub const Limits = struct { max_bytes: usize = 2 << 30 };
const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    profile: *Profile.Owned,
    composition: Composition.Compiled,
    deep_graph: Deep.Circuit,
    fri_graph: Fri.Circuit,
    arithmetic: Assembly.Arithmetic,
    fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.arithmetic.deinit();
        self.fri_graph.deinit();
        self.deep_graph.deinit();
        self.composition.deinit();
        self.profile.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
pub const Capsule = opaque {
    pub fn derive(backing: std.mem.Allocator, selected: *const Profile.Owned, limits: Limits) !*Capsule {
        if (limits.max_bytes == 0) return error.NativeCompilerResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        // Own the canonical metadata, never retain the producer's profile.
        const admitted = try Profile.Owned.derive(a, selected.pin, selected.epoch, selected.roster, selected.limits);
        errdefer admitted.deinit();
        try requireSame(admitted, selected);
        var composition = try Composition.compile(a, admitted);
        errdefer composition.deinit();
        var deep = try Deep.build(a, admitted.shape.deepProfile());
        errdefer deep.deinit();
        var fri = try Fri.build(a, admitted.shape.friProfile());
        errdefer fri.deinit();
        var arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
        errdefer arithmetic.deinit();
        self.* = .{ .allocator = a, .budget = budget, .profile = admitted, .composition = composition, .deep_graph = deep, .fri_graph = fri, .arithmetic = arithmetic };
        return @ptrCast(self);
    }
    /// Immutable compiler products. Only this module can construct an instance.
    pub fn compiler(self: *const Capsule) *const Owned {
        return @ptrCast(@alignCast(self));
    }
    pub fn profile(self: *const Capsule) *const Profile.Owned {
        return self.compiler().profile;
    }
    pub fn requireProfile(self: *const Capsule, selected: *const Profile.Owned) !void {
        try requireSame(self.profile(), selected);
    }
    pub fn deinit(self: *Capsule) void {
        const owned: *Owned = @ptrCast(@alignCast(self));
        owned.deinit();
    }
    pub fn prepareComposition(self: *const Capsule, a: std.mem.Allocator, capture: *const Native.VerifiedCapture) !Shared.Prepared {
        const compiled = &self.compiler().composition;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const inputs = try @import("air/block_v7_native_inputs_v1.zig").composition(temp, self.profile(), compiled, capture);
        const sources = try temp.dupe(Shared.Source, compiled.sources);
        const original = &compiled.circuit;
        const nodes = try a.dupe(@TypeOf(original.nodes[0]), original.nodes);
        errdefer a.free(nodes);
        const outputs = try a.dupe(u32, original.outputs);
        errdefer a.free(outputs);
        const circuit = @import("air/composition_graph_recorder.zig").Circuit{ .allocator = a, .nodes = nodes, .outputs = outputs, .input_count = original.input_count, .identity_digest = original.identity_digest };
        const values = try temp.alloc(core.fields.qm31.QM31, circuit.nodes.len);
        try circuit.evaluateInto(inputs, values);
        var result = Shared.Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = self.profile().seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
        result.seal = result.identity();
        return result;
    }
    pub fn prepareDeep(self: *const Capsule, a: std.mem.Allocator, capture: *const Native.VerifiedCapture) !@import("air/blake3_native_deep.zig").Prepared {
        var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, self.profile().shape.deepProfile(), &capture.proof);
        errdefer inputs.deinit();
        var graph = try @import("air/compiled_pcs_graph_clone_v1.zig").deep(a, &self.compiler().deep_graph);
        errdefer graph.deinit();
        const evaluation = try graph.evaluate(a, inputs.inputs);
        return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
    }
};
fn requireSame(canonical: *const Profile.Owned, selected: *const Profile.Owned) !void {
    // Compare the full externally selected geometry to the privately constructed
    // profile without re-running the constraint recorder/compiler. The canonical
    // identity includes the pin, selected layout, PCS masks and slot source map.
    if (!std.meta.eql(selected.seal, try selected.identity()) or !std.meta.eql(canonical.seal, selected.seal) or
        !std.meta.eql(selected.shape.config, canonical.shape.config) or !std.meta.eql(selected.epoch, canonical.epoch) or
        selected.roster.len != canonical.roster.len) return error.NativeCompilerProfileMismatch;
    for (selected.roster, canonical.roster) |got, want| if (!std.meta.eql(got, want)) return error.NativeCompilerProfileMismatch;
}
