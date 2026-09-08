//! Privately owned PCS graph admitted from a profile, with no mutable graph
//! aliases escaping construction. Witness buffers remain separately owned.
const circuit = @import("pcs_deep_circuit_circuit.zig");
const build = @import("pcs_deep_circuit_build.zig").build;
const std = @import("std");

pub const Prepared = struct {
    handle: *Handle,

    const Handle = opaque {};
    const Storage = struct { value: circuit.Circuit };

    pub const View = struct {
        bindings: []const circuit.InputBinding,
        profile_digest: circuit.digest.Digest,
        graph_digest: circuit.digest.Digest,
        identity_digest: circuit.digest.Digest,
    };

    /// Build and authenticate internally: accepting an already mutable Circuit
    /// here would allow its previous aliases to invalidate admission.
    pub fn init(allocator: std.mem.Allocator, profile_value: circuit.Profile) circuit.Error!Prepared {
        var value = try build(allocator, profile_value);
        errdefer value.deinit();
        const backing = try allocator.create(Storage);
        backing.* = .{ .value = value };
        return .{ .handle = @ptrCast(backing) };
    }

    pub fn deinit(self: *Prepared) void {
        const backing: *Storage = @ptrCast(@alignCast(self.handle));
        const allocator = backing.value.allocator;
        backing.value.deinit();
        allocator.destroy(backing);
        self.* = undefined;
    }

    fn ownedCircuit(self: *const Prepared) *const circuit.Circuit {
        const backing: *const Storage = @ptrCast(@alignCast(self.handle));
        return &backing.value;
    }

    pub fn view(self: *const Prepared) View {
        const owned = self.ownedCircuit();
        return .{
            .bindings = owned.bindings,
            .profile_digest = owned.profile_digest,
            .graph_digest = owned.graph_digest,
            .identity_digest = owned.identity_digest,
        };
    }

    pub fn profile(self: *const Prepared) circuit.Profile {
        return self.ownedCircuit().profile();
    }

    pub fn graph(self: *const Prepared) circuit.graph_mod.CircuitGraph {
        return self.ownedCircuit().graph();
    }

    pub fn laneProfile(self: *const Prepared) circuit.Error!@import("pcs_deep_input_witness.zig").LaneProfile {
        return self.ownedCircuit().laneProfile();
    }

    /// Explicit full audit remains available at admission/verification boundaries.
    pub fn validate(self: *const Prepared) circuit.Error!void {
        try self.ownedCircuit().validate();
    }

    /// The graph is immutable and admitted; every mutable evaluation is still
    /// replayed, including all non-input nodes and designated zero outputs.
    pub fn validateEvaluation(self: *const Prepared, evaluation: *const circuit.Evaluation) circuit.Error!void {
        try self.ownedCircuit().validateEvaluationHot(evaluation);
    }

    pub fn evaluate(self: *const Prepared, allocator: std.mem.Allocator, witness: circuit.Witness) circuit.Error!circuit.Evaluation {
        return self.ownedCircuit().evaluate(allocator, witness);
    }

    pub fn evaluateInactive(self: *const Prepared, allocator: std.mem.Allocator) circuit.Error!circuit.Evaluation {
        return self.ownedCircuit().evaluateInactive(allocator);
    }

    /// No mutable evaluation or alias is accepted from the caller. All values
    /// are computed and checked before they enter private immutable storage.
    pub fn evaluateFrozen(self: *const Prepared, allocator: std.mem.Allocator, witness: circuit.Witness) circuit.Error!FrozenEvaluation {
        var evaluated = try self.evaluate(allocator, witness);
        errdefer evaluated.deinit();
        return FrozenEvaluation.retain(evaluated);
    }

    pub fn inputValuesInto(self: *const Prepared, evaluation: anytype, destination: []circuit.M31) circuit.Error!void {
        const E = @TypeOf(evaluation.*);
        if (E != circuit.Evaluation and E != FrozenEvaluation)
            @compileError("PCS inputs require a mutable or privately owned PCS evaluation");
        try evaluation.validateAgainst(self);
        const values = if (E == FrozenEvaluation) evaluation.view().values else evaluation.values;
        try circuit.copyInputValues(self.view().bindings, values, destination);
    }
};

/// An accepted evaluation with no mutable aliases. It owns its node values and
/// the identity of the immutable graph that computed them, not a validation flag
/// over somebody else's mutable buffers. It may outlive that graph owner.
pub const FrozenEvaluation = struct {
    handle: *Handle,

    const Handle = opaque {};
    const Storage = struct { value: circuit.Evaluation };
    pub const View = struct {
        values: []const circuit.QM31,
        circuit_identity: circuit.digest.Digest,
    };

    fn retain(evaluated: circuit.Evaluation) circuit.Error!FrozenEvaluation {
        const backing = try evaluated.allocator.create(Storage);
        backing.* = .{ .value = evaluated };
        return .{ .handle = @ptrCast(backing) };
    }

    fn ownedEvaluation(self: *const FrozenEvaluation) *const circuit.Evaluation {
        const backing: *const Storage = @ptrCast(@alignCast(self.handle));
        return &backing.value;
    }

    pub fn deinit(self: *FrozenEvaluation) void {
        const backing: *Storage = @ptrCast(@alignCast(self.handle));
        const allocator = backing.value.allocator;
        backing.value.deinit();
        allocator.destroy(backing);
        self.* = undefined;
    }

    pub fn view(self: *const FrozenEvaluation) View {
        const owned = self.ownedEvaluation();
        return .{ .values = owned.values, .circuit_identity = owned.circuit_identity };
    }

    pub fn validateAgainst(self: *const FrozenEvaluation, prepared: *const Prepared) circuit.Error!void {
        const owned = self.ownedEvaluation();
        if (owned.values.len != prepared.graph().nodes.len or
            !std.mem.eql(u8, &owned.circuit_identity, &prepared.view().identity_digest))
            return error.CircuitIdentityMismatch;
    }

    /// Explicit full replay for a proof/audit boundary. Routine owner reads use
    /// validateAgainst because neither the graph nor these values can mutate.
    pub fn auditAgainst(self: *const FrozenEvaluation, prepared: *const Prepared) circuit.Error!void {
        try prepared.validate();
        try prepared.validateEvaluation(self.ownedEvaluation());
    }
};
