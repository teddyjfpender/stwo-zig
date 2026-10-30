//! Native direct equations only. Relation constraints are owned exactly once
//! by the independently certified partition schedule in the same STARK.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Semantic = @import("../air/semantic_component.zig").SemanticComponent;
const Direct = @import("block_v6_direct_component_v1.zig").Component;
pub const Owner = struct {
    a: std.mem.Allocator,
    frame: ?@import("block_v5_native_frame_component_v1.zig").Component = null,
    semantics: []Semantic,
    direct: []Direct,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32) !*Owner {
        try shape.validateBlake3ExecutionWithExternal(external);
        const frame = @import("block_v5_native_frame_v1.zig");
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.a = a;
        self.frame = null;
        self.semantics = try a.alloc(Semantic, shape.n_components);
        errdefer a.free(self.semantics);
        self.direct = try a.alloc(Direct, if (frame.required(shape)) 1 else shape.n_infra);
        errdefer a.free(self.direct);
        self.provers = try a.alloc(engine.air.component_prover.ComponentProver, self.semantics.len + self.direct.len);
        errdefer a.free(self.provers);
        self.verifiers = try a.alloc(core.air.components.Component, self.provers.len);
        errdefer a.free(self.verifiers);
        var offset: usize = 0;
        for (shape.component_descs[0..shape.n_components], self.semantics, 0..) |desc, *component, i| {
            component.* = if (shape.localZeroCustody()) try Semantic.initLocalZero(desc.family, desc.log_size, 2 * i + 1, offset) else try Semantic.init(desc.family, desc.log_size, 2 * i + 1, offset);
            self.provers[i] = component.asProverComponent();
            self.verifiers[i] = component.asVerifierComponent();
            offset += desc.n_columns;
        }
        for (shape.infra_descs[0..shape.n_infra], self.direct[0..shape.n_infra], 0..) |desc, *component, i| {
            if (desc.kind != .clock_update or desc.n_columns != @import("../air/clock_update_interaction.zig").N_MAIN_COLUMNS) return error.InvalidPartitionedInfrastructure;
            component.* = .{ .log_size = desc.log_size, .active_column = 2 * (shape.n_components + i) + 1, .main_offset = offset };
            self.provers[shape.n_components + i] = component.asProverComponent();
            self.verifiers[shape.n_components + i] = component.asVerifierComponent();
            offset += desc.n_columns;
        }
        if (frame.required(shape)) {
            self.frame = .{ .expected = try frame.expected(shape, external) };
            self.provers[0] = self.frame.?.asProverComponent();
            self.verifiers[0] = self.frame.?.asVerifierComponent();
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        a.free(self.verifiers);
        a.free(self.provers);
        a.free(self.direct);
        a.free(self.semantics);
        a.destroy(self);
    }
};
