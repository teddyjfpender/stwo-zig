//! All handles follow the SAME physical shape roster as source columns/logs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const I = air.word16_index_control;
const W = air.word16_cpu;
const B = air.word16_v1;
const M = @import("materials.zig");
const S = @import("sources.zig");
pub const Components = struct {
    materials: *const M.Materials,
    index: [2]I.component.Component,
    local: [3]W.component.Component,
    alu: B.alu_experiment.component.Component,
    binary: [3]B.binary_component.Component,
    pub fn init(materials: *const M.Materials, public: I.equations.Public, ch: S.Challenges, claims: S.Claims, roster: *const B.binary_component.ExpectedRoster) !Components {
        try claims.validate();
        var result: Components = undefined;
        result.materials = materials;
        for ([_]M.Role{ .cpu, .rom }, &result.index) |role, *component| {
            const shape = materials.shape(role);
            component.* = .{ .kind = if (role == .cpu) .cpu else .rom, .log_size = shape.log, .offsets = shape.offsets, .public = public, .cpu_claims = claims.base.cpu, .rom_claims = .{ claims.base.rom, claims.map }, .challenges = ch.data, .rom_challenges = ch.rom, .map_challenges = ch.map };
        }
        for ([_]M.Role{ .boundary, .range16, .range8 }, &result.local) |role, *component| {
            const shape = materials.shape(role);
            component.* = .{ .kind = switch (role) {
                .boundary => .boundary,
                .range16 => .range16,
                .range8 => .range8,
                else => unreachable,
            }, .log_size = shape.log, .offsets = shape.offsets, .public = public.state, .cpu_claims = claims.base.cpu, .claim = switch (role) {
                .boundary => claims.base.boundary,
                .range16 => claims.base.range16,
                .range8 => claims.base.range8,
                else => unreachable,
            }, .challenges = ch.data };
        }
        const a_shape = materials.shape(.alu);
        result.alu = .{ .log_size = a_shape.log, .offsets = a_shape.offsets, .challenges = .{ .range16 = ch.data.range16, .function = ch.data.function }, .claims = claims.alu };
        for ([_]M.Role{ .binary, .and_table, .map_queries }, &result.binary) |role, *component| {
            const shape = materials.shape(role);
            component.* = .{ .kind = switch (role) {
                .binary => .binary,
                .and_table => .and_table,
                .map_queries => .expected_main,
                else => unreachable,
            }, .log_size = shape.log, .offsets = shape.offsets, .challenges = .{ .and_ = ch.and_, .function = if (role == .map_queries) S.mapFunction(ch.map) else ch.data.function }, .claims = switch (role) {
                .binary => claims.base.binary,
                .and_table => .{ .and_ = claims.base.and_table, .function = air.evaluation.Q.zero() },
                .map_queries => .{ .and_ = air.evaluation.Q.zero(), .function = claims.known_map },
                else => unreachable,
            }, .expected_roster = if (role == .map_queries) roster else null };
        }
        return result;
    }
    const Handle = union(enum) {
        index: *const I.component.Component,
        local: *const W.component.Component,
        alu: *const B.alu_experiment.component.Component,
        binary: *const B.binary_component.Component,
        fn prover(self: Handle) engine.air.component_prover.ComponentProver {
            return switch (self) {
                inline else => |value| value.asProverComponent(),
            };
        }
        fn verifier(self: Handle) core.air.components.Component {
            return switch (self) {
                inline else => |value| value.asVerifierComponent(),
            };
        }
    };
    fn select(self: *const Components, role: M.Role) Handle {
        return switch (role) {
            .cpu => .{ .index = &self.index[0] },
            .rom => .{ .index = &self.index[1] },
            .boundary => .{ .local = &self.local[0] },
            .range16 => .{ .local = &self.local[1] },
            .range8 => .{ .local = &self.local[2] },
            .alu => .{ .alu = &self.alu },
            .binary => .{ .binary = &self.binary[0] },
            .and_table => .{ .binary = &self.binary[1] },
            .map_queries => .{ .binary = &self.binary[2] },
        };
    }
    pub fn provers(self: *const Components, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        const out = try a.alloc(engine.air.component_prover.ComponentProver, 9);
        for (self.materials.shapes(), out) |shape, *value| value.* = self.select(shape.role).prover();
        return out;
    }
    pub fn verifiers(self: *const Components, a: std.mem.Allocator) ![]core.air.components.Component {
        const out = try a.alloc(core.air.components.Component, 9);
        for (self.materials.shapes(), out) |shape, *value| value.* = self.select(shape.role).verifier();
        return out;
    }
};
