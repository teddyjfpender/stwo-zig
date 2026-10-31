//! Finite concrete component roster. Construct handles only AFTER this owner
//! reaches its final address; adapters borrow these immutable component fields.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
const W = air.word16_cpu;
const Mat = @import("cpu_materials.zig");
const Sources = @import("cpu_sources.zig");
const Draw = @import("cpu_protocol.zig").Draw;
pub const Components = struct {
    materials: *const Mat.Materials,
    local: [5]W.component.Component,
    binary: [2]air.word16_v1.binary_component.Component = undefined,
    has_binary: bool,
    pub fn init(materials: *const Mat.Materials, public: W.public.Public, challenges: Draw, claims: Sources.Claims, scalar_reference: bool) !Components {
        try claims.validate(materials.geometry.mode);
        var result: Components = undefined;
        result.materials = materials;
        result.has_binary = materials.geometry.mode == .local_binary;
        const roles = [_]Mat.Role{ .cpu, .rom, .boundary, .range16, .range8 };
        for (roles, &result.local) |role, *component| {
            const shape = try materials.shape(role);
            const kind: W.component.Kind = switch (role) {
                .cpu => .cpu,
                .rom => .rom,
                .boundary => .boundary,
                .range16 => .range16,
                .range8 => .range8,
                else => unreachable,
            };
            const claim = switch (role) {
                .cpu => core.fields.qm31.QM31.zero(),
                .rom => claims.rom,
                .boundary => claims.boundary,
                .range16 => claims.range16,
                .range8 => claims.range8,
                else => unreachable,
            };
            component.* = .{ .kind = kind, .log_size = shape.log, .offsets = shape.offsets, .public = public, .cpu_claims = claims.cpu, .claim = claim, .challenges = challenges.cpu, .scalar_reference = scalar_reference };
        }
        if (result.has_binary) {
            const binary = try materials.shape(.binary);
            const table = try materials.shape(.and_table);
            result.binary = .{
                .{ .kind = .binary, .log_size = binary.log, .offsets = binary.offsets, .challenges = .{ .and_ = challenges.and_, .function = challenges.cpu.function }, .claims = claims.binary },
                .{ .kind = .and_table, .log_size = table.log, .offsets = table.offsets, .challenges = .{ .and_ = challenges.and_, .function = challenges.cpu.function }, .claims = .{ .and_ = claims.and_table, .function = core.fields.qm31.QM31.zero() } },
            };
        }
        return result;
    }
    const Handle = union(enum) {
        thin: *const W.component.Component,
        binary: *const air.word16_v1.binary_component.Component,
        fn prover(self: Handle) engine.air.component_prover.ComponentProver {
            return switch (self) {
                .thin => |value| value.asProverComponent(),
                .binary => |value| value.asProverComponent(),
            };
        }
        fn verifier(self: Handle) core.air.components.Component {
            return switch (self) {
                .thin => |value| value.asVerifierComponent(),
                .binary => |value| value.asVerifierComponent(),
            };
        }
    };
    fn select(self: *const Components, role: Mat.Role) !Handle {
        return switch (role) {
            .cpu => .{ .thin = &self.local[0] },
            .rom => .{ .thin = &self.local[1] },
            .boundary => .{ .thin = &self.local[2] },
            .range16 => .{ .thin = &self.local[3] },
            .range8 => .{ .thin = &self.local[4] },
            .binary => if (self.has_binary) .{ .binary = &self.binary[0] } else error.OmittedThinCpuRole,
            .and_table => if (self.has_binary) .{ .binary = &self.binary[1] } else error.OmittedThinCpuRole,
        };
    }
    // The engine concatenates main/interaction masks in COMPONENT order.
    // Use the SAME physical roster as columns/logs; fixed indices alone cannot
    // repair a different component sequence for the non-preprocessed trees.
    pub fn provers(self: *const Components, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        const shapes = self.materials.shapes();
        const result = try a.alloc(engine.air.component_prover.ComponentProver, shapes.len);
        errdefer a.free(result);
        for (shapes.slice(), result) |shape, *value| value.* = (try self.select(shape.role)).prover();
        return result;
    }
    pub fn verifiers(self: *const Components, a: std.mem.Allocator) ![]core.air.components.Component {
        const shapes = self.materials.shapes();
        const result = try a.alloc(core.air.components.Component, shapes.len);
        errdefer a.free(result);
        for (shapes.slice(), result) |shape, *value| value.* = (try self.select(shape.role)).verifier();
        return result;
    }
};
