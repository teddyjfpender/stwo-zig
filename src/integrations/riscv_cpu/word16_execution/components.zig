//! One concrete physical roster, selected ONLY by immutable Materials.shapes.
//! Handles borrow this owner; construct them after it reaches its final address.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.word16_execution;
const B = A.word16_v1;
const W = A.word16_cpu;
const Mat = @import("setup.zig");
const P = @import("protocol.zig");
const AB = @import("arithmetic_bus.zig");
const Q = core.fields.qm31.QM31;
pub const COMPOSITION_LOG_SPLIT: u8 = 1;
pub const Components = struct {
    materials: *const Mat.Materials,
    cpu: X.component.Component,
    rom: X.rom_component.Component,
    boundary: W.component.Component,
    alu: B.alu_experiment.component.Component,
    binary: B.binary_component.Component,
    shift: B.shift_word_packed_experiment.component.Component,
    jalr: X.jalr_component.Component,
    division: A.arithmetic.division.degree3_component.Component,
    multiplication: A.arithmetic.multiplication.degree3_component.Component,
    shift_table: B.shift_word_packed_experiment.table_component.Component,
    and_table: B.binary_component.Component,
    range16: W.component.Component,
    range8: W.component.Component,
    ls: A.memory.load_store_v2.component.Component,
    ls_tail: A.memory.load_store_v2.component.Component,
    initial: A.memory.load_store_v2.component.Component,
    terminal: A.memory.load_store_v2.component.Component,
    selection: A.memory.load_store_v2.component.Component,

    pub fn init(materials: *const Mat.Materials, request: P.Request, ch: P.Draw, claims: P.Claims) !Components {
        try P.validateDivisionClass(materials.geometry, request.division_requests, claims.division);
        try P.validateLsTailClass(materials.geometry, request.memory.ls_count, claims.ls_tail);
        const ls_counts = try materials.geometry.lsCounts(request.memory.ls_count);
        if (!claims.initial.owner.eql(Q.zero()) or !claims.initial.selection.eql(Q.zero()) or !claims.terminal.owner.eql(Q.zero()) or !claims.terminal.selection.eql(Q.zero())) return error.UnconstrainedMemoryClaim;
        if (!ch.cpu.range8.coefficient.eql(Q.one())) return error.InvalidArithmeticByteChallenge;
        var result: Components = undefined;
        result.materials = materials;
        const old_ch = W.lookup.Challenges{ .register = .{ .offset = ch.cpu.register.offset, .coefficients = ch.cpu.register.coefficients }, .function = .{ .offset = ch.cpu.function.offset, .coefficients = ch.cpu.function.coefficients }, .rom = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .range16 = .{ .offset = ch.cpu.range16.offset, .coefficient = ch.cpu.range16.coefficient }, .range8 = .{ .offset = ch.cpu.range8.offset, .coefficient = ch.cpu.range8.coefficient } };
        for (materials.shapes()) |shape| {
            if (!shape.present()) continue;
            switch (shape.role) {
                .cpu => result.cpu = .{ .log_size = shape.log, .offsets = shape.offsets, .public = try X.types.inputs(request.cpu, request.epoch, shape.log), .challenges = ch.cpu, .claim = claims.cpu },
                .rom => result.rom = .{ .log_size = shape.log, .offsets = shape.offsets, .challenges = ch.cpu.rom, .claim = claims.rom },
                .boundary, .range16, .range8 => {
                    const component = W.component.Component{ .kind = switch (shape.role) {
                        .boundary => .boundary,
                        .range16 => .range16,
                        .range8 => .range8,
                        else => unreachable,
                    }, .log_size = shape.log, .offsets = shape.offsets, .public = request.cpu, .cpu_claims = .{ .register = Q.zero(), .function = Q.zero(), .rom = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() }, .claim = switch (shape.role) {
                        .boundary => claims.regboundary,
                        .range16 => claims.r16,
                        .range8 => claims.r8,
                        else => unreachable,
                    }, .challenges = old_ch };
                    switch (shape.role) {
                        .boundary => result.boundary = component,
                        .range16 => result.range16 = component,
                        .range8 => result.range8 = component,
                        else => unreachable,
                    }
                },
                .alu => result.alu = .{ .log_size = shape.log, .offsets = shape.offsets, .challenges = .{ .function = old_ch.function, .range16 = old_ch.range16 }, .claims = claims.alu },
                .binary, .and_table => {
                    const component = B.binary_component.Component{ .kind = if (shape.role == .binary) .binary else .and_table, .log_size = shape.log, .offsets = shape.offsets, .challenges = .{ .function = old_ch.function, .and_ = ch.and_ }, .claims = if (shape.role == .binary) claims.binary else .{ .and_ = claims.and_table, .function = Q.zero() } };
                    if (shape.role == .binary) result.binary = component else result.and_table = component;
                },
                .shift => result.shift = .{ .log_size = shape.log, .offsets = shape.offsets, .challenges = .{ .function = old_ch.function, .range16 = old_ch.range16, .shift = ch.shift_ }, .claims = claims.shift },
                .jalr => result.jalr = .{ .log_size = shape.log, .offsets = shape.offsets, .challenges = ch.cpu.function, .claim = claims.jalr },
                .division => result.division = .{ .base = .{ .log_size = shape.log, .count = request.division_requests, .fixed_offset = shape.offsets[0], .main_offset = shape.offsets[1], .interaction_offset = shape.offsets[2], .challenges = AB.division(ch.cpu.function), .claim = claims.division } },
                .multiplication => result.multiplication = .{ .log_size = shape.log, .count = request.multiplication_requests, .fixed_offset = shape.offsets[0], .main_offset = shape.offsets[1], .interaction_offset = shape.offsets[2], .challenges = AB.multiplication(ch.cpu.function), .claim = claims.multiplication, .byte_alpha = ch.cpu.range8.offset },
                .shift_table => result.shift_table = .{ .offsets = shape.offsets, .prepared = B.shift_word_packed_experiment.table.Prepared.init(ch.shift_), .claim = claims.shift_table },
                .ls, .ls_tail, .initial, .terminal, .selection => {
                    const component = A.memory.load_store_v2.component.Component{ .kind = switch (shape.role) {
                        .ls, .ls_tail => .ls,
                        .initial => .initial,
                        .terminal => .terminal,
                        .selection => .selection,
                        else => unreachable,
                    }, .log_size = shape.log, .offsets = shape.offsets, .rows = switch (shape.role) {
                        .ls => ls_counts.head,
                        .ls_tail => ls_counts.tail,
                        .initial => @intCast(request.memory.initial.len),
                        .terminal => @intCast(request.memory.terminal.len),
                        .selection => 0,
                        else => unreachable,
                    }, .claims = switch (shape.role) {
                        .ls => claims.ls,
                        .ls_tail => claims.ls_tail,
                        .initial => claims.initial,
                        .terminal => claims.terminal,
                        .selection => .{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero(), .selection = claims.selectiontable },
                        else => unreachable,
                    }, .challenges = ch.memory };
                    switch (shape.role) {
                        .ls => result.ls = component,
                        .ls_tail => result.ls_tail = component,
                        .initial => result.initial = component,
                        .terminal => result.terminal = component,
                        .selection => result.selection = component,
                        else => unreachable,
                    }
                },
            }
        }
        return result;
    }
    /// Native degree-three components share split1 without coordinate lifts.
    pub fn provers(self: *const Components, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        return self.proversImpl(false, a);
    }
    pub fn verifiers(self: *const Components, a: std.mem.Allocator) ![]core.air.components.Component {
        return self.verifiersImpl(false, a);
    }
    /// A concrete join with a degree-four component requires actual weighted
    /// quotient extension for EVERY degree-three role, including DIV and MUL.
    pub fn proversForDegree4Join(self: *const Components, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        return self.proversImpl(true, a);
    }
    pub fn verifiersForDegree4Join(self: *const Components, a: std.mem.Allocator) ![]core.air.components.Component {
        return self.verifiersImpl(true, a);
    }
    fn proversImpl(self: *const Components, comptime degree4_join: bool, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        const result = try a.alloc(engine.air.component_prover.ComponentProver, Mat.G.componentCount(&self.materials.shapes()));
        errdefer a.free(result);
        var at: usize = 0;
        inline for (comptime std.enums.values(Mat.Role)) |role| {
            if (self.materials.shape(role).present()) {
                const native = @field(self, @tagName(role)).asProverComponent();
                result[at] = if (degree4_join) try native.withCompositionGeometryOverrideV1(.{ .composition_log_split = 2, .max_constraint_log_degree_bound_delta = 1 }) else native;
                at += 1;
            }
        }
        return result;
    }
    fn verifiersImpl(self: *const Components, comptime degree4_join: bool, a: std.mem.Allocator) ![]core.air.components.Component {
        const result = try a.alloc(core.air.components.Component, Mat.G.componentCount(&self.materials.shapes()));
        errdefer a.free(result);
        var at: usize = 0;
        inline for (comptime std.enums.values(Mat.Role)) |role| {
            if (self.materials.shape(role).present()) {
                const native = @field(self, @tagName(role)).asVerifierComponent();
                result[at] = if (degree4_join) try native.withCompositionGeometryOverrideV1(.{ .composition_log_split = 2, .max_constraint_log_degree_bound_delta = 1 }) else native;
                at += 1;
            }
        }
        return result;
    }
};
