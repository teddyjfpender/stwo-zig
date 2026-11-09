//! Read-only tuple authority shared by CPU metadata and cold device codegen.
//! No witness, challenge, proof, fixed key or producer acceptance is constructed.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const Frame = @import("frame.zig");
pub const Fractions = @import("fractions.zig");
pub const Challenges = @import("challenges.zig");
pub const RoleId = @import("../../../word16_execution/geometry.zig").Role;
pub const Types = @import("../types.zig");
pub const RowSink = @import("inputs.zig").RowSink;
pub const BaseSink = struct {
    row: *RowSink,
    pub fn emit(self: *@This(), relation: Fractions.Relation, tuple: anytype, weight: @import("stwo_core").fields.m31.M31) void {
        self.row.emitBase(relation, tuple, weight);
    }
};
const Main = A.main_only.authority;
const Role = @import("role.zig");
const Table = @import("table_role.zig");
const Roster = @import("roster.zig");
/// Explicit public-value namespace. These are statement inputs, never extra
/// committed trace columns. All elements are canonical base-field words.
pub const Public = struct {
    pub const epoch = 0;
    pub const sponge_first_id = 1;
    pub const initial_pc = 2;
    pub const initial_registers = 3;
    pub const final_registers = initial_registers + 32 * 4;
    pub const register_clocks = final_registers + 32 * 4;
    pub const count = register_clocks + 32;
};
pub const Descriptor = struct {
    origin: Frame.Origin,
    cpu_u8_pairs: bool = false,
    cpu_compact_decode: bool = false,
    pub fn validate(self: Descriptor) !void {
        if (self.cpu_compact_decode and !self.cpu_u8_pairs) return error.InvalidSourceAuthorityLayout;
        if (self.origin == .core and (self.origin.core == .initial or self.origin.core == .terminal)) return error.NoLocalGkrSource;
    }
    fn arithmetic(self: Descriptor) ?Main.Role {
        if (self.origin != .core) return null;
        if (self.origin.core == .cpu and self.cpu_compact_decode) return .cpu_compact;
        return Role.mainRole(self.origin.core) catch null;
    }
    pub fn shape(self: Descriptor) !Main.Shape {
        try self.validate();
        if (self.arithmetic()) |role| return Main.shape(role);
        return switch (self.origin) {
            .core => |role| Table.mainShapeForMode(try Table.kindForRole(role), self.cpu_u8_pairs),
            .tower => @import("op_tower_projection.zig").MAIN_SHAPE,
            .bridge => |family| @import("service_role.zig").mainShapeFor(family),
            .bulk => |kind| @import("bulk_role.zig").mainShapeFor(kind),
            .sponge => |kind| @import("sponge_role.zig").mainShapeFor(kind),
            .dword => |kind| @import("dword_role.zig").mainShapeFor(kind),
        };
    }
    pub fn terms(self: Descriptor) !u32 {
        try self.validate();
        return switch (self.origin) {
            .core => |role| switch (role) {
                .cpu => Fractions.cpuTerms(self.cpu_u8_pairs),
                .and_table => Fractions.andTableTerms(self.cpu_u8_pairs),
                else => Roster.terms(role),
            },
            .tower => @import("op_tower_projection.zig").LOCAL_TERMS,
            .bridge => |family| Roster.bridgeTerms(family),
            .bulk => |kind| @import("bulk_projection.zig").localTerms(kind),
            .sponge => |kind| @import("sponge_projection.zig").localTerms(kind),
            .dword => @import("dword_projection.zig").LOCAL_TERMS,
        };
    }
    pub fn previous(self: Descriptor, column: usize) bool {
        return if (self.arithmetic()) |role| Main.previousMain(role, column) else false;
    }
    /// Physical MAIN/FIXED rows use circle storage. Previous rows are supplied
    /// by the native signed circle offset law, including compact CPU's PC carry.
    pub fn emit(self: Descriptor, comptime F: type, fixed: []const F, main: []const F, previous_main: []const F, public: []const F, sink: anytype) !void {
        const s = try self.shape();
        if (fixed.len != s.fixed or main.len != s.main or previous_main.len != s.main or public.len != Public.count) return error.InvalidSourceAuthorityShape;
        if (self.arithmetic()) |role| {
            if (role == .cpu_compact) return Fractions.cpuCompactFor(F, fixed, main, previous_main, public[Public.epoch], public[Public.initial_pc], sink);
            if (role == .cpu) return Fractions.cpuModeFor(F, fixed, main, public[Public.epoch], self.cpu_u8_pairs, sink);
            return Role.emitLocalFor(F, role, fixed, main, public[Public.epoch], sink);
        }
        switch (self.origin) {
            .core => |role| switch (role) {
                .and_table => Fractions.andTableModeFor(F, fixed, main, self.cpu_u8_pairs, sink),
                .boundary => {
                    const Authority = A.word16_cpu.boundary;
                    var words: [32][4]F = undefined;
                    var clocks: [32]F = undefined;
                    for (0..32) |r| {
                        @memcpy(&words[r], public[Public.initial_registers + 4 * r ..][0..4]);
                        clocks[r] = public[Public.register_clocks + r];
                    }
                    sink.emit(.register, Authority.tupleFromWordsFor(F, fixed, &words, &clocks, false), F.one().neg());
                    for (0..32) |r| @memcpy(&words[r], public[Public.final_registers + 4 * r ..][0..4]);
                    sink.emit(.register, Authority.tupleFromWordsFor(F, fixed, &words, &clocks, true), F.one());
                },
                else => Table.emitLocalFor(try Table.kindForRole(role), null, F, fixed, main, sink),
            },
            .tower => @import("op_tower_projection.zig").emitLocalFor(F, fixed, main, sink),
            .bridge => |family| {
                if (family == .keccak) Fractions.keccakBridgeFor(F, fixed, main, sink) else Fractions.secpBridgeFor(F, Types.bridgeKind(family), fixed, main, sink);
            },
            .bulk => |kind| switch (kind) {
                inline else => |k| @import("bulk_projection.zig").emitLocalFor(F, k, fixed, main, sink),
            },
            .sponge => |kind| switch (kind) {
                inline else => |k| @import("sponge_projection.zig").emitLocalWithFirstFor(F, k, fixed, main, public[Public.sponge_first_id], sink),
            },
            .dword => @import("dword_projection.zig").emitLocalFor(F, main, sink),
        }
    }
};
