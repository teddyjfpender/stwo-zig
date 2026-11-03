//! Read-only constraint adapter for cold GPU lowering. Arithmetic, local GKR
//! binding and global relations retain their original native equation emitters.
//! This module never constructs a key, derives a challenge or accepts a proof.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
pub const Source = @import("source_authority.zig");
pub const MlePoint = @import("../../../logup_gkr/mle_point.zig");
pub const Binding = @import("binding.zig");
pub const Global = @import("global_cpu.zig");
const Main = A.main_only.authority;
const Table = @import("table_role.zig");
const Sponge = @import("sponge_projection.zig");
pub const GlobalWitness = @import("classic_witness.zig");

/// Raw native global tuple authority for resident witness construction. The
/// public sponge ID is a wire, not a host-specialized challenge or row value.
pub fn emitGlobalQueries(d: Source.Descriptor, comptime F: type, fixed: []const F, main: []const F, first_id: F, sink: anytype) !void {
    const geometry = try shape(d);
    if (fixed.len != geometry.fixed or main.len != geometry.main) return error.InvalidConstraintAuthorityShape;
    if (d.origin == .sponge) switch (d.origin.sponge) {
        inline else => |kind| Sponge.emitGlobalWithFirstFor(F, kind, fixed, main, first_id, sink),
    } else try Global.queriesFor(F, d.origin, fixed, main, sink);
}

pub fn hasLocal(d: Source.Descriptor) bool {
    return !(d.origin == .core and (d.origin.core == .initial or d.origin.core == .terminal));
}
pub fn shape(d: Source.Descriptor) !Main.Shape {
    if (d.cpu_compact_decode and !d.cpu_u8_pairs) return error.InvalidSourceAuthorityLayout;
    return if (hasLocal(d)) d.shape() else @import("boundary_role.zig").MAIN_SHAPE;
}
pub fn PublicFor(comptime C: type) type {
    return struct {
        cpu: A.word16_execution.types.InputsFor(C),
        rows: E.CountFor(C),
        nonempty: E.FlagFor(C),
        span: E.CallSpanFor(C),
    };
}
pub fn SharedFor(comptime C: type) type {
    return struct {
        ram: A.memory.closed_ram.types.RamChallengesFor(C),
        kio: A.crypto.keccak.equations.IoFor(C),
        wire: A.crypto.secp256k1.equations.WireFor(C),
    };
}
/// Unlike local source projection, MAIN arithmetic may need prior active,
/// address or remaining fields in every service family.
pub fn previousMain(d: Source.Descriptor, column: usize) bool {
    if (!hasLocal(d)) return column == 0;
    return switch (d.origin) {
        .core => |role| if (@import("role.zig").mainRoleFor(role, d.cpu_compact_decode)) |r| Main.previousMain(r, column) else |_| false,
        .bridge => |family| if (family == .keccak) A.crypto.keccak.word16_bridge.layout.previousMainFor(.bridge, column) else A.crypto.secp256k1.word16_bridge.layout.previousMainFor(.bridge, column),
        .bulk => |kind| A.crypto.bulk_memory.layout.previousMainFor(kind, column),
        .sponge => |kind| A.crypto.keccak_sponge.layout.previousMainFor(kind, column),
        .dword => A.memory.load_store_dword.layout.previousMain(column),
    };
}
pub fn emitMain(d: Source.Descriptor, comptime F: type, public: PublicFor(E.ConstFor(F)), fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    const geometry = try shape(d);
    if (fixed.len != geometry.fixed or main.len != geometry.main or previous.len != geometry.main) return error.InvalidConstraintAuthorityShape;
    if (!hasLocal(d)) {
        A.memory.load_store_v2.equations.emitBoundaryMainFor(F, fixed, main, previous, E.scalarFor(F, public.rows), try E.nonzeroFor(F, public.rows, public.nonempty), sink);
        return;
    }
    switch (d.origin) {
        .core => |role| {
            if (@import("role.zig").mainRoleFor(role, d.cpu_compact_decode)) |r| {
                const p: Main.PublicFor(E.ConstFor(F)) = switch (r) {
                    .cpu => .{ .cpu = public.cpu },
                    .cpu_compact => .{ .cpu_compact = public.cpu },
                    .alu => .{ .alu = {} },
                    .binary => .{ .binary = {} },
                    .shift => .{ .shift = {} },
                    .jalr => .{ .jalr = {} },
                    .ls => .{ .ls = .{ .count = public.rows, .nonempty = public.nonempty } },
                    .mul => .{ .mul = .{ .count = public.rows, .nonempty = public.nonempty } },
                    .div => .{ .div = .{ .count = public.rows, .nonempty = public.nonempty } },
                };
                try Main.emitFor(F, p, fixed, main, previous, sink);
            } else |_| {
                const kind = try Table.kindForRole(role);
                // Paired AND has two multiplicity columns and no MAIN residual.
                // Its alternate shape is already checked by d.shape() above.
                if (kind != .and_table) try Table.emitMainFor(kind, F, fixed, main, previous, sink);
            }
        },
        .bridge => |family| {
            if (family == .keccak) A.crypto.keccak.word16_bridge.equations.emitMainFor(F, fixed, main, previous, public.span, sink) else A.crypto.secp256k1.word16_bridge.equations.emitMainFor(F, Source.Types.bridgeKind(family), fixed, main, previous, public.span, sink);
        },
        .bulk => |kind| switch (kind) {
            inline else => |k| A.crypto.bulk_memory.equations.emitMainFor(F, k, fixed, main, previous, if (comptime E.isExternalLane(F)) .{ .rows = public.rows, .nonempty = public.nonempty orelse return error.MissingConstraintNonempty } else public.rows, sink),
        },
        .sponge => |kind| switch (kind) {
            inline else => |k| A.crypto.keccak_sponge.equations.emitMainFor(F, k, fixed, main, previous, if (comptime E.isExternalLane(F)) .{ .rows = public.rows, .nonempty = public.nonempty orelse return error.MissingConstraintNonempty } else public.rows, sink),
        },
        .dword => try @import("dword_projection.zig").emitMainFor(F, fixed, main, previous, public.rows, public.nonempty, sink),
    }
}
pub fn emitGlobal(d: Source.Descriptor, comptime F: type, fixed: []const F, main: []const F, source_public: []const F, shared: SharedFor(E.ConstFor(F)), claims: Global.ClaimsFor(E.ConstFor(F)), current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    const geometry = try shape(d);
    if (fixed.len != geometry.fixed or main.len != geometry.main or source_public.len != Source.Public.count) return error.InvalidConstraintAuthorityShape;
    if (d.origin == .sponge) switch (d.origin.sponge) {
        inline else => |kind| try Sponge.emitGlobalConstraintsWithFirstFor(F, kind, fixed, main, source_public[Source.Public.sponge_first_id], shared, claims, current, previous, sink),
    } else try Global.emitFor(F, d.origin, shared, claims, fixed, main, current, previous, sink);
}
