//! One concrete full64 execution transcript. Component totals are physical;
//! BINARY exposes two additive ledger fields authenticated by one combined
//! prefix. All fields are mixed before interaction commitment.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const X = A.word16_execution;
const B = A.word16_v1;
const Memory = @import("memory/statement.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
/// One canonical full-core schema: native degree3/split1, MUL200 interaction.
pub const SCHEMA: u32 = 2;
pub const T = @import("../rv64_distributed_v1/manifest.zig").T;
pub const Request = struct {
    cpu: X.types.Boundary,
    epoch: u16 = 1,
    division_requests: u32,
    multiplication_requests: u32,
    memory: Memory.Statement,
};
pub const Draw = struct {
    cpu: X.types.Challenges,
    and_: A.providers.tables.Challenges,
    shift_: A.providers.tables.Challenges,
    memory: A.memory.load_store_v2.types.Challenges,
};
pub const Claims = struct {
    cpu: Q,
    rom: Q,
    regboundary: Q,
    r16: Q,
    r8: Q,
    alu: B.alu_experiment.lookup.Claims,
    binary: B.binary_lookup.Claims,
    shift: B.shift_word_packed_experiment.lookup.Claims,
    and_table: Q,
    shift_table: Q,
    jalr: Q,
    division: Q,
    multiplication: Q,
    ls: A.memory.load_store_v2.types.Claims,
    initial: A.memory.load_store_v2.types.Claims,
    terminal: A.memory.load_store_v2.types.Claims,
    selectiontable: Q,
    pub fn values(self: Claims) [33]Q {
        var out: [33]Q = undefined;
        out[0..17].* = .{ self.cpu, self.rom, self.regboundary, self.r16, self.r8, self.alu.range16, self.alu.function, self.binary.and_, self.binary.function, self.shift.shift, self.shift.range16, self.shift.function, self.and_table, self.shift_table, self.jalr, self.division, self.multiplication };
        var at: usize = 17;
        for ([_]A.memory.load_store_v2.types.Claims{ self.ls, self.initial, self.terminal }) |c| {
            out[at..][0..5].* = .{ c.ram, c.owner, c.range16, c.range8, c.selection };
            at += 5;
        }
        out[32] = self.selectiontable;
        return out;
    }
    pub fn validate(self: Claims) !void {
        for (self.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalExecutionClaim;
        // These fields have no physical columns in boundary components.
        if (!self.initial.range8.isZero() or !self.terminal.range8.isZero()) return error.NonzeroOmittedBoundaryRangeClaim;
        if (!self.initial.owner.isZero() or !self.initial.selection.isZero() or !self.terminal.owner.isZero() or !self.terminal.selection.isZero()) return error.NonzeroOmittedMemoryClaim;
        var total = Q.zero();
        for (self.values()) |q| total = total.add(q);
        if (!total.isZero()) return error.UnclosedExecutionRelations;
    }
};
pub fn digest(channel: *T.P.Channel, d: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn mix(channel: *T.P.Channel, setup: *const @import("setup.zig").Setup, request: Request, image_identity: [32]u8) !void {
    return mixMaterials(channel, &setup.materials, request, image_identity);
}
/// Rootless immutable materials use the SAME transcript authority. Fixed roots
/// are committed by the complete caller roster, not by this helper.
/// An absent physical provider cannot contribute an arbitrary cancelling claim.
/// Count0 is receiver admission; actual query absence follows from CPU FUNCTION
/// closure with globally disjoint operation IDs, not from native census alone.
pub fn validateDivisionClass(geometry: @import("geometry.zig").Geometry, requests: u32, claim: Q) !void {
    if (geometry.omit_empty_division) {
        if (requests != 0) return error.OmittedDivisionRequests;
        if (!claim.isZero()) return error.OmittedDivisionClaim;
    }
}

pub fn mixMaterials(channel: *T.P.Channel, materials: *const @import("setup.zig").Materials, request: Request, image_identity: [32]u8) !void {
    try validateDivisionClass(materials.geometry, request.division_requests, Q.zero());
    T.P.config().mixInto(channel);
    channel.mixU32s(&.{ 0x52563634, 0x57463137, SCHEMA, 53, 40, 30, 19, 33, 1, 1, A.arithmetic.multiplication.degree3_layout.INTERACTION });
    digest(channel, X.features.identity());
    B.binary_lookup.encoding.mix(channel);
    B.alu_experiment.equations.encoding.mix(channel);
    B.shift_word_packed_experiment.lookup.encoding.mix(channel);
    @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.encoding.mix(channel);
    @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.boundary_encoding.mix(channel);
    digest(channel, materials.program.identity);
    digest(channel, image_identity);
    for (materials.shapes()) |shape| {
        channel.mixU32s(&.{ @intFromEnum(shape.role), shape.log, @intCast(shape.widths[0]), @intCast(shape.widths[1]), @intCast(shape.widths[2]) });
    }
    digest(channel, try A.word16_cpu.public.digest(request.cpu, materials.geometry.cpu_log));
    channel.mixU32s(&.{ request.epoch, request.division_requests, request.multiplication_requests });
    digest(channel, request.memory.digest());
}

pub fn draw(channel: *T.P.Channel) Draw {
    channel.mixU32s(&.{ 0x57465247, 6 });
    const register = relation(@FieldType(X.types.Challenges, "register"), channel);
    channel.mixU32s(&.{ 0x5746464e, 13 });
    const function = relation(@FieldType(X.types.Challenges, "function"), channel);
    channel.mixU32s(&.{ 0x5746524f, 30 });
    const rom = relation(@FieldType(X.types.Challenges, "rom"), channel);
    channel.mixU32s(&.{ 0x57464f57, 19 });
    const owner = relation(X.types.OwnerChallenges, channel);
    channel.mixU32s(&.{ 0x57465231, 16 });
    const range16 = @FieldType(X.types.Challenges, "range16"){ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x57465238, 1 });
    const range8 = @FieldType(X.types.Challenges, "range8"){ .offset = channel.drawSecureFelt(), .coefficient = Q.one() };
    channel.mixU32s(&.{ 0x5746414e, 3 });
    const and_ = A.providers.tables.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x57465348, 6, B.shift_word_packed_experiment.table.SEMANTIC_TAG });
    const shift_ = A.providers.tables.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x57465241, 14 });
    const ram = relation(@FieldType(A.memory.load_store_v2.types.Challenges, "ram"), channel);
    channel.mixU32s(&.{ 0x57465345, 5 });
    const selection = relation(@FieldType(A.memory.load_store_v2.types.Challenges, "selection"), channel);
    return .{ .cpu = .{ .register = register, .function = function, .rom = rom, .owner = owner, .range16 = range16, .range8 = range8 }, .and_ = and_, .shift_ = shift_, .memory = .{ .ram = ram, .owner = owner, .range16 = .{ .offset = range16.offset, .coefficient = range16.coefficient }, .range8 = .{ .offset = range8.offset, .coefficient = range8.coefficient }, .selection = selection } };
}
fn relation(comptime R: type, channel: *T.P.Channel) R {
    var r: R = undefined;
    r.offset = channel.drawSecureFelt();
    for (&r.coefficients) |*c| c.* = channel.drawSecureFelt();
    return r;
}
pub fn legacy(ch: X.types.Challenges) A.word16_cpu.lookup.Challenges {
    return .{ .register = .{ .offset = ch.register.offset, .coefficients = ch.register.coefficients }, .function = .{ .offset = ch.function.offset, .coefficients = ch.function.coefficients }, .rom = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .range16 = .{ .offset = ch.range16.offset, .coefficient = ch.range16.coefficient }, .range8 = .{ .offset = ch.range8.offset, .coefficient = ch.range8.coefficient } };
}
