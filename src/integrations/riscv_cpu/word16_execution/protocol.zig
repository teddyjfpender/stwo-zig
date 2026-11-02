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
/// Schema7 retains the narrow public boundary and adds LS32 joint-write range inheritance.
pub const SCHEMA: u32 = 7;
pub const CLAIM_LS_TAIL: usize = 33;
pub const CLAIM_ALU_TAIL = CLAIM_LS_TAIL + 5;
pub const CLAIM_BINARY_TAIL = CLAIM_ALU_TAIL + 2;
pub const CLAIM_SHIFT_TAIL = CLAIM_BINARY_TAIL + 2;
pub const CLAIM_COUNT: usize = CLAIM_SHIFT_TAIL + 3;
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
    ls_tail: A.memory.load_store_v2.types.Claims = zeroMemoryClaim(),
    alu_tail: B.alu_experiment.lookup.Claims = .{ .range16 = Q.zero(), .function = Q.zero() },
    binary_tail: B.binary_lookup.Claims = .{ .and_ = Q.zero(), .function = Q.zero() },
    shift_tail: B.shift_word_packed_experiment.lookup.Claims = .{ .shift = Q.zero(), .range16 = Q.zero(), .function = Q.zero() },
    pub fn values(self: Claims) [CLAIM_COUNT]Q {
        var out: [CLAIM_COUNT]Q = undefined;
        out[0..17].* = .{ self.cpu, self.rom, self.regboundary, self.r16, self.r8, self.alu.range16, self.alu.function, self.binary.and_, self.binary.function, self.shift.shift, self.shift.range16, self.shift.function, self.and_table, self.shift_table, self.jalr, self.division, self.multiplication };
        var at: usize = 17;
        for ([_]A.memory.load_store_v2.types.Claims{ self.ls, self.initial, self.terminal }) |c| {
            out[at..][0..5].* = .{ c.ram, c.owner, c.range16, c.range8, c.selection };
            at += 5;
        }
        out[32] = self.selectiontable;
        out[CLAIM_LS_TAIL..][0..5].* = .{ self.ls_tail.ram, self.ls_tail.owner, self.ls_tail.range16, self.ls_tail.range8, self.ls_tail.selection };
        out[CLAIM_ALU_TAIL..][0..2].* = .{ self.alu_tail.range16, self.alu_tail.function };
        out[CLAIM_BINARY_TAIL..][0..2].* = .{ self.binary_tail.and_, self.binary_tail.function };
        out[CLAIM_SHIFT_TAIL..][0..3].* = .{ self.shift_tail.shift, self.shift_tail.range16, self.shift_tail.function };
        return out;
    }
    pub fn validate(self: Claims) !void {
        for (self.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalExecutionClaim;
        // These fields have no physical columns in boundary components.
        if (!self.initial.range16.isZero() or !self.terminal.range16.isZero() or !self.initial.range8.isZero() or !self.terminal.range8.isZero()) return error.NonzeroOmittedBoundaryRangeClaim;
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

/// Unit MUL truth rows include two unsigned product obligations per DIV.
/// This bound is independent of native instruction census hints.
pub fn validateArithmeticRequests(geometry: @import("geometry.zig").Geometry, request: Request) !void {
    try geometry.validate();
    if (request.division_requests > request.cpu.steps or @as(u64, request.multiplication_requests) > 2 * @as(u64, request.cpu.steps) or
        request.division_requests > (@as(u32, 1) << @intCast(geometry.division_log)) or
        request.multiplication_requests > (@as(u32, 1) << @intCast(geometry.multiplication_log))) return error.ArithmeticRequestCapacity;
}

pub fn mixMaterials(channel: *T.P.Channel, materials: *const @import("setup.zig").Materials, request: Request, image_identity: [32]u8) !void {
    try validateArithmeticRequests(materials.geometry, request);
    try validateDivisionClass(materials.geometry, request.division_requests, Q.zero());
    try validateLsTailClass(materials.geometry, request.memory.ls_count, zeroMemoryClaim());
    try materials.suite.validate();
    materials.suite.config().mixInto(channel);
    channel.mixU32s(&.{ 0x52563634, 0x57463137, SCHEMA, X.layout.main.COUNT, X.layout.inter.COUNT, X.layout.rom.COUNT, 19, CLAIM_COUNT, 1, 1, A.arithmetic.multiplication.degree3_layout.INTERACTION, A.arithmetic.division.word16_product.layout.MAIN, A.arithmetic.division.word16_product.layout.INTERACTION });
    digest(channel, X.features.identity());
    if (materials.geometry.cpu_fused_tail) {
        channel.mixU32s(&.{ 0x46555345, X.layout.fused.COUNT, X.equations.FUSED_CONSTRAINTS });
        digest(channel, X.features.fusedTailIdentity());
    }
    if (materials.geometry.wideClock()) {
        channel.mixU32s(&.{ 0x57494445, materials.geometry.cpu_log, X.layout.WIDE_GAP_SCALE, X.layout.ramStride(materials.geometry.cpu_log) });
        digest(channel, X.features.wideClockIdentity());
    }
    if (materials.geometry.cpu_u8_pairs) {
        channel.mixU32s(&.{ 0x50414952, X.layout.pairs.COUNT, X.equations.PAIR_CONSTRAINTS, A.providers.tables.N_PAIR_CONSTRAINTS });
        digest(channel, X.features.pairIdentity());
    }
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

/// Closed/genesis draw retains its historical transcript byte for byte.
pub fn draw(channel: *T.P.Channel) Draw {
    return drawInternal(channel, null);
}
pub const SHARED_RAM_DRAW_TAG: u32 = 0x57535244;
pub const SHARED_RAM_DRAW_REVISION: u32 = 1;
const RamChallenges = @FieldType(A.memory.load_store_v2.types.Challenges, "ram");
/// Global authorities derive RAM from their complete checked Manifest before
/// entering this core helper. Worker/request APIs never accept a loose alpha.
pub fn drawWithSharedRam(channel: *T.P.Channel, ram: RamChallenges) Draw {
    return drawInternal(channel, ram);
}
fn drawInternal(channel: *T.P.Channel, shared_ram: ?RamChallenges) Draw {
    if (shared_ram != null) channel.mixU32s(&.{ SHARED_RAM_DRAW_TAG, SHARED_RAM_DRAW_REVISION, 14 });
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
    const ram = shared_ram orelse local: {
        channel.mixU32s(&.{ 0x57465241, 14 });
        break :local relation(RamChallenges, channel);
    };
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

pub fn zeroMemoryClaim() A.memory.load_store_v2.types.Claims {
    return .{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero(), .selection = Q.zero() };
}
pub fn ramClaim(claims: Claims) Q {
    return claims.ls.ram.add(claims.ls_tail.ram).add(claims.initial.ram).add(claims.terminal.ram);
}
pub fn validateLsTailClass(geometry: @import("geometry.zig").Geometry, total: u32, claim: A.memory.load_store_v2.types.Claims) !void {
    _ = try geometry.lsCounts(total);
    if (geometry.ls_tail_log == null) {
        const c = [_]Q{ claim.ram, claim.owner, claim.range16, claim.range8, claim.selection };
        for (c) |q| if (!q.isZero()) return error.NonzeroOmittedLsTailClaim;
    }
}

/// Absence is physical. Present pure-fact tails need no public fact count:
/// functional truth membership is supplied by the complete FUNCTION closure.
pub fn validateProviderTailClaims(geometry: @import("geometry.zig").Geometry, claims: Claims) !void {
    if (geometry.alu_tail_log == null and (!claims.alu_tail.range16.isZero() or !claims.alu_tail.function.isZero())) return error.NonzeroOmittedAluTailClaim;
    if (geometry.binary_tail_log == null and (!claims.binary_tail.and_.isZero() or !claims.binary_tail.function.isZero())) return error.NonzeroOmittedBinaryTailClaim;
    if (geometry.shift_tail_log == null and (!claims.shift_tail.shift.isZero() or !claims.shift_tail.range16.isZero() or !claims.shift_tail.function.isZero())) return error.NonzeroOmittedShiftTailClaim;
}
