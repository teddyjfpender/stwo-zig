//! The in-circuit claim closure of one RV64 Ethereum batch: the receiver's
//! `A.validateClaimsView` over wires. Omitted rosters force their claims to
//! zero, the private RAM graph and policy sums close, and the CPU/RAM state
//! effect equals the boundary target of the public registers under the
//! state challenges. Challenge and claim wires are read from the flat
//! draw-order and mix-order slices the transcript walkers produce.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");
const A = @import("../rv64_authenticated_execution.zig");
const walk = @import("transcript_walk.zig");
const public_wires = @import("public_wires.zig");

const rv = A.rv;
const T = A.T;
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const builder = circuit.builder;
const Context = builder.Context(Q);
const Var = builder.Var;
const Error = builder.context.Error;
const Cell = rv.memory.cell_air;
const PA = rv.memory.policy_air;

/// Where each relation's draws and each claim group start in the flat
/// slices, derived by replaying the walkers with counting sinks.
pub const Layout = struct {
    state: usize,
    ram_internal: ?usize,
    total_draws: usize,
    cpu: usize,
    keccak: usize,
    secp: ?usize,
    mul: ?usize,
    ram_tables: ?usize,
    ram_provider: ?usize,
    ram_policy: ?usize,
    total_claims: usize,

    pub fn init(view: A.VerificationView, public: A.Public) !Layout {
        var draws = DrawCounter{};
        try walk.walkDraws(&draws, view);
        var claims = ClaimCounter{};
        try walk.walkClaims(&claims, view, public, zeroClaims(view));
        var layout = Layout{ .state = 0, .ram_internal = draws.ram_internal, .total_draws = draws.count, .cpu = 0, .keccak = 5, .secp = null, .mul = null, .ram_tables = null, .ram_provider = null, .ram_policy = null, .total_claims = claims.count };
        var at: usize = 12;
        if (public.cpu.execution_profile != .keccak_service_v1) {
            layout.secp = at;
            at += 7;
        }
        if (public.cpu.arithmetic_policy == .division_multiplication_services_v3) {
            layout.mul = at;
            at += 2;
        }
        if (view.has_ram) {
            layout.ram_tables = at;
            for (T.TABLES) |table| at += T.sumCount(table);
            layout.ram_provider = at;
            at += 2;
            layout.ram_policy = at;
            at += 1;
        }
        if (at != claims.count) return error.ClaimLayoutMismatch;
        return layout;
    }
};

const DrawCounter = struct {
    count: usize = 0,
    ram_internal: ?usize = null,
    pending_ram: bool = false,
    pub fn tag(self: *DrawCounter, values: []const u32) !void {
        if (values.len == 3 and values[0] == 0x52414d32) self.pending_ram = true;
    }
    pub fn draws(self: *DrawCounter, n: usize) !void {
        if (self.pending_ram) {
            self.ram_internal = self.count;
            self.pending_ram = false;
        }
        self.count += n;
    }
    pub fn drawBulk(self: *DrawCounter, n: usize) !void {
        self.count += n;
    }
};
const ClaimCounter = struct {
    count: usize = 0,
    pub fn tag(_: *ClaimCounter, _: []const u32) !void {}
    pub fn claims(self: *ClaimCounter, values: []const Q) !void {
        self.count += values.len;
    }
};
fn zeroClaims(view: A.VerificationView) A.Claims {
    return .{ .cpu = .{ .cpu = .{ .state = Q.zero(), .rom = Q.zero(), .bytes = Q.zero(), .bitwise = Q.zero(), .shifts = Q.zero() }, .division = Q.zero(), .header = Q.zero(), .permutation = Q.zero(), .chi = Q.zero(), .xor5 = Q.zero(), .bridge = Q.zero(), .bytes = Q.zero() }, .ram = if (view.has_ram) .{ .callers = .{}, .provider = @splat(Q.zero()), .policy = Q.zero(), .bytes = Q.zero() } else null };
}

/// The public wires the closure reads.
pub const Inputs = struct {
    /// pc (initial, final), then 32 initial and 32 final registers.
    u64s: []const public_wires.U64Wires,
    /// before, then after RAM root.
    digests: []const [9]public_wires.Word,
    clocks: []const public_wires.Word,
    draws: []const Var,
    claims: []const Var,
};

/// Emits the closure constraints. `depth` is the RAM geometry depth.
pub fn enforce(ctx: *Context, layout: Layout, view: A.VerificationView, public: A.Public, in: Inputs) Error!void {
    if (in.draws.len != layout.total_draws or in.claims.len != layout.total_claims or in.u64s.len != 66 or in.clocks.len != 32) return error.OutOfMemory;
    const zero = ctx.zero();
    const cpu = public.cpu;
    // Omitted rosters: their claims are zero (`validateEncodingView`).
    if (!view.cpu.base.has_and) try ctx.eq(in.claims[layout.cpu + 3], zero);
    if (!view.cpu.base.has_shift) try ctx.eq(in.claims[layout.cpu + 4], zero);
    if (cpu.division_roster == .none) try ctx.eq(in.claims[layout.keccak], zero);
    if (cpu.roster == .none) for (1..6) |k| try ctx.eq(in.claims[layout.keccak + k], zero);
    if (layout.mul) |mul| if (cpu.multiplication_roster == .none) {
        try ctx.eq(in.claims[mul], zero);
        try ctx.eq(in.claims[mul + 1], zero);
    };
    if (layout.secp) |secp| {
        if (cpu.secp.add.roster == .none and cpu.secp.double.roster == .none) try ctx.eq(in.claims[secp], zero);
        for (cpu.secp.groups(), 0..) |g, k| if (g.roster == .none) for (0..3) |j| try ctx.eq(in.claims[secp + 1 + 3 * k + j], zero);
    }
    // `effect(claims)`: cpu.state + cpu.bytes (rom/bitwise/shifts cancel
    // inside their providers), then every service and RAM-side claim.
    var effect = try ctx.add(in.claims[layout.cpu], in.claims[layout.cpu + 2]);
    for (1..7) |k| effect = try ctx.add(effect, in.claims[layout.keccak + k]);
    if (layout.mul) |mul| {
        effect = try ctx.add(effect, in.claims[mul]);
        effect = try ctx.add(effect, in.claims[mul + 1]);
    }
    if (layout.secp) |secp| for (0..7) |k| {
        effect = try ctx.add(effect, in.claims[secp + k]);
    };
    if (layout.ram_tables) |tables| {
        const debts = try closeRam(ctx, layout, public, in, tables);
        effect = try ctx.add(effect, debts[0]);
        effect = try ctx.add(effect, debts[1]);
    }
    const target = try expectedState(ctx, in);
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose closure: effect {any} target {any}", .{ ctx.get(effect).toM31Array(), ctx.get(target).toM31Array() });
    try ctx.eq(effect, target);
}

/// `I.closeWithoutByte` over wires; returns the state and byte debts.
fn closeRam(ctx: *Context, layout: Layout, public: A.Public, in: Inputs, tables: usize) Error![2]Var {
    const zero = ctx.zero();
    const provider = in.claims[layout.ram_provider.?..][0..2];
    const policy_claim = in.claims[layout.ram_policy.?];
    var starts: [T.TABLES.len]usize = undefined;
    var at = tables;
    for (T.TABLES, &starts) |table, *start| {
        start.* = at;
        at += T.sumCount(table);
    }
    const chunk = in.claims[starts[@intFromEnum(T.Table.chunk)]..];
    const node = in.claims[starts[@intFromEnum(T.Table.node)]..];
    const poseidon_sum = try ctx.add(try ctx.add(provider[1], chunk[0]), try ctx.add(node[0], node[1]));
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose closure: provider0 {any} poseidon sum {any}", .{ ctx.get(provider[0]).toM31Array(), ctx.get(poseidon_sum).toM31Array() });
    try ctx.eq(provider[0], zero);
    try ctx.eq(poseidon_sum, zero);
    var bytes = zero;
    var policy_sum = policy_claim;
    var ram_sum = zero;
    var state_sum = zero;
    for (T.TABLES, starts) |table, start| {
        for (0..T.sumCount(table)) |group| {
            const claim = in.claims[start + group];
            const is_byte = switch (table) {
                .chunk => false,
                .node => group >= 4,
                .common_cells, .edge_cells => group < 7,
                .leaf => group < 5,
                .side => group < 3,
                .common_permits, .edge_permits => group < PA.BYTE_SUMS,
            };
            if (is_byte) {
                bytes = try ctx.add(bytes, claim);
                continue;
            }
            switch (table) {
                .chunk => if (group != 0) {
                    ram_sum = try ctx.add(ram_sum, claim);
                },
                .node => if (group >= 2) {
                    ram_sum = try ctx.add(ram_sum, claim);
                },
                .common_cells, .edge_cells => if (group == Cell.STATE_SUM) {
                    state_sum = try ctx.add(state_sum, claim);
                } else {
                    ram_sum = try ctx.add(ram_sum, claim);
                },
                .common_permits, .edge_permits => if (group == PA.POLICY_SUM) {
                    policy_sum = try ctx.add(policy_sum, claim);
                } else {
                    ram_sum = try ctx.add(ram_sum, claim);
                },
                .leaf, .side => ram_sum = try ctx.add(ram_sum, claim),
            }
        }
    }
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose closure: policy sum {any}", .{ctx.get(policy_sum).toM31Array()});
    try ctx.eq(policy_sum, zero);
    const challenge = in.draws[layout.ram_internal.?..][0 .. 1 + rv.memory.internal_relations.ARITY];
    const depth = try ctx.constant(Q.fromBase(M31.fromCanonical(public.geometry.depth())));
    for (in.digests[0..2], 0..) |digest, epoch| {
        // `Prepared.node(epoch, height, 0, value)`: offsets[node] = offset,
        // and `combine` pairs field j with coefficients[1 + j], which is
        // draw 2 + j (draw 0 is the offset, draw 1 is coefficients[0]).
        var den = challenge[0];
        if (epoch == 1) den = try ctx.sub(den, challenge[2 + 0]);
        den = try ctx.sub(den, try ctx.mul(depth, challenge[2 + 1]));
        for (digest, 0..) |word, k| den = try ctx.sub(den, try ctx.mul(try word.m31(ctx), challenge[2 + 9 + k]));
        if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose closure: node den[{d}] {any} c1 {any} c2 {any} c10 {any} depth {any} word8 {any}", .{ epoch, ctx.get(den).toM31Array(), ctx.get(challenge[1]).toM31Array(), ctx.get(challenge[2]).toM31Array(), ctx.get(challenge[10]).toM31Array(), ctx.get(depth).toM31Array(), ctx.get(try digest[8].m31(ctx)).toM31Array() });
        ram_sum = try ctx.add(ram_sum, try ctx.inv(den));
    }
    if (std.process.hasEnvVarConstant("RV64_RECURSION_DIAGNOSE")) std.log.info("diagnose closure: ram sum {any} state debt {any} byte debt {any}", .{ ctx.get(ram_sum).toM31Array(), ctx.get(state_sum).toM31Array(), ctx.get(bytes).toM31Array() });
    try ctx.eq(ram_sum, zero);
    return .{ state_sum, bytes };
}

/// `Statement.expectedStateWithProfile` over wires: the register boundary
/// tuples under the state challenges (`relations.boundaryTuple`).
fn expectedState(ctx: *Context, in: Inputs) Error!Var {
    const ch = in.draws[0..][0 .. 1 + rv.relations.ARITY];
    const offset = ch[0];
    const c = ch[1..];
    var target = ctx.zero();
    for (1..32) |reg| {
        const reg_const = try ctx.constant(Q.fromBase(M31.fromCanonical(@intCast(reg))));
        // Common part: offset + c1 * reg + c18 + c19 (space 0, address byte 0 = reg).
        var common = try ctx.add(offset, try ctx.mul(c[1], reg_const));
        common = try ctx.add(common, try ctx.add(c[18], c[19]));
        const initial = try valueTerms(ctx, common, c, in.u64s[2 + reg].bytes, null);
        const final = try valueTerms(ctx, common, c, in.u64s[34 + reg].bytes, try in.clocks[reg].m31(ctx));
        target = try ctx.add(target, try ctx.inv(initial));
        target = try ctx.sub(target, try ctx.inv(final));
    }
    return target;
}

fn valueTerms(ctx: *Context, common: Var, c: []const Var, bytes: [8]Var, clock: ?Var) Error!Var {
    var den = common;
    if (clock) |value| den = try ctx.add(den, try ctx.mul(c[9], value));
    for (bytes, 0..) |byte, i| den = try ctx.add(den, try ctx.mul(c[10 + i], byte));
    return den;
}
