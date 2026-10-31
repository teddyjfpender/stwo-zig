//! Concrete private RAM STARK assembly. No public per-cell/hash-state ledger.
//! Standalone receipts leave an explicit CPU-state debt OPEN; execution
//! admission requires these same components/challenges in the CPU/K PCS proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const R = rv.memory;
const T = R.private_trace;
const I = R.private_interaction;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = rv.protocol;
const Column = engine.pcs.ColumnEvaluation;
const Engine = engine.engine.ProverEngine(@import("stwo_cpu_backend").CpuBackend, P.Hasher, P.MerkleChannel, P.Channel);
const Relations = frontend.testing.component_proof.relations.Relations;
const PC = frontend.testing.component_proof.universal_component.Component;
const universal = frontend.testing.component_proof.universal_air;
const postcard = @import("interop_postcard");
const Byte = rv.range.provider;
const physical = rv.witness.physical;
const CA = R.chunk_air;
const Cell = R.cell_air;
const Leaf = R.leaf_air;
const Node = R.node_air;
const Side = R.side_air;
const Permit = R.permit_air;
const PR = R.policy_provider;
const Terminal = R.terminal_air;
const MAX_LOG: u32 = 22;
const MAX_BYTES = 128 * 1024 * 1024;
const Suite = enum { diagnostic, receipt };
fn config(suite: Suite) core.pcs.PcsConfig {
    return if (suite == .receipt) P.config() else .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 10, .fold_step = 1 } };
}
fn magic(suite: Suite) u32 {
    return if (suite == .receipt) 0x52505432 else 0x52505431;
}
pub const Statement = struct {
    geometry: R.values.Geometry,
    before: R.values.Digest,
    after: R.values.Digest,
    policy: *const R.policy.Policy,
    fn validate(self: Statement) !void {
        try self.policy.validateImmutableExecution();
        for ([_]R.values.Digest{ self.before, self.after }) |digest| for (digest) |value| if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
    }
};
/// Counts affect only proof geometry; root/cell/state constraints authenticate
/// semantics. Decode and bound ALL counts before any wide witness allocation.
pub const Counts = struct {
    hashes: u32,
    common_chunks: u32,
    edge_chunks: u32,
    nodes: u32,
    sides: u32,
    edge_permits: u32,
    pub fn fromTrace(trace: *const T.Trace) Counts {
        return fromShapes(trace.shapes);
    }
    pub fn fromShapes(shape: T.Shapes) Counts {
        return .{ .hashes = shape.chunk.hashes, .common_chunks = shape.common_cells.chunks, .edge_chunks = shape.edge_cells.chunks, .nodes = shape.node.nodes, .sides = shape.side.sides, .edge_permits = shape.edge_permits.certificates };
    }
    fn words(self: Counts) [6]u32 {
        return .{ self.hashes, self.common_chunks, self.edge_chunks, self.nodes, self.sides, self.edge_permits };
    }
    pub fn shapes(self: Counts, geometry: R.values.Geometry) !T.Shapes {
        const leaves: u64 = @as(u64, self.common_chunks) + self.edge_chunks;
        if (leaves == 0 or leaves > R.batch.MAX_OPENINGS or self.hashes < leaves or self.hashes > 2 * leaves or self.nodes < geometry.depth() or @as(u64, self.nodes) + self.sides + leaves > 1 << 24 or self.edge_permits > @as(u64, self.edge_chunks) * geometry.cells()) return error.InvalidPrivateRamProofShape;
        const span: R.policy.Span = if (geometry == .chunk512) .chunk512 else .page4096;
        const result = T.Shapes{
            .chunk = .{ .geometry = geometry, .hashes = self.hashes, .log_size = try boundedLog(@as(u64, self.hashes) * (geometry.permutations() + 1)) },
            .common_cells = .{ .geometry = geometry, .chunks = self.common_chunks, .log_size = try boundedLog(@as(u64, self.common_chunks) * geometry.cells()), .policy_mode = .chunk },
            .edge_cells = .{ .geometry = geometry, .chunks = self.edge_chunks, .log_size = try boundedLog(@as(u64, self.edge_chunks) * geometry.cells()), .policy_mode = .word },
            .leaf = .{ .geometry = geometry, .leaves = @intCast(leaves), .log_size = try boundedLog(leaves) },
            .node = .{ .nodes = self.nodes, .log_size = try boundedLog(self.nodes) },
            .side = .{ .geometry = geometry, .sides = self.sides, .log_size = try boundedLog(self.sides) },
            .common_permits = .{ .span = span, .certificates = self.common_chunks, .log_size = try boundedLog(self.common_chunks) },
            .edge_permits = .{ .span = .word8, .certificates = self.edge_permits, .log_size = try boundedLog(self.edge_permits) },
            .provider_log = try boundedLog(@as(u64, self.hashes) * geometry.permutations() + @as(u64, self.nodes) * 4),
        };
        try result.validate();
        return result;
    }
};
fn boundedLog(size: u64) !u32 {
    const log: u32 = @intCast(@max(4, std.math.log2_int_ceil(u64, @max(1, size))));
    if (log > MAX_LOG) return error.PrivateRamProofResourceLimit;
    return log;
}
pub const Offsets = struct { fixed: usize, main: usize, interaction: usize };
pub fn offsets(table: T.Table) Offsets {
    var result = Offsets{ .fixed = 0, .main = 0, .interaction = 0 };
    for (T.TABLES) |prior| {
        if (prior == table) return result;
        result.fixed += T.fixedWidth(prior);
        result.main += T.mainWidth(prior);
        result.interaction += 4 * T.sumCount(prior);
    }
    unreachable;
}
fn offsetsAt(table: T.Table, base: Offsets) Offsets {
    const local = offsets(table);
    return .{ .fixed = base.fixed + local.fixed, .main = base.main + local.main, .interaction = base.interaction + local.interaction };
}
const CALLER_FIXED = 37;
const CALLER_MAIN = 408;
const CALLER_INTERACTION = 292;
const N_FIXED = CALLER_FIXED + 1 + PR.FIXED + Byte.N_FIXED;
const N_MAIN = CALLER_MAIN + universal.N_MAIN_COLUMNS + 1 + 1;
const N_INTERACTION = CALLER_INTERACTION + 8 + PR.INTERACTION + Byte.N_INTERACTION;
pub const N_FIXED_WITHOUT_BYTE = N_FIXED - Byte.N_FIXED;
pub const N_MAIN_WITHOUT_BYTE = N_MAIN - Byte.N_MAIN;
pub const N_INTERACTION_WITHOUT_BYTE = N_INTERACTION - Byte.N_INTERACTION;
const CLAIM_COUNT = CALLER_INTERACTION / 4 + 2 + 1 + 1;
const HEADER = 4 + 6 * 4 + CLAIM_COUNT * 16;
fn mix(channel: *P.Channel, public: Statement, counts: Counts, suite: Suite) void {
    config(suite).mixInto(channel);
    channel.mixU32s(&.{ 0x52505256, R.values.VERSION, public.geometry.logBytes(), MAX_LOG });
    channel.mixU32s(&counts.words());
    channel.mixU32s(&public.before);
    channel.mixU32s(&public.after);
    // This identity is receiver-derived from known ELF/ABI mappings. It is not
    // a producer-advertised hash accepted as an independent authority.
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, public.policy.identity[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
fn appendColumns(result: []Column, data: []M, log: u32) void {
    const size = @as(usize, 1) << @intCast(log);
    std.debug.assert(result.len * size == data.len);
    for (result, 0..) |*column, i| column.* = .{ .log_size = log, .values = data[i * size ..][0..size] };
}
const Fixed = struct {
    allocator: std.mem.Allocator,
    owned: [10][]M,
    columns: []Column,
    fn init(a: std.mem.Allocator, shapes: T.Shapes, rom: *const PR.Trace, bytes: ?*const Byte.Trace, terminal: ?Terminal.Spec) !Fixed {
        var owned: [10][]M = @splat(&.{});
        var used: usize = 0;
        errdefer for (owned[0..used]) |data| a.free(data);
        const columns = try a.alloc(Column, @as(usize, if (bytes != null) N_FIXED else N_FIXED_WITHOUT_BYTE) + @as(usize, if (terminal != null) Terminal.SELECTORS else 0));
        errdefer a.free(columns);
        var cursor: usize = 0;
        for (T.TABLES) |table| {
            const log = T.tableLog(shapes, table);
            const size = @as(usize, 1) << @intCast(log);
            const width = T.fixedWidth(table);
            const data = try a.alloc(M, width * size);
            owned[used] = data;
            used += 1;
            var row: [8]M = undefined;
            for (0..size) |i| {
                T.fixedAt(shapes, table, i, row[0..width]);
                for (row[0..width], 0..) |value, col| data[col * size + physical(i, log)] = value;
            }
            appendColumns(columns[cursor..][0..width], data, log);
            cursor += width;
        }
        std.debug.assert(cursor == CALLER_FIXED);
        const first = try a.alloc(M, @as(usize, 1) << @intCast(shapes.provider_log));
        owned[8] = first;
        used += 1;
        @memset(first, M.zero());
        first[0] = M.one();
        appendColumns(columns[cursor..][0..1], first, shapes.provider_log);
        cursor += 1;
        appendColumns(columns[cursor..][0..PR.FIXED], rom.fixed, rom.shape.log_size);
        cursor += PR.FIXED;
        if (bytes) |table| {
            appendColumns(columns[cursor..][0..Byte.N_FIXED], table.fixed, 8);
            cursor += Byte.N_FIXED;
        }
        if (terminal) |spec| {
            const shape = Terminal.Shape{ .spec = spec, .log_size = shapes.common_cells.log_size };
            try shape.validate();
            const selectors = try a.alloc(M, Terminal.SELECTORS * shape.size());
            owned[9] = selectors;
            used += 1;
            for (0..shape.size()) |i| {
                const row = shape.fixedAt(i);
                for (row[Cell.FIXED..], 0..) |value, col| selectors[col * shape.size() + physical(i, shape.log_size)] = value;
            }
            appendColumns(columns[cursor..], selectors, shape.log_size);
        }
        return .{ .allocator = a, .owned = owned, .columns = columns };
    }
    fn deinit(self: *Fixed) void {
        for (self.owned) |data| self.allocator.free(data);
        self.allocator.free(self.columns);
    }
};
fn mainColumns(a: std.mem.Allocator, source: Source, rom: *PR.Trace, bytes: *Byte.Trace) ![]Column {
    const result = try a.alloc(Column, N_MAIN);
    var at: usize = 0;
    for (T.TABLES) |table| {
        const width = T.mainWidth(table);
        appendColumns(result[at..][0..width], @constCast(source.rows.mains[@intFromEnum(table)]), T.tableLog(source.rows.shapes, table));
        at += width;
    }
    std.debug.assert(at == CALLER_MAIN);
    appendColumns(result[at..][0..universal.N_MAIN_COLUMNS], source.provider_main, source.rows.shapes.provider_log);
    at += universal.N_MAIN_COLUMNS;
    appendColumns(result[at..][0..1], rom.main, rom.shape.log_size);
    at += 1;
    appendColumns(result[at..], bytes.main, 8);
    return result;
}
fn interactionColumns(a: std.mem.Allocator, shapes: T.Shapes, inter: *I.Interaction, rom: *PR.Trace, bytes: *Byte.Trace) ![]Column {
    const result = try a.alloc(Column, N_INTERACTION);
    var at: usize = 0;
    for (T.TABLES) |table| {
        const width = 4 * T.sumCount(table);
        appendColumns(result[at..][0..width], inter.tables[@intFromEnum(table)], T.tableLog(shapes, table));
        at += width;
    }
    std.debug.assert(at == CALLER_INTERACTION);
    appendColumns(result[at..][0..8], inter.provider.columns, shapes.provider_log);
    at += 8;
    appendColumns(result[at..][0..PR.INTERACTION], rom.interaction, rom.shape.log_size);
    at += PR.INTERACTION;
    appendColumns(result[at..], bytes.interaction, 8);
    return result;
}
/// Immutable preprocessing owner for the RAM-only roster. Its columns exclude
/// BYTE: the containing proof commits exactly one global byte table.
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    fixed: Fixed,
    policy: PR.Trace,
    pub fn init(a: std.mem.Allocator, shapes: T.Shapes, mappings: *const R.policy.Policy) !Prepared {
        try mappings.validateImmutableExecution();
        try shapes.validate();
        const zero = try a.alloc(u64, mappings.grants.len);
        defer a.free(zero);
        @memset(zero, 0);
        var policy_trace = try PR.Trace.init(a, mappings, zero);
        errdefer policy_trace.deinit();
        const f = try Fixed.init(a, shapes, &policy_trace, null, null);
        return .{ .allocator = a, .fixed = f, .policy = policy_trace };
    }
    pub fn columns(self: *const Prepared) []const Column {
        return self.fixed.columns;
    }
    pub fn deinit(self: *Prepared) void {
        self.fixed.deinit();
        self.policy.deinit();
        self.* = undefined;
    }
};
/// Borrowed views; owner lifetime must exceed the containing PCS commit.
pub fn mainColumnsWithoutByte(a: std.mem.Allocator, source: Source, rom: *PR.Trace) ![]Column {
    try source.rows.validate();
    const result = try a.alloc(Column, N_MAIN_WITHOUT_BYTE);
    var at: usize = 0;
    for (T.TABLES) |table| {
        const width = T.mainWidth(table);
        appendColumns(result[at..][0..width], @constCast(source.rows.mains[@intFromEnum(table)]), T.tableLog(source.rows.shapes, table));
        at += width;
    }
    appendColumns(result[at..][0..universal.N_MAIN_COLUMNS], source.provider_main, source.rows.shapes.provider_log);
    at += universal.N_MAIN_COLUMNS;
    appendColumns(result[at..], rom.main, rom.shape.log_size);
    return result;
}
pub fn interactionColumnsWithoutByte(a: std.mem.Allocator, shapes: T.Shapes, inter: *I.Interaction, rom: *PR.Trace) ![]Column {
    const result = try a.alloc(Column, N_INTERACTION_WITHOUT_BYTE);
    var at: usize = 0;
    for (T.TABLES) |table| {
        const width = 4 * T.sumCount(table);
        appendColumns(result[at..][0..width], inter.tables[@intFromEnum(table)], T.tableLog(shapes, table));
        at += width;
    }
    appendColumns(result[at..][0..8], inter.provider.columns, shapes.provider_log);
    at += 8;
    appendColumns(result[at..], rom.interaction, rom.shape.log_size);
    return result;
}
pub const Claims = struct {
    callers: I.Claims,
    provider: [2]Q,
    policy: Q,
    bytes: Q,
    pub fn validateWithoutByte(self: *const Claims) !void {
        try self.callers.validate();
        if (!self.bytes.isZero()) return error.UnexpectedPrivateRamByteProviderClaim;
    }
    pub fn mixWithoutByte(self: *const Claims, channel: *P.Channel) void {
        self.callers.mix(channel);
        channel.mixFelts(&self.provider);
        channel.mixFelts(&.{self.policy});
    }
    fn mix(self: *const Claims, channel: *P.Channel) void {
        self.callers.mix(channel);
        channel.mixFelts(&self.provider);
        channel.mixFelts(&.{ self.policy, self.bytes });
    }
};
/// Concrete borrowed component roster for future SAME-PCS CPU/K integration.
/// All offsets are explicit; no frontend type factory or backend selection API.
pub const Components = struct {
    terminal: ?R.terminal_component.Component = null,
    chunk: R.chunk_component.Component,
    common_cells: R.cell_component.Component,
    edge_cells: R.cell_component.Component,
    leaf: R.leaf_component.Component,
    node: R.node_component.Component,
    side: R.side_component.Component,
    common_permits: R.permit_component.Component,
    edge_permits: R.permit_component.Component,
    permutations: PC,
    policy: R.policy_component.Component,
    bytes: rv.providers.byte.Component,
    fn init(shapes: T.Shapes, mappings: *const R.policy.Policy, ch: *const I.Challenges, claims: *const Claims) !Components {
        return initInternal(shapes, mappings, ch, claims, .{ .fixed = 0, .main = 0, .interaction = 0 }, null);
    }
    pub fn initAt(shapes: T.Shapes, mappings: *const R.policy.Policy, ch: *const I.Challenges, claims: *const Claims, base: Offsets) !Components {
        try claims.validateWithoutByte();
        return initInternal(shapes, mappings, ch, claims, base, null);
    }
    fn initInternal(shapes: T.Shapes, mappings: *const R.policy.Policy, ch: *const I.Challenges, claims: *const Claims, base: Offsets, terminal: ?Terminal.Spec) !Components {
        try claims.callers.validate();
        const c = offsetsAt(.chunk, base);
        const a = offsetsAt(.common_cells, base);
        const b = offsetsAt(.edge_cells, base);
        const l = offsetsAt(.leaf, base);
        const n = offsetsAt(.node, base);
        const s = offsetsAt(.side, base);
        const p = offsetsAt(.common_permits, base);
        const e = offsetsAt(.edge_permits, base);
        const rom_shape = PR.Shape{ .grants = mappings.grants, .log_size = try boundedLog(mappings.grants.len) };
        return .{
            .terminal = if (terminal) |spec| try R.terminal_component.Component.init(.{ .spec = spec, .log_size = shapes.common_cells.log_size }, .{ .fixed = a.fixed, .selectors = base.fixed + N_FIXED, .main = a.main, .interaction = a.interaction }, .{ .ram = ch.ram, .state = ch.state, .bytes = ch.bytes }, claims.callers.slice(.common_cells)[0..Cell.SUMS].*) else null,
            .chunk = try R.chunk_component.Component.init(shapes.chunk, .{ .fixed = c.fixed, .main = c.main, .interaction = c.interaction }, .{ .ram = ch.ram, .io = ch.permutations.poseidon2_io }, claims.callers.slice(.chunk)[0..CA.SUMS].*),
            .common_cells = try R.cell_component.Component.init(shapes.common_cells, .{ .fixed = a.fixed, .main = a.main, .interaction = a.interaction }, .{ .ram = ch.ram, .state = ch.state, .bytes = ch.bytes }, claims.callers.slice(.common_cells)[0..Cell.SUMS].*),
            .edge_cells = try R.cell_component.Component.init(shapes.edge_cells, .{ .fixed = b.fixed, .main = b.main, .interaction = b.interaction }, .{ .ram = ch.ram, .state = ch.state, .bytes = ch.bytes }, claims.callers.slice(.edge_cells)[0..Cell.SUMS].*),
            .leaf = try R.leaf_component.Component.init(shapes.leaf, .{ .fixed = l.fixed, .main = l.main, .interaction = l.interaction }, .{ .ram = ch.ram, .bytes = ch.bytes }, claims.callers.slice(.leaf)[0..Leaf.SUMS].*),
            .node = try R.node_component.Component.init(shapes.node, .{ .fixed = n.fixed, .main = n.main, .interaction = n.interaction }, .{ .ram = ch.ram, .bytes = ch.bytes, .io = ch.permutations.poseidon2_io }, claims.callers.slice(.node)[0..Node.SUMS].*),
            .side = try R.side_component.Component.init(shapes.side, .{ .fixed = s.fixed, .main = s.main, .interaction = s.interaction }, .{ .ram = ch.ram, .bytes = ch.bytes }, claims.callers.slice(.side)[0..Side.SUMS].*),
            .common_permits = try R.permit_component.Component.init(shapes.common_permits, .{ .fixed = p.fixed, .main = p.main, .interaction = p.interaction }, .{ .bytes = ch.bytes, .policy = ch.policy, .permit = ch.ram.permitChallenge() }, claims.callers.slice(.common_permits)[0..Permit.SUMS].*),
            .edge_permits = try R.permit_component.Component.init(shapes.edge_permits, .{ .fixed = e.fixed, .main = e.main, .interaction = e.interaction }, .{ .bytes = ch.bytes, .policy = ch.policy, .permit = ch.ram.permitChallenge() }, claims.callers.slice(.edge_permits)[0..Permit.SUMS].*),
            .permutations = .{ .log_size = shapes.provider_log, .n_rows = @intCast(@as(usize, shapes.chunk.hashes) * shapes.chunk.geometry.permutations() + @as(usize, shapes.node.nodes) * 4), .is_first_col_idx = base.fixed + CALLER_FIXED, .is_active_col_idx = base.fixed + CALLER_FIXED, .main_col_offset = base.main + CALLER_MAIN, .interaction_col_offset = base.interaction + CALLER_INTERACTION, .relations = &ch.permutations, .claims = claims.provider, .enable_simd_domain = true },
            .policy = try R.policy_component.Component.init(rom_shape, .{ .fixed = base.fixed + CALLER_FIXED + 1, .main = base.main + CALLER_MAIN + universal.N_MAIN_COLUMNS, .interaction = base.interaction + CALLER_INTERACTION + 8 }, .{ .policy = ch.policy }, .{claims.policy}),
            .bytes = .{ .fixed_offset = base.fixed + CALLER_FIXED + 1 + PR.FIXED, .main_offset = base.main + CALLER_MAIN + universal.N_MAIN_COLUMNS + 1, .interaction_offset = base.interaction + CALLER_INTERACTION + 8 + PR.INTERACTION, .alpha = ch.bytes, .claim = claims.bytes },
        };
    }
    pub fn proversWithoutByte(self: *const Components) ![10]engine.air.component_prover.ComponentProver {
        const all = try self.provers();
        return all[0..10].*;
    }
    pub fn verifiersWithoutByte(self: *const Components) ![10]core.air.components.Component {
        const all = try self.verifiers();
        return all[0..10].*;
    }
    fn provers(self: *const Components) ![11]engine.air.component_prover.ComponentProver {
        return .{ self.chunk.asProverComponent(), if (self.terminal) |*value| value.asProverComponent() else self.common_cells.asProverComponent(), self.edge_cells.asProverComponent(), self.leaf.asProverComponent(), self.node.asProverComponent(), self.side.asProverComponent(), self.common_permits.asProverComponent(), self.edge_permits.asProverComponent(), try self.permutations.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 }), self.policy.asProverComponent(), self.bytes.asProverComponent() };
    }
    fn verifiers(self: *const Components) ![11]core.air.components.Component {
        return .{ self.chunk.asVerifierComponent(), if (self.terminal) |*value| value.asVerifierComponent() else self.common_cells.asVerifierComponent(), self.edge_cells.asVerifierComponent(), self.leaf.asVerifierComponent(), self.node.asVerifierComponent(), self.side.asVerifierComponent(), self.common_permits.asVerifierComponent(), self.edge_permits.asVerifierComponent(), try self.permutations.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 }), self.policy.asVerifierComponent(), self.bytes.asVerifierComponent() };
    }
};
/// Qualification-only open debt. Never sum receipts from independently drawn
/// transcripts: actual execution closure uses one joined CPU/K/RAM proof.
pub const boundByteMass = I.boundByteMass;
pub const boundInternalMass = I.boundInternalMass;
pub const OpenState = struct {
    claim: Q,
    challenge: rv.relations.Challenges,
    pub const cpu_closed = false;
};
pub fn proveOpenState(a: std.mem.Allocator, public: Statement, trace: *T.Trace) ![]u8 {
    return proveSuite(a, public, trace, .diagnostic);
}
pub fn proveReceiptOpenState(a: std.mem.Allocator, public: Statement, trace: *T.Trace) ![]u8 {
    return proveSuite(a, public, trace, .receipt);
}
pub const MainCommit = struct {
    columns: []Column,
    backing: []M,
    pub fn deinit(self: *MainCommit, a: std.mem.Allocator) void {
        a.free(self.columns);
        a.free(self.backing);
        self.* = undefined;
    }
};
pub const Source = struct {
    metadata: ?*T.Trace = null,
    rows: I.Rows,
    provider_main: []M,
    byte_counts: [256]u64,
    policy_counts: []const u64,
    pub fn fromTrace(trace: *T.Trace) Source {
        return .{ .metadata = trace, .rows = I.Rows.fromTrace(trace), .provider_main = trace.provider, .byte_counts = trace.byte_counts, .policy_counts = trace.policy_counts };
    }
    pub fn releaseBorrowedMain(self: *Source) !void {
        const trace = self.metadata orelse return error.InvalidPrivateRamTracePhase;
        try trace.releaseBorrowedMain();
        self.provider_main = &.{};
        self.rows.mains = @splat(&.{});
    }
    /// Allocate all fallible descriptor storage before detaching the ORIGINAL
    /// ragged backing. The returned columns/backing must move together to PCS.
    pub fn takeMainForCommit(self: *Source, a: std.mem.Allocator, rom: *const PR.Trace) !MainCommit {
        return self.takeMain(a, rom, null);
    }
    fn takeMain(self: *Source, a: std.mem.Allocator, rom: *const PR.Trace, bytes: ?*const Byte.Trace) !MainCommit {
        const trace = self.metadata orelse return error.InvalidPrivateRamTracePhase;
        if (!T.sameAllocator(a, trace.allocator)) return error.PrivateRamAllocatorMismatch;
        if (bytes) |table| if (table.main.len != 256) return error.InvalidPrivateRamTracePhase;
        const columns = try a.alloc(Column, if (bytes != null) N_MAIN else N_MAIN_WITHOUT_BYTE);
        errdefer a.free(columns);
        const arena = try trace.detachMain(a, rom.main);
        var at: usize = 0;
        for (T.TABLES) |table| {
            const width = T.mainWidth(table);
            appendColumns(columns[at..][0..width], arena.callers[@intFromEnum(table)], T.tableLog(arena.shapes, table));
            at += width;
        }
        appendColumns(columns[at..][0..universal.N_MAIN_COLUMNS], arena.provider, arena.shapes.provider_log);
        at += universal.N_MAIN_COLUMNS;
        appendColumns(columns[at..][0..1], arena.policy, rom.shape.log_size);
        at += 1;
        if (bytes) |table| {
            @memcpy(arena.byte_tail, table.main);
            appendColumns(columns[at..], arena.byte_tail, 8);
        }
        self.provider_main = &.{};
        self.rows.mains = @splat(&.{});
        return .{ .columns = columns, .backing = arena.backing };
    }
    /// All physical claims come from the shared equations and sealed narrow
    /// metadata. No host-computed RAM target is accepted. On failure metadata
    /// remains available; success forbids a second generation/phase reuse.
    pub fn generateInteractions(self: *const Source, a: std.mem.Allocator, ch: *const I.Challenges) !I.Interaction {
        if (self.metadata) |trace| {
            if (trace.phase != .rows_ready and trace.phase != .main_detached) return error.InvalidPrivateRamTracePhase;
            if (!std.meta.eql(self.rows.shapes, trace.shapes)) return error.InvalidPrivateRamTracePhase;
            const result = try I.Interaction.initMetadata(a, trace, ch);
            trace.phase = .interactions_ready;
            return result;
        }
        return I.Interaction.initRows(a, self.rows, ch);
    }
    pub fn retireMetadata(self: *const Source) !void {
        const trace = self.metadata orelse return error.InvalidPrivateRamTracePhase;
        try trace.retireMetadata();
    }
};
/// A producer may supply arbitrary borrowed witness rows. Only the AIR and
/// typed closure authorize them; this entry does not trust native builder checks.
pub fn proveSourceOpenState(a: std.mem.Allocator, public: Statement, source: Source) ![]u8 {
    return proveSourceSuite(a, public, source, .diagnostic, null);
}
fn proveSuite(a: std.mem.Allocator, public: Statement, trace: *T.Trace, suite: Suite) ![]u8 {
    if (trace.shapes.chunk.geometry != public.geometry or !R.values.equal(public.before, trace.witness.before) or !R.values.equal(public.after, trace.witness.after)) return error.InvalidPrivateRamProofShape;
    return proveSourceSuite(a, public, Source.fromTrace(trace), suite, null);
}
fn proveSourceSuite(a: std.mem.Allocator, public: Statement, source: Source, suite: Suite, terminal: ?Terminal.Spec) ![]u8 {
    try public.validate();
    try source.rows.validate();
    const counts = Counts{ .hashes = source.rows.shapes.chunk.hashes, .common_chunks = source.rows.shapes.common_cells.chunks, .edge_chunks = source.rows.shapes.edge_cells.chunks, .nodes = source.rows.shapes.node.nodes, .sides = source.rows.shapes.side.sides, .edge_permits = source.rows.shapes.edge_permits.certificates };
    const shapes = try counts.shapes(public.geometry);
    if (terminal) |spec| try validateTerminal(public, counts, spec);
    if (!std.meta.eql(shapes, source.rows.shapes) or source.provider_main.len != universal.N_MAIN_COLUMNS * (@as(usize, 1) << @intCast(shapes.provider_log))) return error.InvalidPrivateRamProofShape;
    var bytes = try Byte.Trace.init(a, &source.byte_counts);
    defer bytes.deinit();
    var rom = try PR.Trace.init(a, public.policy, source.policy_counts);
    defer rom.deinit();
    var fixed = try Fixed.init(a, shapes, &rom, &bytes, terminal);
    defer fixed.deinit();
    var scheme = try Engine.init(a, config(suite));
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, a);
    var channel = P.Channel{};
    mixMode(&channel, public, counts, suite, terminal);
    try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &channel);
    if (source.metadata != null) {
        // Existing PCS ownership path adopts this ORIGINAL ragged allocation.
        // Allocate owner-list storage BEFORE the source publication boundary.
        const buffers = try a.alloc([]M, 1);
        var live_source = source;
        const main = live_source.takeMain(a, &rom, &bytes) catch |err| {
            a.free(buffers);
            return err;
        };
        buffers[0] = main.backing;
        try scheme.commitOwnedWithRecorderAndBacking(a, main.columns, buffers, null, &channel);
    } else {
        const main = try mainColumns(a, source, &rom, &bytes);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    }
    const ch = try I.Challenges.draw(a, &channel);
    var interaction = try source.generateInteractions(a, &ch);
    defer interaction.deinit();
    _ = try bytes.generateInteraction(ch.bytes);
    _ = try rom.generateInteraction(.{ .policy = ch.policy });
    const claims = Claims{ .callers = interaction.claims, .provider = interaction.provider.claims, .bytes = bytes.claim, .policy = rom.claim };
    const state_debt = try I.close(public.before, public.after, public.geometry, &claims.callers, claims.provider, claims.bytes, claims.policy, &ch);
    if (terminal != null and !state_debt.isZero()) return error.UnexpectedTerminalStateDebt;
    if (source.metadata != null) try source.retireMetadata();
    claims.mix(&channel);
    const columns = try interactionColumns(a, shapes, &interaction, &rom, &bytes);
    defer a.free(columns);
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    const components = try Components.initInternal(shapes, public.policy, &ch, &claims, .{ .fixed = 0, .main = 0, .interaction = 0 }, terminal);
    const provers = try components.provers();
    moved = true;
    var proof = try Engine.prove(a, &provers, &channel, scheme, .{});
    defer proof.deinit(a);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(a);
    try appendWord(a, &output, proofMagic(suite, terminal));
    for (counts.words()) |word| try appendWord(a, &output, word);
    for (T.TABLES) |table| for (claims.callers.slice(table)) |claim| try appendQ(a, &output, claim);
    for (claims.provider) |claim| try appendQ(a, &output, claim);
    try appendQ(a, &output, claims.policy);
    try appendQ(a, &output, claims.bytes);
    try postcard.serializeProof(P.Hasher, output.writer(a), proof.proof);
    if (output.items.len > MAX_BYTES) return error.PrivateRamProofResourceLimit;
    return output.toOwnedSlice(a);
}
fn proofMagic(suite: Suite, terminal: ?Terminal.Spec) u32 {
    return if (terminal != null) (if (suite == .receipt) 0x52505434 else 0x52505433) else magic(suite);
}
fn mixMode(channel: *P.Channel, public: Statement, counts: Counts, suite: Suite, terminal: ?Terminal.Spec) void {
    mix(channel, public, counts, suite);
    if (terminal) |spec| {
        channel.mixU32s(&.{ 0x5256544f, 1 });
        channel.mixU64(spec.halt_flag);
        for (spec.output) |byte| channel.mixU32s(&.{byte});
    }
}
fn validateTerminal(public: Statement, counts: Counts, spec: Terminal.Spec) !void {
    try spec.validate();
    if (spec.geometry != public.geometry or !R.values.equal(public.before, public.after) or counts.hashes != 1 or counts.common_chunks != 1 or counts.edge_chunks != 0 or counts.nodes != public.geometry.depth() or counts.sides != public.geometry.depth() or counts.edge_permits != 0) return error.InvalidRv64TerminalObservation;
    _ = try public.policy.find(if (public.geometry == .chunk512) .chunk512 else .page4096, spec.base(), 3);
}
pub fn proveTerminalReceipt(a: std.mem.Allocator, public: Statement, trace: *T.Trace, spec: Terminal.Spec) ![]u8 {
    return proveSourceSuite(a, public, Source.fromTrace(trace), .receipt, spec);
}
pub fn proveTerminalDiagnostic(a: std.mem.Allocator, public: Statement, trace: *T.Trace, spec: Terminal.Spec) ![]u8 {
    return proveSourceSuite(a, public, Source.fromTrace(trace), .diagnostic, spec);
}
pub fn verifyTerminalReceipt(a: std.mem.Allocator, public: Statement, spec: Terminal.Spec, bytes: []const u8) !void {
    _ = try verifySuite(a, public, bytes, .receipt, spec);
}
pub fn verifyTerminalDiagnostic(a: std.mem.Allocator, public: Statement, spec: Terminal.Spec, bytes: []const u8) !void {
    _ = try verifySuite(a, public, bytes, .diagnostic, spec);
}
fn appendWord(a: std.mem.Allocator, out: *std.ArrayList(u8), value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try out.appendSlice(a, &bytes);
}
fn appendQ(a: std.mem.Allocator, out: *std.ArrayList(u8), value: Q) !void {
    for (value.toM31Array()) |word| try appendWord(a, out, word.toU32());
}
fn readQ(bytes: []const u8, at: *usize) !Q {
    var words: [4]M = undefined;
    for (&words) |*word| {
        const value = std.mem.readInt(u32, bytes[at.*..][0..4], .little);
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        word.* = M.fromCanonical(value);
        at.* += 4;
    }
    return Q.fromM31Array(words);
}
pub fn verifyOpenState(a: std.mem.Allocator, public: Statement, proof: []const u8) !OpenState {
    return verifySuite(a, public, proof, .diagnostic, null);
}
pub fn verifyReceiptOpenState(a: std.mem.Allocator, public: Statement, proof: []const u8) !OpenState {
    return verifySuite(a, public, proof, .receipt, null);
}
fn verifySuite(a: std.mem.Allocator, public: Statement, bytes: []const u8, suite: Suite, terminal: ?Terminal.Spec) !OpenState {
    try public.validate();
    if (bytes.len <= HEADER or bytes.len > MAX_BYTES or std.mem.readInt(u32, bytes[0..4], .little) != proofMagic(suite, terminal)) return error.InvalidPrivateRamProofShape;
    var count_words: [6]u32 = undefined;
    for (&count_words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 + 4 * i ..][0..4], .little);
    const counts = Counts{ .hashes = count_words[0], .common_chunks = count_words[1], .edge_chunks = count_words[2], .nodes = count_words[3], .sides = count_words[4], .edge_permits = count_words[5] };
    const shapes = try counts.shapes(public.geometry);
    if (terminal) |spec| try validateTerminal(public, counts, spec);
    var claims = Claims{ .callers = .{}, .provider = undefined, .policy = undefined, .bytes = undefined };
    var at: usize = 28;
    for (T.TABLES) |table| for (claims.callers.tables[@intFromEnum(table)][0..T.sumCount(table)]) |*claim| {
        claim.* = try readQ(bytes, &at);
    };
    for (&claims.provider) |*claim| claim.* = try readQ(bytes, &at);
    claims.policy = try readQ(bytes, &at);
    claims.bytes = try readQ(bytes, &at);
    std.debug.assert(at == HEADER);
    const params = config(suite);
    var largest: u32 = @max(8, shapes.provider_log);
    for (T.TABLES) |table| largest = @max(largest, T.tableLog(shapes, table));
    try postcard.proof_preflight.validate(bytes[HEADER..], .{ .config = .{ .pow_bits = params.pow_bits, .log_blowup_factor = params.fri_config.log_blowup_factor, .n_queries = params.fri_config.n_queries, .log_last_layer_degree_bound = params.fri_config.log_last_layer_degree_bound, .fold_step = params.fri_config.fold_step, .lifting_log_size = params.lifting_log_size }, .tree_columns = .{ N_FIXED + @as(u32, if (terminal != null) Terminal.SELECTORS else 0), N_MAIN, N_INTERACTION, 16 }, .max_column_log_size = largest, .hash_size = @sizeOf(P.Hasher.Hash), .max_wire_bytes = MAX_BYTES - HEADER });
    var stream = std.io.fixedBufferStream(bytes[HEADER..]);
    var proof = try postcard.deserializeProof(P.Hasher, a, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(a);
    if (stream.pos != bytes.len - HEADER or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidPrivateRamProofShape;
    const roots = proof.commitment_scheme_proof.commitments.items;
    var byte_table = try Byte.Trace.init(a, &@as([256]u64, @splat(0)));
    defer byte_table.deinit();
    const zero_counts = try a.alloc(u64, public.policy.grants.len);
    defer a.free(zero_counts);
    @memset(zero_counts, 0);
    var rom = try PR.Trace.init(a, public.policy, zero_counts);
    defer rom.deinit();
    var fixed = try Fixed.init(a, shapes, &rom, &byte_table, terminal);
    defer fixed.deinit();
    {
        var setup = try Engine.init(a, params);
        defer Engine.deinit(&setup, a);
        var scratch = P.Channel{};
        try setup.commitBorrowedStreaming(a, fixed.columns, 8, &scratch);
        var canonical = try setup.roots(a);
        defer canonical.deinit(a);
        if (!std.meta.eql(canonical.items[0], roots[0])) return error.InvalidPrivateRamFixedRoot;
    }
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel).init(a, params);
    defer scheme.deinit(a);
    var channel = P.Channel{};
    mixMode(&channel, public, counts, suite, terminal);
    var fixed_logs: [N_FIXED + Terminal.SELECTORS]u32 = undefined;
    for (fixed_logs[0..fixed.columns.len], fixed.columns) |*log, column| log.* = column.log_size;
    var main_logs: [N_MAIN]u32 = undefined;
    var inter_logs: [N_INTERACTION]u32 = undefined;
    for (T.TABLES) |table| {
        const o = offsets(table);
        @memset(main_logs[o.main..][0..T.mainWidth(table)], T.tableLog(shapes, table));
        @memset(inter_logs[o.interaction..][0 .. 4 * T.sumCount(table)], T.tableLog(shapes, table));
    }
    @memset(main_logs[CALLER_MAIN..][0..universal.N_MAIN_COLUMNS], shapes.provider_log);
    main_logs[N_MAIN - 2] = rom.shape.log_size;
    main_logs[N_MAIN - 1] = 8;
    @memset(inter_logs[CALLER_INTERACTION..][0..8], shapes.provider_log);
    @memset(inter_logs[CALLER_INTERACTION + 8 ..][0..PR.INTERACTION], rom.shape.log_size);
    @memset(inter_logs[N_INTERACTION - Byte.N_INTERACTION ..], 8);
    try scheme.commit(a, roots[0], fixed_logs[0..fixed.columns.len], &channel);
    try scheme.commit(a, roots[1], &main_logs, &channel);
    const ch = try I.Challenges.draw(a, &channel);
    const debt = try I.close(public.before, public.after, public.geometry, &claims.callers, claims.provider, claims.bytes, claims.policy, &ch);
    if (terminal != null and !debt.isZero()) return error.UnexpectedTerminalStateDebt;
    claims.mix(&channel);
    try scheme.commit(a, roots[2], &inter_logs, &channel);
    const components = try Components.initInternal(shapes, public.policy, &ch, &claims, .{ .fixed = 0, .main = 0, .interaction = 0 }, terminal);
    const verifiers = try components.verifiers();
    moved = true;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &verifiers, &channel, &scheme, proof);
    return .{ .claim = debt, .challenge = ch.state };
}
