//! Concrete request-owned source lifecycle shared by public-cell and private-RAM
//! coordinators. It owns lookup witnesses, not CPU advice or immutable materials.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const C = @import("rv64_keccak_cpu.zig");
const S = @import("rv64_full.zig").Support;
const rv = frontend.rv64_air;
const D = rv.arithmetic.division;
const Mul = rv.arithmetic.multiplication;
const K = rv.crypto.keccak;
const Secp = rv.crypto.secp256k1;
const SecpContext = @import("rv64_ethereum_secp_context.zig");
const KSources = @import("rv64_keccak_sources.zig");
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const append = C.Support.append;
pub const ProvingSources = struct {
    allocator: std.mem.Allocator,
    materials: *const C.PreparedMaterials,
    public: C.Public,
    trace: *C.Trace,
    rom: rv.program.provider.Request,
    bytes: rv.range.provider.Trace,
    bitwise: ?rv.providers.tables.Request = null,
    shifts: ?rv.providers.tables.Request = null,
    divbus: ?D.cpu_bus.Columns = null,
    header: ?K.cpu_bus.Columns = null,
    mulbus: ?Mul.cpu_bus.Columns = null,
    secp_header: ?Secp.cpu_bus.Columns = null,
    claims: ?C.Claims = null,
    main_released: bool = false,
    interaction_released: bool = false,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    pub fn init(a: std.mem.Allocator, materials: *const C.PreparedMaterials, public: C.Public, trace: *C.Trace, extra_bytes: ?*const [256]u64) !ProvingSources {
        try C.Support.physical(a, materials, public, trace);
        var counts = trace.cpu.byte_counts;
        if (trace.crypto) |*value| for (&counts, value.bridge.byte_counts) |*total, count| {
            total.* = try std.math.add(u64, total.*, count);
        };
        if (trace.multiplication) |*value| for (&counts, value.byte_counts) |*total, count| {
            total.* = try std.math.add(u64, total.*, count);
        };
        for (&counts, trace.secp.byte_counts) |*total, count| total.* = try std.math.add(u64, total.*, count);
        if (extra_bytes) |extra| for (&counts, extra) |*total, count| {
            total.* = try std.math.add(u64, total.*, count);
        };
        var total_queries: u64 = 0;
        for (counts) |count| total_queries = try std.math.add(u64, total_queries, count);
        if (total_queries >= core.fields.m31.Modulus) return error.Rv64ServiceLookupMassExceeded;
        var rom = try S.rom(a, &materials.base.program, trace.cpu.rom_counts);
        errdefer rom.deinit();
        var bytes = try rv.range.provider.Trace.init(a, &counts);
        errdefer bytes.deinit();
        var bitwise: ?rv.providers.tables.Request = if (materials.base.and_table) |*table| try rv.providers.tables.Request.init(a, table, trace.cpu.and_counts) else null;
        errdefer if (bitwise) |*value| value.deinit();
        const shifts: ?rv.providers.tables.Request = if (materials.base.shift_table) |*table| try rv.providers.tables.Request.init(a, table, trace.cpu.shift_counts) else null;
        return .{ .allocator = a, .materials = materials, .public = public, .trace = trace, .rom = rom, .bytes = bytes, .bitwise = bitwise, .shifts = shifts };
    }
    pub fn deinit(self: *ProvingSources) void {
        if (self.secp_header) |*value| value.deinit();
        if (self.mulbus) |*value| value.deinit();
        if (self.header) |*value| value.deinit();
        if (self.divbus) |*value| value.deinit();
        if (self.shifts) |*value| value.deinit();
        if (self.bitwise) |*value| value.deinit();
        self.bytes.deinit();
        self.rom.deinit();
        self.* = undefined;
    }
    fn providerColumns(self: *const ProvingSources, out: *[4]Column) usize {
        var n: usize = 0;
        append(out, &n, self.rom.multiplicities, self.materials.base.program.log_size);
        append(out, &n, self.bytes.main, 8);
        if (self.bitwise) |value| append(out, &n, value.main, 16);
        if (self.shifts) |value| append(out, &n, value.main, 11);
        return n;
    }
    pub fn mainColumns(self: *const ProvingSources) ![]Column {
        if (self.main_released) return error.InvalidRv64ServiceSourcePhase;
        var columns: [4]Column = undefined;
        const n = self.providerColumns(&columns);
        return C.Support.mainColumns(self.allocator, self.trace, columns[0..n]);
    }
    /// Caller invokes only after all main columns have been committed. Source
    /// rows remain trace-owned until this barrier; no transfer is implicit.
    pub fn releaseMain(self: *ProvingSources) !void {
        if (self.main_released) return error.InvalidRv64ServiceSourcePhase;
        const trace = self.trace;
        // K admission is validated before releasing any storage.
        if (trace.crypto) |*value| try value.releaseMain();
        for (&trace.secp.groups) |*group| if (group.*) |*value| {
            try value.releaseMain();
        };
        try trace.cpu.releaseMain();
        if (trace.division) |*value| try value.releaseMain();
        if (trace.multiplication) |*value| try value.releaseMain();
        self.main_released = true;
    }
    /// One-shot after the shared main root. Aggregate state closure remains the
    /// outer coordinator's responsibility; only ROM/DIV/AND/SHIFT close here.
    pub fn generate(self: *ProvingSources, ch: C.Support.Challenges) !C.Claims {
        if (!self.main_released or self.claims != null or self.divbus != null) return error.InvalidRv64ServiceSourcePhase;
        const a = self.allocator;
        const setup = self.materials;
        const public = self.public;
        const trace = self.trace;
        const Stage = engine.stage_profile.StageScope;
        const cpu_claims = blk: {
            var stage = try Stage.begin(self.stage_recorder, "cpu_interaction", "Generate CPU physical interactions");
            defer stage.end();
            break :blk try trace.cpu.generateInteraction(ch.cpu);
        };
        var arithmetic_stage = try Stage.begin(self.stage_recorder, "arithmetic_interaction", "Generate arithmetic callers and multiplication provider");
        var arithmetic_open = true;
        defer if (arithmetic_open) arithmetic_stage.end();
        self.divbus = try D.cpu_bus.build(a, public.statement.steps, setup.base.log_size, trace.indexed, ch.division);
        self.header = try K.cpu_bus.build(a, public.statement.steps, setup.base.log_size, trace.cpu.service_calls, public.first_call_id, ch.bridge.call);
        if (ch.multiplication) |challenge| self.mulbus = try Mul.cpu_bus.build(a, public.statement.steps, setup.base.log_size, trace.multiplication_indexed, challenge);
        const mulclaim = if (trace.multiplication) |*value| try value.generateInteraction(ch.multiplication orelse return error.InvalidRv64ServiceArithmetic, ch.cpu.bytes) else Q.zero();
        arithmetic_stage.end();
        arithmetic_open = false;
        var secp_stage = try Stage.begin(self.stage_recorder, "secp_interaction", "Generate secp callers and providers");
        var secp_open = true;
        defer if (secp_open) secp_stage.end();
        if (ch.secp) |challenge| self.secp_header = try Secp.cpu_bus.build(a, public.statement.steps, setup.base.log_size, trace.secp_headers, public.secp.firstIds(), public.execution_profile, challenge.call);
        const secp_claims = if (ch.secp) |challenge| try trace.secp.generate(challenge) else [_]SecpContext.Claims{ .{}, .{} };
        secp_stage.end();
        secp_open = false;
        const negative = blk: {
            var stage = try Stage.begin(self.stage_recorder, "division_provider_interaction", "Generate division provider interactions");
            defer stage.end();
            break :blk if (trace.division) |*value| try value.generateInteraction(ch.division) else Q.zero();
        };
        if (!negative.add(self.divbus.?.claim).isZero()) return error.Rv64ServiceDivisionClosure;
        const crypto = blk: {
            var stage = try Stage.begin(self.stage_recorder, "keccak_interaction", "Generate Keccak permutation, tables and RAM bridge");
            defer stage.end();
            break :blk if (trace.crypto) |*value| try value.generateWithOptions(ch.keccak, ch.bridge, .{ .pool = engine.work_pool.currentScopedPool(), .recorder = self.stage_recorder }) else KSources.Claims{ .permutation = Q.zero(), .chi = Q.zero(), .xor5 = Q.zero(), .bridge = Q.zero() };
        };
        var range_stage = try Stage.begin(self.stage_recorder, "range_rom_interaction", "Generate shared BYTE, ROM, AND and SHIFT providers");
        defer range_stage.end();
        const result = C.Claims{ .secp_header = if (self.secp_header) |value| value.claim else Q.zero(), .secp_add = secp_claims[0], .secp_double = secp_claims[1], .multiplication = if (self.mulbus) |value| value.claim else Q.zero(), .multiplication_provider = mulclaim, .cpu = cpu_claims, .division = self.divbus.?.claim, .header = self.header.?.claim, .permutation = crypto.permutation, .chi = crypto.chi, .xor5 = crypto.xor5, .bridge = crypto.bridge, .bytes = try self.bytes.generateInteraction(ch.cpu.bytes) };
        try C.Support.validateEncoding(setup, public, result);
        if (!(try self.rom.generateInteraction(&setup.base.program, ch.cpu.rom)).add(result.cpu.rom).isZero()) return error.Rv64FullRomClosure;
        if (self.bitwise) |*value| if (!(try value.generateInteraction(ch.cpu.bitwise)).add(result.cpu.bitwise).isZero()) return error.Rv64FullAndClosure;
        if (self.shifts) |*value| if (!(try value.generateInteraction(ch.cpu.shifts)).add(result.cpu.shifts).isZero()) return error.Rv64FullShiftClosure;
        self.claims = result;
        return result;
    }
    pub fn interactionColumns(self: *const ProvingSources) ![]Column {
        if (self.claims == null or self.interaction_released) return error.InvalidRv64ServiceSourcePhase;
        const trace = self.trace;
        const setup = self.materials;
        const np = setup.base.providerCount();
        const count = trace.cpu.interactionCount() + 8 + 8 + (if (self.mulbus != null) @as(usize, 8) else 0) + (if (self.secp_header != null) @as(usize, 4) else 0) + np * 8 + (if (trace.division != null) @as(usize, D.layout.INTERACTION) else 0) + (if (trace.multiplication != null) @as(usize, Mul.layout.INTERACTION) else 0) + (if (trace.crypto != null) @as(usize, KSources.INTERACTION) else 0) + setup.secp.count() * SecpContext.Source.INTERACTION;
        const columns = try self.allocator.alloc(Column, count);
        errdefer self.allocator.free(columns);
        var at: usize = 0;
        append(columns, &at, trace.cpu.interaction, setup.base.log_size);
        append(columns, &at, self.divbus.?.storage, setup.base.log_size);
        append(columns, &at, self.header.?.storage, setup.base.log_size);
        if (self.mulbus) |value| append(columns, &at, value.storage, setup.base.log_size);
        if (self.secp_header) |value| append(columns, &at, value.storage, setup.base.log_size);
        append(columns, &at, self.rom.interaction, setup.base.program.log_size);
        append(columns, &at, self.bytes.interaction, 8);
        if (self.bitwise) |value| append(columns, &at, value.interaction, 16);
        if (self.shifts) |value| append(columns, &at, value.interaction, 11);
        if (trace.division) |*value| append(columns, &at, value.interaction, setup.division_log);
        if (trace.multiplication) |*value| append(columns, &at, value.interaction, setup.multiplication_log);
        if (trace.crypto) |*value| value.appendInteraction(columns, &at);
        try trace.secp.appendInteraction(columns, &at);
        std.debug.assert(at == columns.len);
        return columns;
    }

    /// The coordinator calls only after successful interaction commitment.
    /// PCS storage and transcript-bound claims survive; the source matrices
    /// are redundant during composition/FRI. No relation obligation is erased.
    pub fn releaseCommittedInteractions(self: *ProvingSources) !void {
        if (self.claims == null or self.interaction_released) return error.InvalidRv64ServiceSourcePhase;
        self.trace.cpu.releaseCommittedInteraction();
        if (self.divbus) |*value| value.deinit();
        self.divbus = null;
        if (self.header) |*value| value.deinit();
        self.header = null;
        if (self.mulbus) |*value| value.deinit();
        self.mulbus = null;
        if (self.secp_header) |*value| value.deinit();
        self.secp_header = null;
        retire(self.rom.allocator, &self.rom.interaction);
        retire(self.bytes.allocator, &self.bytes.interaction);
        if (self.bitwise) |*value| retire(value.allocator, &value.interaction);
        if (self.shifts) |*value| retire(value.allocator, &value.interaction);
        if (self.trace.division) |*value| retire(value.allocator, &value.interaction);
        if (self.trace.multiplication) |*value| retire(value.allocator, &value.interaction);
        if (self.trace.crypto) |*value| {
            retire(value.permutation.allocator, &value.permutation.interaction);
            retire(value.chi.allocator, &value.chi.interaction);
            retire(value.xor5.allocator, &value.xor5.interaction);
            retire(value.bridge.allocator, &value.bridge.interaction);
        }
        for (&self.trace.secp.groups) |*group| if (group.*) |*value| {
            retire(value.product.allocator, &value.product.interaction);
            retire(value.linear.allocator, &value.linear.interaction);
            retire(value.bridge.allocator, &value.bridge.interaction);
        };
        self.interaction_released = true;
    }
};

fn retire(a: std.mem.Allocator, values: *[]core.fields.m31.M31) void {
    a.free(values.*);
    values.* = &.{};
}
