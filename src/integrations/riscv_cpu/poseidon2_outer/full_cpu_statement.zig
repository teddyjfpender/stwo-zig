//! Complete CPU statement equations over explicit scope digests for mixed P2 census.
//! The caller admits immutable setup/topology and the root authenticates the
//! returned public frame against its independently reconstructed request,
//! manifest, local receipt and physical-claim vector. This module is not a
//! root receiver and deliberately does not replace native boundary validation.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("../rv64_recursion/om31_native/common.zig");
const V = @import("../rv64_recursion/om31_native/mod.zig");
const Public = @import("../rv64_recursion/om31_native/frame.zig");
const Gkr = @import("../logup_gkr/om31_circuit_verifier.zig");
const Child = @import("../rv64_recursion/om31_native/cpu_child.zig");
const Oods = @import("../rv64_recursion/om31_native/cpu_oods.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Worker = @import("../word16_global_execution/services/gkr_local/cpu_worker.zig");
const M = @import("../word16_global_execution/services/gkr_local/manifest.zig");
const W = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const F = C.F;
fn flag(ctx: *C.Context, count: F, native: u32) !F {
    const nonzero = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else C.O.one());
    const inverse = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else try C.O.fromBase(core.fields.m31.M31.fromCanonical(native)).inv());
    try ctx.noteWitnessHint(nonzero.c0.v, .is_nonzero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(nonzero.c1.v, .zero, ctx.zero(), ctx.zero());
    // count is the canonical M31 projection of an admitted public count.
    try ctx.noteWitnessHint(inverse.c0.v, .pointwise_inverse_or_zero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(inverse.c1.v, .zero, ctx.zero(), ctx.zero());
    try C.eq(ctx, nonzero.mul(nonzero.sub(F.one())), F.zero());
    try C.eq(ctx, count.mul(F.one().sub(nonzero)), F.zero());
    try C.eq(ctx, count.mul(inverse), nonzero);
    return nonzero;
}
fn exposeRoot(frame: *Public.Frame, hash: C.Hash) !Public.Digest {
    try frame.free_words.appendSlice(frame.ctx.scratch(), &hash.words);
    return hash.words;
}
pub const Statement = struct {
    /// The original public witnesses, retained for typed-summary constraints.
    /// Saving these handles adds no guesses or equations to legacy leaves.
    pub const ChainInputs = struct {
        steps: Public.Word,
        epoch: Public.Word,
        initial_pc: [4]Public.Word,
        final_pc: [4]Public.Word,
        initial_registers: [32][4]Public.Word,
        final_registers: [32][4]Public.Word,
        register_clocks: [32]Public.Word,
        sponge_first: Public.Word,
        rows: []const Public.Word,
        calls: []const Public.Word,
        first_ids: []const Public.Word,
    };
    setup: *const R.CpuSetup,
    plan: Components.Plan,
    config: W.PcsConfig,
    binding: ?Public.Binding,
    ordinal: Public.Word,
    statement: Public.Digest,
    manifest: Public.Digest,
    claims: []const F,
    pending: Child.Pending,
    publics: []const Oods.PublicFor(F),
    chain_inputs: ChainInputs,

    /// Native input is witness assignment only. Every request scalar consumed
    /// by an equation is a guessed public word in `frame`; none becomes a
    /// circuit constant. Program/geometry/config and fixed authority are the
    /// independently admitted immutable topology.
    pub fn init(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.ExpectedWorker, manifest: [32]u8, native_claims: []const C.O, physical: struct { fixed: C.Hash, main: C.Hash }, native_child: anytype, config: W.PcsConfig, binding: ?Public.Binding) !Statement {
        const ctx = frame.ctx;
        const a = ctx.scratch();
        if (expected.kind != .cpu) return error.WideCpuProofShape;
        if (binding != null) try W.validateCandidateConfig(config) else try W.validateConfig(config);
        if (binding) |authority| if (authority.profile) |profile| {
            if (!std.meta.eql(config, W.Candidate.configFor(profile))) return error.UnsupportedWideServicesConfig;
        };
        const fixed_root = if (binding) |b| b.root else setup.key.root;
        if (!std.mem.eql(u8, &fixed_root, &expected.fixed)) return error.WideCpuStatementMismatch;
        const derived_instances = try @import("../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, setup);
        const admitted_instances = expected.local_instances orelse return error.WideCpuLocalRequired;
        if (derived_instances.len != admitted_instances.len) return error.WideCpuRosterMismatch;
        for (derived_instances, admitted_instances) |derived, admitted| if (!std.meta.eql(derived, admitted)) return error.WideCpuRosterMismatch;
        try Public.requireDigest(ctx, physical.fixed, fixed_root);
        const ordinal = try frame.guessU32(expected.ordinal);
        const statement = try frame.guessDigest(expected.statement);
        const scope = Child.Scope{ .ordinal = ordinal.word, .statement = statement, .fixed = try exposeRoot(frame, physical.fixed), .main = try exposeRoot(frame, physical.main) };
        const manifest_words = try frame.guessDigest(manifest);
        const child_proof = try Gkr.wireProof(ctx, native_child);
        var pending = try Child.verify(ctx, scope, expected.local_instances orelse return error.WideCpuLocalRequired, &child_proof);
        errdefer pending.artifact.deinit(ctx.gpa);
        _ = try exposeRoot(frame, pending.receipt);
        const claims = try a.alloc(F, native_claims.len);
        for (claims, native_claims) |*wire, value| wire.* = try frame.guessOm(value);
        const shared = try Public.drawShared(ctx, manifest_words);
        const cpu = request.base.cpu;
        const steps_word = try frame.guessU32(cpu.steps);
        const epoch_word = try frame.guessU32(request.base.epoch);
        const steps = steps_word.base;
        const epoch = epoch_word.base;
        var chain_inputs: ChainInputs = undefined;
        chain_inputs.steps = steps_word.word;
        chain_inputs.epoch = epoch_word.word;
        var initial_pc: [4]F = undefined;
        var final_pc: [4]F = undefined;
        for (0..4) |i| {
            const initial = try frame.guessU32(@as(u16, @truncate(cpu.initial_pc >> @as(u6, @intCast(16 * i)))));
            const final = try frame.guessU32(@as(u16, @truncate(cpu.final_pc >> @as(u6, @intCast(16 * i)))));
            initial_pc[i] = initial.base;
            final_pc[i] = final.base;
            chain_inputs.initial_pc[i] = initial.word;
            chain_inputs.final_pc[i] = final.word;
        }
        var source_public = [_]F{F.zero()} ** Oods.Authority.Source.Public.count;
        const SP = Oods.Authority.Source.Public;
        source_public[SP.epoch] = epoch;
        source_public[SP.initial_pc] = initial_pc[0].add(initial_pc[1].mul(F.fromBase(core.fields.m31.M31.fromCanonical(65536))));
        for (0..32) |r| {
            for (0..4) |i| {
                const initial = try frame.guessU32(@as(u16, @truncate(cpu.initial_registers[r] >> @as(u6, @intCast(16 * i)))));
                const final = try frame.guessU32(@as(u16, @truncate(cpu.final_registers[r] >> @as(u6, @intCast(16 * i)))));
                source_public[SP.initial_registers + 4 * r + i] = initial.base;
                source_public[SP.final_registers + 4 * r + i] = final.base;
                chain_inputs.initial_registers[r][i] = initial.word;
                chain_inputs.final_registers[r][i] = final.word;
            }
            const clock = try frame.guessU32(cpu.register_clocks[r]);
            source_public[SP.register_clocks + r] = clock.base;
            chain_inputs.register_clocks[r] = clock.word;
        }
        const inputs = A.word16_execution.types.InputsFor(F){ .steps = steps, .initial_pc = initial_pc, .final_pc = final_pc, .epoch = epoch, .wide_clock = A.word16_execution.layout.wideClock(setup.materials.geometry.cpu_log) };
        const plan = try Components.Plan.init(a, setup);
        if (claims.len != plan.claim_count) return error.InvalidWideCpuClaims;
        const instances = expected.local_instances.?;
        if (instances.len != plan.binding_count) return error.WideCpuRosterMismatch;
        const publics = try a.alloc(Oods.PublicFor(F), plan.slots.len);
        const ls_counts = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
        const dword_counts = try T.dwordCounts(setup.bridges, request.ls_dword);
        const sponge_first_word = try frame.guessU32(request.sponge.first_id);
        const sponge_first = sponge_first_word.base;
        chain_inputs.sponge_first = sponge_first_word.word;
        const row_words = try a.alloc(Public.Word, plan.slots.len);
        const call_words = try a.alloc(Public.Word, plan.slots.len);
        const first_words = try a.alloc(Public.Word, plan.slots.len);
        chain_inputs.rows = row_words;
        chain_inputs.calls = call_words;
        chain_inputs.first_ids = first_words;
        for (publics, plan.slots, 0..) |*public, slot, slot_index| {
            var rows_native: u32 = 0;
            var calls_native: u32 = 0;
            var first_native: u32 = 1;
            switch (slot.origin) {
                .core => |role| rows_native = switch (role) {
                    .initial => @intCast(request.base.memory.initial.len),
                    .terminal => @intCast(request.base.memory.terminal.len),
                    .ls => ls_counts.head,
                    .ls_tail => ls_counts.tail,
                    .multiplication => request.base.multiplication_requests,
                    .division => request.base.division_requests,
                    else => 0,
                },
                .bridge => |family| {
                    calls_native = request.calls[@intFromEnum(family)];
                    first_native = first[@intFromEnum(family)];
                },
                .bulk => |kind| rows_native = request.bulk.rows(kind),
                .sponge => |kind| rows_native = request.sponge.rows(kind),
                .dword => |index| rows_native = dword_counts[index],
            }
            const row_word = try frame.guessU32(rows_native);
            const call_word = try frame.guessU32(calls_native);
            const first_word = try frame.guessU32(first_native);
            const rows = row_word.base;
            const calls = call_word.base;
            const first_id = first_word.base;
            row_words[slot_index] = row_word.word;
            call_words[slot_index] = call_word.word;
            first_words[slot_index] = first_word.word;
            var sp = source_public;
            sp[SP.sponge_first_id] = sponge_first;
            const nclaims = Oods.Authority.Global.claimCount(slot.origin);
            public.* = .{
                .main = .{ .cpu = inputs, .rows = rows, .nonempty = try flag(ctx, rows, rows_native), .span = .{ .calls = calls, .first_id = first_id, .nonempty = try flag(ctx, calls, calls_native) } },
                .source = sp,
                .shared = .{ .ram = shared.ram, .kio = shared.kio, .wire = shared.wire },
                .claims = try Oods.Authority.Global.claimsFromVector(F, slot.origin, claims[slot.claim_offset..][0..nclaims]),
                .local = if (slot.binding_index) |index| try Oods.localFromArtifact(F, a, instances[index], index, pending.artifact, pending.challenges, pending.eta) else null,
            };
        }
        return .{ .setup = setup, .plan = plan, .config = config, .binding = binding, .ordinal = ordinal.word, .statement = statement, .manifest = manifest_words, .claims = claims, .pending = pending, .publics = publics, .chain_inputs = chain_inputs };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        self.pending.artifact.deinit(ctx.gpa);
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try Public.mixWorkerBegin(ctx, channel, self.config, .cpu, self.ordinal, self.statement, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(_: *Statement, _: *C.Context, _: *C.Channel) !void {}
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try Public.mixManifestAndClaims(ctx, channel, self.manifest, self.claims);
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        var accumulator = E.lane.PointAccumulator(F).init(alpha);
        for (self.plan.slots, self.publics) |slot, public| {
            const descriptor = Oods.Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = self.setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = self.setup.materials.geometry.cpu_compact_decode };
            _ = try Oods.evaluateRole(F, ctx.scratch(), descriptor, slot, public, .{ .x = point.x, .y = point.y }, self.globalLog(), sampled, &accumulator);
        }
        return accumulator.finalize();
    }
    fn globalLog(self: *const Statement) u32 {
        var log: u32 = 0;
        for (self.plan.slots) |slot| log = @max(log, slot.log);
        return log;
    }
};

/// Exact root-side public frame projection. The receiver supplies independently
/// admitted setup/request/manifest/root/receipt/claims after native inventory,
/// boundary and global closure validation. No producer-declared scalar is an
/// authority merely because this encoder can serialize it.
pub fn expectedWords(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, expected: M.ExpectedWorker, manifest: [32]u8, main_root: [32]u8, receipt: [32]u8, claims: []const C.O) ![]u32 {
    var words: std.ArrayList(u32) = .empty;
    errdefer words.deinit(a);
    try words.append(a, expected.ordinal);
    for ([_][32]u8{ expected.statement, expected.fixed, main_root, manifest, receipt }) |digest| for (0..8) |i| try words.append(a, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));
    for (claims) |claim| for (claim.toM31Array()) |coordinate| try words.append(a, coordinate.v);
    const cpu = request.base.cpu;
    try words.appendSlice(a, &.{ cpu.steps, request.base.epoch });
    for (0..4) |i| {
        const shift: u6 = @intCast(i * 16);
        try words.appendSlice(a, &.{ @as(u16, @truncate(cpu.initial_pc >> shift)), @as(u16, @truncate(cpu.final_pc >> shift)) });
    }
    for (0..32) |r| {
        for (0..4) |i| {
            const shift: u6 = @intCast(i * 16);
            try words.appendSlice(a, &.{ @as(u16, @truncate(cpu.initial_registers[r] >> shift)), @as(u16, @truncate(cpu.final_registers[r] >> shift)) });
        }
        try words.append(a, cpu.register_clocks[r]);
    }
    try words.append(a, request.sponge.first_id);
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    if (claims.len != plan.claim_count) return error.InvalidWideCpuClaims;
    const ls = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
    const dword = try T.dwordCounts(setup.bridges, request.ls_dword);
    for (plan.slots) |slot| {
        var rows: u32 = 0;
        var calls: u32 = 0;
        var first_id: u32 = 1;
        switch (slot.origin) {
            .core => |role| rows = switch (role) {
                .initial => @intCast(request.base.memory.initial.len),
                .terminal => @intCast(request.base.memory.terminal.len),
                .ls => ls.head,
                .ls_tail => ls.tail,
                .multiplication => request.base.multiplication_requests,
                .division => request.base.division_requests,
                else => 0,
            },
            .bridge => |family| {
                calls = request.calls[@intFromEnum(family)];
                first_id = first[@intFromEnum(family)];
            },
            .bulk => |kind| rows = request.bulk.rows(kind),
            .sponge => |kind| rows = request.sponge.rows(kind),
            .dword => |index| rows = dword[index],
        }
        try words.appendSlice(a, &.{ rows, calls, first_id });
    }
    return words.toOwnedSlice(a);
}
