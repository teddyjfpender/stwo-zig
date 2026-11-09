//! Native-GKR CPU PCS statement core. Typed execution admission is supplied by
//! typed_cpu/typed_leaf around this SAME public-handle projection.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const V = @import("mod.zig");
const Public = @import("frame.zig");
const Hash = @import("canon_hash.zig");
const Child = @import("native_gkr_child.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const Types = @import("../../word16_global_execution/services/types.zig");
const Legacy = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Native = @import("../../word16_global_execution/services/native_gkr/v2.zig");
const S = @import("../../word16_global_execution/services/native_gkr/section.zig");
const Plan = @import("../../word16_global_execution/services/native_gkr/native_roster.zig");
const CPU = @import("../../word16_global_execution/services/native_gkr/cpu_component.zig");
const Compact = @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig");
const Class = @import("../../word16_global_execution/services/native_gkr/class_authority.zig");
const Rungs = @import("../../word16_global_execution/services/native_gkr/canonical_rungs.zig");
const Canon = @import("../../../../products/ethereum/statement/cpu/word16_global_execution/ethereum/canon_native.zig");
const F = C.F;
pub const Authority = struct { family: Canon.Family, rung: u32, ordinal: u32, steps_in: u64, execution: [32]u8 };
pub const PublicData = struct { main: CPU.Authority.PublicFor(F), source: [CPU.Authority.Source.Public.count]F };
fn base(ctx: *C.Context, word: Public.Word) !F {
    return C.base(try circuit.native_verifier.channel.wordToM31(C.Q, ctx, word));
}
fn flag(ctx: *C.Context, count: F, native: u32) !F {
    const nonzero = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else C.O.one());
    const inverse = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else try C.O.fromBase(core.fields.m31.M31.fromCanonical(native)).inv());
    try ctx.noteWitnessHint(nonzero.c0.v, .is_nonzero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(nonzero.c1.v, .zero, ctx.zero(), ctx.zero());
    try ctx.noteWitnessHint(inverse.c0.v, .pointwise_inverse_or_zero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(inverse.c1.v, .zero, ctx.zero(), ctx.zero());
    try C.eq(ctx, nonzero.mul(nonzero.sub(F.one())), F.zero());
    try C.eq(ctx, count.mul(F.one().sub(nonzero)), F.zero());
    try C.eq(ctx, count.mul(inverse), nonzero);
    return nonzero;
}
fn sample(values: []const []const []const F, tree: usize, column: usize, index: usize, count: usize) !F {
    if (tree >= values.len or column >= values[tree].len or values[tree][column].len != count or index >= count) return error.InvalidRv64MaskShape;
    return values[tree][column][index];
}
pub const Statement = struct {
    setup: *const R.CpuSetup,
    source_plan: Legacy.Plan,
    native_plan: Plan.Plan,
    config: W.PcsConfig,
    binding: Public.Binding,
    chain_inputs: @import("cpu_leaf.zig").Statement.ChainInputs,
    compact_header: Hash.CompactHeader,
    compact_metadata: Hash.CompactCpuMetadata,
    statement: Public.Digest,
    main: C.Hash,
    chi: Public.Digest,
    global: Native.GlobalSplitFor(F),
    publics: []PublicData,
    shared: CPU.Authority.SharedFor(F),
    wired: Child.Wired,
    pending: ?Child.Pending = null,
    bindings: []Native.Binding.ParametersFor(F) = &.{},
    pub fn init(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [Types.FAMILIES]u32, authority: Authority, chi: [32]u8, physical: *const V.Proof, section: *const S.Section, config: W.PcsConfig, binding: Public.Binding) !Statement {
        const ctx = frame.ctx;
        const a = ctx.scratch();
        try W.validateCandidateConfig(config);
        if (binding.profile != W.candidateProfile(config)) return error.WideCandidateProfileMismatch;
        if (physical.commitments.len != 4) return error.NativeGkrCpuProofShape;
        const vector = Canon.cpuVector(.{ .geometry = setup.materials.geometry, .bridges = setup.bridges });
        const rung = Rungs.cpuRung(authority.family, vector) orelse return error.NativeChainNotStrict;
        if (rung != authority.rung) return error.NativeChainNotStrict;
        const structure = try Class.cpuStructure(a, try Rungs.cpuStructure(authority.family, rung, Canon.layoutFlags(setup.materials.geometry)), setup);
        try Public.requireDigest(ctx, physical.commitments[0], binding.root);
        var source_plan = try Legacy.Plan.init(a, setup);
        errdefer source_plan.deinit();
        var native_plan = try Plan.cpu(a, setup);
        errdefer native_plan.deinit();
        var inputs = try Compact.fromRequest(a, setup, &source_plan, request, first);
        defer inputs.deinit(a);
        const relations: @import("../../word16_global_execution/services/gkr_local/manifest.zig").Relations = .{ .ram = true, .kio = setup.bridges.keccak != null or setup.bridges.sponge.any(), .wire = @import("../../word16_global_execution/services/gkr_local/cpu_worker.zig").wirePresent(setup.bridges) };
        const relation_bits = @as(u32, @intFromBool(relations.ram)) | (@as(u32, @intFromBool(relations.kio)) << 1) | (@as(u32, @intFromBool(relations.wire)) << 2);
        const metadata = try Compact.metadataFor(request, first, authority.ordinal, authority.steps_in, authority.execution, relation_bits);
        const compact_header = try Hash.constantCompactHeader(ctx, .{ .domain = Compact.domainDigest(), .class_key = structure, .program = setup.materials.program.identity, .config_identity = try Compact.configIdentity(config), .fixed_identity = binding.identity, .fixed_root = binding.root });
        const compact_metadata = try Hash.guessCompactCpuMetadata(ctx, metadata);
        const chain_inputs = try Hash.guessCompactCpuInputs(ctx, inputs);
        const statement = try Hash.compactCpu(ctx, compact_header, chain_inputs, compact_metadata);
        const chi_words = try frame.guessDigest(chi);
        const shared = try Public.drawShared(ctx, chi_words);
        const public_data = try a.alloc(PublicData, source_plan.slots.len);
        var source_public = [_]F{F.zero()} ** CPU.Authority.Source.Public.count;
        const SP = CPU.Authority.Source.Public;
        source_public[SP.epoch] = try base(ctx, chain_inputs.epoch);
        source_public[SP.sponge_first_id] = try base(ctx, chain_inputs.sponge_first);
        source_public[SP.initial_pc] = (try base(ctx, chain_inputs.initial_pc[0])).add((try base(ctx, chain_inputs.initial_pc[1])).mul(F.fromBase(core.fields.m31.M31.fromCanonical(65536))));
        for (0..32) |r| {
            for (0..4) |i| {
                source_public[SP.initial_registers + 4 * r + i] = try base(ctx, chain_inputs.initial_registers[r][i]);
                source_public[SP.final_registers + 4 * r + i] = try base(ctx, chain_inputs.final_registers[r][i]);
            }
            source_public[SP.register_clocks + r] = try base(ctx, chain_inputs.register_clocks[r]);
        }
        var cpu: A.word16_execution.types.InputsFor(F) = .{ .steps = try base(ctx, chain_inputs.steps), .initial_pc = undefined, .final_pc = undefined, .epoch = source_public[SP.epoch], .wide_clock = A.word16_execution.layout.wideClock(setup.materials.geometry.cpu_log) };
        for (&cpu.initial_pc, &cpu.final_pc, chain_inputs.initial_pc, chain_inputs.final_pc) |*initial, *final, initial_word, final_word| {
            initial.* = try base(ctx, initial_word);
            final.* = try base(ctx, final_word);
        }
        for (public_data, 0..) |*public, index| {
            const rows = try base(ctx, chain_inputs.rows[index]);
            const calls = try base(ctx, chain_inputs.calls[index]);
            public.* = .{ .main = .{ .cpu = cpu, .rows = rows, .nonempty = try flag(ctx, rows, inputs.rows[index]), .span = .{ .calls = calls, .first_id = try base(ctx, chain_inputs.first_ids[index]), .nonempty = try flag(ctx, calls, inputs.calls[index]) } }, .source = source_public };
        }
        return .{ .setup = setup, .source_plan = source_plan, .native_plan = native_plan, .config = config, .binding = binding, .chain_inputs = chain_inputs, .compact_header = compact_header, .compact_metadata = compact_metadata, .statement = statement, .main = physical.commitments[1], .chi = chi_words, .global = .{}, .publics = public_data, .shared = .{ .ram = shared.ram, .kio = shared.kio, .wire = shared.wire }, .wired = try Child.wire(ctx, &native_plan.roster, section) };
    }
    pub fn deinit(self: *Statement, ctx: *C.Context) void {
        if (self.pending) |*pending| pending.deinit(ctx);
        self.pending = null;
    }
    pub fn mixPublic(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        try Public.mixWorkerBegin(ctx, channel, self.config, .cpu, self.compact_metadata.ordinal, self.statement, self.binding);
    }
    pub fn nTreesBeforeChallenges(_: *Statement) usize {
        return 2;
    }
    pub fn drawChallenges(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        if (self.pending != null) return error.NativeGkrCpuProofPhase;
        self.pending = try Child.verify(ctx, channel, .{ .ordinal = self.compact_metadata.ordinal, .statement = self.statement, .fixed = self.compact_header.fixed_root, .main = self.main.words, .shared = self.chi }, &self.native_plan.roster, &self.wired);
        self.global = self.pending.?.global;
        self.bindings = try ctx.scratch().alloc(Native.Binding.ParametersFor(F), self.native_plan.spans.len);
        for (self.bindings, 0..) |*binding, index| binding.* = try Native.Binding.parametersFor(F, ctx.scratch(), &self.native_plan.roster, index, self.pending.?.artifact.ood_point, self.pending.?.artifact.claims_to_verify_by_instance, &self.pending.?.binding);
    }
    pub fn mixClaims(self: *Statement, ctx: *C.Context, channel: *C.Channel) !void {
        if (self.pending == null) return error.NativeGkrCpuProofPhase;
        const g = self.global;
        try Public.mixManifestAndClaims(ctx, channel, self.chi, &.{ g.ram_internal.add(g.ram_initial).add(g.ram_terminal), g.kio, g.wire });
    }
    pub fn globalLog(self: *const Statement) u32 {
        var log: u32 = 0;
        for (self.native_plan.roster.components) |component| log = @max(log, component.row_log);
        return log;
    }
    pub fn evalComposition(self: *Statement, ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        const pending = &(self.pending orelse return error.NativeGkrCpuProofPhase);
        const a = ctx.scratch();
        var accumulator = E.lane.PointAccumulator(F).init(alpha);
        for (self.source_plan.slots, self.native_plan.spans, self.publics, self.bindings) |slot, span, public, binding| {
            const descriptor = CPU.Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = self.setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = self.setup.materials.geometry.cpu_compact_decode };
            const shape = try CPU.Authority.shape(descriptor);
            const fixed = try a.alloc(F, shape.fixed);
            defer a.free(fixed);
            const main = try a.alloc(F, shape.main);
            defer a.free(main);
            const previous = try a.alloc(F, shape.main);
            defer a.free(previous);
            for (fixed, 0..) |*value, c| value.* = try sample(sampled, 0, span.fixed_offset + c, 0, 1);
            for (main, previous, 0..) |*value, *prior, c| {
                const shifted = CPU.Authority.previousMain(descriptor, c);
                value.* = try sample(sampled, 1, span.main_offset + c, 0, if (shifted) 2 else 1);
                prior.* = if (shifted) try sample(sampled, 1, span.main_offset + c, 1, 2) else F.zero();
            }
            var eq: [8]F = undefined;
            var next: [8]F = undefined;
            var prefix: [8]F = undefined;
            var prior: [8]F = undefined;
            for (0..8) |c| {
                eq[c] = try sample(sampled, 2, span.inter_offset + c, 0, 2);
                next[c] = try sample(sampled, 2, span.inter_offset + c, 1, 2);
                prefix[c] = try sample(sampled, 2, span.inter_offset + 8 + c, 0, 2);
                prior[c] = try sample(sampled, 2, span.inter_offset + 8 + c, 1, 2);
            }
            const local = try A.geometry.localPointFor(F, .{ .x = point.x, .y = point.y }, self.globalLog(), slot.log);
            const anchors = try CPU.Authority.MlePoint.evalAnchorsFor(F, slot.log, local);
            var sink = E.SinkFor(F){ .accumulator = &accumulator, .scale = try A.geometry.denominatorInverseFor(F, .{ .x = point.x, .y = point.y }, self.globalLog(), slot.log) };
            const weights: [4][]const F = .{ binding.weights[0], binding.weights[1], binding.weights[2], binding.weights[3] };
            try CPU.emitFor(F, descriptor, public.main, &public.source, &pending.local, &self.shared, weights, pending.binding.gamma, binding.target_per_row, .{ .eq = F.fromPartialEvals(eq), .eq_next2 = F.fromPartialEvals(next), .prefix = F.fromPartialEvals(prefix), .prefix_previous = F.fromPartialEvals(prior) }, .{ .first = anchors[0], .second = anchors[1], .carry = try CPU.Authority.MlePoint.evalCarryQuotientFor(F, &binding.point, local), .eq0 = binding.point.eq0, .eq1 = binding.point.eq1 }, fixed, main, previous, &sink);
            if (sink.count != span.constraints) return error.NativeGkrCpuProofShape;
        }
        return accumulator.finalize();
    }
};

test "native GKR CPU statement verifier contract is fully typed" {
    try std.testing.expect(@intFromPtr(&Statement.init) != 0);
    try std.testing.expect(@intFromPtr(&Statement.evalComposition) != 0);
}
