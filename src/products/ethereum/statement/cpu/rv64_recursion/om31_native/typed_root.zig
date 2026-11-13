//! Ethereum semantics of an ALREADY AUTHENTICATED 180-word root. This helper
//! does not verify a STARK or admit its key. The root entrypoint must first
//! verify under a source-derived key in its independently pinned T_rec.
const Types = @import("stwo_riscv_cpu_integration").rv64_services_types;
const std = @import("std");
const Core = @import("stwo_core");
const A = @import("ethereum_frontend_component").rv64_air;
const Summary = @import("stwo_riscv_cpu_integration").rv64_om31_typed_summary;
const Canon = @import("stwo_riscv_cpu_integration").rv64_native_schema;
const Protocol = @import("stwo_riscv_cpu_integration").rv64_execution.global.protocol;
const Execution = @import("stwo_riscv_cpu_integration").rv64_gkr_execution;
const Fixed = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority_set;
const Manifest = @import("stwo_riscv_cpu_integration").rv64_gkr_manifest;
const Boundary = @import("stwo_riscv_cpu_integration").rv64_execution.services.gkr.expected_boundary;
const Terminal = @import("../../word16_global_execution/ethereum/terminal.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Memory = @import("stwo_riscv_cpu_integration").rv64_execution.memory.statement;
const Worker = @import("stwo_riscv_cpu_integration").rv64_gkr_worker_protocol;
const Table = @import("stwo_riscv_cpu_integration").rv64_vk_table;
const P = Core.fields.m31.Modulus;
pub const Counter = Summary.Counter;
/// Every field here is receiver policy/source authority. Never hydrate this
/// object from a proof's table roots, source IDs or allocation parameters.
pub const Authority = struct {
    image: *const Image.Owner,
    program_identity: [32]u8,
    native_config: Worker.PcsConfig,
    tnat: [32]u8,
    trec: [32]u8,
    max_total_steps: u64,
    max_public_cells: usize = 1 << 22,
    /// Source profile policy. Classic C1/C2 contribute zero here.
    outer_gkr_wrappers: u32 = 0,
    pub fn expected(self: Authority, public: Public) !Protocol.Expected {
        if (self.max_total_steps == 0 or public.total_steps == 0 or public.total_steps >= P or public.total_steps > self.max_total_steps) return error.TypedRootStepBudget;
        if (self.image.max_prefix_steps == 0 or self.image.max_prefix_steps >= 1 << 23) return error.InvalidExecutionBudget;
        return .{
            .program_identity = self.program_identity,
            .admission = .{ .image = Memory.fromOwner(self.image), .image_identity = self.image.identity, .initial_pc = self.image.initial_pc, .initial_registers = self.image.initial_registers, .max_prefix_steps = self.image.max_prefix_steps },
            .total_steps = public.total_steps,
            .max_total_steps = self.max_total_steps,
            .final_pc = self.image.terminal_pc,
            .final_registers = public.final_registers,
        };
    }
};
/// Public execution outputs/terminal witness. They are authenticated by the
/// typed root's constraints and checked below; they are not policy authority.
pub const Public = struct {
    total_steps: u64,
    final_registers: [32]u64,
    initial: []const Memory.Cell,
    terminal: []const Memory.Cell,
};
pub fn outputCommitment(output: [43]u8) [32]u8 {
    var words: [45]u32 = undefined;
    words[0] = 1;
    words[1] = output.len;
    for (output, words[2..]) |byte, *word| word.* = byte;
    return Table.tagged("rv64-m7-typed-terminal/v1", &words);
}
fn same(a: [32]u8, b: [32]u8) bool {
    return std.mem.eql(u8, &a, &b);
}
pub fn checkAuthenticated(authority: Authority, public: Public, summary: Summary.Native) ![43]u8 {
    // Defend callers which constructed Native directly instead of decoding it.
    _ = try Summary.Native.fromWords(&summary.words());
    // Every fold has arity at least two, so a tree over n distinct contiguous
    // leaves has at most 2n-1 outer proofs. Charge folds and wrappers too.
    const outer_count = try std.math.add(u32, 2 * summary.count - 1, authority.outer_gkr_wrappers);
    if (outer_count > 256) return error.OuterGkrProofBudget;
    if (!same(summary.tnat, authority.tnat) or !same(summary.trec, authority.trec) or !same(summary.image, authority.image.identity)) return error.TypedRootAuthority;
    const expected = try authority.expected(public);
    const base = Execution.executionIdentity(authority.native_config, expected);
    const scope = try Fixed.gkrExecutionIdentity(base, authority.native_config);
    if (!same(summary.expected, base) or !same(summary.statement, scope)) return error.TypedRootExecutionScope;
    if (summary.lo != 0 or summary.count != summary.hi + 1 or summary.steps_in != 0 or summary.steps_out != public.total_steps) return error.TypedRootCoverage;
    if (!same(summary.m_in, Canon.chainIv(Canon.versionIdentityV2(Canon.RUNGS, .native_gkr)))) return error.TypedRootChainIv;
    if (!same(summary.chi, Canon.chi(scope, summary.m_out))) return error.TypedRootChi;
    if (!same(summary.s_in, Canon.stateDigest(expected.admission.initial_pc, expected.admission.initial_registers, false)) or
        !same(summary.s_out, Canon.stateDigest(expected.final_pc, expected.final_registers, true))) return error.TypedRootState;
    if (summary.ctr_in[Counter.cpu_next] != 0 or summary.ctr_out[Counter.cpu_next] == 0 or summary.ctr_out[Counter.cpu_next] > summary.count) return error.TypedRootCpuCount;
    const cpu_count = summary.ctr_out[Counter.cpu_next];
    for (0..Types.FAMILIES) |family| {
        if (summary.ctr_in[Counter.cpu_calls + family] != 0 or summary.ctr_in[Counter.truth_next + family] != 1) return error.TypedRootCounters;
        if (family != 0 and summary.ctr_out[Counter.truth_next + family] != @as(u64, summary.ctr_out[Counter.cpu_calls + family]) + 1) return error.TypedRootCounters;
    }
    if (summary.ctr_in[Counter.sponge_next] != @as(u64, summary.ctr_out[Counter.cpu_calls]) + 1 or
        summary.ctr_out[Counter.sponge_next] != summary.ctr_out[Counter.truth_next]) return error.TypedRootSpongeSpan;
    // This profile uses the direct public RAM target, with no MB leaf class.
    for ([_]usize{ Counter.boundary_lo, Counter.boundary_hi }) |index| if (summary.ctr_in[index] != 0 or summary.ctr_out[index] != 0) return error.TypedRootBoundaryClass;
    if (public.initial.len > authority.max_public_cells or public.terminal.len > authority.max_public_cells) return error.TypedRootBoundaryBudget;
    try Protocol.validatePublicBoundary(expected.admission, public.initial, public.terminal, cpu_count);
    // Charge public boundary events even if a leaf's source mass also counted
    // its private boundary chips. Double charging is conservative; netting is not.
    const boundary_mass = try std.math.add(u64, public.initial.len, public.terminal.len);
    if (try std.math.add(u64, summary.mass[0], boundary_mass) >= P) return error.GlobalRamCharacteristicBound;
    const shared = Manifest.drawShared(summary.chi);
    const initial_claim = try Boundary.claim(public.initial, true, shared.ram);
    const terminal_claim = try Boundary.claim(public.terminal, false, shared.ram);
    if (!summary.bus[0].eql(initial_claim.add(terminal_claim).neg()) or !summary.bus[1].isZero() or !summary.bus[2].isZero()) return error.TypedRootBusClosure;
    const final = A.word16_execution.types.Boundary{ .steps = 0, .initial_pc = 0, .initial_registers = @splat(0), .final_pc = expected.final_pc, .final_registers = expected.final_registers, .register_clocks = @splat(0) };
    const output = try Terminal.require(authority.image, final, public.terminal);
    if (!summary.output_seen or !same(summary.output, outputCommitment(output))) return error.TypedRootTerminal;
    return output;
}

test "typed root semantic gate recomputes public RAM target image scope and terminal" {
    const a = std.testing.allocator;
    const Fixture = @import("../../word16_global_execution/ethereum/terminal_fixture.zig").Fixture;
    const Program = @import("stwo_riscv_cpu_integration").rv64_program.Program;
    const Cpu = @import("stwo_riscv_cpu_integration").rv64_cpu_source.Source;
    const Collector = @import("stwo_riscv_cpu_integration").rv64_execution.memory.collector;
    var fixture = try Fixture.init(a, .honest);
    defer fixture.deinit();
    var program = try Program.initWithAuthority(a, &fixture.image.authority);
    defer program.deinit();
    var cpu = try Cpu.capture(a, &program, fixture.boundary, 1, 5, &fixture.tape);
    defer cpu.deinit();
    var memory = try Collector.collect(a, Memory.fromOwner(&fixture.image), cpu.memory.items, 1);
    defer memory.deinit();
    const authority = Authority{ .image = &fixture.image, .program_identity = program.identity, .native_config = Worker.Candidate.configFor(.conjectured128_b2_q108_p20_fold4), .tnat = @splat(11), .trec = @splat(12), .max_total_steps = 64 };
    const public = Public{ .total_steps = fixture.boundary.steps, .final_registers = fixture.boundary.final_registers, .initial = memory.initial, .terminal = memory.terminal };
    const expected = try authority.expected(public);
    const base = Execution.executionIdentity(authority.native_config, expected);
    const scope = try Fixed.gkrExecutionIdentity(base, authority.native_config);
    var summary = Summary.Native{ .tnat = authority.tnat, .trec = authority.trec, .image = fixture.image.identity, .statement = scope, .expected = base, .chi = undefined, .lo = 0, .hi = 0, .count = 1, .m_in = Canon.chainIv(Canon.versionIdentityV2(Canon.RUNGS, .native_gkr)), .m_out = @splat(33), .s_in = Canon.stateDigest(expected.admission.initial_pc, expected.admission.initial_registers, false), .s_out = Canon.stateDigest(expected.final_pc, expected.final_registers, true), .bus = @splat(Core.fields.om31.OM31.zero()), .mass = @splat(0), .ctr_in = @splat(0), .ctr_out = @splat(0), .steps_in = 0, .steps_out = @intCast(public.total_steps), .output = outputCommitment(fixture.image.expected_output), .output_seen = true, .depth = 0 };
    summary.chi = Canon.chi(scope, summary.m_out);
    for (0..Types.FAMILIES) |family| {
        summary.ctr_in[Counter.truth_next + family] = 1;
        summary.ctr_out[Counter.truth_next + family] = 1;
    }
    summary.ctr_in[Counter.sponge_next] = 1;
    summary.ctr_out[Counter.sponge_next] = 1;
    summary.ctr_out[Counter.cpu_next] = 1;
    const shared = Manifest.drawShared(summary.chi);
    summary.bus[0] = (try Boundary.claim(memory.initial, true, shared.ram)).add(try Boundary.claim(memory.terminal, false, shared.ram)).neg();
    try std.testing.expectEqualSlices(u8, &fixture.image.expected_output, &(try checkAuthenticated(authority, public, summary)));
    // This test deliberately supplies an already-authenticated summary: it
    // tests semantic reception, and makes no STARK/production proof claim.
    for (0..15) |mutation| {
        var changed = summary;
        switch (mutation) {
            0 => changed.tnat[0] ^= 1,
            1 => changed.trec[0] ^= 1,
            2 => changed.image[0] ^= 1,
            3 => changed.statement[0] ^= 1,
            4 => changed.expected[0] ^= 1,
            5 => changed.steps_out += 1,
            6 => changed.m_in[0] ^= 1,
            7 => changed.chi[0] ^= 1,
            8 => changed.s_out[0] ^= 1,
            9 => changed.ctr_out[Counter.truth_next + 1] += 1,
            10 => changed.bus[0] = changed.bus[0].add(Core.fields.om31.OM31.one()),
            11 => changed.output[0] ^= 1,
            12 => changed.mass[0] = P - 1,
            13 => changed.ctr_in[Counter.sponge_next] = 0,
            14 => {
                changed.hi = 128;
                changed.count = 129;
            },
            else => unreachable,
        }
        if (checkAuthenticated(authority, public, changed)) |_| return error.TypedRootMutationAccepted else |_| {}
    }
    var bad_terminal = try a.dupe(Memory.Cell, memory.terminal);
    defer a.free(bad_terminal);
    var bad = public;
    bad.terminal = bad_terminal;
    bad_terminal[0].state.rights ^= 1;
    try std.testing.expectError(error.InvalidGlobalMemoryTerminal, checkAuthenticated(authority, bad, summary));
    bad_terminal[0] = memory.terminal[0];
    bad_terminal[0].address += 8;
    try std.testing.expectError(error.GlobalTouchedSetMismatch, checkAuthenticated(authority, bad, summary));
    bad_terminal[0] = memory.terminal[0];
    bad_terminal[0].state.epoch = 2;
    try std.testing.expectError(error.InvalidGlobalMemoryTerminal, checkAuthenticated(authority, bad, summary));
    bad = public;
    bad.initial = memory.initial[1..];
    try std.testing.expectError(error.GlobalTouchedSetMismatch, checkAuthenticated(authority, bad, summary));
}
