//! One joined lifecycle: core providers construct once, RAM contributes narrow
//! range metadata, then all physical claims close under one PCS transcript.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const CPU = A.CPU;
const CS = A.CS;
const RAM = A.RAM;
const R = A.R;
const I = A.I;
const P = A.P;
const Column = A.Column;
const Q = A.Q;
const engine = A.engine;
const MainArena = @import("rv64_authenticated_main_arena.zig").MainArena;
const Stage = @import("stwo_prover_api").stage_profile;
pub const DiagnosticOptions = struct { cpu: bool = false, ram: bool = false, arithmetic: bool = false, crypto: bool = false };
pub fn proveTrace(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source) !A.Bundle {
    return prove(a, owner, public, trace, source_value, true, null, null, .{});
}
/// Test-only storage oracle. Proof suite, constraints and transcript are equal.
pub fn proveReference(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source) !A.Bundle {
    if (!@import("builtin").is_test) return error.TestOnlyReference;
    return prove(a, owner, public, trace, source_value, false, null, null, .{});
}
pub fn proveProfiled(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source, recorder: *Stage.Recorder) !A.Bundle {
    return prove(a, owner, public, trace, source_value, true, recorder, null, .{});
}
pub fn proveArena(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source, arena: *MainArena, recorder: ?*Stage.Recorder) !A.Bundle {
    return prove(a, owner, public, trace, source_value, true, recorder, arena, .{});
}
/// Explicit diagnostics retain an extra CPU main snapshot. Never enabled by
/// the production path; rows use the exact same polynomial authority and FS.
pub fn proveDiagnosed(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source, arena: ?*MainArena, recorder: ?*Stage.Recorder, diagnostics: DiagnosticOptions) !A.Bundle {
    return prove(a, owner, public, trace, source_value, true, recorder, arena, diagnostics);
}
fn prove(a: std.mem.Allocator, owner: *const A.Prepared, public: A.Public, trace: *CPU.Trace, source_value: ?RAM.Source, compact: bool, recorder: ?*Stage.Recorder, arena: ?*MainArena, diagnostics: DiagnosticOptions) !A.Bundle {
    try owner.validate(public);
    if ((source_value != null) != (public.ram != null)) return error.InvalidAuthenticatedRamRoster;
    var source = source_value;
    if (source) |value| if (!std.meta.eql(value.rows.shapes, try public.ram.?.shapes(public.geometry))) return error.InvalidAuthenticatedRamGeometry;
    var policy: ?R.policy_provider.Trace = if (source) |value| try R.policy_provider.Trace.init(a, owner.policy, value.policy_counts) else null;
    defer if (policy) |*value| value.deinit();
    var sources = try CS.ProvingSources.init(a, &owner.cpu, public.cpu, trace, if (source) |*value| &value.byte_counts else null);
    defer sources.deinit();
    sources.stage_recorder = recorder;
    var original_cpu_main = if (diagnostics.cpu) try a.dupe(A.core.fields.m31.M31, trace.cpu.main) else &.{};
    defer a.free(original_cpu_main);
    var original_div_main = if (diagnostics.arithmetic and trace.division != null) try a.dupe(A.core.fields.m31.M31, trace.division.?.main) else &.{};
    defer a.free(original_div_main);
    var original_mul_main = if (diagnostics.arithmetic and trace.multiplication != null) try a.dupe(A.core.fields.m31.M31, trace.multiplication.?.main) else &.{};
    defer a.free(original_mul_main);
    const KDiagnostic = @import("rv64_keccak_native_diagnostic.zig");
    var kdiag: ?KDiagnostic.Snapshot = if (diagnostics.crypto and trace.crypto != null) try KDiagnostic.Snapshot.init(a, &trace.crypto.?) else null;
    defer if (kdiag) |*value| value.deinit();
    var original_ram_provider = if (diagnostics.ram and source != null) try a.dupe(A.core.fields.m31.M31, source.?.provider_main) else &.{};
    defer a.free(original_ram_provider);
    var channel = P.Channel{};
    try A.mixPublic(&channel, owner, public);
    var scheme = try A.Scheme.init(a, P.config());
    if (compact) scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    {
        var commit_stage = try Stage.StageScope.begin(recorder, "fixed_commit", "Prepare and commit fixed columns");
        defer commit_stage.end();
        const fixed = try owner.fixedColumns(a);
        defer a.free(fixed);
        try scheme.commitBorrowedStreamingWithRecorder(a, fixed, 8, recorder, &channel);
    }
    {
        var commit_stage = try Stage.StageScope.begin(recorder, "main_commit", "Prepare and commit shared main columns");
        defer commit_stage.end();
        const cpu_main = try sources.mainColumns();
        defer a.free(cpu_main);
        var ram_main: ?RAM.MainCommit = if (source != null and arena == null) try source.?.takeMainForCommit(a, &policy.?) else null;
        defer if (ram_main) |*value| value.deinit(a);
        const ram_borrowed: ?[]Column = if (source != null and arena != null) try RAM.mainColumnsWithoutByte(a, source.?, &policy.?) else null;
        defer if (ram_borrowed) |value| a.free(value);
        const main = try A.join(a, cpu_main, if (ram_main) |value| value.columns else ram_borrowed orelse &.{});
        defer a.free(main);
        if (arena) |value| {
            try value.sealFromColumns(main);
            // Drop borrowed aliases while the outer arena still owns its storage.
            // A failed consuming PCS call must leave no dangling source views.
            try sources.releaseMain();
            if (source) |*ram_source| try ram_source.releaseBorrowedMain();
            const owned = try value.takeForCommit(a);
            // PCS consumes the original one-arena backing and headers on ALL paths.
            try scheme.commitOwnedWithRecorderAndBacking(a, owned.columns, owned.backing, recorder, &channel);
        } else {
            try scheme.commitBorrowedStreamingWithRecorder(a, main, 8, recorder, &channel);
            try sources.releaseMain();
        }
        if (ram_main) |*value| {
            value.deinit(a);
            ram_main = null;
        }
    }
    // Every consumer/provider main tree is sealed before shared challenges.
    var interaction_stage = try Stage.StageScope.begin(recorder, "authenticated_interaction", "Generate all shared physical interactions");
    var interaction_stage_open = true;
    defer if (interaction_stage_open) interaction_stage.end();
    const ch = try A.draw(a, &channel, owner);
    const cpu_claims = try sources.generate(ch.cpu);
    var ram_stage = try Stage.StageScope.begin(recorder, "ram_interaction", "Generate private RAM callers, hash and policy providers");
    var ram_stage_open = true;
    defer if (ram_stage_open) ram_stage.end();
    var ram_inter: ?I.Interaction = if (source) |value| try value.generateInteractions(a, &ch.ram.?) else null;
    defer if (ram_inter) |*value| value.deinit();
    const ram_claims: ?RAM.Claims = if (ram_inter) |*value| .{ .callers = value.claims, .provider = value.provider.claims, .policy = try policy.?.generateInteraction(.{ .policy = ch.ram.?.policy }), .bytes = Q.zero() } else null;
    ram_stage.end();
    ram_stage_open = false;
    const claims = A.Claims{ .cpu = cpu_claims, .ram = ram_claims };
    try A.validateClaims(owner, public, claims, &ch);
    var cpu = try CS.Components.init(&owner.cpu, public.cpu, claims.cpu, ch.cpu);
    var profiles = @import("rv64_component_profiles.zig").Group.init(recorder);
    cpu.setPrivateRecorders(&profiles);
    defer {
        cpu.setPrivateRecorders(null);
        profiles.deinit();
    }
    if (diagnostics.cpu or diagnostics.ram or diagnostics.arithmetic or diagnostics.crypto) {
        var degree = try @import("rv64_cpu_degree_diagnostic.zig").inspect(a, &cpu.base.cpu, 0x4453435945544832);
        defer degree.deinit();
        const json = try std.json.Stringify.valueAlloc(a, .{ .constraints = degree.constraints, .samples = degree.samples, .violations = degree.violations }, .{});
        defer a.free(json);
        std.debug.print("RV64_CPU_DEGREE_DIAGNOSTIC {s}\n", .{json});
        if (degree.violations.len != 0) return error.UndeclaredCpuConstraintDegree;
    }
    if (diagnostics.cpu) {
        const columns = try sources.interactionColumns();
        defer a.free(columns);
        const result = try @import("rv64_cpu_diagnostic.zig").inspect(a, &owner.cpu, public.cpu, trace, original_cpu_main, claims.cpu, ch.cpu, columns, .{});
        const json = try std.json.Stringify.valueAlloc(a, result, .{});
        defer a.free(json);
        std.debug.print("RV64_CPU_DIAGNOSTIC {s}\n", .{json});
        if (result.first_failure != null) return error.NativeCpuConstraintViolation;
        a.free(original_cpu_main);
        original_cpu_main = &.{};
    }
    if (diagnostics.ram) if (source) |*value| {
        const failure = try @import("rv64_ram_diagnostic.zig").audit(value, &ch.ram.?, &ram_inter.?);
        const ram_json = try std.json.Stringify.valueAlloc(a, failure, .{});
        defer a.free(ram_json);
        std.debug.print("RV64_RAM_DIAGNOSTIC {s}\n", .{ram_json});
        if (failure != null) return error.NativeRamConstraintViolation;
        const provider_failure = try @import("rv64_ram_diagnostic.zig").auditProviders(value, &ch.ram.?, &ram_inter.?, original_ram_provider, &policy.?);
        const provider_json = try std.json.Stringify.valueAlloc(a, provider_failure, .{});
        defer a.free(provider_json);
        std.debug.print("RV64_RAM_PROVIDER_DIAGNOSTIC {s}\n", .{provider_json});
        if (provider_failure != null) return error.NativeRamProviderConstraintViolation;
        a.free(original_ram_provider);
        original_ram_provider = &.{};
    };
    if (diagnostics.arithmetic) {
        const Diag = @import("rv64_arithmetic_diagnostic.zig");
        const div_failure = if (trace.division) |*value| try Diag.division(value, original_div_main, ch.cpu.division, claims.cpu.division.neg()) else null;
        const mul_failure = if (trace.multiplication) |*value| try Diag.multiplication(value, original_mul_main, ch.cpu.multiplication.?, ch.cpu.cpu.bytes, claims.cpu.multiplication_provider) else null;
        const json = try std.json.Stringify.valueAlloc(a, .{ .division = div_failure, .multiplication = mul_failure }, .{});
        defer a.free(json);
        std.debug.print("RV64_ARITHMETIC_DIAGNOSTIC {s}\n", .{json});
        if (div_failure != null or mul_failure != null) return error.NativeArithmeticConstraintViolation;
        a.free(original_div_main);
        original_div_main = &.{};
        a.free(original_mul_main);
        original_mul_main = &.{};
    }
    if (kdiag) |*value| {
        const failure = try value.inspect(&trace.crypto.?, ch.cpu.keccak, ch.cpu.bridge, .{ .permutation = claims.cpu.permutation, .chi = claims.cpu.chi, .xor5 = claims.cpu.xor5, .bridge = claims.cpu.bridge });
        const json = try std.json.Stringify.valueAlloc(a, failure, .{});
        defer a.free(json);
        std.debug.print("RV64_KECCAK_DIAGNOSTIC {s}\n", .{json});
        if (failure != null) return error.NativeKeccakConstraintViolation;
        value.deinit();
        kdiag = null;
    }
    if (source) |value| try value.retireMetadata();
    interaction_stage.end();
    interaction_stage_open = false;
    var ram: ?RAM.Components = if (public.ram) |counts| try RAM.Components.initAt(try counts.shapes(public.geometry), owner.policy, &ch.ram.?, &claims.ram.?, try owner.offsets(a, public)) else null;
    {
        var commit_stage = try Stage.StageScope.begin(recorder, "interaction_commit", "Prepare and commit shared interaction columns");
        defer commit_stage.end();
        const cpu_inter = try sources.interactionColumns();
        defer a.free(cpu_inter);
        const ram_columns: ?[]Column = if (ram_inter) |*value| try RAM.interactionColumnsWithoutByte(a, owner.shapes.?, value, &policy.?) else null;
        defer if (ram_columns) |value| a.free(value);
        const inter = try A.join(a, cpu_inter, ram_columns orelse &.{});
        defer a.free(inter);
        A.mixClaims(&channel, public, claims);
        try scheme.commitBorrowedStreamingWithRecorder(a, inter, 8, recorder, &channel);
    }
    // The PCS now owns independent commitment/evaluation storage. Match the
    // standalone full/lean lifecycle: retain claims, retire duplicate source rows.
    try sources.releaseCommittedInteractions();
    if (ram_inter) |*value| {
        value.deinit();
        ram_inter = null;
    }
    if (policy) |*value| {
        value.allocator.free(value.interaction);
        value.interaction = &.{};
    }
    var cpu_handles: [CPU.MAX_COMPONENTS]engine.air.component_prover.ComponentProver = undefined;
    const n = cpu.provers(&cpu_handles);
    var handles: [CPU.MAX_COMPONENTS + 10]engine.air.component_prover.ComponentProver = undefined;
    @memcpy(handles[0..n], cpu_handles[0..n]);
    const extra: usize = if (ram) |*value| blk: {
        const rs = try value.proversWithoutByte();
        @memcpy(handles[n..][0..10], &rs);
        break :blk 10;
    } else 0;
    owns_scheme = false;
    var extended = engine.prove.proveExWithRecorder(A.B, P.Hasher, P.MerkleChannel, a, handles[0 .. n + extra], &channel, scheme, false, recorder) catch |err| {
        // Error returns also join worker lifetimes. Keep the proving error if
        // optional telemetry cannot be adopted while handling that failure.
        profiles.join() catch {};
        return err;
    };
    defer extended.aux.deinit(a);
    errdefer extended.proof.deinit(a);
    try profiles.join();
    return .{ .claims = claims, .proof = extended.proof };
}
