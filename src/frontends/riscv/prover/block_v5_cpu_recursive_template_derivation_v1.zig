//! Independent expected-key reconstruction. RAM/range use original admitted
//! fixed setup; other families retain original fresh verifier-row derivation.
//! Received keys and producer callback results never select expected setup.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Providers = @import("block_v5_recursive_provider_definition_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Profile = Parent.protocol.Profile;
const WordFixed = @import("../recursion/block_v5_word_recursive_fixed_roster_v1.zig");

pub fn OwnedFor(comptime Template: type) type {
    return struct {
        a: std.mem.Allocator,
        template: Template,
        pub fn deinit(self: *@This()) void {
            self.a.free(self.template.schedule);
            self.* = undefined;
        }
    };
}
fn derive(comptime Bus: type, comptime Protocol: type, comptime Template: type, a: std.mem.Allocator, admitted: anytype, capture: anytype, profile: Profile, transcript_capacity: u32) !OwnedFor(Template) {
    if (!std.meta.eql(profile.config(), admitted.config) or transcript_capacity == 0)
        return error.RecursiveTemplateDerivationSecurityMismatch;
    try capture.validate(admitted, admitted.template_id);
    var rows = try Bus.prepare(a, admitted, capture, transcript_capacity);
    defer rows.deinit();
    const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &rows.recursive, profile);
    const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
    const key_id = try key.identity();
    const schedule = try a.dupe(Bus.Wire, rows.wires);
    return .{ .a = a, .template = .{ .key = key, .key_id = key_id, .schedule = schedule } };
}
/// This factory has no proof/capture argument. It reconstructs the expected
/// native memory setup from original admission before any live witness exists.
/// Compact fixed rows die before returning; only the key and routing survive.
pub fn providerPolicyForBackend(comptime family: @import("block_v5_recursive_provider_family_v1.zig").Family, comptime Backend: type, a: std.mem.Allocator, admitted: *const Providers.ForFamily(family).Prepared, profile: Profile, transcript_capacity: u32) !OwnedFor(@import("block_v5_recursive_provider_store_v1.zig").ForFamily(family).TemplatePolicy) {
    comptime if (family != .ram_lanes and family != .range16) @compileError("independent word setup requires RAM or range admission");
    if (!std.meta.eql(profile.config(), admitted.config) or transcript_capacity == 0)
        return error.RecursiveTemplateDerivationSecurityMismatch;
    const Fixed = WordFixed.ForFamily(if (family == .ram_lanes) .ram_lanes else .range16);
    const limits = WordFixed.Limits{ .max_bytes = admitted.limits.max_preparation_bytes };
    var fixed = try Fixed.ForBackend(Backend).deriveKeyAndScheduleForPolicy(a, admitted, admitted.template_id, transcript_capacity, profile, limits);
    errdefer fixed.deinit();
    return .{ .a = a, .template = .{ .key = fixed.key, .key_id = try fixed.key.identity(), .schedule = fixed.wires } };
}

/// Cheap live metadata parity before producer admission. The original producer
/// independently commits live fixed columns and admits the expected root; fresh
/// receivers authenticate that same root on reconstruction. This is not proof
/// authority and cannot replace either check.
pub fn requirePolicyRows(comptime family: @import("block_v5_recursive_provider_family_v1.zig").Family, template: anytype, prepared: anytype, profile: Profile) !void {
    // Original live key derivation partitions G rows before deriving geometry.
    // Independent setup already uses that exact partition; retain the original
    // live operation before comparing logs and committing the producer rows.
    try prepared.recursive.rows.partitionHashRows();
    try requirePolicyMetadata(family, template, prepared.recursive.context, try @import("../recursion/blake3_parent_fixed_key_v1.zig").rowLogs(prepared.recursive.rows.fixed), prepared.wires, profile);
}
/// Metadata only: no original admission, key factory or proof authority is
/// produced. The live wrapper supplies original already-partitioned row logs.
pub fn requirePolicyMetadata(comptime family: @import("block_v5_recursive_provider_family_v1.zig").Family, template: anytype, context: Parent.protocol.Context, logs: [@import("../recursion/air/blake3_parent_row_storage.zig").Airs.len]u32, wires: []const Providers.ForFamily(family).Bus.Wire, profile: Profile) !void {
    comptime if (family != .ram_lanes and family != .range16) @compileError("independent word parity requires RAM or range");
    const key = template.key;
    if (key.profile != profile or !std.meta.eql(key.config, profile.config()) or
        !std.meta.eql(key.context, context) or
        !std.meta.eql(key.config, key.context.child_config) or
        !std.meta.eql(try key.identity(), template.key_id) or
        !std.meta.eql(try Providers.ForFamily(family).Bus.scheduleDigest(template.schedule), key.public_schedule_digest) or
        template.schedule.len != wires.len) return error.UntrustedIndependentWordTemplate;
    for (template.schedule, wires) |expected, actual| if (!std.meta.eql(expected, actual)) return error.UntrustedIndependentWordTemplate;
    if (!std.meta.eql(key.log_sizes, logs)) return error.UntrustedIndependentWordTemplate;
}
pub fn provider(comptime family: @import("block_v5_recursive_provider_family_v1.zig").Family, a: std.mem.Allocator, proof: *const Providers.ForFamily(family).Native.Proof, admitted: *const Providers.ForFamily(family).Prepared, profile: Profile, transcript_capacity: u32) !OwnedFor(@import("block_v5_recursive_provider_store_v1.zig").ForFamily(family).TemplatePolicy) {
    const D = Providers.ForFamily(family);
    const Capture = switch (family) {
        .range16 => @import("block_v5_range16_recursive_capture_v1.zig"),
        .ram_lanes => @import("block_v5_ram_lanes_recursive_capture_v1.zig"),
        .program_table => @import("block_v5_program_table_recursive_capture_v1.zig"),
        .native_lookup => @import("block_v5_native_lookup_recursive_capture_v1.zig"),
    };
    if (family == .ram_lanes or family == .range16) {
        var expected = try providerPolicyForBackend(family, Cpu, a, admitted, profile, transcript_capacity);
        errdefer expected.deinit();
        // Mandatory original-proof verification remains. Its private capture
        // is discarded and supplies no expected-key geometry or witness rows.
        var checked = try Capture.ForBackend(Cpu).verifyBorrowed(a, proof, admitted);
        defer checked.deinit();
        return expected;
    }
    var capture = try Capture.ForBackend(Cpu).verifyBorrowed(a, proof, admitted);
    defer capture.deinit();
    return derive(D.Bus, D.Protocol, @import("block_v5_recursive_provider_store_v1.zig").ForFamily(family).TemplatePolicy, a, admitted, &capture, profile, transcript_capacity);
}
pub fn arithmetic(a: std.mem.Allocator, proof: *const @import("block_v5_precompile_family_proof_v1.zig").Proof, admitted: *const @import("block_v5_caller_arithmetic_recursive_admission_v1.zig").Prepared, profile: Profile, transcript_capacity: u32) !OwnedFor(Executions.ForFamily(.caller_arithmetic).Template) {
    const D = Executions.ForFamily(.caller_arithmetic);
    var capture = try @import("block_v5_caller_arithmetic_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, proof, admitted);
    defer capture.deinit();
    return derive(D.Bus, D.Protocol, D.Template, a, admitted, &capture, profile, transcript_capacity);
}
pub fn callerFused(a: std.mem.Allocator, original: *const @import("block_v5_precompile_family_proof_v1.zig").Proof, fused: *const @import("block_v5_caller_fused_proof_v1.zig").Proof, pair: *const @import("block_v5_caller_recursive_admission_pair_v1.zig").Pair, profile: Profile, transcript_capacity: u32) !OwnedFor(Executions.ForFamily(.caller_fused).Template) {
    const D = Executions.ForFamily(.caller_fused);
    // The independently owned pair binds arithmetic/fused roots, frames,
    // witness, exact caller recipe and original execution index together.
    try pair.require();
    var caller = try @import("block_v5_caller_arithmetic_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, original, &pair.arithmetic);
    defer caller.deinit();
    var capture = try @import("block_v5_caller_fused_recursive_capture_v1.zig").ForBackend(Cpu).verifyAfterFreshCaller(a, fused, &caller.receipt, &pair.fused);
    defer capture.deinit();
    return derive(D.Bus, D.Protocol, D.Template, a, &pair.fused, &capture, profile, transcript_capacity);
}
pub fn nativeFused(a: std.mem.Allocator, proof: *const @import("block_v5_native_capacity_fused_proof_v1.zig").Proof, admitted: *const @import("block_v5_native_capacity_fused_recursive_admission_v1.zig").Prepared, profile: Profile, transcript_capacity: u32) !OwnedFor(Executions.ForFamily(.native_capacity_fused).Template) {
    const D = Executions.ForFamily(.native_capacity_fused);
    var capture = try @import("block_v5_native_capacity_fused_recursive_capture_v1.zig").ForBackend(Cpu).verifyBorrowed(a, proof, admitted, admitted.template_id);
    defer capture.deinit();
    return derive(D.Bus, D.Protocol, D.Template, a, admitted, &capture, profile, transcript_capacity);
}
