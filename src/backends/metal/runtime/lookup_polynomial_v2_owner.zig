//! Fail-closed ownership and job identity for Metal lookup-polynomial V2.
//!
//! The frontend capability contains a borrowed authority pointer. Admission
//! copies that authority, authenticates the exported owner, narrows every
//! physical coordinate to the Metal ABI, and seals the complete job before a
//! pipeline is resolved or any device work can be submitted.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const codegen = @import("lookup_polynomial_v2_codegen.zig");

const Authority = prover_component.LookupPolynomialAuthorityV2;
const Capability = prover_component.LookupPolynomialCapabilityV2;
const Program = prover_component.OwnedLookupPolynomialProgramV2;

pub const job_format_version: u16 = 1;
pub const job_identity_domain = "stwo/metal/lookup-polynomial-v2-job/v1\x00";
pub const Identity = [32]u8;

pub const ProgramOwner = struct {
    authority: Authority,
    program: Program,
    codegen_identity: Identity,

    /// On success ownership moves out of `program`; on failure it is untouched.
    pub fn init(program: *Program, expected: *const Authority) !ProgramOwner {
        try program.validateAgainst(expected);
        const identity = try codegen.codegenIdentity(program);
        const result = ProgramOwner{
            .authority = expected.*,
            .program = program.*,
            .codegen_identity = identity,
        };
        program.* = undefined;
        return result;
    }

    pub fn deinit(self: *ProgramOwner) void {
        self.program.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ProgramOwner) !void {
        try self.program.validateAgainst(&self.authority);
        const actual = try codegen.codegenIdentity(&self.program);
        if (!std.mem.eql(u8, &actual, &self.codegen_identity))
            return error.InvalidCodegenIdentity;
    }

    pub fn kernelName(self: *const ProgramOwner, allocator: std.mem.Allocator) ![]u8 {
        try self.validate();
        return codegen.kernelName(allocator, &self.program);
    }
};

/// Pointer-free copy of the complete physical dispatch authority. Its digest
/// is useful for admission receipts; it is not part of the proof protocol.
pub const JobIdentity = struct {
    format_version: u16 = job_format_version,
    authority: Authority,
    codegen_identity: Identity,
    trace_log_size: u32,
    selector_tree_index: u32,
    selector_column: u32,
    main_tree_index: u32,
    first_main_column: u32,
    main_column_count: u32,
    interaction_tree_index: u32,
    first_interaction_column: u32,
    interaction_column_count: u32,
    constraint_count: u32,
    identity: Identity,

    pub fn init(
        capability: Capability,
        owner: *const ProgramOwner,
        constraint_count: usize,
    ) !JobIdentity {
        try owner.validate();
        if (!std.meta.eql(owner.authority, capability.authority.*))
            return error.InvalidLookupV2Authority;
        var result = JobIdentity{
            .authority = owner.authority,
            .codegen_identity = owner.codegen_identity,
            .trace_log_size = capability.trace_log_size,
            .selector_tree_index = try abiCoordinate(capability.selector_tree_index),
            .selector_column = try abiCoordinate(capability.selector_column),
            .main_tree_index = try abiCoordinate(capability.main_tree_index),
            .first_main_column = try abiCoordinate(capability.first_main_column),
            .main_column_count = try abiCoordinate(capability.main_column_count),
            .interaction_tree_index = try abiCoordinate(capability.interaction_tree_index),
            .first_interaction_column = try abiCoordinate(capability.first_interaction_column),
            .interaction_column_count = try abiCoordinate(capability.interaction_column_count),
            .constraint_count = try abiCoordinate(constraint_count),
            .identity = .{0} ** 32,
        };
        try result.validateStructure(owner);
        result.identity = result.identityDigest();
        try result.validate(owner);
        return result;
    }

    pub fn validate(self: *const JobIdentity, owner: *const ProgramOwner) !void {
        try self.validateStructure(owner);
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.identity))
            return error.InvalidJobIdentity;
    }

    fn validateStructure(self: *const JobIdentity, owner: *const ProgramOwner) !void {
        try owner.validate();
        try self.authority.validate();
        if (self.format_version != job_format_version or
            !std.meta.eql(self.authority, owner.authority) or
            !std.mem.eql(u8, &self.codegen_identity, &owner.codegen_identity))
        {
            return error.InvalidLookupV2Authority;
        }
        if (self.trace_log_size == std.math.maxInt(u32) or
            self.main_column_count == 0 or
            self.constraint_count == 0 or
            self.constraint_count != self.authority.batch_count or
            self.main_column_count != owner.program.layout.column_count or
            self.interaction_column_count != self.authority.interaction_column_count)
        {
            return error.InvalidLookupV2Geometry;
        }
        _ = std.math.add(u32, self.first_main_column, self.main_column_count) catch
            return error.InvalidLookupV2Geometry;
        _ = std.math.add(
            u32,
            self.first_interaction_column,
            self.interaction_column_count,
        ) catch return error.InvalidLookupV2Geometry;
    }

    fn identityDigest(self: *const JobIdentity) Identity {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(job_identity_domain);
        hashInt(&hasher, u16, self.format_version);
        hasher.update(&self.authority.component_identity);
        hasher.update(&self.authority.partition_identity);
        hasher.update(&self.authority.layout_identity);
        hasher.update(&self.authority.program_identity);
        hasher.update(&self.codegen_identity);
        inline for (.{
            self.trace_log_size,
            self.selector_tree_index,
            self.selector_column,
            self.main_tree_index,
            self.first_main_column,
            self.main_column_count,
            self.interaction_tree_index,
            self.first_interaction_column,
            self.interaction_column_count,
            self.constraint_count,
        }) |value| hashInt(&hasher, u32, value);
        return hasher.finalResult();
    }
};

fn abiCoordinate(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.LookupV2GeometryOverflow;
}

fn hashInt(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn unsupportedProgramExport(
    _: *const anyopaque,
    _: std.mem.Allocator,
) anyerror!Program {
    return error.UnexpectedExport;
}

fn unsupportedParameterExport(
    _: *const anyopaque,
    _: std.mem.Allocator,
) anyerror![]@import("stwo_core").fields.qm31.QM31 {
    return error.UnexpectedExport;
}

fn fixtureProgram(allocator: std.mem.Allocator) !Program {
    const component_identity = [_]u8{0x11} ** 32;
    const partition_identity = [_]u8{0x22} ** 32;
    const event_degrees = try allocator.dupe(
        prover_component.LookupPolynomialEventDegreeV2,
        &.{
            .{ .ordinal = 0, .numerator_degree = 0, .denominator_degree = 1 },
            .{ .ordinal = 1, .numerator_degree = 1, .denominator_degree = 1 },
            .{ .ordinal = 2, .numerator_degree = 0, .denominator_degree = 1 },
        },
    );
    errdefer allocator.free(event_degrees);
    const batches = try allocator.dupe(
        prover_component.LookupPolynomialBatchV2,
        &.{
            .{ .first_entry = 0, .entry_count = 1, .interaction_degree = 2 },
            .{ .first_entry = 1, .entry_count = 2, .interaction_degree = 3 },
        },
    );
    errdefer allocator.free(batches);
    const layout = try prover_component.LookupPolynomialLayoutV2.init(
        component_identity,
        partition_identity,
        2,
        3,
        event_degrees,
        batches,
    );
    const nodes = try allocator.dupe(prover_component.BasePolynomialNode, &.{
        .{ .op = .column, .value = 0 },
        .{ .op = .column, .value = 1 },
        .{ .op = .constant, .value = 1 },
    });
    errdefer allocator.free(nodes);
    const entries = try allocator.alloc(prover_component.LookupPolynomialEntry, 3);
    errdefer allocator.free(entries);
    entries[0] = testEntry(2, &.{0});
    entries[1] = testEntry(0, &.{1});
    entries[2] = testEntry(1, &.{ 0, 1 });
    var result = Program{
        .allocator = allocator,
        .layout = layout,
        .nodes = nodes,
        .entries = entries,
        .event_degrees = event_degrees,
        .batches = batches,
        .program_identity = .{0} ** 32,
    };
    errdefer result.deinit();
    try result.seal();
    return result;
}

fn testEntry(numerator: u32, values: []const u32) prover_component.LookupPolynomialEntry {
    var result = prover_component.LookupPolynomialEntry{
        .numerator = numerator,
        .arity = @intCast(values.len),
    };
    @memcpy(result.values[0..values.len], values);
    return result;
}

fn testCapability(authority: *const Authority) Capability {
    return .{
        .authority = authority,
        .trace_log_size = 8,
        .selector_tree_index = 0,
        .selector_column = 3,
        .main_tree_index = 1,
        .first_main_column = 5,
        .main_column_count = 2,
        .interaction_tree_index = 2,
        .first_interaction_column = 7,
        .interaction_column_count = 8,
        .export_program = unsupportedProgramExport,
        .export_parameters = unsupportedParameterExport,
    };
}

test "lookup V2 owner seals variable-batch program and physical job identity" {
    var program = try fixtureProgram(std.testing.allocator);
    const authority = try program.authority();
    var owner = try ProgramOwner.init(&program, &authority);
    defer owner.deinit();
    try owner.validate();

    const job = try JobIdentity.init(testCapability(&authority), &owner, 2);
    try job.validate(&owner);
    const name = try owner.kernelName(std.testing.allocator);
    defer std.testing.allocator.free(name);
    try std.testing.expect(std.mem.startsWith(u8, name, "stwo_zig_lookup_poly_v2_"));
    try std.testing.expectEqual(@as(usize, 24 + 64), name.len);
}

test "lookup V2 admission rejects authority, geometry, and job mutations" {
    var program = try fixtureProgram(std.testing.allocator);
    defer program.deinit();
    var authority = try program.authority();
    var changed_authority = authority;
    changed_authority.program_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProgramIdentity,
        ProgramOwner.init(&program, &changed_authority),
    );

    var owned_program = try fixtureProgram(std.testing.allocator);
    var owner = try ProgramOwner.init(&owned_program, &authority);
    defer owner.deinit();
    var capability = testCapability(&authority);
    capability.interaction_column_count -= 4;
    try std.testing.expectError(
        error.InvalidLookupV2Geometry,
        JobIdentity.init(capability, &owner, 2),
    );
    capability = testCapability(&authority);
    capability.main_column_count += 1;
    try std.testing.expectError(
        error.InvalidLookupV2Geometry,
        JobIdentity.init(capability, &owner, 2),
    );
    try std.testing.expectError(
        error.InvalidLookupV2Geometry,
        JobIdentity.init(testCapability(&authority), &owner, 1),
    );

    var job = try JobIdentity.init(testCapability(&authority), &owner, 2);
    job.first_interaction_column += 1;
    try std.testing.expectError(error.InvalidJobIdentity, job.validate(&owner));
}

test "lookup V2 codegen follows authenticated singleton and pair boundaries" {
    var program = try fixtureProgram(std.testing.allocator);
    defer program.deinit();
    const authority = try program.authority();
    const source = try codegen.generateLibrary(std.testing.allocator, &.{.{
        .authority = authority,
        .program = program,
    }});
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        "riscv_qm_mul(delta0, d0)",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        "riscv_qm_mul(riscv_qm_mul(delta1, d1), d2)",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "c2 =") == null);
}
