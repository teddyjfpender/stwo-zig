const std = @import("std");
const builtin = @import("builtin");
pub const resource_admission = @import("native_resource_admission");

pub const Backend = enum { cpu_native, metal_hybrid };

pub const Blake2Backend = enum { auto, scalar, simd };
pub const ResourceProfile = resource_admission.Profile;

pub const MetalRuntimeMode = enum {
    source_jit,
    authenticated_aot,
};

pub const MetalRuntimeSelection = struct {
    mode: MetalRuntimeMode = .source_jit,
    aot_bundle: ?[]const u8 = null,
    manifest_sha256: ?[32]u8 = null,
};

pub const ProductIdentity = struct {
    schema_version: u32,
    name: []const u8,
    frontend: []const u8,
    backend: []const u8,
    role: []const u8,
    protocol_features: []const u8,
    protocol_manifest_sha256: []const u8,
    identity_sha256: []const u8,
    implementation_repository: []const u8,
    implementation_commit: []const u8,
    implementation_tree: ?[]const u8,
    implementation_dirty: bool,
    dirty_content_sha256: ?[]const u8,
    zig_version: []const u8,
    target_arch: []const u8,
    target_os: []const u8,
    target_abi: []const u8,
    cpu_model: []const u8,
    cpu_features_sha256: []const u8,
    optimize: []const u8,
    runtime_manifest: []const u8,
    sdk_manifest: []const u8,
    aot_manifest: []const u8,

    pub fn validate(self: ProductIdentity) !void {
        if (self.schema_version != 2) return error.UnsupportedProductIdentitySchema;
        inline for (.{
            self.name,
            self.frontend,
            self.backend,
            self.role,
            self.protocol_features,
            self.implementation_repository,
            self.target_arch,
            self.target_os,
            self.target_abi,
            self.cpu_model,
            self.optimize,
            self.runtime_manifest,
            self.sdk_manifest,
            self.aot_manifest,
        }) |field| if (field.len == 0) return error.EmptyProductIdentityField;
        if (!isLowerHex(self.identity_sha256, 64)) return error.InvalidIdentityDigest;
        if (!isLowerHex(self.protocol_manifest_sha256, 64)) return error.InvalidProtocolDigest;
        if (!isLowerHex(self.implementation_commit, 40)) return error.InvalidImplementationCommit;
        const tree = self.implementation_tree orelse return error.MissingImplementationTree;
        if (!isLowerHex(tree, 40)) return error.InvalidImplementationTree;
        if (self.implementation_dirty != (self.dirty_content_sha256 != null))
            return error.InconsistentDirtyIdentity;
        if (self.dirty_content_sha256) |digest| {
            if (!isLowerHex(digest, 64)) return error.InvalidDirtyContentDigest;
        }
        if (!std.mem.eql(u8, self.zig_version, builtin.zig_version_string))
            return error.ZigVersionMismatch;
        if (!isLowerHex(self.cpu_features_sha256, 64)) return error.InvalidCpuFeaturesDigest;
        var protocol_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.protocol_features, &protocol_digest, .{});
        const expected = std.fmt.bytesToHex(protocol_digest, .lower);
        if (!std.mem.eql(u8, self.protocol_manifest_sha256, &expected))
            return error.ProtocolManifestMismatch;
    }
};

fn isLowerHex(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

pub const EvidenceClass = enum {
    verified_unprofiled,
    profiled_diagnostic,
    correctness_only,
};

pub const Example = enum {
    wide_fibonacci,
    xor,
    plonk,
    plonk_logup,
    state_machine,
    blake,
    poseidon,
};

pub const WideFibonacciParameters = struct {
    log_n_rows: u32 = 12,
    sequence_len: u32 = 16,
};

pub const XorParameters = struct {
    log_size: u32 = 10,
    log_step: u32 = 2,
    offset: usize = 3,
};

pub const PlonkParameters = struct {
    log_n_rows: u32 = 10,
};

pub const PlonkLogupParameters = struct {
    log_n_rows: u32 = 10,
};

pub const StateMachineParameters = struct {
    log_n_rows: u32 = 10,
    initial_x: u32 = 9,
    initial_y: u32 = 3,
};

pub const BlakeParameters = struct {
    log_n_rows: u32 = 8,
    n_rounds: u32 = 2,
};

pub const PoseidonParameters = struct {
    log_n_instances: u32 = 13,
};

pub const Workload = union(Example) {
    wide_fibonacci: WideFibonacciParameters,
    xor: XorParameters,
    plonk: PlonkParameters,
    plonk_logup: PlonkLogupParameters,
    state_machine: StateMachineParameters,
    blake: BlakeParameters,
    poseidon: PoseidonParameters,
};

pub const Protocol = enum {
    smoke,
    functional,
    secure,

    pub fn parameters(self: Protocol) ProtocolParameters {
        return switch (self) {
            .smoke => .{ .pow_bits = 0 },
            .functional => .{ .pow_bits = 10 },
            .secure => .{ .pow_bits = 26, .n_queries = 70 },
        };
    }
};

pub const ProtocolParameters = struct {
    pow_bits: u32,
    log_blowup_factor: u32 = 1,
    log_last_layer_degree_bound: u32 = 0,
    n_queries: usize = 3,
    fold_step: u32 = 1,
};

pub const Args = struct {
    example: Example = .wide_fibonacci,
    wide_fibonacci: WideFibonacciParameters = .{},
    xor: XorParameters = .{},
    plonk: PlonkParameters = .{},
    plonk_logup: PlonkLogupParameters = .{},
    state_machine: StateMachineParameters = .{},
    blake: BlakeParameters = .{},
    poseidon: PoseidonParameters = .{},
    protocol: Protocol = .functional,
    warmups: usize = MIN_HEADLINE_WARMUPS,
    samples: usize = 5,
    profiled: bool = false,
    proof_artifact_out: ?[]const u8 = null,
    proof_artifact_report_path: ?[]const u8 = null,
    blake2_backend: Blake2Backend = .auto,
    metal_runtime: MetalRuntimeSelection = .{},
    product_identity: ?ProductIdentity = null,
    resource_profile: ResourceProfile = .standard,

    pub fn workload(self: Args) Workload {
        return switch (self.example) {
            .wide_fibonacci => .{ .wide_fibonacci = self.wide_fibonacci },
            .xor => .{ .xor = self.xor },
            .plonk => .{ .plonk = self.plonk },
            .plonk_logup => .{ .plonk_logup = self.plonk_logup },
            .state_machine => .{ .state_machine = self.state_machine },
            .blake => .{ .blake = self.blake },
            .poseidon => .{ .poseidon = self.poseidon },
        };
    }

    pub fn evidenceClass(self: Args, meets_sampling_contract: bool) EvidenceClass {
        if (self.profiled) return .profiled_diagnostic;
        return if (meets_sampling_contract) .verified_unprofiled else .correctness_only;
    }
};

pub const ParseResult = union(enum) { run: Args, help };

const MAX_SEQUENCE_LEN: u32 = 512;
const MAX_BLAKE_ROUNDS: u32 = 32;
const POSEIDON_LOG_INSTANCES_PER_ROW: u32 = 3;
const POSEIDON_TRACE_COLUMNS: u64 = 1296;
const MAX_XOR_OFFSET: usize = (1 << 31) - 1;
const M31_MODULUS: u32 = 0x7fffffff;
pub const MIN_HEADLINE_WARMUPS: usize = 10;
pub const MAX_WARMUPS: usize = 30;

pub fn parseArgs(backend: Backend, argv: []const []const u8) !ParseResult {
    var result = Args{};
    var saw_wide_parameter = false;
    var saw_xor_parameter = false;
    var saw_state_machine_parameter = false;
    var saw_blake_parameter = false;
    var saw_poseidon_parameter = false;
    var log_n_rows_override: ?u32 = null;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return .help;
        if (std.mem.eql(u8, arg, "--profiled")) {
            result.profiled = true;
            continue;
        }
        if (index + 1 >= argv.len) return error.MissingArgumentValue;
        index += 1;
        const value = argv[index];
        if (std.mem.eql(u8, arg, "--example")) {
            result.example = std.meta.stringToEnum(Example, value) orelse
                return error.InvalidExample;
        } else if (std.mem.eql(u8, arg, "--log-n-rows")) {
            log_n_rows_override = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--log-rows")) {
            result.wide_fibonacci.log_n_rows = try std.fmt.parseInt(u32, value, 10);
            saw_wide_parameter = true;
        } else if (std.mem.eql(u8, arg, "--sequence-len")) {
            result.wide_fibonacci.sequence_len = try std.fmt.parseInt(u32, value, 10);
            saw_wide_parameter = true;
        } else if (std.mem.eql(u8, arg, "--log-size")) {
            result.xor.log_size = try std.fmt.parseInt(u32, value, 10);
            saw_xor_parameter = true;
        } else if (std.mem.eql(u8, arg, "--log-step")) {
            result.xor.log_step = try std.fmt.parseInt(u32, value, 10);
            saw_xor_parameter = true;
        } else if (std.mem.eql(u8, arg, "--offset")) {
            result.xor.offset = try std.fmt.parseInt(usize, value, 10);
            saw_xor_parameter = true;
        } else if (std.mem.eql(u8, arg, "--initial-x")) {
            result.state_machine.initial_x = try std.fmt.parseInt(u32, value, 10);
            saw_state_machine_parameter = true;
        } else if (std.mem.eql(u8, arg, "--initial-y")) {
            result.state_machine.initial_y = try std.fmt.parseInt(u32, value, 10);
            saw_state_machine_parameter = true;
        } else if (std.mem.eql(u8, arg, "--n-rounds")) {
            result.blake.n_rounds = try std.fmt.parseInt(u32, value, 10);
            saw_blake_parameter = true;
        } else if (std.mem.eql(u8, arg, "--log-n-instances")) {
            result.poseidon.log_n_instances = try std.fmt.parseInt(u32, value, 10);
            saw_poseidon_parameter = true;
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            result.protocol = std.meta.stringToEnum(Protocol, value) orelse
                return error.InvalidProtocol;
        } else if (std.mem.eql(u8, arg, "--warmups")) {
            result.warmups = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--samples")) {
            result.samples = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--proof-artifact-out")) {
            result.proof_artifact_out = value;
        } else if (std.mem.eql(u8, arg, "--blake2-backend")) {
            result.blake2_backend = std.meta.stringToEnum(Blake2Backend, value) orelse
                return error.InvalidBlake2Backend;
        } else if (std.mem.eql(u8, arg, "--resource-profile")) {
            result.resource_profile = std.meta.stringToEnum(ResourceProfile, value) orelse
                return error.InvalidResourceProfile;
        } else if (std.mem.eql(u8, arg, "--metal-runtime")) {
            if (backend == .cpu_native) return error.MetalOptionRequiresMetalBackend;
            result.metal_runtime.mode = parseMetalRuntimeMode(value) orelse
                return error.InvalidMetalRuntimeMode;
        } else if (std.mem.eql(u8, arg, "--metal-aot-bundle")) {
            if (backend == .cpu_native) return error.MetalOptionRequiresMetalBackend;
            result.metal_runtime.aot_bundle = value;
        } else if (std.mem.eql(u8, arg, "--metal-aot-manifest-sha256")) {
            if (backend == .cpu_native) return error.MetalOptionRequiresMetalBackend;
            result.metal_runtime.manifest_sha256 = try parseSha256(value);
        } else {
            return error.UnknownArgument;
        }
    }
    if (log_n_rows_override) |log_n_rows| switch (result.example) {
        .wide_fibonacci => result.wide_fibonacci.log_n_rows = log_n_rows,
        .plonk => result.plonk.log_n_rows = log_n_rows,
        .plonk_logup => result.plonk_logup.log_n_rows = log_n_rows,
        .state_machine => result.state_machine.log_n_rows = log_n_rows,
        .blake => result.blake.log_n_rows = log_n_rows,
        .xor, .poseidon => return error.IrrelevantWorkloadParameter,
    };
    if (result.example == .wide_fibonacci and
        (saw_xor_parameter or saw_state_machine_parameter or saw_blake_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .xor and
        (saw_wide_parameter or saw_state_machine_parameter or saw_blake_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .plonk and
        (saw_wide_parameter or saw_xor_parameter or saw_state_machine_parameter or saw_blake_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .plonk_logup and
        (saw_wide_parameter or saw_xor_parameter or saw_state_machine_parameter or saw_blake_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .state_machine and
        (saw_wide_parameter or saw_xor_parameter or saw_blake_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .blake and
        (saw_wide_parameter or saw_xor_parameter or saw_state_machine_parameter or saw_poseidon_parameter))
        return error.IrrelevantWorkloadParameter;
    if (result.example == .poseidon and
        (saw_wide_parameter or saw_xor_parameter or saw_state_machine_parameter or saw_blake_parameter))
        return error.IrrelevantWorkloadParameter;
    try validate(result);
    return .{ .run = result };
}

fn parseMetalRuntimeMode(value: []const u8) ?MetalRuntimeMode {
    if (std.mem.eql(u8, value, "source-jit")) return .source_jit;
    if (std.mem.eql(u8, value, "authenticated-aot")) return .authenticated_aot;
    return null;
}

fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidSha256;
    return digest;
}

fn validate(args: Args) !void {
    _ = try admitWorkload(args.workload(), args.resource_profile);
    if (args.warmups > MAX_WARMUPS) return error.TooManyWarmups;
    if (args.samples == 0 or args.samples > 21) return error.InvalidSampleCount;
    if (args.proof_artifact_out) |path| if (path.len == 0)
        return error.InvalidProofArtifactPath;
    if (args.proof_artifact_report_path != null and args.proof_artifact_out == null)
        return error.InvalidProofArtifactPath;
    switch (args.metal_runtime.mode) {
        .source_jit => if (args.metal_runtime.aot_bundle != null or
            args.metal_runtime.manifest_sha256 != null)
            return error.InvalidMetalRuntimeConfiguration,
        .authenticated_aot => {
            const bundle = args.metal_runtime.aot_bundle orelse
                return error.InvalidMetalRuntimeConfiguration;
            if (bundle.len == 0 or args.metal_runtime.manifest_sha256 == null)
                return error.InvalidMetalRuntimeConfiguration;
        },
    }
}

pub fn admitWorkload(
    workload: Workload,
    profile: ResourceProfile,
) !resource_admission.Admission {
    return switch (workload) {
        .wide_fibonacci => |parameters| blk: {
            if (parameters.sequence_len < 2 or parameters.sequence_len > MAX_SEQUENCE_LEN)
                return error.InvalidSequenceLength;
            break :blk resource_admission.admit(
                profile,
                parameters.log_n_rows,
                parameters.sequence_len,
            );
        },
        .xor => |parameters| blk: {
            const admission = try resource_admission.admit(profile, parameters.log_size, 15);
            if (parameters.log_step > parameters.log_size) return error.InvalidStep;
            if (parameters.offset > MAX_XOR_OFFSET) return error.InvalidOffset;
            const period = @as(usize, 1) << @intCast(parameters.log_step);
            if (parameters.offset >= period) return error.InvalidOffset;
            break :blk admission;
        },
        .plonk => |parameters| resource_admission.admit(profile, parameters.log_n_rows, 8),
        .plonk_logup => |parameters| resource_admission.admit(
            profile,
            parameters.log_n_rows,
            16,
        ),
        .state_machine => |parameters| blk: {
            if (parameters.initial_x >= M31_MODULUS or parameters.initial_y >= M31_MODULUS)
                return error.InvalidInitialState;
            const rows = @as(u64, 1) << @intCast(parameters.log_n_rows);
            const committed_cells = try std.math.mul(u64, rows, 9);
            break :blk resource_admission.admitExact(
                profile,
                parameters.log_n_rows,
                12,
                committed_cells,
            );
        },
        .blake => |parameters| blk: {
            if (parameters.n_rounds == 0 or parameters.n_rounds > MAX_BLAKE_ROUNDS)
                return error.InvalidRoundCount;
            const columns = try std.math.mul(u64, parameters.n_rounds, 96);
            break :blk resource_admission.admit(profile, parameters.log_n_rows, columns);
        },
        .poseidon => |parameters| blk: {
            if (parameters.log_n_instances <= POSEIDON_LOG_INSTANCES_PER_ROW or
                parameters.log_n_instances > resource_admission.MAX_LOG_ROWS + POSEIDON_LOG_INSTANCES_PER_ROW)
                return error.InvalidLogNInstances;
            const log_n_rows = parameters.log_n_instances - POSEIDON_LOG_INSTANCES_PER_ROW;
            break :blk resource_admission.admit(profile, log_n_rows, POSEIDON_TRACE_COLUMNS);
        },
    };
}

pub fn writeUsage(writer: anytype, backend: Backend) !void {
    try writer.writeAll(
        \\Usage: native-proof-bench-{cpu|metal} [options]
        \\
        \\  --example NAME       wide_fibonacci, xor, plonk, plonk_logup, state_machine, blake, or poseidon
        \\  --log-n-rows N       Wide Fibonacci, Plonk variants, State Machine, or Blake log2 rows
        \\  --log-rows N         Legacy Wide Fibonacci log2 rows alias
        \\  --sequence-len N     Wide Fibonacci trace column count
        \\  --log-size N         XOR log2 rows
        \\  --log-step N         XOR periodic-indicator log2 step
        \\  --offset N           XOR periodic-indicator offset
        \\  --initial-x N        State Machine initial x coordinate
        \\  --initial-y N        State Machine initial y coordinate
        \\  --n-rounds N         Blake round count (maximum: 32)
        \\  --log-n-instances N  Poseidon log2 instance count
        \\  --protocol NAME      smoke, functional, or secure (default: functional)
        \\  --warmups N          Verified untimed warmups (minimum: 10, maximum: 30)
        \\  --samples N          Verified timed samples (maximum: 21)
        \\  --proof-artifact-out PATH
        \\  --blake2-backend MODE  auto, scalar, or simd (default: auto)
        \\  --resource-profile NAME  standard, large, or extreme (default: standard)
        \\  --profiled           Diagnostic instrumentation; never headline MHz
    );
    if (backend == .metal_hybrid) try writer.writeAll(
        \\  --metal-runtime MODE  source-jit or authenticated-aot
        \\  --metal-aot-bundle PATH
        \\  --metal-aot-manifest-sha256 HEX
    );
    try writer.writeAll(
        \\  -h, --help           Show this help
        \\
    );
}

test "native proof config: parses tagged workloads and legacy wide requests" {
    const xor_args = (try parseArgs(.cpu_native, &.{
        "--example", "xor", "--log-size",           "8",               "--log-step", "3",
        "--offset",  "5",   "--protocol",           "smoke",           "--warmups",  "0",
        "--samples", "5",   "--proof-artifact-out", "/tmp/proof.json",
    })).run;
    try std.testing.expectEqual(Example.xor, xor_args.example);
    try std.testing.expectEqual(@as(u32, 8), xor_args.xor.log_size);
    try std.testing.expectEqual(@as(usize, 5), xor_args.xor.offset);
    const xor_admission = try admitWorkload(xor_args.workload(), xor_args.resource_profile);
    try std.testing.expectEqual(@as(u64, 3_840), xor_admission.geometry.committed_cells);

    const wide = (try parseArgs(.cpu_native, &.{ "--log-rows", "7", "--sequence-len", "9" })).run;
    try std.testing.expectEqual(@as(u32, 7), wide.wide_fibonacci.log_n_rows);
    try std.testing.expectEqual(@as(u32, 9), wide.wide_fibonacci.sequence_len);

    const plonk = (try parseArgs(.cpu_native, &.{ "--log-n-rows", "8", "--example", "plonk" })).run;
    try std.testing.expectEqual(Example.plonk, plonk.example);
    try std.testing.expectEqual(@as(u32, 8), plonk.plonk.log_n_rows);

    const state = (try parseArgs(.cpu_native, &.{
        "--example",   "state_machine", "--log-n-rows", "8",
        "--initial-x", "17",            "--initial-y",  "19",
    })).run;
    try std.testing.expectEqual(Example.state_machine, state.example);
    try std.testing.expectEqual(@as(u32, 17), state.state_machine.initial_x);
    try std.testing.expectEqual(@as(u32, 19), state.state_machine.initial_y);

    const blake = (try parseArgs(.cpu_native, &.{
        "--example", "blake", "--log-n-rows", "7", "--n-rounds", "3",
    })).run;
    try std.testing.expectEqual(Example.blake, blake.example);
    try std.testing.expectEqual(@as(u32, 7), blake.blake.log_n_rows);
    try std.testing.expectEqual(@as(u32, 3), blake.blake.n_rounds);

    const poseidon = (try parseArgs(.cpu_native, &.{
        "--example", "poseidon", "--log-n-instances", "13",
    })).run;
    try std.testing.expectEqual(Example.poseidon, poseidon.example);
    try std.testing.expectEqual(@as(u32, 13), poseidon.poseidon.log_n_instances);
}

test "native proof config: bounds and tags fail closed" {
    try std.testing.expectError(error.InvalidSampleCount, parseArgs(.cpu_native, &.{ "--samples", "0" }));
    try std.testing.expectError(error.InvalidStep, parseArgs(.cpu_native, &.{ "--example", "xor", "--log-step", "11" }));
    try std.testing.expectError(error.InvalidLogRows, parseArgs(.cpu_native, &.{
        "--example", "xor", "--log-size", "4294967295", "--log-step", "4294967295",
    }));
    try std.testing.expectError(error.InvalidOffset, parseArgs(.cpu_native, &.{ "--example", "xor", "--offset", "4" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "xor", "--log-rows", "5" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "plonk", "--sequence-len", "4" }));
    try std.testing.expectError(error.InvalidInitialState, parseArgs(.cpu_native, &.{ "--example", "state_machine", "--initial-x", "2147483647" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "state_machine", "--offset", "1" }));
    try std.testing.expectError(error.InvalidRoundCount, parseArgs(.cpu_native, &.{ "--example", "blake", "--n-rounds", "0" }));
    try std.testing.expectError(error.InvalidRoundCount, parseArgs(.cpu_native, &.{ "--example", "blake", "--n-rounds", "33" }));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, parseArgs(.cpu_native, &.{ "--example", "blake", "--log-n-rows", "18", "--n-rounds", "2" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "plonk", "--n-rounds", "2" }));
    try std.testing.expectError(error.InvalidLogNInstances, parseArgs(.cpu_native, &.{ "--example", "poseidon", "--log-n-instances", "3" }));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, parseArgs(.cpu_native, &.{ "--example", "poseidon", "--log-n-instances", "18" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "poseidon", "--log-n-rows", "8" }));
    try std.testing.expectError(error.IrrelevantWorkloadParameter, parseArgs(.cpu_native, &.{ "--example", "blake", "--log-n-instances", "8" }));
    try std.testing.expectError(error.MissingArgumentValue, parseArgs(.cpu_native, &.{"--log-rows"}));
}

test "native proof config: resource profiles preserve default and admit reviewed large geometry" {
    try std.testing.expectError(error.CommittedCellBudgetExceeded, parseArgs(.cpu_native, &.{
        "--example", "wide_fibonacci", "--log-n-rows", "20", "--sequence-len", "100",
    }));
    const large = (try parseArgs(.cpu_native, &.{
        "--example",          "wide_fibonacci",
        "--log-n-rows",       "20",
        "--sequence-len",     "100",
        "--resource-profile", "large",
    })).run;
    try std.testing.expectEqual(ResourceProfile.large, large.resource_profile);
    const admission = try admitWorkload(large.workload(), large.resource_profile);
    try std.testing.expectEqual(@as(u64, 104_857_600), admission.geometry.committed_cells);
    const extreme = (try parseArgs(.cpu_native, &.{
        "--example",          "wide_fibonacci",
        "--log-n-rows",       "22",
        "--sequence-len",     "100",
        "--resource-profile", "extreme",
    })).run;
    try std.testing.expectEqual(ResourceProfile.extreme, extreme.resource_profile);
    const extreme_admission = try admitWorkload(extreme.workload(), extreme.resource_profile);
    try std.testing.expectEqual(@as(u64, 419_430_400), extreme_admission.geometry.committed_cells);
    try std.testing.expectEqual(@as(u64, 6_710_886_400), extreme_admission.geometry.accounted_bytes);
    try std.testing.expectError(error.CommittedCellBudgetExceeded, parseArgs(.cpu_native, &.{
        "--example",          "wide_fibonacci",
        "--log-n-rows",       "22",
        "--sequence-len",     "100",
        "--resource-profile", "large",
    }));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, parseArgs(.cpu_native, &.{
        "--example",          "wide_fibonacci",
        "--log-n-rows",       "22",
        "--sequence-len",     "512",
        "--resource-profile", "large",
    }));
    try std.testing.expectError(error.InvalidResourceProfile, parseArgs(.cpu_native, &.{
        "--resource-profile", "unbounded",
    }));
}

test "native proof config: headline warmup floor defaults to ten" {
    const defaults = (try parseArgs(.cpu_native, &.{})).run;
    try std.testing.expectEqual(MIN_HEADLINE_WARMUPS, defaults.warmups);

    const diagnostic = (try parseArgs(.cpu_native, &.{ "--warmups", "1" })).run;
    try std.testing.expectEqual(@as(usize, 1), diagnostic.warmups);
    try std.testing.expectEqual(
        EvidenceClass.correctness_only,
        diagnostic.evidenceClass(false),
    );
}

test "native proof config: backend selectors are explicit and fail closed" {
    const selected = (try parseArgs(.metal_hybrid, &.{
        "--blake2-backend",            "scalar",
        "--metal-runtime",             "authenticated-aot",
        "--metal-aot-bundle",          "/tmp/native-core",
        "--metal-aot-manifest-sha256", "ab" ** 32,
    })).run;
    try std.testing.expectEqual(Blake2Backend.scalar, selected.blake2_backend);
    try std.testing.expectEqual(MetalRuntimeMode.authenticated_aot, selected.metal_runtime.mode);
    try std.testing.expectEqualStrings("/tmp/native-core", selected.metal_runtime.aot_bundle.?);
    try std.testing.expectEqual([_]u8{0xab} ** 32, selected.metal_runtime.manifest_sha256.?);

    try std.testing.expectError(
        error.MetalOptionRequiresMetalBackend,
        parseArgs(.cpu_native, &.{ "--metal-runtime", "source-jit" }),
    );
    try std.testing.expectError(
        error.MetalOptionRequiresMetalBackend,
        parseArgs(.cpu_native, &.{ "--metal-aot-manifest-sha256", "not-a-digest" }),
    );
    try std.testing.expectError(
        error.InvalidMetalRuntimeConfiguration,
        parseArgs(.metal_hybrid, &.{ "--metal-runtime", "authenticated-aot" }),
    );
    try std.testing.expectError(
        error.InvalidMetalRuntimeConfiguration,
        parseArgs(.metal_hybrid, &.{ "--metal-aot-bundle", "/tmp/native-core" }),
    );
    try std.testing.expectError(
        error.InvalidSha256,
        parseArgs(.metal_hybrid, &.{ "--metal-aot-manifest-sha256", "AB" ** 32 }),
    );
    try std.testing.expectError(
        error.InvalidBlake2Backend,
        parseArgs(.cpu_native, &.{ "--blake2-backend", "vector" }),
    );
}
