//! Strict command-line contract for the production proof tool.

const std = @import("std");
const resource_admission = @import("native_resource_admission");

pub const Command = enum { prove, bench, verify, applications };

pub const Backend = enum {
    cpu,
    metal_hybrid,
};

pub const Air = enum {
    wide_fibonacci,
    xor,
    plonk,
    state_machine,
    blake,
    poseidon,
};

pub const Protocol = enum { secure, functional, smoke };
pub const Blake2Backend = enum { auto, scalar, simd };
pub const ResourceProfile = resource_admission.Profile;
pub const MetalRuntimeMode = enum { source_jit, authenticated_aot };

pub const MetalRuntime = struct {
    mode: MetalRuntimeMode = .source_jit,
    aot_bundle: ?[]const u8 = null,
    manifest_sha256: ?[32]u8 = null,
};

pub const WideFibonacci = struct {
    log_n_rows: u32 = 12,
    sequence_len: u32 = 16,
};

pub const Xor = struct {
    log_size: u32 = 10,
    log_step: u32 = 2,
    offset: usize = 3,
};

pub const Plonk = struct { log_n_rows: u32 = 10 };

pub const StateMachine = struct {
    log_n_rows: u32 = 10,
    initial_x: u32 = 9,
    initial_y: u32 = 3,
};

pub const Blake = struct {
    log_n_rows: u32 = 8,
    n_rounds: u32 = 2,
};

pub const Poseidon = struct { log_n_instances: u32 = 13 };

pub const Workload = union(Air) {
    wide_fibonacci: WideFibonacci,
    xor: Xor,
    plonk: Plonk,
    state_machine: StateMachine,
    blake: Blake,
    poseidon: Poseidon,
};

pub const Run = struct {
    backend: Backend,
    protocol: Protocol,
    workload: Workload,
    blake2_backend: Blake2Backend,
    metal_runtime: MetalRuntime,
    resource_profile: ResourceProfile,
};

pub const Prove = struct {
    run: Run,
    output: []const u8,
    report_out: ?[]const u8,
};

pub const Bench = struct {
    run: Run,
    report_out: ?[]const u8,
    proof_out: ?[]const u8,
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const ElfRun = struct {
    elf_path: []const u8,
    input_path: ?[]const u8,
    backend: Backend,
    protocol: Protocol,
    blake2_backend: Blake2Backend,
    metal_runtime: MetalRuntime,
    experimental: bool,
};

pub const ProveElf = struct {
    run: ElfRun,
    output: []const u8,
    report_out: ?[]const u8,
};

pub const BenchElf = struct {
    run: ElfRun,
    report_out: ?[]const u8,
    proof_out: ?[]const u8,
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const Verify = struct {
    artifact: []const u8,
    elf_path: ?[]const u8,
    protocol: Protocol,
    expected_statement_digest: ?[32]u8,
};

pub const Parsed = union(enum) {
    prove: Prove,
    bench: Bench,
    prove_elf: ProveElf,
    bench_elf: BenchElf,
    verify: Verify,
    applications: void,
    help: ?Command,
};

const MAX_SEQUENCE_LEN: u32 = 512;
const MAX_BLAKE_ROUNDS: u32 = 32;
const MAX_XOR_OFFSET: usize = (1 << 31) - 1;
const M31_MODULUS: u32 = 0x7fffffff;
const POSEIDON_LOG_INSTANCES_PER_ROW: u32 = 3;
const POSEIDON_COLUMNS: u64 = 1264;
const MAX_WARMUPS: usize = 10;
const MAX_SAMPLES: usize = 21;

const Flag = enum {
    air,
    backend,
    protocol,
    output,
    artifact,
    report_out,
    proof_out,
    warmups,
    samples,
    log_n_rows,
    sequence_len,
    log_size,
    log_step,
    offset,
    initial_x,
    initial_y,
    n_rounds,
    log_n_instances,
    blake2_backend,
    resource_profile,
    metal_runtime,
    metal_aot_bundle,
    metal_aot_manifest_sha256,
    elf,
    input,
    profiled,
    experimental,
    expect_statement_digest,
    count,
};

const WORKLOAD_FLAGS = [_]Flag{
    .log_n_rows, .sequence_len, .log_size, .log_step,        .offset,
    .initial_x,  .initial_y,    .n_rounds, .log_n_instances,
};

const Scratch = struct {
    seen: [@intFromEnum(Flag.count)]bool = [_]bool{false} ** @intFromEnum(Flag.count),
    air: ?Air = null,
    backend: ?Backend = null,
    protocol: Protocol = .secure,
    output: ?[]const u8 = null,
    artifact: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    proof_out: ?[]const u8 = null,
    warmups: usize = 10,
    samples: usize = 5,
    log_n_rows: u32 = 0,
    sequence_len: u32 = 16,
    log_size: u32 = 10,
    log_step: u32 = 2,
    offset: usize = 3,
    initial_x: u32 = 9,
    initial_y: u32 = 3,
    n_rounds: u32 = 2,
    log_n_instances: u32 = 13,
    blake2_backend: Blake2Backend = .auto,
    resource_profile: ResourceProfile = .standard,
    metal_runtime: MetalRuntime = .{},
    elf: ?[]const u8 = null,
    input: ?[]const u8 = null,
    profiled: bool = false,
    experimental: bool = false,
    expected_statement_digest: ?[32]u8 = null,

    fn mark(self: *Scratch, flag: Flag) !void {
        const index = @intFromEnum(flag);
        if (self.seen[index]) return error.DuplicateArgument;
        self.seen[index] = true;
    }

    fn has(self: Scratch, flag: Flag) bool {
        return self.seen[@intFromEnum(flag)];
    }
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 0) return error.MissingCommand;
    if (isHelp(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .help = null };
    }

    const command = parseEnum(Command, argv[0]) orelse return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1])) return .{ .help = command };
    if (command == .applications) {
        if (argv.len != 1) return error.IrrelevantArgument;
        return .{ .applications = {} };
    }

    var scratch = Scratch{};
    var index: usize = 1;
    while (index < argv.len) {
        const name = argv[index];
        const flag = parseFlag(name) orelse return error.UnknownArgument;
        try scratch.mark(flag);
        index += 1;
        if (flag == .profiled or flag == .experimental) {
            if (flag == .profiled) scratch.profiled = true;
            if (flag == .experimental) scratch.experimental = true;
            continue;
        }
        if (index == argv.len) return error.MissingArgumentValue;
        const value = argv[index];
        try assign(&scratch, flag, value);
        index += 1;
    }

    try rejectIrrelevant(command, scratch);
    try rejectElfConflicts(scratch);
    return switch (command) {
        .prove => if (scratch.has(.elf)) .{ .prove_elf = .{
            .run = try makeElfRun(scratch),
            .output = try requiredPath(scratch.output, error.MissingOutput),
            .report_out = try optionalPath(scratch.report_out),
        } } else .{ .prove = .{
            .run = try makeRun(scratch),
            .output = try requiredPath(scratch.output, error.MissingOutput),
            .report_out = try optionalPath(scratch.report_out),
        } },
        .bench => if (scratch.has(.elf)) .{ .bench_elf = .{
            .run = try makeElfRun(scratch),
            .report_out = try optionalPath(scratch.report_out),
            .proof_out = try optionalPath(scratch.proof_out),
            .warmups = scratch.warmups,
            .samples = scratch.samples,
            .profiled = scratch.profiled,
        } } else .{ .bench = .{
            .run = try makeRun(scratch),
            .report_out = try optionalPath(scratch.report_out),
            .proof_out = try optionalPath(scratch.proof_out),
            .warmups = scratch.warmups,
            .samples = scratch.samples,
            .profiled = scratch.profiled,
        } },
        .verify => .{ .verify = .{
            .artifact = try requiredPath(scratch.artifact, error.MissingArtifact),
            .elf_path = try optionalPath(scratch.elf),
            .protocol = scratch.protocol,
            .expected_statement_digest = scratch.expected_statement_digest,
        } },
        .applications => unreachable,
    };
}

fn rejectElfConflicts(scratch: Scratch) !void {
    if (!scratch.has(.elf)) {
        if (scratch.has(.input)) return error.InputRequiresElf;
        if (scratch.has(.experimental)) return error.ExperimentalRequiresElf;
        return;
    }
    if (scratch.has(.air)) return error.ElfExcludesAir;
    if (scratch.has(.resource_profile)) return error.ResourceProfileExcludesElf;
    for (WORKLOAD_FLAGS) |flag| {
        if (scratch.has(flag)) return error.IrrelevantWorkloadArgument;
    }
}

fn assign(scratch: *Scratch, flag: Flag, value: []const u8) !void {
    switch (flag) {
        .air => scratch.air = parseEnum(Air, value) orelse return error.InvalidAir,
        .backend => scratch.backend = parseBackend(value) orelse return error.InvalidBackend,
        .protocol => scratch.protocol = parseEnum(Protocol, value) orelse return error.InvalidProtocol,
        .output => scratch.output = value,
        .artifact => scratch.artifact = value,
        .report_out => scratch.report_out = value,
        .proof_out => scratch.proof_out = value,
        .warmups => scratch.warmups = try parseInt(usize, value),
        .samples => scratch.samples = try parseInt(usize, value),
        .log_n_rows => scratch.log_n_rows = try parseInt(u32, value),
        .sequence_len => scratch.sequence_len = try parseInt(u32, value),
        .log_size => scratch.log_size = try parseInt(u32, value),
        .log_step => scratch.log_step = try parseInt(u32, value),
        .offset => scratch.offset = try parseInt(usize, value),
        .initial_x => scratch.initial_x = try parseInt(u32, value),
        .initial_y => scratch.initial_y = try parseInt(u32, value),
        .n_rounds => scratch.n_rounds = try parseInt(u32, value),
        .log_n_instances => scratch.log_n_instances = try parseInt(u32, value),
        .blake2_backend => scratch.blake2_backend = parseEnum(Blake2Backend, value) orelse
            return error.InvalidBlake2Backend,
        .resource_profile => scratch.resource_profile = parseEnum(ResourceProfile, value) orelse
            return error.InvalidResourceProfile,
        .metal_runtime => scratch.metal_runtime.mode = parseMetalRuntime(value) orelse
            return error.InvalidMetalRuntime,
        .metal_aot_bundle => scratch.metal_runtime.aot_bundle = value,
        .metal_aot_manifest_sha256 => scratch.metal_runtime.manifest_sha256 = try parseSha256(value),
        .elf => scratch.elf = value,
        .input => scratch.input = value,
        .expect_statement_digest => scratch.expected_statement_digest = try parseSha256(value),
        .profiled, .experimental => unreachable,
        .count => unreachable,
    }
}

fn makeRun(scratch: Scratch) !Run {
    const air = scratch.air orelse return error.MissingAir;
    const backend = try checkedBackend(scratch);
    const workload = try makeWorkload(air, scratch);
    _ = try admitWorkload(workload, scratch.resource_profile);
    return .{
        .backend = backend,
        .protocol = scratch.protocol,
        .workload = workload,
        .blake2_backend = scratch.blake2_backend,
        .metal_runtime = scratch.metal_runtime,
        .resource_profile = scratch.resource_profile,
    };
}

fn makeElfRun(scratch: Scratch) !ElfRun {
    return .{
        .elf_path = try requiredPath(scratch.elf, error.MissingElf),
        .input_path = try optionalPath(scratch.input),
        .backend = try checkedBackend(scratch),
        .protocol = scratch.protocol,
        .blake2_backend = scratch.blake2_backend,
        .metal_runtime = scratch.metal_runtime,
        .experimental = scratch.experimental,
    };
}

fn checkedBackend(scratch: Scratch) !Backend {
    const backend = scratch.backend orelse return error.MissingBackend;
    if (backend == .cpu and hasAny(scratch, &.{
        .metal_runtime,
        .metal_aot_bundle,
        .metal_aot_manifest_sha256,
    })) return error.MetalArgumentRequiresMetalBackend;
    try validateMetalRuntime(scratch.metal_runtime);
    return backend;
}

fn makeWorkload(air: Air, scratch: Scratch) !Workload {
    const log_n_rows = if (scratch.has(.log_n_rows)) scratch.log_n_rows else switch (air) {
        .wide_fibonacci => @as(u32, 12),
        .plonk, .state_machine => 10,
        .blake => 8,
        .xor, .poseidon => 0,
    };
    const relevant = switch (air) {
        .wide_fibonacci => &[_]Flag{ .log_n_rows, .sequence_len },
        .xor => &[_]Flag{ .log_size, .log_step, .offset },
        .plonk => &[_]Flag{.log_n_rows},
        .state_machine => &[_]Flag{ .log_n_rows, .initial_x, .initial_y },
        .blake => &[_]Flag{ .log_n_rows, .n_rounds },
        .poseidon => &[_]Flag{.log_n_instances},
    };
    for (WORKLOAD_FLAGS) |flag| {
        if (scratch.has(flag) and !contains(relevant, flag)) return error.IrrelevantWorkloadArgument;
    }
    return switch (air) {
        .wide_fibonacci => .{ .wide_fibonacci = .{
            .log_n_rows = log_n_rows,
            .sequence_len = scratch.sequence_len,
        } },
        .xor => .{ .xor = .{
            .log_size = scratch.log_size,
            .log_step = scratch.log_step,
            .offset = scratch.offset,
        } },
        .plonk => .{ .plonk = .{ .log_n_rows = log_n_rows } },
        .state_machine => .{ .state_machine = .{
            .log_n_rows = log_n_rows,
            .initial_x = scratch.initial_x,
            .initial_y = scratch.initial_y,
        } },
        .blake => .{ .blake = .{
            .log_n_rows = log_n_rows,
            .n_rounds = scratch.n_rounds,
        } },
        .poseidon => .{ .poseidon = .{ .log_n_instances = scratch.log_n_instances } },
    };
}

pub fn admitWorkload(
    workload: Workload,
    profile: ResourceProfile,
) !resource_admission.Admission {
    return switch (workload) {
        .wide_fibonacci => |value| blk: {
            if (value.sequence_len < 2 or value.sequence_len > MAX_SEQUENCE_LEN)
                return error.InvalidSequenceLength;
            break :blk resource_admission.admit(profile, value.log_n_rows, value.sequence_len);
        },
        .xor => |value| blk: {
            const admission = try resource_admission.admit(profile, value.log_size, 3);
            if (value.log_step > value.log_size) return error.InvalidStep;
            if (value.offset > MAX_XOR_OFFSET) return error.InvalidOffset;
            const period = @as(usize, 1) << @intCast(value.log_step);
            if (value.offset >= period) return error.InvalidOffset;
            break :blk admission;
        },
        .plonk => |value| resource_admission.admit(profile, value.log_n_rows, 8),
        .state_machine => |value| blk: {
            if (value.initial_x >= M31_MODULUS or value.initial_y >= M31_MODULUS)
                return error.InvalidInitialState;
            break :blk resource_admission.admit(profile, value.log_n_rows, 3);
        },
        .blake => |value| blk: {
            if (value.n_rounds == 0 or value.n_rounds > MAX_BLAKE_ROUNDS)
                return error.InvalidRoundCount;
            break :blk resource_admission.admit(
                profile,
                value.log_n_rows,
                try std.math.mul(u64, value.n_rounds, 96),
            );
        },
        .poseidon => |value| blk: {
            if (value.log_n_instances <= POSEIDON_LOG_INSTANCES_PER_ROW or
                value.log_n_instances > resource_admission.MAX_LOG_ROWS + POSEIDON_LOG_INSTANCES_PER_ROW)
                return error.InvalidLogNInstances;
            break :blk resource_admission.admit(
                profile,
                value.log_n_instances - POSEIDON_LOG_INSTANCES_PER_ROW,
                POSEIDON_COLUMNS,
            );
        },
    };
}

fn validateMetalRuntime(runtime: MetalRuntime) !void {
    switch (runtime.mode) {
        .source_jit => if (runtime.aot_bundle != null or runtime.manifest_sha256 != null)
            return error.InvalidMetalRuntimeConfiguration,
        .authenticated_aot => {
            const bundle = runtime.aot_bundle orelse return error.InvalidMetalRuntimeConfiguration;
            if (bundle.len == 0 or runtime.manifest_sha256 == null)
                return error.InvalidMetalRuntimeConfiguration;
        },
    }
}

fn rejectIrrelevant(command: Command, scratch: Scratch) !void {
    for (0..@intFromEnum(Flag.count)) |index| {
        if (!scratch.seen[index]) continue;
        const flag: Flag = @enumFromInt(index);
        const allowed = switch (command) {
            .prove => isRunFlag(flag) or contains(&.{ .output, .report_out, .elf, .input, .experimental }, flag),
            .bench => isRunFlag(flag) or contains(&.{
                .report_out, .proof_out, .warmups, .samples, .profiled, .elf, .input, .experimental,
            }, flag),
            .verify => contains(&.{ .artifact, .elf, .protocol, .expect_statement_digest }, flag),
            .applications => false,
        };
        if (!allowed) return error.IrrelevantArgument;
    }
    if (command == .bench) {
        if (scratch.warmups > MAX_WARMUPS) return error.TooManyWarmups;
        if (scratch.samples == 0 or scratch.samples > MAX_SAMPLES) return error.InvalidSampleCount;
    }
}

fn isRunFlag(flag: Flag) bool {
    return contains(&.{
        .air,            .backend,          .protocol,      .log_n_rows,       .sequence_len,              .log_size,
        .log_step,       .offset,           .initial_x,     .initial_y,        .n_rounds,                  .log_n_instances,
        .blake2_backend, .resource_profile, .metal_runtime, .metal_aot_bundle, .metal_aot_manifest_sha256,
    }, flag);
}

fn hasAny(scratch: Scratch, flags: []const Flag) bool {
    for (flags) |flag| if (scratch.has(flag)) return true;
    return false;
}

fn contains(flags: []const Flag, needle: Flag) bool {
    for (flags) |flag| if (flag == needle) return true;
    return false;
}

fn parseFlag(value: []const u8) ?Flag {
    const entries = .{
        .{ "--air", Flag.air },
        .{ "--backend", Flag.backend },
        .{ "--protocol", Flag.protocol },
        .{ "--output", Flag.output },
        .{ "--artifact", Flag.artifact },
        .{ "--report-out", Flag.report_out },
        .{ "--proof-out", Flag.proof_out },
        .{ "--warmups", Flag.warmups },
        .{ "--samples", Flag.samples },
        .{ "--log-n-rows", Flag.log_n_rows },
        .{ "--sequence-len", Flag.sequence_len },
        .{ "--log-size", Flag.log_size },
        .{ "--log-step", Flag.log_step },
        .{ "--offset", Flag.offset },
        .{ "--initial-x", Flag.initial_x },
        .{ "--initial-y", Flag.initial_y },
        .{ "--n-rounds", Flag.n_rounds },
        .{ "--log-n-instances", Flag.log_n_instances },
        .{ "--blake2-backend", Flag.blake2_backend },
        .{ "--resource-profile", Flag.resource_profile },
        .{ "--metal-runtime", Flag.metal_runtime },
        .{ "--metal-aot-bundle", Flag.metal_aot_bundle },
        .{ "--metal-aot-manifest-sha256", Flag.metal_aot_manifest_sha256 },
        .{ "--elf", Flag.elf },
        .{ "--input", Flag.input },
        .{ "--profiled", Flag.profiled },
        .{ "--experimental", Flag.experimental },
        .{ "--expect-statement-digest", Flag.expect_statement_digest },
    };
    inline for (entries) |entry| if (std.mem.eql(u8, value, entry[0])) return entry[1];
    return null;
}

fn parseBackend(value: []const u8) ?Backend {
    if (std.mem.eql(u8, value, "cpu")) return .cpu;
    if (std.mem.eql(u8, value, "metal-hybrid")) return .metal_hybrid;
    return null;
}

fn parseMetalRuntime(value: []const u8) ?MetalRuntimeMode {
    if (std.mem.eql(u8, value, "source-jit")) return .source_jit;
    if (std.mem.eql(u8, value, "authenticated-aot")) return .authenticated_aot;
    return null;
}

fn parseEnum(comptime T: type, value: []const u8) ?T {
    return std.meta.stringToEnum(T, value);
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10);
}

fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidSha256;
    return digest;
}

fn requiredPath(path: ?[]const u8, comptime missing: anyerror) ![]const u8 {
    const value = path orelse return missing;
    if (value.len == 0) return error.InvalidPath;
    return value;
}

fn optionalPath(path: ?[]const u8) !?[]const u8 {
    if (path) |value| if (value.len == 0) return error.InvalidPath;
    return path;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(writer: anytype, command: ?Command) !void {
    if (command == null) {
        try writer.writeAll(
            \\Usage: stwo-zig <command> [options]
            \\
            \\Commands:
            \\  prove          Produce and verify one proof artifact
            \\  bench          Benchmark the same verified proving path
            \\  verify         Verify a proof artifact
            \\  applications   List compiled-in AIR applications
            \\
            \\Run `stwo-zig <command> --help` for command options.
        );
        return writer.writeByte('\n');
    }
    switch (command.?) {
        .prove => try writer.writeAll(
            \\Usage: stwo-zig prove --air NAME --backend NAME --output PATH [run options]
            \\       stwo-zig prove --elf PATH --backend NAME --output PATH [--input PATH]
            \\
            \\  --report-out PATH  Write the machine-readable proving report
            \\  --elf PATH         Prove a Sail-profile RV32IM guest ELF instead of --air
            \\  --input PATH       Guest input bytes (requires --elf)
            \\  --experimental     Admit the staged Stark-V adapter before its release gate
        ),
        .bench => try writer.writeAll(
            \\Usage: stwo-zig bench --air NAME --backend NAME [run options] [benchmark options]
            \\       stwo-zig bench --elf PATH --backend NAME [--input PATH] [benchmark options]
            \\
            \\Benchmark options:
            \\  --report-out PATH  Write the machine-readable benchmark report
            \\  --proof-out PATH   Retain a verified proof artifact
            \\  --warmups N        Verified untimed warmups (default: 10, maximum: 10)
            \\  --samples N        Verified timed samples (default: 5, maximum: 21)
            \\  --profiled        Enable diagnostic stage instrumentation
            \\  --elf PATH         Benchmark a Sail-profile RV32IM guest ELF instead of --air
            \\  --input PATH       Guest input bytes (requires --elf)
            \\  --experimental     Admit the staged Stark-V adapter before its release gate
        ),
        .verify => return writer.writeAll(
            \\Usage: stwo-zig verify --artifact PATH [--elf PATH] [--protocol secure|functional|smoke]
            \\  --elf PATH         Required for RISC-V artifacts; rebuilds the program root
            \\       [--expect-statement-digest SHA256]
            \\
        ),
        .applications => return writer.writeAll(
            \\Usage: stwo-zig applications
            \\
        ),
    }
    try writer.writeAll(
        \\
        \\Run options:
        \\  --air NAME            wide_fibonacci, xor, plonk, state_machine, blake, poseidon
        \\  --backend NAME        cpu or metal-hybrid (required; no fallback)
        \\  --protocol NAME       secure, functional, or smoke (default: secure)
        \\  --blake2-backend NAME auto, scalar, or simd (default: auto)
        \\  --resource-profile NAME standard or large (default: standard)
        \\  --log-n-rows N        Wide Fibonacci, Plonk, State Machine, or Blake rows
        \\  --sequence-len N      Wide Fibonacci sequence length
        \\  --log-size N          XOR log2 rows
        \\  --log-step N          XOR periodic-indicator log2 step
        \\  --offset N            XOR periodic-indicator offset
        \\  --initial-x N         State Machine initial x
        \\  --initial-y N         State Machine initial y
        \\  --n-rounds N          Blake round count
        \\  --log-n-instances N   Poseidon log2 instance count
        \\  --metal-runtime MODE  source-jit or authenticated-aot
        \\  --metal-aot-bundle PATH
        \\  --metal-aot-manifest-sha256 HEX
        \\
    );
}

test "prove requires explicit application backend and output" {
    try std.testing.expectError(error.MissingAir, parse(&.{ "prove", "--backend", "cpu", "--output", "proof.json" }));
    try std.testing.expectError(error.MissingBackend, parse(&.{ "prove", "--air", "wide_fibonacci", "--output", "proof.json" }));
    try std.testing.expectError(error.MissingOutput, parse(&.{ "prove", "--air", "wide_fibonacci", "--backend", "cpu" }));

    const result = (try parse(&.{
        "prove",    "--air",          "wide_fibonacci", "--backend",   "cpu",
        "--output", "proof.json",     "--report-out",   "report.json", "--log-n-rows",
        "14",       "--sequence-len", "25",
    })).prove;
    try std.testing.expectEqual(Backend.cpu, result.run.backend);
    try std.testing.expectEqual(Protocol.secure, result.run.protocol);
    try std.testing.expectEqual(ResourceProfile.standard, result.run.resource_profile);
    try std.testing.expectEqual(@as(u32, 14), result.run.workload.wide_fibonacci.log_n_rows);
    try std.testing.expectEqualStrings("proof.json", result.output);
    try std.testing.expectEqualStrings("report.json", result.report_out.?);
}

test "bench parses outputs sampling and a tagged workload" {
    const result = (try parse(&.{
        "bench",       "--air",       "xor",        "--backend", "metal-hybrid", "--protocol", "smoke",
        "--log-size",  "8",           "--log-step", "3",         "--offset",     "5",          "--report-out",
        "report.json", "--proof-out", "proof.json", "--warmups", "2",            "--samples",  "7",
        "--profiled",
    })).bench;
    try std.testing.expectEqual(Backend.metal_hybrid, result.run.backend);
    try std.testing.expectEqual(Protocol.smoke, result.run.protocol);
    try std.testing.expectEqual(@as(usize, 5), result.run.workload.xor.offset);
    try std.testing.expectEqual(@as(usize, 2), result.warmups);
    try std.testing.expectEqual(@as(usize, 7), result.samples);
    try std.testing.expect(result.profiled);
}

test "commands reject duplicate unknown missing and irrelevant arguments" {
    try std.testing.expectError(error.DuplicateArgument, parse(&.{
        "prove", "--air", "xor", "--air", "plonk",
    }));
    try std.testing.expectError(error.UnknownArgument, parse(&.{ "verify", "--payload", "proof.json" }));
    try std.testing.expectError(error.MissingArgumentValue, parse(&.{ "verify", "--artifact" }));
    try std.testing.expectError(error.IrrelevantArgument, parse(&.{ "verify", "--artifact", "proof.json", "--backend", "cpu" }));
    try std.testing.expectError(error.IrrelevantArgument, parse(&.{ "prove", "--warmups", "1" }));
    try std.testing.expectError(error.IrrelevantArgument, parse(&.{ "applications", "--backend", "cpu" }));
    try std.testing.expectError(error.IrrelevantWorkloadArgument, parse(&.{
        "prove",          "--air", "plonk", "--backend", "cpu", "--output", "proof.json",
        "--sequence-len", "8",
    }));
}

test "backend and Metal runtime selection fail closed" {
    try std.testing.expectError(error.InvalidBackend, parse(&.{
        "prove", "--air", "plonk", "--backend", "auto", "--output", "proof.json",
    }));
    try std.testing.expectError(error.MetalArgumentRequiresMetalBackend, parse(&.{
        "prove",           "--air",      "plonk", "--backend", "cpu", "--output", "proof.json",
        "--metal-runtime", "source-jit",
    }));
    try std.testing.expectError(error.InvalidMetalRuntimeConfiguration, parse(&.{
        "prove",           "--air",             "plonk", "--backend", "metal-hybrid", "--output", "proof.json",
        "--metal-runtime", "authenticated-aot",
    }));
    const result = (try parse(&.{
        "prove",            "--air", "blake",           "--backend",         "metal-hybrid",       "--output",             "proof.json",
        "--blake2-backend", "simd",  "--metal-runtime", "authenticated-aot", "--metal-aot-bundle", "native-core.metallib", "--metal-aot-manifest-sha256",
        "ab" ** 32,
    })).prove;
    try std.testing.expectEqual(Blake2Backend.simd, result.run.blake2_backend);
    try std.testing.expectEqual(MetalRuntimeMode.authenticated_aot, result.run.metal_runtime.mode);
}

test "bounds paths verification and help fail closed" {
    try std.testing.expectError(error.InvalidPath, parse(&.{ "verify", "--artifact", "" }));
    const verify = (try parse(&.{ "verify", "--artifact", "proof.json" })).verify;
    try std.testing.expectEqual(Protocol.secure, verify.protocol);
    try std.testing.expect(verify.expected_statement_digest == null);
    const bound = (try parse(&.{
        "verify", "--artifact", "proof.json", "--expect-statement-digest", "ab" ** 32,
    })).verify;
    try std.testing.expectEqualSlices(u8, &([_]u8{0xab} ** 32), &bound.expected_statement_digest.?);
    try std.testing.expectError(error.InvalidSampleCount, parse(&.{
        "bench", "--air", "plonk", "--backend", "cpu", "--samples", "0",
    }));
    try std.testing.expectError(error.InvalidRoundCount, parse(&.{
        "prove",      "--air", "blake", "--backend", "cpu", "--output", "proof.json",
        "--n-rounds", "33",
    }));
    try std.testing.expectError(error.InvalidSha256, parse(&.{
        "prove",                       "--air",    "plonk", "--backend", "metal-hybrid", "--output", "proof.json",
        "--metal-aot-manifest-sha256", "AB" ** 32,
    }));
    try std.testing.expectEqual(Command.bench, (try parse(&.{ "bench", "--help" })).help.?);
    try std.testing.expect((try parse(&.{"--help"})).help == null);
}

test "elf runs parse guest inputs and stay mutually exclusive with air" {
    const result = (try parse(&.{
        "prove",    "--elf",      "guest.elf", "--backend", "cpu",
        "--output", "proof.json", "--input",   "input.bin", "--experimental",
    })).prove_elf;
    try std.testing.expectEqual(Backend.cpu, result.run.backend);
    try std.testing.expectEqual(Protocol.secure, result.run.protocol);
    try std.testing.expectEqualStrings("guest.elf", result.run.elf_path);
    try std.testing.expectEqualStrings("input.bin", result.run.input_path.?);
    try std.testing.expectEqualStrings("proof.json", result.output);
    try std.testing.expect(result.run.experimental);

    try std.testing.expectError(error.ElfExcludesAir, parse(&.{
        "prove",     "--elf", "guest.elf", "--air",      "plonk",
        "--backend", "cpu",   "--output",  "proof.json",
    }));
    try std.testing.expectError(error.InputRequiresElf, parse(&.{
        "prove",   "--air",     "plonk", "--backend", "cpu", "--output", "proof.json",
        "--input", "input.bin",
    }));
    try std.testing.expectError(error.ExperimentalRequiresElf, parse(&.{
        "prove", "--air", "plonk", "--backend", "cpu", "--output", "proof.json", "--experimental",
    }));
    try std.testing.expectError(error.IrrelevantArgument, parse(&.{
        "verify", "--artifact", "proof.json", "--experimental",
    }));
    try std.testing.expectError(error.MissingBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--output", "proof.json",
    }));
    try std.testing.expectError(error.MissingOutput, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "cpu",
    }));
    try std.testing.expectError(error.InvalidPath, parse(&.{
        "prove", "--elf", "", "--backend", "cpu", "--output", "proof.json",
    }));
}

test "bench ELF keeps sampling and verify accepts an ELF identity binding" {
    const result = (try parse(&.{
        "bench",     "--elf", "guest.elf", "--backend", "cpu",
        "--warmups", "2",     "--samples", "3",
    })).bench_elf;
    try std.testing.expectEqualStrings("guest.elf", result.run.elf_path);
    try std.testing.expect(result.run.input_path == null);
    try std.testing.expectEqual(@as(usize, 2), result.warmups);
    try std.testing.expectEqual(@as(usize, 3), result.samples);

    try std.testing.expectError(error.IrrelevantWorkloadArgument, parse(&.{
        "bench", "--elf", "guest.elf", "--backend", "cpu", "--log-n-rows", "10",
    }));
    try std.testing.expectError(error.InputRequiresElf, parse(&.{
        "bench", "--air", "plonk", "--backend", "cpu", "--input", "input.bin",
    }));
    const verify = (try parse(&.{
        "verify", "--artifact", "proof.json", "--elf", "guest.elf",
    })).verify;
    try std.testing.expectEqualStrings("guest.elf", verify.elf_path.?);
    try std.testing.expectError(error.IrrelevantArgument, parse(&.{
        "verify", "--artifact", "proof.json", "--input", "input.bin",
    }));
    try std.testing.expectError(error.MetalArgumentRequiresMetalBackend, parse(&.{
        "prove",           "--elf",      "guest.elf", "--backend", "cpu", "--output", "proof.json",
        "--metal-runtime", "source-jit",
    }));
}

test "usage names the explicit backend and artifact contracts" {
    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try writeUsage(stream.writer(), .prove);
    const usage = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, usage, "--backend NAME") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "--output PATH") != null);
    try std.testing.expect(std.mem.indexOf(u8, usage, "no fallback") != null);
}
