//! Machine-readable request and attempt contract for one recursive CSP run.
//!
//! The request is emitted by the Python cohort controller from one sealed CSP
//! plan row. The native executable revalidates every file and execution fact;
//! paths and expected values are never treated as proof authority.

const std = @import("std");

pub const REQUEST_SCHEMA = "stwo.riscv.recursion-csp-workload.v3";
pub const REQUEST_SCHEMA_VERSION: u32 = 3;
pub const ATTEMPT_SCHEMA = "stwo.riscv.recursion-csp-attempt.v3";
pub const ATTEMPT_SCHEMA_VERSION: u32 = 3;
pub const ARTIFACT_KIND = "stwo_riscv_recursive_outer_wire";
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;
pub const EXCHANGE_MODE = "fixed_outer_proof_wire_v1";
pub const PAYLOAD_ENCODING = "canonical_little_endian_fixed_wire_v1";
pub const PAYLOAD_SCOPE = "verified_outer_child_wire";
pub const RECEIPT_SCHEMA = "riscv_recursive_outer_verify_v1";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_ELF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STEPS: usize = 10_000_000;
pub const MAX_WORKERS: usize = 256;

pub const Request = struct {
    schema: []const u8,
    schema_version: u32,
    plan_digest: []const u8,
    workload_id: []const u8,
    target: []const u8,
    input_size: u64,
    guest_path: []const u8,
    guest_sha256: []const u8,
    input_path: []const u8,
    input_sha256: []const u8,
    expected_output_digest: []const u8,
    expected_cycles: u64,
    native_measurement_commit: []const u8,
    expected_public_values_sha256: []const u8,
    native_statement_sha256: []const u8,
    expected_recursive_profile_id: []const u8,
    expected_recursive_profile_shape_sha256: []const u8,
    expected_profile_registry_sha256: []const u8,
    worker_count: usize,
    max_steps: usize,

    pub fn validate(self: Request) !void {
        if (!std.mem.eql(u8, self.schema, REQUEST_SCHEMA) or
            self.schema_version != REQUEST_SCHEMA_VERSION)
        {
            return error.InvalidRequestSchema;
        }
        try requireSha256(self.plan_digest);
        try requireSha256(self.workload_id);
        try requireSha256(self.guest_sha256);
        try requireSha256(self.input_sha256);
        try requireSha256(self.expected_output_digest);
        try requireCommit(self.native_measurement_commit);
        try requireSha256(self.expected_public_values_sha256);
        try requireSha256(self.native_statement_sha256);
        try requireIdentifier(self.expected_recursive_profile_id);
        try requireSha256(self.expected_recursive_profile_shape_sha256);
        try requireSha256(self.expected_profile_registry_sha256);
        if (self.target.len == 0 or self.target.len > 64 or
            self.input_size == 0 or self.expected_cycles == 0 or
            self.worker_count == 0 or self.worker_count > MAX_WORKERS or
            self.max_steps != MAX_STEPS)
        {
            return error.InvalidRequestValue;
        }
        try requireIdentifier(self.target);
        try requireRepositoryRelativePath(self.guest_path);
        try requireRepositoryRelativePath(self.input_path);
        if (std.mem.eql(u8, self.guest_path, self.input_path))
            return error.InvalidRequestValue;
    }
};

pub const ParsedRequest = struct {
    raw: []u8,
    parsed: std.json.Parsed(Request),

    pub fn deinit(self: *ParsedRequest, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.raw);
        self.* = undefined;
    }
};

pub fn parseRequestFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) !ParsedRequest {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, MAX_REQUEST_BYTES);
    errdefer allocator.free(raw);
    const parsed = try std.json.parseFromSlice(Request, allocator, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return .{ .raw = raw, .parsed = parsed };
}

fn requireCommit(value: []const u8) !void {
    if (value.len != 40) return error.InvalidCommit;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f')))
            return error.InvalidCommit;
    }
}

pub fn requireSha256(value: []const u8) !void {
    if (value.len != 64) return error.InvalidDigest;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f')))
            return error.InvalidDigest;
    }
}

fn requireRepositoryRelativePath(path: []const u8) !void {
    if (path.len == 0 or std.fs.path.isAbsolute(path) or
        std.mem.indexOfScalar(u8, path, '\\') != null or
        std.mem.indexOfScalar(u8, path, ':') != null)
    {
        return error.InvalidRequestPath;
    }
    for (path) |byte| {
        const valid = std.ascii.isAlphanumeric(byte) or
            byte == '/' or byte == '_' or byte == '-' or byte == '.';
        if (!valid) return error.InvalidRequestPath;
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidRequestPath;
        }
    }
}

test "recursive CSP request accepts only exact canonical identities and paths" {
    const request = Request{
        .schema = REQUEST_SCHEMA,
        .schema_version = REQUEST_SCHEMA_VERSION,
        .plan_digest = "01" ** 32,
        .workload_id = "02" ** 32,
        .target = "sha256",
        .input_size = 128,
        .guest_path = "vectors/riscv_csp/guests/sha256.elf",
        .guest_sha256 = "03" ** 32,
        .input_path = "vectors/riscv_csp/inputs/msg_128.bin",
        .input_sha256 = "04" ** 32,
        .expected_output_digest = "05" ** 32,
        .expected_cycles = 14_056,
        .native_measurement_commit = "08" ** 20,
        .expected_public_values_sha256 = "06" ** 32,
        .native_statement_sha256 = "07" ** 32,
        .expected_recursive_profile_id = "hash_compact",
        .expected_recursive_profile_shape_sha256 = "09" ** 32,
        .expected_profile_registry_sha256 = "0a" ** 32,
        .worker_count = 8,
        .max_steps = MAX_STEPS,
    };
    try request.validate();

    var invalid = request;
    invalid.guest_path = "../guest.elf";
    try std.testing.expectError(error.InvalidRequestPath, invalid.validate());
    invalid = request;
    invalid.workload_id = "A1" ** 32;
    try std.testing.expectError(error.InvalidDigest, invalid.validate());
    invalid = request;
    invalid.worker_count = 0;
    try std.testing.expectError(error.InvalidRequestValue, invalid.validate());
    invalid = request;
    invalid.native_measurement_commit = "A8" ** 20;
    try std.testing.expectError(error.InvalidCommit, invalid.validate());
}

fn requireIdentifier(value: []const u8) !void {
    if (value.len == 0 or value.len > 64) return error.InvalidRequestValue;
    for (value, 0..) |byte, index| {
        const valid = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            (index != 0 and byte == '_');
        if (!valid) return error.InvalidRequestValue;
    }
}
