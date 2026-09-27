//! Strict typed transport for v5 provider/projection proofs. Policy, security,
//! roots, geometry and claim count are supplied independently of artifact bytes.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const Q = core.fields.qm31.QM31;
const suite = core.proof_suites.Blake3;
pub const Family = enum(u32) {
    native = 1,
    request,
    rom,
    native_projection,
    native_provider,
    opcode_memory,
    caller,
    caller_program,
    caller_state,
    caller_tables,
    external_memory,
    packed_memory,
    range16,
    native_fused,
    caller_fused,
    ram_lanes,
    native_readonly,
    caller_readonly,
};
pub fn ProofFor(comptime family: Family) type {
    return switch (family) {
        .native => @import("block_v5_native_execution_proof_v3.zig").Proof,
        .request => @import("block_v5_program_request_proof_v1.zig").Proof,
        .rom => @import("block_v5_program_table_proof_v1.zig").Proof,
        .native_readonly => @import("block_v5_readonly_input_proof_v1.zig").Proof,
        .caller_readonly => @import("block_v5_caller_readonly_proof_v1.zig").Proof,
        .ram_lanes => @import("block_v5_ram_lanes_proof_v1.zig").Proof,
        .caller_fused => @import("block_v5_caller_fused_proof_v1.zig").Proof,
        .native_fused => @import("block_v5_native_projection_fused_proof_v2.zig").Proof,
        .native_projection => @import("block_v5_native_lookup_request_proof_v1.zig").Proof,
        .native_provider => @import("block_v5_native_lookup_proof_v1.zig").Proof,
        .opcode_memory => @import("block_v5_opcode_memory_sidecar_proof_v1.zig").Proof,
        .caller => @import("block_v5_precompile_family_proof_v1.zig").Proof,
        .caller_program => @import("block_v5_program_extension_proof_v1.zig").Proof,
        .caller_state => @import("block_v5_precompile_state_request_proof_v1.zig").Proof,
        .caller_tables => @import("block_v5_precompile_lookup_proof_v1.zig").Proof,
        .external_memory => @import("block_v5_external_memory_sidecar_proof_v1.zig").Proof,
        .packed_memory => @import("block_v5_word_memory_proof_v1.zig").Proof,
        .range16 => @import("block_v5_range16_proof_v1.zig").Proof,
    };
}
fn PayloadFor(comptime family: Family) type {
    return if (family == .caller_state) ProofFor(.caller_program) else ProofFor(family);
}
pub const Geometry = struct {
    tree_count: u8,
    tree_columns: [5]u32,
    max_column_log: u32,
    max_merkle_log: u32,
    sample_width_limits: [5]u32 = .{ 2, 6, 2, 2, 1 },
    allow_empty_main_tree: bool = false,
    pub fn validate(self: Geometry) !void {
        if ((self.tree_count != 4 and self.tree_count != 5) or self.max_column_log > 30 or
            self.max_merkle_log > 30 or self.max_merkle_log < self.max_column_log)
            return error.InvalidV5BundleGeometry;
        for (self.tree_columns[0..self.tree_count], 0..) |count, index|
            if (count == 0 and !(index == 1 and self.allow_empty_main_tree)) return error.InvalidV5BundleGeometry;
        for (self.sample_width_limits[0..self.tree_count]) |width| if (width == 0 or width > 16) return error.InvalidV5BundleGeometry;
        if (self.tree_count == 4 and (self.tree_columns[4] != 0 or self.sample_width_limits[4] != 1))
            return error.InvalidV5BundleGeometry;
    }
};
pub const Expected = struct {
    family: Family,
    index: u32,
    policy_digest: [32]u8,
    config: core.pcs.PcsConfig,
    roots: [3][32]u8,
    root_count: u8 = 2,
    geometry: Geometry,
    claim_count: u32,
    /// Independent second census for the canonical full native fusion.
    memory_claim_count: u32 = 0,
    state_claim_count: u32 = 0,
    readonly_interval_count: u32 = 0,
    table_claim_count: u32 = 0,
    /// Checked before any received claim array allocation.
    pub fn totalClaims(self: Expected) !u32 {
        return std.math.add(u32, try std.math.add(u32, self.claim_count, self.state_claim_count), try std.math.add(u32, self.table_claim_count, self.memory_claim_count));
    }
    pub fn validate(self: Expected) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        try self.geometry.validate();
        if (std.mem.allEqual(u8, &self.policy_digest, 0) or self.root_count < 2 or self.root_count > 3 or
            self.root_count >= self.geometry.tree_count or
            (self.claim_count == 0 and self.family != .native and self.family != .caller))
            return error.InvalidV5BundleExpected;
        if (self.family != .native_fused and self.family != .caller_fused and self.family != .caller_readonly and self.memory_claim_count != 0) return error.InvalidV5BundleExpected;
        if (self.family == .native_fused and
            ((self.memory_claim_count == 0 and (self.geometry.tree_count != 4 or self.root_count != 2)) or
                (self.memory_claim_count != 0 and (self.geometry.tree_count != 5 or self.root_count != 3))))
            return error.InvalidV5BundleExpected;
        if (self.family == .caller_fused or self.family == .caller_readonly) {
            if (self.state_claim_count != self.claim_count or self.table_claim_count == 0 or self.memory_claim_count == 0 or self.geometry.tree_count != 5 or self.root_count != 3) return error.InvalidV5BundleExpected;
        } else if (self.state_claim_count != 0 or self.table_claim_count != 0) return error.InvalidV5BundleExpected;
        if (self.family == .native_readonly) {
            if (self.claim_count != 1 or self.geometry.tree_count != 4 or self.root_count != 2 or self.readonly_interval_count == 0) return error.InvalidV5BundleExpected;
        } else if (self.family == .caller_readonly) {
            if (self.readonly_interval_count == 0) return error.InvalidV5BundleExpected;
        } else if (self.readonly_interval_count != 0) return error.InvalidV5BundleExpected;
        _ = try self.totalClaims();
        for (self.roots[0..self.root_count]) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidV5BundleExpected;
    }
};
pub const Limits = struct {
    artifact_bytes: usize,
    proof_bytes: usize,
    max_claims: u32,
    pub fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or self.max_claims == 0)
            return error.InvalidV5BundleCodecLimits;
    }
};
const MAGIC = "B5STOR01";
const HEADER: usize = 8 + 4 + 4 + 32 + 4 + 4 + 8;
fn claimCount(comptime T: type, proof: *const T) usize {
    return if (@hasField(T, "program_claims")) proof.program_claims.len else if (@hasField(T, "claims")) proof.claims.len else 1;
}
fn validateProof(comptime T: type, proof: *const T, expected: Expected) !void {
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.config) or claimCount(T, proof) != expected.claim_count)
        return error.UntrustedV5BundleProofPolicy;
    if (@hasField(T, "memory_claims")) {
        if (proof.memory_claims.len != expected.memory_claim_count) return error.UntrustedV5BundleMemoryClaimCount;
    } else if (expected.memory_claim_count != 0) return error.UntrustedV5BundleMemoryClaimCount;
    if (@hasField(T, "state_claims")) {
        if (proof.state_claims.len != expected.state_claim_count or proof.table_claims.len != expected.table_claim_count) return error.UntrustedV5BundleProjectionClaimCount;
    }
    if (@hasField(T, "readonly_claims")) {
        if (proof.readonly_claims.len != expected.memory_claim_count) return error.UntrustedV5BundleMemoryClaimCount;
        for (proof.readonly_claims) |claim| if (claim.counters.len != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
    }
    if (@hasField(T, "counters")) if (proof.counters.len != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
    const commitments = proof.stark.commitment_scheme_proof.commitments.items;
    if (commitments.len != expected.geometry.tree_count) return error.UntrustedV5BundleProofRoots;
    for (expected.roots[0..expected.root_count], commitments[0..expected.root_count]) |root, actual|
        if (!std.meta.eql(root, actual)) return error.UntrustedV5BundleProofRoots;
}
pub fn encode(comptime family: Family, a: std.mem.Allocator, proof: *const ProofFor(family), expected: Expected, limits: Limits) ![]u8 {
    if (family == .native or family == .caller or family == .ram_lanes) @compileError("use strict native/caller/lane codec");
    try limits.validate();
    try expected.validate();
    if (expected.family != family or try expected.totalClaims() > limits.max_claims) return error.UntrustedV5BundleProofPolicy;
    const payload = if (family == .caller_state) &proof.projection else proof;
    try validateProof(PayloadFor(family), payload, expected);
    var counter = @import("block_v5_cpu_counting_writer_v1.zig").Counting.init(limits.artifact_bytes);
    writeMetadata(family, &counter.writer, payload, expected) catch |err| {
        if (counter.exceeded) return error.V5BundleArtifactTooLarge;
        return err;
    };
    const body = counter.count;
    const proof_ceiling = body +| limits.proof_bytes;
    counter.limit = @min(limits.artifact_bytes, proof_ceiling);
    postcard.serializeProof(suite.Hasher, &counter.writer, payload.stark) catch |err| {
        if (counter.exceeded) return if (proof_ceiling <= limits.artifact_bytes) error.V5BundleProofTooLarge else error.V5BundleArtifactTooLarge;
        return err;
    };
    const length = counter.count;
    if (length - body > limits.proof_bytes) return error.V5BundleProofTooLarge;
    const raw = try a.alloc(u8, length);
    errdefer a.free(raw);
    var writer = std.Io.Writer.fixed(raw);
    try writeMetadata(family, &writer, payload, expected);
    if (writer.buffered().len != body) return error.ChangedV5BundleSerialization;
    try postcard.serializeProof(suite.Hasher, &writer, payload.stark);
    if (writer.buffered().len != length) return error.ChangedV5BundleSerialization;
    std.mem.writeInt(u32, raw[52..56], std.math.cast(u32, body - HEADER) orelse return error.Overflow, .little);
    std.mem.writeInt(u64, raw[56..64], length - body, .little);
    return raw;
}
fn writeMetadata(comptime family: Family, writer: *std.Io.Writer, payload: *const PayloadFor(family), expected: Expected) !void {
    try writer.writeAll(MAGIC);
    try wire.writeInt(writer, u32, @intFromEnum(family));
    try wire.writeInt(writer, u32, expected.index);
    try writer.writeAll(&expected.policy_digest);
    try wire.writeInt(writer, u32, expected.claim_count);
    try wire.writeInt(writer, u32, 0);
    try wire.writeInt(writer, u64, 0);
    if (@hasField(PayloadFor(family), "memory_claims")) try wire.writeInt(writer, u32, expected.memory_claim_count);
    if (@hasField(PayloadFor(family), "program_claims")) {
        try wire.writeInt(writer, u32, expected.state_claim_count);
        try wire.writeInt(writer, u32, expected.table_claim_count);
        inline for (.{ "program_claims", "state_claims", "table_claims" }) |field| for (@field(payload, field)) |claim| try writeValue(@TypeOf(claim), writer, claim);
    } else if (@hasField(PayloadFor(family), "claims")) {
        for (payload.claims) |claim| try writeValue(@TypeOf(claim), writer, claim);
    } else try writeValue(@TypeOf(payload.claim), writer, payload.claim);
    if (@hasField(PayloadFor(family), "memory_claims")) for (payload.memory_claims) |claim| try writeValue(@TypeOf(claim), writer, claim);
    if (@hasField(PayloadFor(family), "readonly_claims")) {
        try wire.writeInt(writer, u32, expected.readonly_interval_count);
        for (payload.readonly_claims) |part| {
            try writeValue(@TypeOf(part.claim), writer, part.claim);
            for (part.counters) |count| try wire.writeInt(writer, u64, count);
        }
    }
    if (@hasField(PayloadFor(family), "counters")) {
        try wire.writeInt(writer, u32, expected.readonly_interval_count);
        for (payload.counters) |count| try wire.writeInt(writer, u64, count);
    }
}
pub fn decode(comptime family: Family, a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !ProofFor(family) {
    if (family == .native or family == .caller or family == .ram_lanes) @compileError("use strict native/caller/lane codec");
    try limits.validate();
    try expected.validate();
    if (expected.family != family or try expected.totalClaims() > limits.max_claims or raw.len > limits.artifact_bytes)
        return error.UntrustedV5BundleProofPolicy;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC) or try cursor.readInt(u32) != @intFromEnum(family) or
        try cursor.readInt(u32) != expected.index or !std.mem.eql(u8, try cursor.take(32), &expected.policy_digest) or
        try cursor.readInt(u32) != expected.claim_count) return error.UntrustedV5BundleEnvelope;
    const metadata_len = try cursor.readInt(u32);
    const proof_len = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (proof_len == 0 or proof_len > limits.proof_bytes) return error.V5BundleProofTooLarge;
    var claims_cursor = wire.Cursor.init(try cursor.take(metadata_len));
    const T = PayloadFor(family);
    if (@hasField(T, "memory_claims")) {
        if (try claims_cursor.readInt(u32) != expected.memory_claim_count) return error.UntrustedV5BundleMemoryClaimCount;
    }
    if (@hasField(T, "program_claims")) {
        if (try claims_cursor.readInt(u32) != expected.state_claim_count or try claims_cursor.readInt(u32) != expected.table_claim_count) return error.UntrustedV5BundleProjectionClaimCount;
    }
    const proof_raw = try cursor.take(proof_len);
    try cursor.requireDone();
    // Structural admission is allocation-free and precedes all sequence
    // decoding. Exact masks/equations remain the fresh verifier's obligation.
    if (family == .native_readonly or family == .caller_readonly) try scanReadonlyMetadata(T, claims_cursor, expected);
    try preflight(proof_raw, expected, limits);
    var result: T = undefined;
    if (@hasField(T, "program_claims")) {
        inline for (.{ "program_claims", "state_claims", "table_claims", "memory_claims" }) |field| @field(result, field) = &.{};
    } else {
        if (@hasField(T, "memory_claims")) result.memory_claims = &.{};
        if (@hasField(T, "claims")) if (@typeInfo(@FieldType(T, "claims")) == .pointer) {
            result.claims = &.{};
        };
    }
    if (@hasField(T, "readonly_claims")) result.readonly_claims = &.{};
    if (@hasField(T, "counters")) result.counters = &.{};
    errdefer freeClaims(T, a, &result);
    if (@hasField(T, "program_claims")) {
        const counts = .{ expected.claim_count, expected.state_claim_count, expected.table_claim_count };
        inline for (.{ "program_claims", "state_claims", "table_claims" }, counts) |field, count| {
            const Child = @typeInfo(@FieldType(T, field)).pointer.child;
            @field(result, field) = try a.alloc(Child, count);
            for (@field(result, field)) |*claim| claim.* = try readValue(Child, &claims_cursor);
        }
    } else if (@hasField(T, "claims")) {
        const Claims = @FieldType(T, "claims");
        switch (@typeInfo(Claims)) {
            .pointer => |pointer| {
                result.claims = try a.alloc(pointer.child, expected.claim_count);
                for (result.claims) |*claim| claim.* = try readValue(pointer.child, &claims_cursor);
            },
            .array => |array| {
                if (array.len != expected.claim_count) return error.UntrustedV5BundleClaimCount;
                for (&result.claims) |*claim| claim.* = try readValue(array.child, &claims_cursor);
            },
            else => @compileError("unsupported claim storage"),
        }
    } else result.claim = try readValue(@FieldType(T, "claim"), &claims_cursor);
    if (@hasField(T, "memory_claims")) {
        const Child = @typeInfo(@FieldType(T, "memory_claims")).pointer.child;
        result.memory_claims = try a.alloc(Child, expected.memory_claim_count);
        for (result.memory_claims) |*claim| claim.* = try readValue(Child, &claims_cursor);
    }
    if (@hasField(T, "readonly_claims")) {
        if (try claims_cursor.readInt(u32) != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
        const Child = @typeInfo(@FieldType(T, "readonly_claims")).pointer.child;
        result.readonly_claims = try a.alloc(Child, expected.memory_claim_count);
        for (result.readonly_claims) |*part| part.* = .{ .claim = undefined, .counters = &.{} };
        for (result.readonly_claims) |*part| {
            part.claim = try readValue(@FieldType(Child, "claim"), &claims_cursor);
            part.counters = try a.alloc(u64, expected.readonly_interval_count);
            for (part.counters) |*count| count.* = try claims_cursor.readInt(u64);
        }
    }
    if (@hasField(T, "counters")) {
        if (try claims_cursor.readInt(u32) != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
        result.counters = try a.alloc(u64, expected.readonly_interval_count);
        for (result.counters) |*count| count.* = try claims_cursor.readInt(u64);
    }
    try claims_cursor.requireDone();
    var stream = std.io.fixedBufferStream(proof_raw);
    result.stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer result.stark.deinit(a);
    if (stream.pos != proof_raw.len) return error.TrailingV5BundleProof;
    try validateProof(T, &result, expected);
    return if (family == .caller_state) .{ .projection = result } else result;
}
// Canonical scalar/length scan before ANY claim/counter sequence allocation.
fn scanReadonlyMetadata(comptime T: type, start: wire.Cursor, expected: Expected) !void {
    var cursor = start;
    if (@hasField(T, "program_claims")) {
        const counts = .{ expected.claim_count, expected.state_claim_count, expected.table_claim_count, expected.memory_claim_count };
        inline for (.{ "program_claims", "state_claims", "table_claims", "memory_claims" }, counts) |field, count| {
            const Child = @typeInfo(@FieldType(T, field)).pointer.child;
            for (0..count) |_| _ = try readValue(Child, &cursor);
        }
        if (try cursor.readInt(u32) != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
        const Part = @typeInfo(@FieldType(T, "readonly_claims")).pointer.child;
        const bytes = try std.math.mul(usize, expected.readonly_interval_count, @sizeOf(u64));
        for (0..expected.memory_claim_count) |_| {
            _ = try readValue(@FieldType(Part, "claim"), &cursor);
            _ = try cursor.take(bytes);
        }
    } else {
        _ = try readValue(@FieldType(T, "claim"), &cursor);
        if (try cursor.readInt(u32) != expected.readonly_interval_count) return error.UntrustedV5ReadonlyCounterCount;
        _ = try cursor.take(try std.math.mul(usize, expected.readonly_interval_count, @sizeOf(u64)));
    }
    try cursor.requireDone();
}
fn freeClaims(comptime T: type, a: std.mem.Allocator, proof: *T) void {
    if (@hasField(T, "readonly_claims")) {
        for (proof.readonly_claims) |part| a.free(part.counters);
        a.free(proof.readonly_claims);
    }
    if (@hasField(T, "counters")) a.free(proof.counters);
    if (@hasField(T, "program_claims")) {
        inline for (.{ "program_claims", "state_claims", "table_claims" }) |field| a.free(@field(proof, field));
    }
    if (@hasField(T, "memory_claims")) a.free(proof.memory_claims);
    if (@hasField(T, "claims")) {
        if (@typeInfo(@FieldType(T, "claims")) == .pointer) a.free(proof.claims);
    }
}
fn preflight(raw: []const u8, expected: Expected, limits: Limits) !void {
    const config = expected.config;
    const pconfig = postcard.proof_preflight.Config{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size };
    const geometry = expected.geometry;
    if (geometry.tree_count == 5) return postcard.proof_preflight.validateFive(raw, .{ .config = pconfig, .tree_columns = geometry.tree_columns, .max_column_log_size = geometry.max_column_log, .max_merkle_column_log_size = geometry.max_merkle_log, .sample_width_limits = geometry.sample_width_limits, .allow_empty_main_tree = geometry.allow_empty_main_tree, .hash_size = 32, .max_wire_bytes = limits.proof_bytes });
    return postcard.proof_preflight.validate(raw, .{ .config = pconfig, .tree_columns = geometry.tree_columns[0..4].*, .max_column_log_size = geometry.max_column_log, .max_merkle_column_log_size = geometry.max_merkle_log, .sample_width_limits = geometry.sample_width_limits[0..4].*, .allow_zero_samples = true, .allow_empty_main_tree = geometry.allow_empty_main_tree, .hash_size = 32, .max_wire_bytes = limits.proof_bytes });
}
fn writeValue(comptime T: type, writer: *std.Io.Writer, value: T) !void {
    if (T == Q) {
        for (value.toM31Array()) |coordinate| if (coordinate.toU32() >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        return wire.writeQm31(writer, value);
    }
    switch (@typeInfo(T)) {
        .int => |int| {
            if (int.signedness != .unsigned or int.bits > 64) @compileError("noncanonical claim integer");
            try wire.writeInt(writer, T, value);
        },
        .array => for (value) |entry| try writeValue(@TypeOf(entry), writer, entry),
        .@"struct" => |structure| inline for (structure.fields) |field| try writeValue(field.type, writer, @field(value, field.name)),
        else => @compileError("claim metadata must contain only unsigned integers, canonical QM31, arrays and structs"),
    }
}
fn readValue(comptime T: type, cursor: *wire.Cursor) !T {
    if (T == Q) return cursor.readQm31();
    switch (@typeInfo(T)) {
        .int => |int| {
            if (int.signedness != .unsigned or int.bits > 64) @compileError("noncanonical claim integer");
            return cursor.readInt(T);
        },
        .array => |array| {
            var result: T = undefined;
            for (&result) |*entry| entry.* = try readValue(array.child, cursor);
            return result;
        },
        .@"struct" => |structure| {
            var result: T = undefined;
            inline for (structure.fields) |field| @field(result, field.name) = try readValue(field.type, cursor);
            return result;
        },
        else => @compileError("unsupported claim metadata"),
    }
}
