//! INACTIVE distributed protocol data. A receipt is a commitment message, not
//! proof of a computation. Only an eventual complete proof receiver may accept.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").rv64_air;
pub const P = air.protocol;
pub const Scheme = engine.pcs.CommitmentSchemeProver(@import("stwo_cpu_backend").CpuBackend, P.Hasher, P.MerkleChannel);
pub const Digest = [32]u8;
/// Distinct from a packet content SHA and a native nine-limb RAM value root.
pub const CommitmentRoot = struct { value: P.Hasher.Hash };
pub const Protocol = enum(u32) { functional13_v1 = 1, ram64_v2 = 2, functional13_unified_v2 = 3 };
pub const Role = enum(u32) { cpu = 1, alu = 2, binary = 3, shift = 4, load_store = 5, keccak_ram = 6, secp_ram = 7, ram_initialization = 8, ram_teardown = 9, terminal = 10, public_consumer = 11 };
pub const Context = struct {
    protocol: Protocol = .functional13_v1,
    request_id: u64,
    request_digest: Digest,
    instance: Digest,
    program_key: Digest,
    input: Digest,
    policy: Digest,
    terminal: Digest,
    opcode_map: Digest,
    relation_epoch: u64,
    positive_limit: u64 = 0x7fff_fffe,
    // The global relation does not remove the local register clock bound.
    local_register_clock_bits: u32 = 24,
};
/// Receiver-derived exact role inventory. Transport spans are identity/planning
/// metadata; they do NOT assert a bijection for reusable functional facts.
/// The schema fixes which tuple/weight columns this precommitted tree owns.
pub const Spec = struct {
    ordinal: u32,
    role: Role,
    schema: Digest,
    job_witness: Digest,
    public_statement: Digest,
    instance_epoch: u64,
    first_request: u64,
    request_count: u64,
    fixed_tree: u16 = 0,
    shared_tree: u16 = 1,
    expected_fixed: CommitmentRoot,
    /// Trace/base logs; PCS columns include the suite's fixed FRI blowup.
    column_logs: []const u32,
};
pub const Receipt = struct {
    ordinal: u32,
    spec_digest: Digest,
    fixed: CommitmentRoot,
    shared: CommitmentRoot,
};
pub const MAX_ROOTS = 4096;
pub const MAX_COLUMNS = 65536;
pub const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;

/// Uses the ACTUAL committed PCS tree. Resolves observed deferred commitments;
/// no packet SHA, native root or arbitrary external challenge enters this API.
pub fn fromCommitted(a: std.mem.Allocator, scheme: *Scheme, spec: Spec) !Receipt {
    try validateSpec(spec);
    if (!std.meta.eql(scheme.config, P.config()) or scheme.revision_config != null) return error.DistributedSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2) return error.InvalidStage1Phase;
    const tree = &scheme.trees.items[spec.shared_tree];
    if (tree.columns.len != spec.column_logs.len) return error.Stage1GeometryMismatch;
    for (tree.columns, spec.column_logs) |column, log| if (column.log_size != log + P.config().fri_config.log_blowup_factor) return error.Stage1GeometryMismatch;
    if (!std.mem.eql(u8, &roots.items[spec.fixed_tree], &spec.expected_fixed.value)) return error.Stage1FixedRootMismatch;
    return .{ .ordinal = spec.ordinal, .spec_digest = specDigest(spec), .fixed = .{ .value = roots.items[spec.fixed_tree] }, .shared = .{ .value = roots.items[spec.shared_tree] } };
}
pub fn validateSpec(spec: Spec) !void {
    if (spec.role != .cpu and spec.role != .alu and spec.role != .binary and spec.role != .shift and spec.role != .public_consumer) return error.UnsupportedDistributedRamProfile;
    if (spec.column_logs.len == 0 or spec.column_logs.len > MAX_COLUMNS or spec.fixed_tree != 0 or spec.shared_tree != 1) return error.InvalidDistributedSpec;
    if (spec.role == .public_consumer) {
        if (spec.column_logs.len != 14) return error.InvalidDistributedSpec;
        for (spec.column_logs) |log| if (log != 5) return error.InvalidDistributedSpec;
    }
    _ = std.math.add(u64, spec.first_request, spec.request_count) catch return error.InvalidDistributedSpec;
    for (spec.column_logs) |log| if (log < 5 or log > (if (spec.role == .cpu) @as(u32, 22) else @as(u32, 20))) return error.InvalidDistributedSpec;
}
pub fn specDigest(spec: Spec) Digest {
    var channel = P.Channel{};
    channel.mixU32s(&.{ 0x52563634, 0x44535043, 1 });
    mixSpec(&channel, spec);
    return channel.digestBytes();
}
pub fn mixSpec(channel: *P.Channel, spec: Spec) void {
    channel.mixU32s(&.{ spec.ordinal, @intFromEnum(spec.role), spec.fixed_tree, spec.shared_tree });
    for ([_]Digest{ spec.schema, spec.job_witness, spec.public_statement, spec.expected_fixed.value }) |digest| mixDigest(channel, digest);
    channel.mixU64(spec.instance_epoch);
    channel.mixU64(spec.first_request);
    channel.mixU64(spec.request_count);
    channel.mixU64(spec.column_logs.len);
    channel.mixU32s(spec.column_logs);
}
pub fn mixDigest(channel: *P.Channel, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
/// Binds global operation IDs and their family-local semantic enumeration.
pub fn opcodeMapIdentity() Digest {
    const Ops = air.word16_v1.operations;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16.bus13.operation-map.v1\x00add,sub,addw,subw,slt,sltu,eq,ne,ge,geu\x00and,or,xor\x00sll,srl,sra,sllw,srlw,sraw");
    for ([_]Ops.Family{ .alu, .binary, .shift }, [_]u8{ 10, 3, 6 }) |family, count| {
        hash.update(&.{ @intFromEnum(family), count });
        for (0..count) |i| hash.update(&.{Ops.busIdFor(family, @intCast(i))});
    }
    return hash.finalResult();
}
