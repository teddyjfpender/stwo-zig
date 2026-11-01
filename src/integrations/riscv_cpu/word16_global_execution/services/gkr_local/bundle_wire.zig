//! Durable wide execution transport. File digests detect corruption only;
//! independent setup, execution admission and every native verifier establish
//! acceptance. No producer-supplied configuration or accepted/security flag.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Legacy = @import("../wire.zig");
const R = @import("../roster.zig");
const C = @import("coordinator.zig");
const CPU = @import("cpu_worker.zig");
const TruthWorker = @import("truth_worker.zig");
const P = @import("../protocol.zig");
const Manifest = @import("manifest.zig");
const StageWire = @import("manifest_wire.zig");
const Cells = @import("../../../word16_execution/cells_wire.zig");
const Receipt = @import("../../../rv64_ethereum_batch_receipt.zig");
pub const Limits = Legacy.Limits;
pub const CpuDeclaration = Legacy.CpuDeclaration;
pub const TruthDeclaration = Legacy.TruthDeclaration;
const File = struct { bytes: u64, sha256: [32]u8 };
const Cpu = struct { declaration: CpuDeclaration, request: Legacy.CompactRequest, claims: []const [8]u32, proof: File };
const Truth = struct { declaration: TruthDeclaration, claims: []const [8]u32, proof: File };
pub const Metadata = struct {
    schema: u32 = 1,
    core_schema: u32 = @import("../../../word16_execution/protocol.zig").SCHEMA,
    field_degree: u32 = 8,
    profile: []const u8 = Manifest.PROFILE,
    cpus: []const Cpu,
    truths: []const Truth,
    stage_one: File,
    memory_words: u32,
    cells_sha256: [32]u8,
};
pub const Loaded = struct {
    cpu_declarations: []CpuDeclaration,
    truth_declarations: []TruthDeclaration,
    bundle: C.Bundle,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.bundle.deinit(a);
        a.free(self.cpu_declarations);
        a.free(self.truth_declarations);
        self.* = undefined;
    }
};
fn hash(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}
fn fileInfo(bytes: []const u8) File {
    return .{ .bytes = bytes.len, .sha256 = hash(bytes) };
}
fn hashCells(dir: std.fs.Dir, words: u32) ![32]u8 {
    var file = try dir.openFile("cells.bin", .{});
    defer file.close();
    if (try file.getEndPos() != 16 + 46 * @as(u64, words)) return error.InvalidMemorySidecarSize;
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    while (true) {
        const n = try file.read(&buffer);
        if (n == 0) break;
        digest.update(buffer[0..n]);
    }
    return digest.finalResult();
}
fn proofName(buffer: []u8, truth: bool, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}-{d}.bin", .{ if (truth) "truth" else "cpu", index });
}
fn claimCount(declaration: CpuDeclaration) usize {
    const Global = @import("global_cpu.zig");
    var n = Global.claimCount(.{ .core = .ls }) + Global.claimCount(.{ .core = .initial }) + Global.claimCount(.{ .core = .terminal });
    if (declaration.geometry.ls_tail_log != null) n += Global.claimCount(.{ .core = .ls_tail });
    for (std.enums.values(@import("../types.zig").Family)) |family| if (declaration.bridges.at(family) != null) {
        n += Global.claimCount(.{ .bridge = family });
    };
    return n;
}
fn canonical(values: []const [8]u32) !void {
    for (values) |value| for (value) |coordinate| if (coordinate >= core.fields.m31.Modulus) return error.NoncanonicalWideBundleClaim;
}
pub fn validate(metadata: Metadata, limits: Limits) !void {
    if (metadata.schema != 1 or metadata.core_schema != @import("../../../word16_execution/protocol.zig").SCHEMA or metadata.field_degree != 8 or !std.mem.eql(u8, metadata.profile, Manifest.PROFILE)) return error.WideBundleProfile;
    try Legacy.validateDeclarations(metadata.cpus, metadata.truths, metadata.memory_words, limits);
    var total: u64 = metadata.stage_one.bytes;
    if (total == 0 or total > StageWire.MAX_BYTES) return error.WideBundleStageLimit;
    for (metadata.cpus) |cpu| {
        if (cpu.claims.len != claimCount(cpu.declaration)) return error.InvalidWideGlobalClaimShape;
        try canonical(cpu.claims);
        total = try std.math.add(u64, total, cpu.proof.bytes);
    }
    for (metadata.truths) |truth| {
        if (truth.claims.len != 5) return error.InvalidWideTruthClaims;
        try canonical(truth.claims);
        total = try std.math.add(u64, total, truth.proof.bytes);
    }
    if (total > limits.max_total_proof_bytes) return error.ServicesWireBudget;
}
fn toWire(a: std.mem.Allocator, values: []const O) ![][8]u32 {
    const out = try a.alloc([8]u32, values.len);
    errdefer a.free(out);
    for (out, values) |*wire, value| for (wire, value.toM31Array()) |*coordinate, field| {
        if (field.v >= core.fields.m31.Modulus) return error.NoncanonicalWideBundleClaim;
        coordinate.* = field.v;
    };
    return out;
}
fn fromWire(a: std.mem.Allocator, values: []const [8]u32) ![]O {
    try canonical(values);
    const out = try a.alloc(O, values.len);
    for (out, values) |*value, wire| {
        var coordinates: [8]M = undefined;
        for (&coordinates, wire) |*field, coordinate| field.* = M.fromCanonical(coordinate);
        value.* = O.fromM31Array(coordinates);
    }
    return out;
}
/// Output directory must be new. Metadata is written last; no overwrite or
/// producer-declared acceptance substitutes for the independent receiver.
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const C.Bundle) !void {
    if (setups.len == 0 or bundle.requests.len != setups.len or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.InvalidWideServicesProofInventory;
    const initial = bundle.requests[0].base.memory.initial;
    const terminal = bundle.requests[bundle.requests.len - 1].base.memory.terminal;
    if (initial.len != terminal.len or initial.len > 1 << 22) return error.InvalidMemorySidecarCount;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const cpus = try scratch.alloc(Cpu, setups.len);
    for (setups, bundle.requests, bundle.cpus, cpus, 0..) |setup, request, proof, *out, i| {
        if ((i != 0 and request.base.memory.initial.len != 0) or (i + 1 != setups.len and request.base.memory.terminal.len != 0)) return error.InvalidServicesWireBoundary;
        out.* = .{ .declaration = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges }, .request = Legacy.CompactRequest.from(request), .claims = try toWire(scratch, proof.claims), .proof = fileInfo(proof.bytes) };
    }
    const tt = try scratch.alloc(Truth, truths.len);
    for (truths, bundle.truths, tt) |truth, proof, *out| out.* = .{ .declaration = TruthDeclaration.from(truth), .claims = try toWire(scratch, proof.claims), .proof = fileInfo(proof.bytes) };
    var metadata = Metadata{ .cpus = cpus, .truths = tt, .stage_one = fileInfo(bundle.stage_one_bytes), .memory_words = @intCast(initial.len), .cells_sha256 = @splat(0) };
    try validate(metadata, .{});
    try Cells.write(dir, initial, terminal);
    metadata.cells_sha256 = try hashCells(dir, metadata.memory_words);
    const json = try std.json.Stringify.valueAlloc(scratch, metadata, .{ .whitespace = .indent_2 });
    if (json.len > (Limits{}).max_metadata_bytes) return error.ServicesMetadataLimit;
    for (bundle.cpus, 0..) |proof, i| {
        var buffer: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buffer, false, i), proof.bytes);
    }
    for (bundle.truths, 0..) |proof, i| {
        var buffer: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buffer, true, i), proof.bytes);
    }
    try Receipt.writeExclusive(dir, "stage-one.bin", bundle.stage_one_bytes);
    try Receipt.writeExclusive(dir, "bundle.json", json);
    try std.posix.fsync(dir.fd);
}
fn readFile(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, expected: File) ![]u8 {
    var file = try dir.openFile(name, .{});
    defer file.close();
    if (try file.getEndPos() != expected.bytes) return error.WideBundleFileChanged;
    const bytes = try file.readToEndAlloc(a, std.math.cast(usize, expected.bytes) orelse return error.ServicesProofLimit);
    errdefer a.free(bytes);
    if (!std.mem.eql(u8, &hash(bytes), &expected.sha256)) return error.WideBundleFileChanged;
    return bytes;
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, limits: Limits) !Loaded {
    const bytes = try dir.readFileAlloc(a, "bundle.json", limits.max_metadata_bytes);
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(Metadata, a, bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    const metadata = parsed.value;
    try validate(metadata, limits);
    if (!std.mem.eql(u8, &try hashCells(dir, metadata.memory_words), &metadata.cells_sha256)) return error.WideBundleCellsChanged;
    const cells = try Cells.read(a, dir, metadata.memory_words);
    var owns_cells = true;
    errdefer if (owns_cells) cells.deinit(a);
    const cpu_declarations = try a.alloc(CpuDeclaration, metadata.cpus.len);
    errdefer a.free(cpu_declarations);
    const truth_declarations = try a.alloc(TruthDeclaration, metadata.truths.len);
    errdefer a.free(truth_declarations);
    const requests = try a.alloc(P.Request, metadata.cpus.len);
    errdefer a.free(requests);
    const cpus = try a.alloc(CPU.CpuEncoded, metadata.cpus.len);
    errdefer a.free(cpus);
    var cpu_done: usize = 0;
    errdefer for (cpus[0..cpu_done]) |*proof| proof.deinit(a);
    for (metadata.cpus, cpus, requests, cpu_declarations, 0..) |cpu, *proof, *request, *declaration, i| {
        const claims = try fromWire(a, cpu.claims);
        errdefer a.free(claims);
        var buffer: [64]u8 = undefined;
        proof.* = .{ .bytes = try readFile(a, dir, try proofName(&buffer, false, i), cpu.proof), .claims = claims };
        cpu_done += 1;
        declaration.* = cpu.declaration;
        request.* = cpu.request.expand(if (i == 0) cells.initial else &.{}, if (i + 1 == metadata.cpus.len) cells.terminal else &.{});
    }
    const tt = try a.alloc(TruthWorker.TruthEncoded, metadata.truths.len);
    errdefer a.free(tt);
    var truth_done: usize = 0;
    errdefer for (tt[0..truth_done]) |*proof| proof.deinit(a);
    for (metadata.truths, tt, truth_declarations, 0..) |truth, *proof, *declaration, i| {
        const claims = try fromWire(a, truth.claims);
        errdefer a.free(claims);
        var buffer: [64]u8 = undefined;
        proof.* = .{ .bytes = try readFile(a, dir, try proofName(&buffer, true, i), truth.proof), .claims = claims };
        truth_done += 1;
        declaration.* = truth.declaration;
    }
    const stage = try readFile(a, dir, "stage-one.bin", metadata.stage_one);
    owns_cells = false;
    return .{ .cpu_declarations = cpu_declarations, .truth_declarations = truth_declarations, .bundle = .{ .requests = requests, .stage_one_bytes = stage, .cpus = cpus, .truths = tt } };
}
