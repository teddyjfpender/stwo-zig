//! Variable-roster transport only. Hashes detect corruption; independent keys,
//! Expected image/state and execution.verify still establish acceptance.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = @import("execution.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const T = @import("types.zig");
const G = @import("../protocol.zig");
const Geo = @import("../../word16_execution/geometry.zig").Geometry;
const Cells = @import("../../word16_execution/cells_wire.zig");
const Cell = @import("../../word16_execution/memory/statement.zig").Cell;
const Receipt = @import("../../rv64_ethereum_batch_receipt.zig");
pub const Limits = struct { max_cpus: usize = 256, max_truths: usize = 256, max_metadata_bytes: usize = 16 << 20, max_memory_words: u32 = 1 << 22, max_proof_bytes: u64 = 64 << 20, max_total_proof_bytes: u64 = 1 << 30, max_total_steps: u64 = 1 << 30, max_native_row_sum: u64 = 1 << 32 };
pub const CompactRequest = struct {
    cpu: @FieldType(G.Old.Request, "cpu"),
    epoch: u16,
    division_requests: u32,
    multiplication_requests: u32,
    memory_epoch: u16,
    ls_count: u32,
    calls: [3]u32,
    fn from(r: P.Request) @This() {
        return .{ .cpu = r.base.cpu, .epoch = r.base.epoch, .division_requests = r.base.division_requests, .multiplication_requests = r.base.multiplication_requests, .memory_epoch = r.base.memory.epoch, .ls_count = r.base.memory.ls_count, .calls = r.calls };
    }
    fn expand(self: @This(), initial: []const Cell, terminal: []const Cell) P.Request {
        return .{ .base = .{ .cpu = self.cpu, .epoch = self.epoch, .division_requests = self.division_requests, .multiplication_requests = self.multiplication_requests, .memory = .{ .initial = initial, .terminal = terminal, .epoch = self.memory_epoch, .ls_count = self.ls_count } }, .calls = self.calls };
    }
};
pub const CpuDeclaration = struct { geometry: Geo, bridges: T.Logs };
pub const TruthDeclaration = struct {
    family: T.Family,
    first_id: u32,
    calls: u32,
    logs: [2]u32,
    pub fn from(t: R.Truth) @This() {
        return .{ .family = t.family(), .first_id = t.first(), .calls = t.count(), .logs = switch (t) {
            .keccak => |k| .{ k.setup.log, 0 },
            .secp => |s| s.setup.logs,
        } };
    }
};
const File = struct { bytes: u64, sha256: [32]u8 };
const Cpu = struct { declaration: CpuDeclaration, request: CompactRequest, claims: E.CpuClaims, proof: File };
const Truth = struct { declaration: TruthDeclaration, claims: [3]G.Q, proof: File };
pub const Metadata = struct { schema: u32 = 1, core_schema: u32 = G.Old.SCHEMA, cpus: []const Cpu, truths: []const Truth, specs: []const [32]u8, roots: []const G.Receipt, seal: [32]u8, memory_words: u32, cells_sha256: [32]u8 };
pub const Loaded = struct {
    cpu_declarations: []CpuDeclaration,
    truth_declarations: []TruthDeclaration,
    bundle: E.Bundle,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.bundle.deinit(a);
        a.free(self.cpu_declarations);
        a.free(self.truth_declarations);
    }
};
fn hash(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}
fn hashCells(dir: std.fs.Dir, words: u32) ![32]u8 {
    var f = try dir.openFile("cells.bin", .{});
    defer f.close();
    if (try f.getEndPos() != 16 + 46 * @as(u64, words)) return error.InvalidMemorySidecarSize;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return h.finalResult();
}
fn proofName(buf: []u8, truth: bool, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}-{d}.bin", .{ if (truth) "truth" else "cpu", index });
}
fn rowSum(g: Geo) !u64 {
    var n: u64 = 4 * 65536 + 256 + 32;
    inline for (std.meta.fields(Geo)) |field| {
        if (comptime std.mem.endsWith(u8, field.name, "_log")) {
            if (comptime field.type == u32) {
                n = try std.math.add(u64, n, @as(u64, 1) << @intCast(@field(g, field.name)));
            } else if (comptime field.type == ?u32) {
                if (@field(g, field.name)) |log| n = try std.math.add(u64, n, @as(u64, 1) << @intCast(log));
            }
        }
    }
    return n;
}
/// Native admission only, before sidecar/key allocation. Proof acceptance still
/// invokes complete independent-material/image admission in execution.verify.
pub fn validate(m: Metadata, limits: Limits) !void {
    if (m.schema != 1 or m.core_schema != G.Old.SCHEMA or m.cpus.len == 0 or m.cpus.len > limits.max_cpus or m.truths.len > limits.max_truths or m.cpus.len > 65535 or m.truths.len > 65535 - m.cpus.len or m.specs.len != m.cpus.len + m.truths.len or m.roots.len != m.specs.len) return error.InvalidServicesWireRoster;
    if (m.memory_words > limits.max_memory_words or m.memory_words > 1 << 22) return error.InvalidMemorySidecarCount;
    var totals: [3]u64 = @splat(0);
    var sum_steps: u64 = 0;
    var proof_bytes: u64 = 0;
    var native_rows: u64 = 0;
    var ram: u64 = 2 * @as(u64, m.memory_words);
    for (m.cpus, 0..) |cpu, index| {
        const g = cpu.declaration.geometry;
        try g.validate();
        try cpu.request.cpu.validate(g.cpu_log);
        if (cpu.request.epoch != index + 1 or cpu.request.memory_epoch != cpu.request.epoch or cpu.request.division_requests > cpu.request.cpu.steps or cpu.request.multiplication_requests > cpu.request.cpu.steps or @as(u64, cpu.request.calls[0]) + cpu.request.calls[1] + cpu.request.calls[2] + cpu.request.ls_count > cpu.request.cpu.steps) return error.InvalidServicesWireRequest;
        _ = try g.lsCounts(cpu.request.ls_count);
        if (g.omit_empty_division and cpu.request.division_requests != 0) return error.InvalidServicesWireRequest;
        sum_steps = try std.math.add(u64, sum_steps, cpu.request.cpu.steps);
        native_rows = try std.math.add(u64, native_rows, try rowSum(g));
        var mass16 = try g.range16Mass();
        var mass8 = try g.range8Mass();
        for (0..3) |k| {
            const f: T.Family = @enumFromInt(k);
            const log = cpu.declaration.bridges.at(f);
            if ((log != null) != (cpu.request.calls[k] != 0) or totals[k] >= core.fields.m31.Modulus - 1) return error.InvalidServicesWireRequest;
            if (log) |l| {
                if (k == 0) {
                    _ = try A.crypto.keccak.word16_bridge.types.validateGeometry(cpu.request.calls[k], @intCast(1 + totals[k]), l);
                } else {
                    _ = try A.crypto.secp256k1.word16_bridge.types.validateGeometry(@enumFromInt(k), cpu.request.calls[k], @intCast(1 + totals[k]), l);
                }
                const n = @as(u64, 1) << @intCast(l);
                native_rows = try std.math.add(u64, native_rows, n);
                mass16 = try std.math.add(u64, mass16, (if (k == 0) @as(u64, A.crypto.keccak.word16_bridge.layout.U16.len) else A.crypto.secp256k1.word16_bridge.layout.U16.len) * n);
                mass8 = try std.math.add(u64, mass8, (if (k == 0) @as(u64, A.crypto.keccak.word16_bridge.layout.U8.len) else A.crypto.secp256k1.word16_bridge.layout.U8.len) * n);
            }
            totals[k] = try std.math.add(u64, totals[k], cpu.request.calls[k]);
        }
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        ram = try std.math.add(u64, ram, 2 * @as(u64, cpu.request.ls_count) + 50 * @as(u64, cpu.request.calls[0]) + 48 * @as(u64, cpu.request.calls[1]) + 24 * @as(u64, cpu.request.calls[2]));
        try cpu.claims.canonical();
        for (cpu.claims.extras, 0..) |c, k| if (cpu.declaration.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        if (cpu.proof.bytes == 0 or cpu.proof.bytes > limits.max_proof_bytes) return error.ServicesProofLimit;
        proof_bytes = try std.math.add(u64, proof_bytes, cpu.proof.bytes);
    }
    if (m.memory_words >= (@as(u64, 1) << @intCast(m.cpus[0].declaration.geometry.initialLog())) or m.memory_words >= (@as(u64, 1) << @intCast(m.cpus[m.cpus.len - 1].declaration.geometry.terminalLog()))) return error.InvalidServicesWireBoundary;
    if (sum_steps > limits.max_total_steps or ram >= core.fields.m31.Modulus or 50 * totals[0] >= core.fields.m31.Modulus) return error.ServicesWireBudget;
    var next: [3]u64 = @splat(1);
    var previous: u8 = 0;
    var wire: u64 = 9 * totals[1] + 6 * totals[2];
    for (m.truths) |truth| {
        const t = truth.declaration;
        const k = @intFromEnum(t.family);
        if (k < previous or t.calls == 0 or t.first_id != next[k]) return error.InvalidCombinedTruthSpan;
        previous = k;
        if (t.family == .keccak) {
            if (t.logs[0] > 21 or t.logs[1] != 0) return error.InvalidServicesTruthGeometry;
            try A.crypto.keccak.layout.validateGeometry(t.calls, t.first_id, t.logs[0]);
            native_rows = try std.math.add(u64, native_rows, (@as(u64, 1) << @intCast(t.logs[0])) + 8192 + 1024);
        } else {
            const S = A.crypto.secp256k1;
            const program = S.program.get(@enumFromInt(k));
            const mass = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = program, .calls = t.calls, .first_id = t.first_id, .log = t.logs[0] }, .{ .kind = .linear, .program = program, .calls = t.calls, .first_id = t.first_id, .log = t.logs[1] } }, &.{});
            wire = try std.math.add(u64, wire, mass.wires);
            native_rows = try std.math.add(u64, native_rows, (@as(u64, 1) << @intCast(t.logs[0])) + (@as(u64, 1) << @intCast(t.logs[1])) + 256);
        }
        next[k] = try std.math.add(u64, next[k], t.calls);
        for (truth.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalServicesClaim;
        if (truth.proof.bytes == 0 or truth.proof.bytes > limits.max_proof_bytes) return error.ServicesProofLimit;
        proof_bytes = try std.math.add(u64, proof_bytes, truth.proof.bytes);
    }
    for (next, totals) |n, total| if (n != total + 1) return error.InvalidCombinedTruthSpan;
    if (wire >= core.fields.m31.Modulus or proof_bytes > limits.max_total_proof_bytes or native_rows > limits.max_native_row_sum) return error.ServicesWireBudget;
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const E.Bundle) !void {
    if (setups.len == 0 or setups.len != bundle.cpus.len or truths.len != bundle.truths.len) return error.InvalidServicesWireRoster;
    const initial = bundle.cpus[0].request.base.memory.initial;
    const terminal = bundle.cpus[bundle.cpus.len - 1].request.base.memory.terminal;
    if (initial.len != terminal.len or initial.len > 1 << 22) return error.InvalidServicesWireBoundary;
    const cpus = try a.alloc(Cpu, setups.len);
    defer a.free(cpus);
    for (setups, bundle.cpus, cpus, 0..) |setup, c, *out, index| {
        if ((index != 0 and c.request.base.memory.initial.len != 0) or (index + 1 != setups.len and c.request.base.memory.terminal.len != 0)) return error.InvalidServicesWireBoundary;
        out.* = .{ .declaration = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges }, .request = CompactRequest.from(c.request), .claims = c.claims, .proof = .{ .bytes = c.bytes.len, .sha256 = hash(c.bytes) } };
    }
    const tt = try a.alloc(Truth, truths.len);
    defer a.free(tt);
    for (truths, bundle.truths, tt) |t, p, *out| out.* = .{ .declaration = TruthDeclaration.from(t), .claims = p.claims, .proof = .{ .bytes = p.bytes.len, .sha256 = hash(p.bytes) } };
    var meta = Metadata{ .cpus = cpus, .truths = tt, .specs = bundle.manifest.specs, .roots = bundle.manifest.roots, .seal = bundle.manifest.digest, .memory_words = @intCast(initial.len), .cells_sha256 = undefined };
    try validate(meta, .{});
    try bundle.manifest.check(meta.specs);
    try Cells.write(dir, initial, terminal);
    meta.cells_sha256 = try hashCells(dir, meta.memory_words);
    const json = try std.json.Stringify.valueAlloc(a, meta, .{ .whitespace = .indent_2 });
    defer a.free(json);
    if (json.len > (Limits{}).max_metadata_bytes) return error.ServicesMetadataLimit;
    for (bundle.cpus, 0..) |cpu, index| {
        var buf: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buf, false, index), cpu.bytes);
    }
    for (bundle.truths, 0..) |truth, index| {
        var buf: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buf, true, index), truth.bytes);
    }
    try Receipt.writeExclusive(dir, "bundle.json", json);
    try std.posix.fsync(dir.fd);
}
fn readProof(a: std.mem.Allocator, dir: std.fs.Dir, truth: bool, index: usize, file: File) ![]u8 {
    var buf: [64]u8 = undefined;
    var f = try dir.openFile(try proofName(&buf, truth, index), .{});
    defer f.close();
    if (try f.getEndPos() != file.bytes) return error.ServicesProofChanged;
    const bytes = try f.readToEndAlloc(a, @intCast(file.bytes));
    errdefer a.free(bytes);
    if (!std.mem.eql(u8, &hash(bytes), &file.sha256)) return error.ServicesProofChanged;
    return bytes;
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, limits: Limits) !Loaded {
    const bytes = try dir.readFileAlloc(a, "bundle.json", limits.max_metadata_bytes);
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(Metadata, a, bytes, .{});
    defer parsed.deinit();
    const m = parsed.value;
    try validate(m, limits);
    var manifest = try G.Manifest.init(a, m.specs, m.roots);
    errdefer manifest.deinit();
    if (!std.mem.eql(u8, &manifest.digest, &m.seal)) return error.GlobalExecutionManifestChanged;
    if (!std.mem.eql(u8, &try hashCells(dir, m.memory_words), &m.cells_sha256)) return error.ServicesCellsChanged;
    const cells = try Cells.read(a, dir, m.memory_words);
    var owns_cells = true;
    errdefer if (owns_cells) cells.deinit(a);
    const decl = try a.alloc(CpuDeclaration, m.cpus.len);
    errdefer a.free(decl);
    const td = try a.alloc(TruthDeclaration, m.truths.len);
    errdefer a.free(td);
    const cpus = try a.alloc(E.CpuEncoded, m.cpus.len);
    errdefer a.free(cpus);
    var cpu_done: usize = 0;
    errdefer for (cpus[0..cpu_done]) |p| a.free(p.bytes);
    for (m.cpus, cpus, decl, 0..) |c, *out, *d, index| {
        d.* = c.declaration;
        out.* = .{ .bytes = try readProof(a, dir, false, index, c.proof), .request = c.request.expand(if (index == 0) cells.initial else &.{}, if (index + 1 == m.cpus.len) cells.terminal else &.{}), .claims = c.claims };
        cpu_done += 1;
    }
    const tt = try a.alloc(E.TruthEncoded, m.truths.len);
    errdefer a.free(tt);
    var truth_done: usize = 0;
    errdefer for (tt[0..truth_done]) |t| a.free(t.bytes);
    for (m.truths, tt, td, 0..) |t, *out, *d, index| {
        d.* = t.declaration;
        out.* = .{ .bytes = try readProof(a, dir, true, index, t.proof), .claims = t.claims };
        truth_done += 1;
    }
    owns_cells = false;
    return .{ .cpu_declarations = decl, .truth_declarations = td, .bundle = .{ .manifest = manifest, .cpus = cpus, .truths = tt } };
}
