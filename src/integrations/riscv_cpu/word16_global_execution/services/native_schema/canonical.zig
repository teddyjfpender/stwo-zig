//! RV64 M5 canonical native classes and native protocol version
//! `rv64-m5-native-chi-chain/v1` (stream canon-native).
//!
//! Executable spec: scripts/rv64_m5_canon_native_ref.py; interface section
//! design/riscv/rv64-m5-canon-native.md (= /workspace/m3/M5-INTERFACES.md
//! "canon-native"); golden vectors vectors/rv64-m5/canon-native-v1-vectors.json,
//! pinned byte for byte by the tests below. Binding argument:
//! rv64-m5-binding.md sec. 3.3 (chi chain), 5.1 (mb family), 9.3(4).
//!
//! Every hash input is a domain tag followed by a fixed-length (per class)
//! sequence of canonical u32 words, little-endian:
//!   H(tag, words) = Blake2s-256(Blake2s-256(tag) || LE32(words)).
//! Geometry (class rung) selection never changes statement authority: the
//! padded declaration is mixed and verified exactly as any admitted geometry.
const std = @import("std");
const W = @import("cpu_declaration.zig");
const T = @import("../types.zig");
const Blake = std.crypto.hash.blake2.Blake2s256;

pub const VERSION_NAME = "rv64-m5-native-chi-chain/v1";
/// Production `gkr_local/fractions.zig` Relation count (byte_pair included);
/// the v1 identity carries the 9 -> 10 bump of rv64-m7-profiles.md 2.1.
pub const LOCAL_RELATIONS: u32 = 10;
pub const GLOBAL_RELATIONS: u32 = 3;
/// Class rungs per family: the plan M5 kill rule fired (cells-weighted strict-roster tax at R=3 is 41.6 % > 40 %).
pub const RUNGS: u32 = 4;

pub const Family = enum(u32) {
    cpu_first = 0,
    cpu_middle = 1,
    cpu_last = 2,
    cpu_single = 3,
    truth_keccak = 16,
    truth_add = 17,
    truth_double = 18,
    truth_sha256 = 19,
    truth_arith256_mod = 20,
    truth_bn254_g1_add = 21,
    truth_bn254_g1_double = 22,
    truth_bn254_fp2_mul = 23,
    truth_bls12_381_fp2_mul = 24,
    truth_arith384_mont = 25,
    truth_bls12_381_g1_add = 26,
    truth_bls12_381_g1_double = 27,
    mb = 32,
    pub fn truth(f: T.Family) Family {
        return @enumFromInt(16 + @as(u32, @intFromEnum(f)));
    }
    pub fn cpu(index: usize, count: usize) Family {
        if (count == 1) return .cpu_single;
        if (index == 0) return .cpu_first;
        return if (index + 1 == count) .cpu_last else .cpu_middle;
    }
};
pub const Kind = enum(u32) { cpu = 1, truth = 2, mb = 3 };

/// Frozen component ids of a CPU class rung vector (index in this list).
pub const CPU_COMPONENTS = [_][]const u8{
    "cpu_log",              "alu_log",                 "alu_tail_log",               "binary_log",             "binary_tail_log",      "shift_log",
    "shift_tail_log",       "jalr_log",                "division_log",               "multiplication_log",     "ls_log",               "ls_tail_log",
    "boundary_log",         "initial_log",             "terminal_log",               "bridge.keccak",          "bridge.add",           "bridge.double",
    "bridge.sha256",        "bridge.arith256_mod",     "bridge.bn254_g1_add",        "bridge.bn254_g1_double", "bridge.bn254_fp2_mul", "bridge.bls12_381_fp2_mul",
    "bridge.arith384_mont", "bridge.bls12_381_g1_add", "bridge.bls12_381_g1_double", "bridge.bulk.desc",       "bridge.bulk.copy",     "bridge.bulk.set",
    "bridge.bulk.ucopy",    "bridge.bulk.cdesc",       "bridge.bulk.cmp",            "bridge.bulk.jdesc",      "bridge.bulk.jscan",    "bridge.bulk.jtab",
    "bridge.sponge.call",   "bridge.sponge.perm",      "bridge.ls_dword",            "bridge.ls_dword_tail",   "bridge.zbb",
};
pub const CPU_COMPONENT_COUNT = CPU_COMPONENTS.len;
pub const TRUTH_COMPONENTS = [_][]const u8{ "main", "aux" };
const GEOMETRY_COMPONENTS = 15;
const BRIDGE_FAMILIES = 12;

/// Component -> log (0 = absent) of one CPU declaration, in CPU_COMPONENTS order.
pub const CpuVector = [CPU_COMPONENT_COUNT]u32;

fn optLog(v: ?u32) u32 {
    return v orelse 0;
}
fn someLog(v: u32) ?u32 {
    return if (v == 0) null else v;
}
const geometry_fields = .{ "cpu_log", "alu_log", "alu_tail_log", "binary_log", "binary_tail_log", "shift_log", "shift_tail_log", "jalr_log", "division_log", "multiplication_log", "ls_log", "ls_tail_log", "boundary_log", "initial_log", "terminal_log" };
const bridge_fields = .{ "keccak", "add", "double", "sha256", "arith256_mod", "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul", "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double" };
const bulk_fields = .{ "desc", "copy", "set", "ucopy", "cdesc", "cmp", "jdesc", "jscan", "jtab" };

pub fn cpuVector(d: W.CpuDeclaration) CpuVector {
    var v: CpuVector = @splat(0);
    inline for (geometry_fields, 0..) |name, i| {
        const value = @field(d.geometry, name);
        v[i] = if (@typeInfo(@TypeOf(value)) == .optional) optLog(value) else value;
    }
    // initial/terminal fall back to the shared boundary log when unset.
    v[13] = d.geometry.initialLog();
    v[14] = d.geometry.terminalLog();
    inline for (bridge_fields, 0..) |name, i| v[GEOMETRY_COMPONENTS + i] = optLog(@field(d.bridges, name));
    inline for (bulk_fields, 0..) |name, i| v[GEOMETRY_COMPONENTS + BRIDGE_FAMILIES + i] = optLog(@field(d.bridges.bulk, name));
    v[36] = optLog(d.bridges.sponge.call);
    v[37] = optLog(d.bridges.sponge.perm);
    v[38] = optLog(d.bridges.ls_dword);
    v[39] = optLog(d.bridges.ls_dword_tail);
    v[40] = optLog(d.bridges.zbb);
    return v;
}
/// Writes the logs of `v` into a copy of `d` (layout flags kept).
pub fn applyCpuVector(d: W.CpuDeclaration, v: CpuVector) W.CpuDeclaration {
    var out = d;
    inline for (geometry_fields, 0..) |name, i| {
        const F = @TypeOf(@field(out.geometry, name));
        @field(out.geometry, name) = if (@typeInfo(F) == .optional) someLog(v[i]) else v[i];
    }
    inline for (bridge_fields, 0..) |name, i| @field(out.bridges, name) = someLog(v[GEOMETRY_COMPONENTS + i]);
    inline for (bulk_fields, 0..) |name, i| @field(out.bridges.bulk, name) = someLog(v[GEOMETRY_COMPONENTS + BRIDGE_FAMILIES + i]);
    out.bridges.sponge.call = someLog(v[36]);
    out.bridges.sponge.perm = someLog(v[37]);
    out.bridges.ls_dword = someLog(v[38]);
    out.bridges.ls_dword_tail = someLog(v[39]);
    out.bridges.zbb = someLog(v[40]);
    return out;
}
/// Presence-preserving padding (v1 admissible mode): every PRESENT component
/// is raised to the rung's log; absent components stay absent (today's
/// admission ties presence to non-zero counts). Fails closed when the rung
/// does not dominate the declaration.
pub fn padCpuVector(actual: CpuVector, rung: CpuVector) !CpuVector {
    var out = actual;
    for (actual, rung, &out) |a, r, *o| {
        if (a == 0) continue;
        if (r == 0) return error.CanonRungMissingComponent;
        if (r < a) return error.CanonRungTooSmall;
        o.* = r;
    }
    return out;
}
pub fn dominates(rung: CpuVector, actual: CpuVector) bool {
    for (actual, rung) |a, r| if (a != 0 and (r == 0 or r < a)) return false;
    return true;
}
/// Smallest rung (ascending order) dominating `actual`, or null.
pub fn selectRung(rungs: []const CpuVector, actual: CpuVector) ?usize {
    for (rungs, 0..) |r, i| if (dominates(r, actual)) return i;
    return null;
}

// ------------------------------------------------------------------ hashing
pub const Tag = enum {
    class_key,
    structure,
    vk,
    nat_leaf,
    nat_empty,
    node,
    table,
    version,
    state,
    stmt,
    rho,
    iv,
    seg,
    chi,
    /// rv64-m6-native/v2 (stream native-format): new version identity and a
    /// structure digest that also binds the geometry layout flags.
    version_v2,
    structure_v2,
    pub fn name(t: Tag) []const u8 {
        return switch (t) {
            .class_key => "rv64-m5-class-key/v1",
            .structure => "rv64-m5-native-structure/v1",
            .vk => "rv64-m5-native-vk/v1",
            .nat_leaf => "rv64-m5-tnat-leaf/v1",
            .nat_empty => "rv64-m5-tnat-empty/v1",
            .node => "rv64-m5-merkle-node/v1",
            .table => "rv64-m5-tnat-header/v1",
            .version => "rv64-m5-native-version/v1",
            .state => "rv64-m5-state/v1",
            .stmt => "rv64-m5-stmt/v1",
            .rho => "rv64-m5-rho/v1",
            .iv => "rv64-m5-chain-iv/v1",
            .seg => "rv64-m5-seg",
            .chi => "rv64-m5-chi",
            .version_v2 => "rv64-m6-native-chi-chain/v2",
            .structure_v2 => "rv64-m6-native-structure/v2",
        };
    }
    pub fn digest(t: Tag) [32]u8 {
        var out: [32]u8 = undefined;
        Blake.hash(t.name(), &out, .{});
        return out;
    }
};
pub const Digest = [32]u8;
pub const Hasher = struct {
    h: Blake,
    pub fn init(t: Tag) Hasher {
        var h = Blake.init(.{});
        const d = t.digest();
        h.update(&d);
        return .{ .h = h };
    }
    pub fn word(self: *Hasher, w: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, w, .little);
        self.h.update(&b);
    }
    pub fn words(self: *Hasher, ws: []const u32) void {
        for (ws) |w| self.word(w);
    }
    pub fn constantWord(self: *Hasher, value: u32) void {
        self.word(value);
    }
    pub fn int64(self: *Hasher, v: u64) void {
        self.word(@truncate(v));
        self.word(@truncate(v >> 32));
    }
    /// A digest is 8 LE u32 words, i.e. exactly its 32 bytes.
    pub fn digest(self: *Hasher, d: Digest) void {
        self.h.update(&d);
    }
    pub fn final(self: *Hasher) Digest {
        var out: Digest = undefined;
        self.h.final(&out);
        return out;
    }
};

pub fn versionIdentity(rungs: u32) Digest {
    var h = Hasher.init(.version);
    h.words(&.{ 1, LOCAL_RELATIONS, GLOBAL_RELATIONS, rungs, @intFromEnum(Family.mb) });
    return h.final();
}
/// rv64-m6-native/v2 version identity: v1 words + strict roster flag + gkr mode
/// (0 = v2-strict, 1 = v2-gkr). Enters every chi through the chain IV.
pub const V2_NAME = "rv64-m6-native/v2";
pub const GkrMode = enum(u32) { strict_local = 0, native_gkr = 1 };
pub fn versionIdentityV2(rungs: u32, mode: GkrMode) Digest {
    var h = Hasher.init(.version_v2);
    h.words(&.{ 2, LOCAL_RELATIONS, GLOBAL_RELATIONS, rungs, @intFromEnum(Family.mb), 1, @intFromEnum(mode) });
    return h.final();
}
/// Geometry layout flags word of a v2 class (bit i = flag i below). Under v2
/// `omit_empty_division` is always false (division is committed at its rung
/// log), so the word is a class constant of the production layout.
pub const LAYOUT_FLAGS = .{ "omit_empty_division", "cpu_fused_tail", "cpu_u8_pairs", "cpu_compact_decode", "mul_u8_pairs", "ls_fused_pairs", "alu_fused_tail", "ls_dword_fused_pairs" };
pub fn layoutFlags(g: anytype) u32 {
    var w: u32 = 0;
    inline for (LAYOUT_FLAGS, 0..) |name, i| w |= @as(u32, @intFromBool(@field(g, name))) << i;
    return w;
}
/// v2 S^nat: v1 (id, log) pairs of the RUNG vector + the layout flags word.
/// Strict roster => the declaration vector equals the rung vector, so the
/// chain and T_nat hash the same digest (canon-native review A1).
pub fn structureDigestV2(family: u32, rung: u32, ids: []const u32, logs: []const u32, flags: u32) Digest {
    std.debug.assert(ids.len == logs.len);
    var h = Hasher.init(.structure_v2);
    h.words(&.{ family, rung, @intCast(ids.len) });
    for (ids, logs) |id, log| h.words(&.{ id, log });
    h.word(flags);
    return h.final();
}
pub fn cpuStructureV2(family: Family, rung: u32, v: CpuVector, flags: u32) Digest {
    var ids: [CPU_COMPONENT_COUNT]u32 = undefined;
    var logs: [CPU_COMPONENT_COUNT]u32 = undefined;
    var n: usize = 0;
    for (v, 0..) |log, i| if (log != 0) {
        ids[n] = @intCast(i);
        logs[n] = log;
        n += 1;
    };
    return structureDigestV2(@intFromEnum(family), rung, ids[0..n], logs[0..n], flags);
}
/// Exact strict-roster rung: the unique rung whose vector equals `actual`.
pub fn strictRung(rungs: []const CpuVector, actual: CpuVector) ?usize {
    for (rungs, 0..) |r, i| if (std.mem.eql(u32, &r, &actual)) return i;
    return null;
}
/// S^nat summary of one class: (component id, log) pairs sorted by id; absent logs are 0.
pub fn structureDigest(family: u32, rung: u32, ids: []const u32, logs: []const u32) Digest {
    std.debug.assert(ids.len == logs.len);
    var h = Hasher.init(.structure);
    h.words(&.{ family, rung, @intCast(ids.len) });
    for (ids, logs) |id, log| h.words(&.{ id, log });
    return h.final();
}
/// Structure of a CPU rung vector: every component present in the rung (log != 0).
pub fn cpuStructure(family: Family, rung: u32, v: CpuVector) Digest {
    var ids: [CPU_COMPONENT_COUNT]u32 = undefined;
    var logs: [CPU_COMPONENT_COUNT]u32 = undefined;
    var n: usize = 0;
    for (v, 0..) |log, i| if (log != 0) {
        ids[n] = @intCast(i);
        logs[n] = log;
        n += 1;
    };
    return structureDigest(@intFromEnum(family), rung, ids[0..n], logs[0..n]);
}
pub const ClassKey = struct {
    family: u32,
    rung: u32,
    profile_identity: Digest,
    image: Digest,
    rung_table_id: Digest,
    pub fn digest(self: ClassKey) Digest {
        var h = Hasher.init(.class_key);
        h.words(&.{ self.family, self.rung });
        h.digest(self.profile_identity);
        h.digest(self.image);
        h.digest(self.rung_table_id);
        return h.final();
    }
};
pub const NativeVk = struct {
    family: u32,
    rung: u32,
    suite: Digest,
    fixed_identity: Digest,
    fixed_root: Digest,
    profile_identity: Digest,
    structure: Digest,
    pub fn hash(self: NativeVk) Digest {
        var h = Hasher.init(.vk);
        h.words(&.{ self.family, self.rung });
        inline for (.{ "suite", "fixed_identity", "fixed_root", "profile_identity", "structure" }) |f| h.digest(@field(self, f));
        return h.final();
    }
};
pub fn natLeaf(index: u32, family: u32, rung: u32, vkhash: Digest) Digest {
    var h = Hasher.init(.nat_leaf);
    h.words(&.{ index, family, rung });
    h.digest(vkhash);
    return h.final();
}
pub fn natEmpty(index: u32) Digest {
    var h = Hasher.init(.nat_empty);
    h.word(index);
    return h.final();
}
pub fn node(left: Digest, right: Digest) Digest {
    var h = Hasher.init(.node);
    h.digest(left);
    h.digest(right);
    return h.final();
}
pub fn tableDepth(n: usize) u32 {
    var d: u32 = 1;
    while ((@as(usize, 1) << @intCast(d)) < n) d += 1;
    return d;
}
pub const MAX_TABLE_DEPTH = 12;
/// Fixed-depth T_nat root over leaves in canonical order (empty-padded).
pub fn tableRoot(a: std.mem.Allocator, leaves: []const Digest) !Digest {
    if (leaves.len == 0) return error.EmptyNativeVkTable;
    const depth = tableDepth(leaves.len);
    if (depth > MAX_TABLE_DEPTH) return error.NativeVkTableTooLarge;
    const level = try a.alloc(Digest, @as(usize, 1) << @intCast(depth));
    defer a.free(level);
    for (level, 0..) |*x, i| x.* = if (i < leaves.len) leaves[i] else natEmpty(@intCast(i));
    var n = level.len;
    while (n > 1) : (n /= 2) for (0..n / 2) |i| {
        level[i] = node(level[2 * i], level[2 * i + 1]);
    };
    return level[0];
}
pub fn tablePath(a: std.mem.Allocator, leaves: []const Digest, index: usize, out: []Digest) !void {
    const depth = tableDepth(leaves.len);
    if (out.len != depth or index >= leaves.len) return error.InvalidNativeVkPath;
    const level = try a.alloc(Digest, @as(usize, 1) << @intCast(depth));
    defer a.free(level);
    for (level, 0..) |*x, i| x.* = if (i < leaves.len) leaves[i] else natEmpty(@intCast(i));
    var n = level.len;
    var at = index;
    var j: usize = 0;
    while (n > 1) : (n /= 2) {
        out[j] = level[at ^ 1];
        j += 1;
        at >>= 1;
        for (0..n / 2) |i| level[i] = node(level[2 * i], level[2 * i + 1]);
    }
}
pub fn verifyPath(root: Digest, depth: u32, index: usize, leaf: Digest, path: []const Digest) bool {
    if (path.len != depth or index >= (@as(usize, 1) << @intCast(depth))) return false;
    var cur = leaf;
    var at = index;
    for (path) |sib| {
        cur = if (at & 1 == 0) node(cur, sib) else node(sib, cur);
        at >>= 1;
    }
    return std.mem.eql(u8, &cur, &root);
}
pub fn tableHeader(image: Digest, profile_identity: Digest, rung_table_id: Digest, depth: u32, count: u32, root: Digest) Digest {
    var h = Hasher.init(.table);
    h.words(&.{ 1, depth, count });
    h.digest(image);
    h.digest(profile_identity);
    h.digest(rung_table_id);
    h.digest(root);
    return h.final();
}

// ------------------------------------------------------------------ chain
pub fn stateDigest(pc: u64, regs: [32]u64, halted: bool) Digest {
    var h = Hasher.init(.state);
    emitState(pc, regs, @as(u32, @intFromBool(halted)), &h);
    return h.final();
}
/// Shared native/circuit encoding. The writer decides how a u64 is represented
/// (native integer or two constrained u32 words); field order is one authority.
pub fn emitState(pc: anytype, regs: anytype, halted: anytype, h: anytype) void {
    h.int64(pc);
    for (regs) |r| h.int64(r);
    h.word(halted);
}
pub const Mass = struct { ram: u64, kio: u64, wire: u64 };
pub const CpuStatement = struct {
    ordinal: u32,
    cpu_ordinal: u32,
    steps_in: u64,
    steps: u32,
    ls_count: u32,
    ls_dword: u32,
    calls: [T.FAMILIES]u32,
    first_ids: [T.FAMILIES]u32,
    sponge: [3]u32,
    bulk: [8]u32,
    mass: Mass,
    relations: u32,
    legacy: Digest,
    pub fn digest(s: CpuStatement) Digest {
        var h = Hasher.init(.stmt);
        emitCpuStatement(@as(u32, @intFromEnum(Kind.cpu)), s, &h);
        return h.final();
    }
};
pub fn emitCpuStatement(kind: anytype, s: anytype, h: anytype) void {
    h.words(&.{ kind, s.ordinal, s.cpu_ordinal });
    h.int64(s.steps_in);
    h.words(&.{ s.steps, s.ls_count, s.ls_dword });
    h.words(&s.calls);
    h.words(&s.first_ids);
    h.words(&s.sponge);
    h.words(&s.bulk);
    massWords(h, s.mass);
    h.word(s.relations);
    h.digest(s.legacy);
}
fn massWords(h: anytype, m: anytype) void {
    h.int64(m.ram);
    h.int64(m.kio);
    h.int64(m.wire);
}
pub const TruthStatement = struct {
    ordinal: u32,
    family: u32,
    first_id: u32,
    calls: u32,
    logs: [2]u32,
    mass: Mass,
    relations: u32,
    legacy: Digest,
    pub fn digest(s: TruthStatement) Digest {
        var h = Hasher.init(.stmt);
        emitTruthStatement(@as(u32, @intFromEnum(Kind.truth)), s, &h);
        return h.final();
    }
};
pub fn emitTruthStatement(kind: anytype, s: anytype, h: anytype) void {
    h.words(&.{ kind, s.ordinal, s.family, s.first_id, s.calls, s.logs[0], s.logs[1] });
    massWords(h, s.mass);
    h.word(s.relations);
    h.digest(s.legacy);
}
pub const MbStatement = struct {
    ordinal: u32,
    chunk: u32,
    cells: u32,
    first_addr: u64,
    last_addr: u64,
    prev_last_addr: u64,
    image_commit: Digest,
    initial_digest: Digest,
    terminal_digest: Digest,
    mass_ram: u64,
    pub fn digest(s: MbStatement) Digest {
        var h = Hasher.init(.stmt);
        h.words(&.{ @intFromEnum(Kind.mb), s.ordinal, s.chunk, s.cells });
        h.int64(s.first_addr);
        h.int64(s.last_addr);
        h.int64(s.prev_last_addr);
        h.digest(s.image_commit);
        h.digest(s.initial_digest);
        h.digest(s.terminal_digest);
        h.int64(s.mass_ram);
        return h.final();
    }
};
pub const P_M31: u32 = 0x7fffffff;
/// rho_k over today's stage-one manifest entry: MAIN root, local GKR receipt
/// digest and its terminal marginals (instances of canonical OM31 values).
pub fn rho(main: Digest, local: ?Digest, marginals: []const []const [8]u32) !Digest {
    var h = Hasher.init(.rho);
    h.digest(main);
    h.word(@intFromBool(local != null));
    h.digest(local orelse @splat(0));
    h.word(@intCast(marginals.len));
    for (marginals) |inst| {
        h.word(@intCast(inst.len));
        for (inst) |v| for (v) |c| {
            if (c >= P_M31) return error.NoncanonicalChainCoordinate;
            h.word(c);
        };
    }
    return h.final();
}
/// Native-GKR v2 seals MAIN before chi and proves the numerical section only
/// afterwards. Including that later section in rho would make chi circular.
/// This is byte-identical to rho(main, null, &.{}); the new chain version
/// supplies the format separation. Existing receipt-bearing rho is unchanged.
pub fn emitMainOnlyRho(main: anytype, h: anytype) void {
    h.digest(main);
    h.constantWord(0);
    h.constantDigest(@splat(0));
    h.constantWord(0);
}
pub fn mainOnlyRho(main: Digest) Digest {
    var writer = struct {
        h: Hasher,
        pub fn digest(s: *@This(), d: Digest) void {
            s.h.digest(d);
        }
        pub fn constantDigest(s: *@This(), d: Digest) void {
            s.h.digest(d);
        }
        pub fn constantWord(s: *@This(), w: u32) void {
            s.h.word(w);
        }
    }{ .h = Hasher.init(.rho) };
    emitMainOnlyRho(main, &writer);
    return writer.h.final();
}
pub fn chainIv(version: Digest) Digest {
    var h = Hasher.init(.iv);
    h.digest(version);
    return h.final();
}
pub const Segment = struct { k: u32, family: u32, rung: u32, vkhash: Digest, stmt: Digest, s_in: Digest, s_out: Digest, rho: Digest };
pub fn chainStep(m: Digest, s: Segment) Digest {
    var h = Hasher.init(.seg);
    emitChainStep(m, s, &h);
    return h.final();
}
pub fn emitChainStep(m: anytype, s: anytype, h: anytype) void {
    h.digest(m);
    h.words(&.{ s.k, s.family, s.rung });
    inline for (.{ "vkhash", "stmt", "s_in", "s_out", "rho" }) |f| h.digest(@field(s, f));
}
/// m_kappa over segments in index order (segment k must carry index k).
pub fn chainFinal(version: Digest, segments: []const Segment) !Digest {
    if (segments.len == 0) return error.EmptyNativeChain;
    var m = chainIv(version);
    for (segments, 0..) |s, k| {
        if (s.k != k) return error.NativeChainOrder;
        m = chainStep(m, s);
    }
    return m;
}
pub fn chi(statement: Digest, m_final: Digest) Digest {
    var h = Hasher.init(.chi);
    h.digest(statement);
    h.digest(m_final);
    return h.final();
}

// ------------------------------------------------------------------ tests (golden vectors from the Python reference)
fn hex(comptime s: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
fn seq(start: u8) Digest {
    var out: Digest = undefined;
    for (&out, 0..) |*b, i| b.* = start +% @as(u8, @intCast(i));
    return out;
}
const testing = std.testing;
test "canon-native v1 tag digests match the reference" {
    try testing.expectEqual(hex("daba9ad463c003e97080f3f6685608c2e7a6161b4d591173c20c7cded13b3e46"), Tag.chi.digest());
    try testing.expectEqual(hex("941148b446eb12cf769df8785dbfebf280bbb7c1c05d01ab9e9fbcb7fef3140b"), Tag.node.digest());
    try testing.expectEqual(hex("5ad650a926f613d1334906d6e45baf25826d807baa4831f47364209dbc5f5cf0"), Tag.nat_leaf.digest());
    try testing.expectEqual(hex("53f3ea3333dad678f8f80726a51a376b14c12a52070cdcc857a0fe4999fe35c8"), Tag.nat_empty.digest());
    // Leaf, empty and node tags are distinct (binding checklist 12).
    try testing.expect(!std.mem.eql(u8, &Tag.nat_leaf.digest(), &Tag.node.digest()));
    try testing.expect(!std.mem.eql(u8, &Tag.nat_empty.digest(), &Tag.node.digest()));
}
const ref = struct {
    const profile = seq(1);
    const image = seq(33);
    const suite = seq(65);
    // table: cpu_middle {1:22,2:18,3:absent} {1:22,2:19,3:16} {1:22,2:20,3:17}; truth_keccak {0:16} {0:17} {0:18}
    const cpu_ids = [_]u32{ 1, 2, 3 };
    const cpu_logs = [3][3]u32{ .{ 22, 18, 0 }, .{ 22, 19, 16 }, .{ 22, 20, 17 } };
    const truth_ids = [_]u32{0};
    const truth_logs = [3][1]u32{ .{16}, .{17}, .{18} };
    fn structure(family: u32, rung: u32) Digest {
        return if (family == 1) structureDigest(1, rung, &cpu_ids, &cpu_logs[rung]) else structureDigest(16, rung, &truth_ids, &truth_logs[rung]);
    }
    fn rungTable() Digest {
        var h = Hasher.init(.structure);
        h.words(&.{ 0xFFFFFFFF, 2 });
        for ([_]u32{ 1, 16 }) |f| {
            h.words(&.{ f, 3 });
            for (0..3) |r| h.digest(structure(f, @intCast(r)));
        }
        return h.final();
    }
};
test "canon-native v1 version, structure, rung table and class key match the reference" {
    try testing.expectEqual(hex("e6a9b68cce4e5f4965c086281d0fad7e84c36387eedb6fc36742cbadd8e5e155"), ref.structure(1, 1));
    const rt = ref.rungTable();
    try testing.expectEqual(hex("914e734dc16dae1788447b8942fae77738efbd86a7f8863756d2b3f6d52feb45"), rt);
    const key = ClassKey{ .family = 1, .rung = 1, .profile_identity = ref.profile, .image = ref.image, .rung_table_id = rt };
    try testing.expectEqual(hex("cc74a1a04f351a1047b07a752555a200ac86eceb0ef241f5f6b0e32b54497e33"), key.digest());
}
test "canon-native v1 native VK table root, path and header match the reference" {
    const a = testing.allocator;
    var leaves: [6]Digest = undefined;
    var vks: [6]Digest = undefined;
    for (0..6) |i| {
        const f: u32 = if (i < 3) 1 else 16;
        const r: u32 = @intCast(i % 3);
        vks[i] = (NativeVk{ .family = f, .rung = r, .suite = ref.suite, .fixed_identity = seq(100 + @as(u8, @intCast(i))), .fixed_root = seq(150 + @as(u8, @intCast(i))), .profile_identity = ref.profile, .structure = ref.structure(f, r) }).hash();
        leaves[i] = natLeaf(@intCast(i), f, r, vks[i]);
    }
    try testing.expectEqual(hex("795fcf6f1d3f6d7e30df0255901c56b5d333f144e17ca8f084cce532bd12698d"), leaves[0]);
    try testing.expectEqual(hex("bbcb4737dca63ebbcb41ed2b9c6fc2db0e5b402ff3c25653e5a4668f5dac2d0f"), leaves[5]);
    const root = try tableRoot(a, &leaves);
    const depth = tableDepth(leaves.len);
    try testing.expectEqual(@as(u32, 3), depth);
    var vectors = try loadVectors(a);
    defer vectors.deinit();
    const tnat = vectors.value.object.get("vectors").?.object.get("tnat").?.object;
    try testing.expectEqual(hexRuntime(tnat.get("root").?.string), root);
    var path: [3]Digest = undefined;
    try tablePath(a, &leaves, 4, &path);
    for (tnat.get("path_index_4").?.array.items, path) |want, got| try testing.expectEqual(hexRuntime(want.string), got);
    try testing.expect(verifyPath(root, depth, 4, leaves[4], &path));
    // Wrong index, wrong leaf, short path: rejected (G04 shape).
    try testing.expect(!verifyPath(root, depth, 3, leaves[4], &path));
    try testing.expect(!verifyPath(root, depth, 4, leaves[3], &path));
    try testing.expect(!verifyPath(root, depth, 4, leaves[4], path[0..2]));
    try testing.expectEqual(hexRuntime(tnat.get("header").?.string), tableHeader(ref.image, ref.profile, ref.rungTable(), depth, 6, root));
    // vkhash agreement too
    for (tnat.get("vkhash").?.array.items, vks) |want, got| try testing.expectEqual(hexRuntime(want.string), got);
}
fn hexRuntime(s: []const u8) Digest {
    var out: Digest = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
const vectors_json = @embedFile("canon_native_v1_vectors.json");
fn loadVectors(a: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, a, vectors_json, .{});
}
test "canon-native v1 state, stmt_k, rho, chain and chi match the reference byte for byte" {
    const a = testing.allocator;
    var vectors = try loadVectors(a);
    defer vectors.deinit();
    const v = vectors.value.object.get("vectors").?.object;
    const version = versionIdentity(RUNGS);
    try testing.expectEqual(hexRuntime(v.get("version_identity").?.string), version);
    var regs0: [32]u64 = undefined;
    var regs1: [32]u64 = undefined;
    for (0..32) |i| {
        regs0[i] = @as(u64, i) * 0x0101010101;
        regs1[i] = @as(u64, i) *% 0x9E3779B97F4A7C15;
    }
    const s0 = stateDigest(0x80000000, regs0, false);
    const s1 = stateDigest(0x80001234, regs1, false);
    const s2 = stateDigest(0x80004000, regs1, true);
    for (v.get("state").?.array.items, [_]Digest{ s0, s1, s2 }) |want, got| try testing.expectEqual(hexRuntime(want.string), got);
    const st0 = (CpuStatement{ .ordinal = 0, .cpu_ordinal = 1, .steps_in = 0, .steps = 4194303, .ls_count = 1000, .ls_dword = 77, .calls = .{ 3, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0 }, .first_ids = @splat(1), .sponge = .{ 1, 4, 9 }, .bulk = .{ 2, 10, 20, 0, 1, 3, 0, 0 }, .mass = .{ .ram = 9000, .kio = 75, .wire = 12 }, .relations = 7, .legacy = seq(200) }).digest();
    const st1 = (TruthStatement{ .ordinal = 1, .family = 16, .first_id = 1, .calls = 3, .logs = .{ 16, 0x1b0415 }, .mass = .{ .ram = 0, .kio = 75, .wire = 0 }, .relations = 2, .legacy = seq(7) }).digest();
    const st2 = (MbStatement{ .ordinal = 2, .chunk = 0, .cells = 513, .first_addr = 0x1000, .last_addr = 0x9ff8, .prev_last_addr = 0, .image_commit = seq(9), .initial_digest = seq(10), .terminal_digest = seq(11), .mass_ram = 1026 }).digest();
    for (v.get("stmt").?.array.items, [_]Digest{ st0, st1, st2 }) |want, got| try testing.expectEqual(hexRuntime(want.string), got);
    const inst0 = [_][8]u32{.{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    const inst1 = [_][8]u32{ @splat(0x7FFFFFFE), @splat(0) };
    const r0 = try rho(seq(50), seq(51), &.{ &inst0, &inst1 });
    const r1 = try rho(seq(60), null, &.{});
    const r2 = try rho(seq(70), null, &.{});
    for (v.get("rho").?.array.items, [_]Digest{ r0, r1, r2 }) |want, got| try testing.expectEqual(hexRuntime(want.string), got);
    // Non-canonical OM31 coordinate (w + p alias) is refused (Z07 shape).
    const bad = [_][8]u32{.{ P_M31, 0, 0, 0, 0, 0, 0, 0 }};
    try testing.expectError(error.NoncanonicalChainCoordinate, rho(seq(50), null, &.{&bad}));
    const tnat = v.get("tnat").?.object;
    const vk = tnat.get("vkhash").?.array.items;
    const segs = [_]Segment{
        .{ .k = 0, .family = 1, .rung = 1, .vkhash = hexRuntime(vk[1].string), .stmt = st0, .s_in = s0, .s_out = s1, .rho = r0 },
        .{ .k = 1, .family = 16, .rung = 0, .vkhash = hexRuntime(vk[3].string), .stmt = st1, .s_in = s1, .s_out = s1, .rho = r1 },
        .{ .k = 2, .family = 32, .rung = 0, .vkhash = hexRuntime(vk[5].string), .stmt = st2, .s_in = s1, .s_out = s1, .rho = r2 },
    };
    const chain = v.get("chain").?.array.items;
    try testing.expectEqual(hexRuntime(chain[0].string), chainIv(version));
    var m = chainIv(version);
    for (segs, 1..) |s, i| {
        m = chainStep(m, s);
        try testing.expectEqual(hexRuntime(chain[i].string), m);
    }
    try testing.expectEqual(m, try chainFinal(version, &segs));
    try testing.expectEqual(hexRuntime(v.get("chi").?.string), chi(seq(240), m));
    // Permuted, dropped and duplicated segments change chi or are refused (S08-S11 shape).
    const permuted = [_]Segment{ segs[1], segs[0], segs[2] };
    try testing.expectError(error.NativeChainOrder, chainFinal(version, &permuted));
    var relabelled = permuted;
    relabelled[0].k = 0;
    relabelled[1].k = 1;
    try testing.expect(!std.mem.eql(u8, &chi(seq(240), m), &chi(seq(240), try chainFinal(version, &relabelled))));
    try testing.expect(!std.mem.eql(u8, &m, &(try chainFinal(version, segs[0..2]))));
    // A different version identity (another rung count) changes the chain start.
    try testing.expect(!std.mem.eql(u8, &chainIv(version), &chainIv(versionIdentity(3))));
}
test "canon-native padding raises present components only and fails closed" {
    var actual: CpuVector = @splat(0);
    actual[0] = 22;
    actual[1] = 18;
    actual[15] = 15;
    var rung: CpuVector = @splat(0);
    rung[0] = 22;
    rung[1] = 19;
    rung[2] = 17;
    rung[15] = 17;
    const padded = try padCpuVector(actual, rung);
    try testing.expectEqual(@as(u32, 19), padded[1]);
    try testing.expectEqual(@as(u32, 0), padded[2]);
    try testing.expectEqual(@as(u32, 17), padded[15]);
    var small = rung;
    small[1] = 17;
    try testing.expectError(error.CanonRungTooSmall, padCpuVector(actual, small));
    var missing = rung;
    missing[15] = 0;
    try testing.expectError(error.CanonRungMissingComponent, padCpuVector(actual, missing));
    try testing.expectEqual(@as(?usize, 1), selectRung(&.{ small, rung }, actual));
    try testing.expectEqual(@as(?usize, null), selectRung(&.{small}, actual));
}
test "canon-native vector round-trips a declaration" {
    var d = W.CpuDeclaration{ .geometry = .{ .cpu_log = 22, .alu_log = 18, .alu_tail_log = 16, .ls_log = 18, .initial_log = 21, .terminal_log = 5, .cpu_fused_tail = true }, .bridges = .{ .keccak = 15, .ls_dword = 19 } };
    d.bridges.bulk.copy = 17;
    d.bridges.sponge.perm = 12;
    const v = cpuVector(d);
    try testing.expectEqual(@as(u32, 21), v[13]);
    try testing.expectEqual(@as(u32, 17), v[28]);
    const back = applyCpuVector(d, v);
    try testing.expect(std.meta.eql(back, d));
    try testing.expectEqual(CPU_COMPONENT_COUNT, 41);
}
