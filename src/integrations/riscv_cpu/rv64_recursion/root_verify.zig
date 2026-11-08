//! Root-only receiver (stream rootverify, M5 plan "verifier" column, binding
//! note rv64-m5-binding.md §5). The receiver derives a VK table ONCE from its
//! own pinned binary (never from producer stores), then verifies a block by:
//!   1. checking the table header against its own profile/binary/image;
//!   2. recomputing every leaf statement digest from the receiver-admitted
//!      bundle metadata (no native proof is verified: leaves do that in-circuit);
//!   3. recomputing every fold digest bottom-up from table VKs (no child
//!      recursion proof is read: folds verify children in-circuit);
//!   4. verifying ONLY the root proof, under a verifier-only authority rebuilt
//!      from the table VK, against the recomputed root digest.
//!
//! Table profiles (named; unknown ids are refused):
//! - `rv64-m4-fold-v2-compat/v0`: today's proof format. Fold VKs are keyed by
//!   the fold v2 geometry class (`om31_outer.classKey`, binding argued in
//!   rv64-m3-topo-binding.md). Leaf VKs are keyed by the native leaf class
//!   (native FIXED binding + declaration + PCS config); see `leafKey` for the
//!   determinism premise and how derive checks it.
//! - `rv64-m5-vk-table/v1`: reserved for canon-vk's canonical leaves/folds
//!   (T_rec/T_nat in the root statement); refused until that format exists.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Om31 = @import("stwo_circuit_cpu_integration").om31;
const Prove = Om31.prove;
const Wire = Om31.wire;
const Bridge = @import("om31_outer.zig");
const Dag = @import("om31_native/ready_dag.zig");
const PPMod = circuit.common.preprocessed;
const List = circuit.common.component_list;
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const N_COLUMNS = PPMod.N_PREPROCESSED_COLUMNS;
const N_COMPONENTS = List.N_COMPONENTS;
const HybridKey = @import("../outer_gkr/hybrid_receiver.zig").Key;
const HybridWire = @import("../outer_gkr/hybrid_wire.zig");
fn hybridActive() bool {
    return @import("om31_native/outer_wrap.zig").hybridProfileActive();
}

/// v1 (M6 fold-v3): adds the receiver-derived NATIVE VK section (`native`),
/// bound by the table root (root-v2). v0 tables (M5) are refused: re-derive.
pub const SCHEMA = "rv64-vk-receiver-table/v1";
/// Upper bound of one VK-only native setup artifact (header 256 B + VK).
pub const MAX_NATIVE_ARTIFACT_BYTES: usize = 64 << 10;
pub const Profile = enum {
    m4_fold_v2_compat,
    m5_canon_v1,
    pub fn id(self: Profile) []const u8 {
        return switch (self) {
            .m4_fold_v2_compat => "rv64-m4-fold-v2-compat/v0",
            .m5_canon_v1 => "rv64-m5-vk-table/v1",
        };
    }
    /// Unknown profile ids are refused; known-but-unimplemented ones too.
    pub fn parse(name: []const u8) !Profile {
        inline for (std.meta.fields(Profile)) |field| {
            const value: Profile = @enumFromInt(field.value);
            if (std.mem.eql(u8, name, value.id())) {
                if (value == .m5_canon_v1) return error.VkTableProfileNotImplemented;
                return value;
            }
        }
        return error.UnknownVkTableProfile;
    }
};
/// Fold v2 message domain (`om31_outer.zig` `domain`); derive cross-checks
/// every fold digest against `Bridge.expectedDigest`, so a drift is caught.
const FOLD_DOMAIN: u32 = 0x4f464c31;
pub const N_DIGEST_OUTPUTS = 8;

// ---------------------------------------------------------------- verifier key

/// Compact OM31 verifier key: everything `Prove.verify` and the fold v2
/// class/digest need, and nothing a prover needs. ~0.5 KB per circuit.
pub const VerifierKey = struct {
    /// Preprocessed column layout, in commitment (pp.columns) order.
    column: [N_COLUMNS]u8,
    log_size: [N_COLUMNS]u32,
    logs: [N_COMPONENTS]u32,
    n_outputs: u32,
    total_constraints: u32,
    max_evaluation_log_size: u32,
    fixed_root: [32]u8,
    identity: [32]u8,

    pub fn fromAuthority(key: *const Prove.Authority) !VerifierKey {
        var out: VerifierKey = undefined;
        for (key.layout.entries, 0..) |entry, i| {
            out.column[i] = try columnIndex(entry.id);
            out.log_size[i] = entry.log_size;
            if (key.fixed_logs[i] != entry.log_size) return error.VkLayoutFixedLogMismatch;
        }
        out.logs = key.logs.toArray();
        out.n_outputs = @intCast(key.pp.n_outputs);
        out.total_constraints = @intCast(key.bound.total_constraints);
        out.max_evaluation_log_size = @intCast(key.bound.max_evaluation_log_size);
        out.fixed_root = key.fixedRoot();
        out.identity = key.identity;
        return out;
    }
    pub fn layout(self: *const VerifierKey) PPMod.ColumnLayout {
        var out: PPMod.ColumnLayout = undefined;
        for (&out.entries, self.column, self.log_size) |*entry, column, log| entry.* = .{ .id = ALL_COLUMN_IDS[column], .log_size = log };
        return out;
    }
    /// Verifier-only authority. The identity and bound AIR are recomputed from
    /// the layout and root; a key whose recorded fields disagree is refused.
    pub fn authority(self: *const VerifierKey, a: std.mem.Allocator, stub: *PPMod.PreprocessedCircuit) !Prove.Authority {
        stub.* = stubOf(self.n_outputs);
        var key = try Prove.Authority.initVerifier(a, stub, self.layout(), self.fixed_root);
        errdefer key.deinit();
        if (!std.mem.eql(u8, &key.identity, &self.identity)) return error.VkTableIdentityMismatch;
        if (!std.mem.eql(u32, &key.logs.toArray(), &self.logs)) return error.VkTableLogsMismatch;
        if (key.bound.total_constraints != self.total_constraints or key.bound.max_evaluation_log_size != self.max_evaluation_log_size) return error.VkTableBoundMismatch;
        return key;
    }
    /// Exactly the per-child part of `om31_outer.classKey`.
    fn hashClassPart(self: *const VerifierKey, h: *std.crypto.hash.sha2.Sha256) void {
        var bytes: [4]u8 = undefined;
        for (self.logs) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            h.update(&bytes);
        }
        for (self.log_size) |log| {
            std.mem.writeInt(u32, &bytes, log, .little);
            h.update(&bytes);
        }
        for (self.column, self.log_size) |column, log| {
            const id = ALL_COLUMN_IDS[column];
            std.mem.writeInt(u32, &bytes, @intCast(id.len), .little);
            h.update(&bytes);
            h.update(id);
            std.mem.writeInt(u32, &bytes, log, .little);
            h.update(&bytes);
        }
        for ([_]u32{ self.n_outputs, self.total_constraints, self.max_evaluation_log_size }) |value| {
            std.mem.writeInt(u32, &bytes, value, .little);
            h.update(&bytes);
        }
    }
};

const ALL_COLUMN_IDS: [N_COLUMNS][]const u8 = blk: {
    const head = PPMod.EQ_COLUMN_IDS ++ PPMod.QM31_OPS_COLUMN_IDS ++ PPMod.TRIPLE_XOR_COLUMN_IDS ++ PPMod.M31_TO_U32_COLUMN_IDS ++ PPMod.BLAKE_G_GATE_COLUMN_IDS;
    var out: [N_COLUMNS][]const u8 = undefined;
    for (head, 0..) |id, i| out[i] = id;
    for (PPMod.FIXED_COLUMNS, head.len..) |column, i| out[i] = column.id;
    break :blk out;
};
fn columnIndex(id: []const u8) !u8 {
    for (ALL_COLUMN_IDS, 0..) |known, i| if (std.mem.eql(u8, known, id)) return @intCast(i);
    return error.VkUnknownPreprocessedColumn;
}
var empty_column: [0]M31 = .{};
fn stubOf(n_outputs: u32) PPMod.PreprocessedCircuit {
    var pp: PPMod.PreprocessedCircuit = .{ .columns = undefined, .first_permutation_row = 0, .n_outputs = n_outputs };
    for (&pp.columns, ALL_COLUMN_IDS) |*column, id| column.* = .{ .id = id, .values = &empty_column };
    return pp;
}

/// `om31_outer.classKey` over compact keys (children are 8-output digests).
pub fn foldClassKey(left: *const VerifierKey, right: *const VerifierKey) [32]u8 {
    return foldClassKeyK(&.{ left, right }) catch unreachable;
}
/// k-ary form (M6 fold-v3): hashes `Bridge.versionWord(k)` exactly as
/// `om31_outer.classKey` does (binary keeps word `version`, so binary keys
/// are unchanged; k > 2 binds the arity).
pub fn foldClassKeyK(children: []const *const VerifierKey) ![32]u8 {
    return foldClassKeyKForFamily(children, hybridActive());
}
/// Family is receiver policy. Compact entries remain original source VKs;
/// hybrid identities and AIR programs are always reconstructed from them.
pub fn foldClassKeyKForFamily(children: []const *const VerifierKey, hybrid: bool) ![32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(if (hybrid) "rv64-om31-hybrid-fold-class/v2\x00" else "rv64-om31-fold-class/v2\x00");
    h.update(Om31.protocol.domainName());
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, try Bridge.versionWord(children.len), .little);
    h.update(&bytes);
    if (hybrid) h.update(&@import("../outer_gkr/child_verifier.zig").CODE_ID);
    for (children) |key| {
        if (hybrid) {
            const a = std.heap.page_allocator;
            var stub: PPMod.PreprocessedCircuit = undefined;
            var source = try key.authority(a, &stub);
            defer source.deinit();
            var derived = try HybridKey.init(a, &source, 256);
            defer derived.deinit();
            h.update(derived.profile.domainName());
            for (derived.artifacts) |artifact| h.update(&artifact.program.identity);
        }
        key.hashClassPart(&h);
    }
    return h.finalResult();
}
pub fn effectiveIdentityForFamily(a: std.mem.Allocator, key: *const VerifierKey, hybrid: bool) ![32]u8 {
    if (!hybrid) return key.identity;
    var stub: PPMod.PreprocessedCircuit = undefined;
    var source = try key.authority(a, &stub);
    defer source.deinit();
    var derived = try HybridKey.init(a, &source, 256);
    defer derived.deinit();
    return derived.identity;
}
/// Canonical packed outputs of a digest-output circuit (`requireDigest`).
fn outputCoordinates(digest: [32]u8) [N_DIGEST_OUTPUTS][4]u32 {
    var out: [N_DIGEST_OUTPUTS][4]u32 = undefined;
    for (&out, 0..) |*q, i| {
        const w = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        q.* = .{ w & 0xffff, w >> 16, 0, 0 };
    }
    return out;
}
pub const FoldChild = struct { key: *const VerifierKey, digest: [32]u8 };
/// `om31_outer.expectedDigest` over compact keys and child digests.
pub fn foldDigest(children: [2]FoldChild) ![32]u8 {
    return foldDigestK(&children);
}
/// k-ary form: message version word `Bridge.versionWord(k)`.
pub fn foldDigestK(children: []const FoldChild) ![32]u8 {
    return foldDigestKForFamily(children, hybridActive());
}
pub fn foldDigestKForFamily(children: []const FoldChild, hybrid: bool) ![32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    const put = struct {
        fn word(hash: *std.crypto.hash.blake2.Blake2s256, buffer: *[4]u8, value: u32) void {
            std.mem.writeInt(u32, buffer, value, .little);
            hash.update(buffer);
        }
    };
    put.word(&h, &bytes, if (hybrid) 0x48464c32 else FOLD_DOMAIN);
    put.word(&h, &bytes, try Bridge.versionWord(children.len));
    for (children) |child| {
        if (child.key.n_outputs != N_DIGEST_OUTPUTS) return error.InvalidOm31CircuitOutputCount;
        const identity = try effectiveIdentityForFamily(std.heap.page_allocator, child.key, hybrid);
        for (0..8) |i| put.word(&h, &bytes, std.mem.readInt(u32, identity[4 * i ..][0..4], .little));
        for (0..8) |i| put.word(&h, &bytes, std.mem.readInt(u32, child.key.fixed_root[4 * i ..][0..4], .little));
        put.word(&h, &bytes, N_DIGEST_OUTPUTS);
        for (outputCoordinates(child.digest)) |q| for (q) |c| put.word(&h, &bytes, c);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
/// Leaf statement digest exactly as `leaf_graph.finish`.
pub fn leafDigest(words: []const u32) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    for (words) |word| {
        std.mem.writeInt(u32, &bytes, word, .little);
        h.update(&bytes);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

// ---------------------------------------------------------------- leaf class key

/// m4-compat leaf class key. Premise (the leaf analogue of the fold v2
/// "topology = f(classKey)" claim): a leaf circuit's topology, PP and FIXED
/// root are a function of its native VK class: family/kind, the receiver's
/// native FIXED binding (source root, fixed identity, fixed root, profile),
/// the producer-declared geometry that the receiver re-derived that binding
/// from, the native PCS config and the outer protocol/AIR. Every per-segment
/// statement value (ordinal, statement, manifest, MAIN root, claims, steps,
/// registers, ids) is a guessed frame word hashed into the leaf output, not a
/// circuit constant. Evidence [M]: 3 truth leaves have byte-identical
/// authorities across 26235156 and 24628607 at different ordinals and
/// statements. `derive` enforces the premise on every key it sees twice
/// (`VkLeafClassMismatch`); a false premise can only make root-only REJECT an
/// honest proof (the producer's leaf authority would differ from the table's,
/// so the fold digest differs), and --audit stays the acceptance path for this
/// profile. M5 canonical leaves make it true by construction.
pub fn leafKey(kind: []const u8, declaration_json: []const u8, source_root: [32]u8, fixed_identity: [32]u8, fixed_root: [32]u8, native_profile: []const u8, config_json: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-rootverify/m4-leaf-class/v0\x00");
    h.update(Om31.protocol.domainName());
    for ([_][]const u8{ kind, declaration_json, native_profile, config_json }) |part| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, part.len, .little);
        h.update(&bytes);
        h.update(part);
    }
    h.update(&source_root);
    h.update(&fixed_identity);
    h.update(&fixed_root);
    return h.finalResult();
}

// ---------------------------------------------------------------- table

pub const Header = struct {
    schema: []const u8 = SCHEMA,
    profile: []const u8,
    native_profile: []const u8,
    outer_domain: []const u8,
    fold_version: u32,
    /// Human record of the pinned source commit the deriving binary was built from.
    source_commit: []const u8,
    /// The deriving receiver binary (sha256 of /proc/self/exe). A table is
    /// accepted only by the very binary that derived it.
    receiver_sha256: []const u8,
    /// Program identity of the guest image (ELF + ROM authority).
    image: []const u8,
};
pub const KeyJson = struct {
    columns: []const u8,
    log_sizes: []const u32,
    logs: []const u32,
    n_outputs: u32,
    total_constraints: u32,
    max_evaluation_log_size: u32,
    fixed_root: []const u8,
    identity: []const u8,
};
pub const EntryJson = struct { kind: []const u8, key: []const u8, label: []const u8 = "", vk: KeyJson };
/// One receiver-derived native setup component: the VK-only setup artifact
/// (`setup_cache.zig` header + VK: suite identity, source root and logs,
/// candidate FIXED identity/root/cells/logs) under its component key (code
/// identity, suite, geometry/bridges or truth parameters, program identity).
pub const NativeJson = struct { key: []const u8, artifact: []const u8 };
pub const NativeEntry = struct { key: [32]u8, artifact: []const u8 };
pub const TableJson = struct {
    header: Header,
    entries: []const EntryJson,
    native: []const NativeJson = &.{},
    /// H over the sorted entries; the receiver recomputes it on load.
    table_root: []const u8,
    derive_ns: u64 = 0,
    derived_from: []const []const u8 = &.{},
};
pub const Kind = enum { leaf, fold };
pub const Entry = struct { kind: Kind, key: [32]u8, vk: VerifierKey, label: []const u8 = "" };

pub const Table = struct {
    allocator: std.mem.Allocator,
    header: Header,
    entries: std.ArrayList(Entry) = .empty,
    native: std.ArrayList(NativeEntry) = .empty,
    strings: std.heap.ArenaAllocator,
    derive_ns: u64 = 0,
    derived_from: std.ArrayList([]const u8) = .empty,

    pub fn init(a: std.mem.Allocator, header: Header) !Table {
        var self = Table{ .allocator = a, .header = undefined, .strings = std.heap.ArenaAllocator.init(a) };
        self.header = try dupeHeader(self.strings.allocator(), header);
        return self;
    }
    pub fn deinit(self: *Table) void {
        self.entries.deinit(self.allocator);
        self.native.deinit(self.allocator);
        self.derived_from.deinit(self.allocator);
        self.strings.deinit();
        self.* = undefined;
    }
    pub fn find(self: *const Table, kind: Kind, key: [32]u8) ?*const VerifierKey {
        for (self.entries.items) |*entry| if (entry.kind == kind and std.mem.eql(u8, &entry.key, &key)) return &entry.vk;
        return null;
    }
    /// Adds a receiver-derived key; an existing key must be byte-identical
    /// (the class premise), otherwise derivation fails closed.
    pub fn put(self: *Table, kind: Kind, key: [32]u8, vk: VerifierKey, label: []const u8) !bool {
        if (self.find(kind, key)) |existing| {
            if (!std.meta.eql(existing.*, vk)) return if (kind == .leaf) error.VkLeafClassMismatch else error.VkFoldClassMismatch;
            return false;
        }
        try self.entries.append(self.allocator, .{ .kind = kind, .key = key, .vk = vk, .label = try self.strings.allocator().dupe(u8, label) });
        return true;
    }
    pub fn findNative(self: *const Table, key: [32]u8) ?[]const u8 {
        for (self.native.items) |entry| if (std.mem.eql(u8, &entry.key, &key)) return entry.artifact;
        return null;
    }
    /// Adds a receiver-derived native artifact; a repeated key must carry the
    /// byte-identical artifact (setup is a pure function of its key).
    pub fn putNative(self: *Table, key: [32]u8, artifact: []const u8) !bool {
        if (artifact.len == 0 or artifact.len > MAX_NATIVE_ARTIFACT_BYTES) return error.InvalidNativeVkArtifact;
        if (self.findNative(key)) |existing| {
            if (!std.mem.eql(u8, existing, artifact)) return error.VkNativeClassMismatch;
            return false;
        }
        try self.native.append(self.allocator, .{ .key = key, .artifact = try self.strings.allocator().dupe(u8, artifact) });
        return true;
    }
    fn nativeLess(_: void, l: NativeEntry, r: NativeEntry) bool {
        return std.mem.order(u8, &l.key, &r.key) == .lt;
    }
    fn lessThan(_: void, l: Entry, r: Entry) bool {
        if (l.kind != r.kind) return @intFromEnum(l.kind) < @intFromEnum(r.kind);
        return std.mem.order(u8, &l.key, &r.key) == .lt;
    }
    pub fn sort(self: *Table) void {
        std.sort.pdq(Entry, self.entries.items, {}, lessThan);
        std.sort.pdq(NativeEntry, self.native.items, {}, nativeLess);
    }
    /// Domain-tagged digest over the canonical (sorted) entry list.
    pub fn root(self: *const Table) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        // v1 root: EVERY header field is bound (the v0 root left schema,
        // fold_version, source_commit and receiver_sha256 out, so a stale
        // table could be relabelled to the current receiver without a reseal).
        // The root is still unkeyed: anyone who can write the table can reseal
        // it. Authenticity comes from where the table lives and, when the
        // operator passes it, the `--table-root` pin; never from this digest.
        // root-v2 (schema v1): also binds the native VK section, so the
        // `--table-root` pin authenticates the native setup the receiver restores.
        h.update("rv64-vk-receiver-table/v1/root-v2\x00");
        for ([_][]const u8{ self.header.schema, self.header.profile, self.header.native_profile, self.header.outer_domain, self.header.source_commit, self.header.receiver_sha256, self.header.image }) |part| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, part.len, .little);
            h.update(&bytes);
            h.update(part);
        }
        updateU32(&h, self.header.fold_version);
        for (self.entries.items) |entry| {
            h.update(&[_]u8{@intFromEnum(entry.kind)});
            h.update(&entry.key);
            h.update(std.mem.asBytes(&entry.vk.column));
            for (entry.vk.log_size) |v| updateU32(&h, v);
            for (entry.vk.logs) |v| updateU32(&h, v);
            for ([_]u32{ entry.vk.n_outputs, entry.vk.total_constraints, entry.vk.max_evaluation_log_size }) |v| updateU32(&h, v);
            h.update(&entry.vk.fixed_root);
            h.update(&entry.vk.identity);
        }
        h.update("native\x00");
        var count: [8]u8 = undefined;
        std.mem.writeInt(u64, &count, self.native.items.len, .little);
        h.update(&count);
        for (self.native.items) |entry| {
            h.update(&entry.key);
            std.mem.writeInt(u64, &count, entry.artifact.len, .little);
            h.update(&count);
            h.update(entry.artifact);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn toJson(self: *Table, a: std.mem.Allocator) ![]u8 {
        self.sort();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const t = arena.allocator();
        const entries = try t.alloc(EntryJson, self.entries.items.len);
        for (entries, self.entries.items) |*out, *entry| {
            const columns = try t.alloc(u8, N_COLUMNS * 2);
            const hex = "0123456789abcdef";
            for (entry.vk.column, 0..) |c, i| {
                columns[2 * i] = hex[c >> 4];
                columns[2 * i + 1] = hex[c & 15];
            }
            out.* = .{ .kind = @tagName(entry.kind), .key = try hexAlloc(t, &entry.key), .label = entry.label, .vk = .{ .columns = columns, .log_sizes = &entry.vk.log_size, .logs = &entry.vk.logs, .n_outputs = entry.vk.n_outputs, .total_constraints = entry.vk.total_constraints, .max_evaluation_log_size = entry.vk.max_evaluation_log_size, .fixed_root = try hexAlloc(t, &entry.vk.fixed_root), .identity = try hexAlloc(t, &entry.vk.identity) } };
        }
        const native = try t.alloc(NativeJson, self.native.items.len);
        for (native, self.native.items) |*out, entry| out.* = .{ .key = try hexAlloc(t, &entry.key), .artifact = try hexAlloc(t, entry.artifact) };
        const table_root = self.root();
        return std.json.Stringify.valueAlloc(a, TableJson{ .header = self.header, .entries = entries, .native = native, .table_root = try hexAlloc(t, &table_root), .derive_ns = self.derive_ns, .derived_from = self.derived_from.items }, .{ .whitespace = .indent_1 });
    }
    pub fn fromJson(a: std.mem.Allocator, bytes: []const u8) !Table {
        const parsed = try std.json.parseFromSlice(TableJson, a, bytes, .{});
        defer parsed.deinit();
        const v = parsed.value;
        if (!std.mem.eql(u8, v.header.schema, SCHEMA)) return error.UnknownVkTableSchema;
        _ = try Profile.parse(v.header.profile);
        var self = try Table.init(a, v.header);
        errdefer self.deinit();
        self.derive_ns = v.derive_ns;
        for (v.derived_from) |name| try self.derived_from.append(a, try self.strings.allocator().dupe(u8, name));
        for (v.entries) |e| {
            const kind = std.meta.stringToEnum(Kind, e.kind) orelse return error.InvalidVkTableEntry;
            var vk: VerifierKey = undefined;
            if (e.vk.columns.len != 2 * N_COLUMNS or e.vk.log_sizes.len != N_COLUMNS or e.vk.logs.len != N_COMPONENTS) return error.InvalidVkTableEntry;
            _ = try std.fmt.hexToBytes(&vk.column, e.vk.columns);
            for (vk.column) |c| if (c >= N_COLUMNS) return error.VkUnknownPreprocessedColumn;
            @memcpy(&vk.log_size, e.vk.log_sizes);
            @memcpy(&vk.logs, e.vk.logs);
            vk.n_outputs = e.vk.n_outputs;
            vk.total_constraints = e.vk.total_constraints;
            vk.max_evaluation_log_size = e.vk.max_evaluation_log_size;
            try hex32(&vk.fixed_root, e.vk.fixed_root);
            try hex32(&vk.identity, e.vk.identity);
            var key: [32]u8 = undefined;
            try hex32(&key, e.key);
            if (!try self.put(kind, key, vk, e.label)) return error.DuplicateVkTableEntry;
        }
        for (v.native) |e| {
            var key: [32]u8 = undefined;
            try hex32(&key, e.key);
            if (e.artifact.len == 0 or e.artifact.len % 2 != 0 or e.artifact.len / 2 > MAX_NATIVE_ARTIFACT_BYTES) return error.InvalidNativeVkArtifact;
            const raw = try a.alloc(u8, e.artifact.len / 2);
            defer a.free(raw);
            _ = std.fmt.hexToBytes(raw, e.artifact) catch return error.InvalidVkTableHex;
            if (!try self.putNative(key, raw)) return error.DuplicateVkTableEntry;
        }
        self.sort();
        var want: [32]u8 = undefined;
        try hex32(&want, v.table_root);
        if (!std.mem.eql(u8, &want, &self.root())) return error.VkTableRootMismatch;
        return self;
    }
};
fn updateU32(h: *std.crypto.hash.blake2.Blake2s256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    h.update(&bytes);
}
fn dupeHeader(a: std.mem.Allocator, h: Header) !Header {
    return .{ .schema = try a.dupe(u8, h.schema), .profile = try a.dupe(u8, h.profile), .native_profile = try a.dupe(u8, h.native_profile), .outer_domain = try a.dupe(u8, h.outer_domain), .fold_version = h.fold_version, .source_commit = try a.dupe(u8, h.source_commit), .receiver_sha256 = try a.dupe(u8, h.receiver_sha256), .image = try a.dupe(u8, h.image) };
}
pub fn hexAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try a.alloc(u8, bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = hex[b >> 4];
        out[2 * i + 1] = hex[b & 15];
    }
    return out;
}
fn hex32(out: *[32]u8, text: []const u8) !void {
    if (text.len != 64) return error.InvalidVkTableHex;
    _ = try std.fmt.hexToBytes(out, text);
}

/// Receiver policy: the header must match THIS binary, THIS outer protocol,
/// the receiver-selected native profile and the request's image. Nothing in
/// the header is producer-chosen; a table from any other derivation is refused.
pub fn requireHeader(table: *const Table, expected: Header) !void {
    if (!std.mem.eql(u8, table.header.schema, SCHEMA)) return error.UnknownVkTableSchema;
    const profile = try Profile.parse(table.header.profile);
    if (!std.mem.eql(u8, table.header.profile, expected.profile) or profile != try Profile.parse(expected.profile)) return error.VkTableProfileMismatch;
    if (!std.mem.eql(u8, table.header.native_profile, expected.native_profile)) return error.VkTableNativeProfileMismatch;
    if (!std.mem.eql(u8, table.header.outer_domain, expected.outer_domain) or table.header.fold_version != expected.fold_version) return error.VkTableOuterProfileMismatch;
    if (!std.mem.eql(u8, table.header.receiver_sha256, expected.receiver_sha256)) return error.VkTableNotDerivedByThisReceiver;
    if (!std.mem.eql(u8, table.header.image, expected.image)) return error.VkTableImageMismatch;
}
/// Operator pin: when the receiver passes `--table-root HEX` (recorded from its
/// own derive output in a place the producer cannot write), the loaded table's
/// recomputed root must equal it. This is the only authenticity check of the
/// table; the header and root alone are self-declared.
pub fn requirePinnedRoot(table: *const Table, pin_hex: []const u8) !void {
    var pin: [32]u8 = undefined;
    hex32(&pin, pin_hex) catch return error.InvalidVkTableRootPin;
    if (!std.mem.eql(u8, &pin, &table.root())) return error.VkTableRootPinMismatch;
}
/// Refuse any table that lives in (or under) the producer's proof directory.
/// This is a guard against the obvious in-store case only: the receiver
/// cannot know the producer's whole run tree, so a table placed next to the
/// proof directory passes this check (measured, review A3). Authenticity is
/// the operator's `--table-root` pin.
pub fn requireReceiverLocal(table_real: []const u8, proof_real: []const u8) !void {
    if (std.mem.startsWith(u8, table_real, proof_real) and (table_real.len == proof_real.len or table_real[proof_real.len] == '/')) return error.StoreSuppliedVkRefused;
}
/// sha256 of the running executable (Linux), streamed.
pub fn selfSha256(a: std.mem.Allocator) ![64]u8 {
    var file = try std.fs.openFileAbsolute("/proc/self/exe", .{});
    defer file.close();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    const buffer = try a.alloc(u8, 4 << 20);
    defer a.free(buffer);
    while (true) {
        const n = try file.read(buffer);
        if (n == 0) break;
        h.update(buffer[0..n]);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

// ---------------------------------------------------------------- derive sink

/// Derive collector. Installed only by `derive-vk-tables` around today's full
/// independent receiver (`execution_wrap.verifyExisting`), which builds every
/// authority from source and freshly verifies every proof. Records each
/// authority as a compact key and cross-checks this module's fold class/digest
/// re-implementation against the circuit code's on every fold.
pub const Sink = struct {
    allocator: std.mem.Allocator,
    leaves: std.ArrayList(struct { ordinal: usize, vk: VerifierKey, digest: [32]u8 }) = .empty,
    folds: std.ArrayList(struct { class: [32]u8, vk: VerifierKey }) = .empty,
    failure: ?anyerror = null,
    cross_checked_folds: usize = 0,
    pub fn deinit(self: *Sink) void {
        self.leaves.deinit(self.allocator);
        self.folds.deinit(self.allocator);
    }
};
pub threadlocal var active_sink: ?*Sink = null;
/// Hook (execution_wrap leaf acceptance): no-op unless a derive is running.
pub fn recordLeaf(ordinal: usize, authority: *const Prove.Authority, digest: [32]u8) void {
    const sink = active_sink orelse return;
    if (sink.failure != null) return;
    const vk = VerifierKey.fromAuthority(authority) catch |err| {
        sink.failure = err;
        return;
    };
    sink.leaves.append(sink.allocator, .{ .ordinal = ordinal, .vk = vk, .digest = digest }) catch |err| {
        sink.failure = err;
    };
}
/// Hook (execution_wrap fold acceptance of a freshly built class authority).
pub fn recordFold(children: [2]Bridge.Child, class: [32]u8, digest: [32]u8, authority: *const Prove.Authority) void {
    const sink = active_sink orelse return;
    if (sink.failure != null) return;
    recordFoldImpl(sink, children, class, digest, authority) catch |err| {
        sink.failure = err;
    };
}
/// Same record + cross-check, into an explicit sink (parallel derive,
/// `root_derive.zig`, calls it on the coordinating thread).
pub fn recordFoldInto(sink: *Sink, children: [2]Bridge.Child, class: [32]u8, digest: [32]u8, authority: *const Prove.Authority) !void {
    return recordFoldImpl(sink, children, class, digest, authority);
}
fn recordFoldImpl(sink: *Sink, children: [2]Bridge.Child, class: [32]u8, digest: [32]u8, authority: *const Prove.Authority) !void {
    return recordFoldImplK(sink, &children, class, digest, authority);
}
/// k-ary record + cross-check (M6 integrate: diet-wire k-ary folds under the
/// fold-v3 parallel derive). Binary folds take the same path with k = 2, so
/// their class keys and digests are the binary forms (`foldClassKeyK` /
/// `foldDigestK` keep word `version` at k = 2).
pub fn recordFoldIntoK(sink: *Sink, children: []const Bridge.Child, class: [32]u8, digest: [32]u8, authority: *const Prove.Authority) !void {
    return recordFoldImplK(sink, children, class, digest, authority);
}
fn recordFoldImplK(sink: *Sink, children: []const Bridge.Child, class: [32]u8, digest: [32]u8, authority: *const Prove.Authority) !void {
    if (children.len < 2 or children.len > Dag.max_arity) return error.VkFoldArityOutOfRange;
    var vks: [Dag.max_arity]VerifierKey = undefined;
    var keys: [Dag.max_arity]*const VerifierKey = undefined;
    var fold_children: [Dag.max_arity]FoldChild = undefined;
    for (children, 0..) |child, i| {
        vks[i] = try VerifierKey.fromAuthority(child.authority);
        keys[i] = &vks[i];
    }
    if (!std.mem.eql(u8, &(try foldClassKeyK(keys[0..children.len])), &class)) return error.VkFoldClassReimplementationDrift;
    for (children, 0..) |child, i| fold_children[i] = .{ .key = keys[i], .digest = try digestOf(child.produced.outputs) };
    const mine = try foldDigestK(fold_children[0..children.len]);
    if (!std.mem.eql(u8, &mine, &digest)) return error.VkFoldDigestReimplementationDrift;
    try sink.folds.append(sink.allocator, .{ .class = class, .vk = try VerifierKey.fromAuthority(authority) });
    sink.cross_checked_folds += 1;
}
fn digestOf(outputs: []const Q) ![32]u8 {
    if (outputs.len != N_DIGEST_OUTPUTS) return error.CurrentOm31OutputCount;
    var out: [32]u8 = undefined;
    for (outputs, 0..) |value, i| {
        const c = value.toM31Array();
        if (c[0].v > 65535 or c[1].v > 65535 or c[2].v != 0 or c[3].v != 0) return error.NoncanonicalCurrentOm31Output;
        std.mem.writeInt(u32, out[4 * i ..][0..4], c[0].v | (c[1].v << 16), .little);
    }
    return out;
}

// ---------------------------------------------------------------- root-only verify

pub const LeafInput = struct { key: [32]u8, digest: [32]u8 };
pub const RootReport = struct {
    leaves: usize,
    folds: usize,
    root_digest: [32]u8,
    root_identity: [32]u8,
    root_kind: Kind,
    tree_ns: u64,
    authority_ns: u64,
    decode_ns: u64,
    verify_ns: u64,
};
const Pending = struct { first: usize, count: usize, vk: *const VerifierKey, digest: [32]u8, kind: Kind };
fn combine(table: *const Table, left: Pending, right: Pending, folds: *usize) !Pending {
    if (left.first + left.count != right.first) return error.RecursiveLeafAdjacency;
    const class = foldClassKey(left.vk, right.vk);
    const vk = table.find(.fold, class) orelse return error.VkTableMissingFoldClass;
    folds.* += 1;
    return .{ .first = left.first, .count = left.count + right.count, .vk = vk, .digest = try foldDigest(.{ .{ .key = left.vk, .digest = left.digest }, .{ .key = right.vk, .digest = right.digest } }), .kind = .fold };
}
/// Expected root (VK, digest) for the ordered leaves under fold arity
/// `arity`: the receiver's own `ready_dag.Plan.initArity` (streaming k-ary
/// carry, finalized rightmost-upward; k = 2 is `runImpl`'s binary carry and
/// `expectedRoot` below, node for node).
pub fn expectedRootArity(a: std.mem.Allocator, table: *const Table, leaves: []const LeafInput, arity: usize, folds: *usize) !Pending {
    if (leaves.len == 0 or leaves.len > 256) return error.ServicesRootRoster;
    const plan = try Dag.Plan.initArity(leaves.len, arity);
    if (hybridActive()) try @import("om31_native/outer_wrap.zig").requireHybridProofBudget(plan.count);
    const nodes = try a.alloc(Pending, plan.count);
    defer a.free(nodes);
    for (plan.nodes[0..plan.count], 0..) |node, id| {
        if (node.isLeaf()) {
            const leaf = leaves[node.first_leaf];
            const vk = table.find(.leaf, leaf.key) orelse return error.VkTableMissingLeafClass;
            if (vk.n_outputs != N_DIGEST_OUTPUTS) return error.InvalidOm31CircuitOutputCount;
            nodes[id] = .{ .first = node.first_leaf, .count = 1, .vk = vk, .digest = leaf.digest, .kind = .leaf };
            continue;
        }
        var keys: [Dag.max_arity]*const VerifierKey = undefined;
        var children: [Dag.max_arity]FoldChild = undefined;
        var next = nodes[node.children[0]].first;
        for (node.kids(), 0..) |kid, i| {
            const c = nodes[kid];
            if (c.first != next) return error.RecursiveLeafAdjacency;
            next += c.count;
            keys[i] = c.vk;
            children[i] = .{ .key = c.vk, .digest = c.digest };
        }
        const class = try foldClassKeyK(keys[0..node.arity]);
        const vk = table.find(.fold, class) orelse return error.VkTableMissingFoldClass;
        folds.* += 1;
        nodes[id] = .{ .first = nodes[node.children[0]].first, .count = next - nodes[node.children[0]].first, .vk = vk, .digest = try foldDigestK(children[0..node.arity]), .kind = .fold };
    }
    const final = nodes[plan.root];
    if (final.first != 0 or final.count != leaves.len) return error.RecursiveLeafCoverage;
    return final;
}
/// Expected root (VK, digest) for the ordered leaves: the streaming binary
/// carry tree of `execution_wrap.runImpl`, finalized rightmost-upward.
pub fn expectedRoot(table: *const Table, leaves: []const LeafInput, folds: *usize) !Pending {
    if (leaves.len == 0 or leaves.len > 256) return error.ServicesRootRoster;
    var stack = [_]?Pending{null} ** 9;
    for (leaves, 0..) |leaf, ordinal| {
        const vk = table.find(.leaf, leaf.key) orelse return error.VkTableMissingLeafClass;
        if (vk.n_outputs != N_DIGEST_OUTPUTS) return error.InvalidOm31CircuitOutputCount;
        var current: Pending = .{ .first = ordinal, .count = 1, .vk = vk, .digest = leaf.digest, .kind = .leaf };
        var level: usize = 0;
        while (stack[level]) |left| : (level += 1) {
            current = try combine(table, left, current, folds);
            stack[level] = null;
        }
        stack[level] = current;
    }
    var root: ?Pending = null;
    for (&stack) |*entry| if (entry.*) |left| {
        entry.* = null;
        root = if (root) |right| try combine(table, left, right, folds) else left;
    };
    const final = root orelse return error.RecursiveLeafCoverage;
    if (final.first != 0 or final.count != leaves.len) return error.RecursiveLeafCoverage;
    return final;
}
/// Verify ONLY the root proof bytes against the table-derived root VK and the
/// recomputed digest. The root VK's identity is recomputed, the wire decode is
/// bound to it, the outputs must be the canonical digest words and the proof
/// is freshly verified under the receiver's own authority.
pub fn verifyRoot(a: std.mem.Allocator, table: *const Table, leaves: []const LeafInput, root_bytes: []const u8) !RootReport {
    var timer = try std.time.Timer.start();
    var folds: usize = 0;
    const arity = try @import("om31_native/execution_wrap.zig").foldArity();
    const expected = try expectedRootArity(a, table, leaves, arity, &folds);
    if (folds != (try Dag.Plan.initArity(leaves.len, arity)).count - leaves.len) return error.RecursiveLeafCoverage;
    const tree_ns = timer.lap();
    var stub: PPMod.PreprocessedCircuit = undefined;
    var authority = try expected.vk.authority(a, &stub);
    defer authority.deinit();
    const authority_ns = timer.lap();
    if (hybridActive()) {
        var key = try HybridKey.init(a, &authority, 256);
        defer key.deinit();
        var decoded = try HybridWire.decode(a, &key, root_bytes);
        defer decoded.deinit();
        const decode_ns = timer.lap();
        if (!std.mem.eql(u8, &(try digestOf(decoded.base.outputs)), &expected.digest)) return error.CurrentOm31OutputDigest;
        var capture = try key.verify(a, decoded.base.outputs, decoded.base.claims, &decoded.section, &decoded.base.proof);
        capture.deinit(a);
        return .{ .leaves = leaves.len, .folds = folds, .root_digest = expected.digest, .root_identity = key.identity, .root_kind = expected.kind, .tree_ns = tree_ns, .authority_ns = authority_ns, .decode_ns = decode_ns, .verify_ns = timer.read() };
    }
    var decoded = try Wire.decode(a, authority.identity, 8, root_bytes);
    defer decoded.deinit();
    const decode_ns = timer.lap();
    if (!std.mem.eql(u8, &(try digestOf(decoded.outputs)), &expected.digest)) return error.CurrentOm31OutputDigest;
    var capture = try Prove.verify(a, &authority, decoded.outputs, decoded.claims, &decoded.proof);
    capture.deinit(a);
    return .{ .leaves = leaves.len, .folds = folds, .root_digest = expected.digest, .root_identity = authority.identity, .root_kind = expected.kind, .tree_ns = tree_ns, .authority_ns = authority_ns, .decode_ns = decode_ns, .verify_ns = timer.read() };
}

test "root_verify: profile ids are named and unknown ids refused" {
    try std.testing.expectEqual(Profile.m4_fold_v2_compat, try Profile.parse("rv64-m4-fold-v2-compat/v0"));
    try std.testing.expectError(error.VkTableProfileNotImplemented, Profile.parse("rv64-m5-vk-table/v1"));
    try std.testing.expectError(error.UnknownVkTableProfile, Profile.parse("rv64-m4-fold-v2-compat/v1"));
    try std.testing.expectError(error.UnknownVkTableProfile, Profile.parse(""));
}
test "root_verify: producer-directory tables are refused" {
    try std.testing.expectError(error.StoreSuppliedVkRefused, requireReceiverLocal("/run/case/proof/vk.json", "/run/case/proof"));
    try std.testing.expectError(error.StoreSuppliedVkRefused, requireReceiverLocal("/run/case/proof", "/run/case/proof"));
    try requireReceiverLocal("/run/case/proof-vk.json", "/run/case/proof");
    try requireReceiverLocal("/home/r/vk.json", "/run/case/proof");
}
fn testKey(seed: u8) VerifierKey {
    var vk: VerifierKey = undefined;
    for (&vk.column, 0..) |*c, i| c.* = @intCast(i);
    for (&vk.log_size, 0..) |*l, i| l.* = 10 + @as(u32, @intCast(i % 7));
    for (&vk.logs, 0..) |*l, i| l.* = 12 + @as(u32, @intCast(i % 5));
    vk.n_outputs = 8;
    vk.total_constraints = 100 + seed;
    vk.max_evaluation_log_size = 20;
    vk.fixed_root = @splat(seed);
    vk.identity = @splat(seed +% 1);
    return vk;
}
fn testTable(a: std.mem.Allocator) !Table {
    return Table.init(a, .{ .profile = Profile.m4_fold_v2_compat.id(), .native_profile = "n", .outer_domain = Om31.protocol.domainName(), .fold_version = Bridge.version, .source_commit = "c", .receiver_sha256 = "r", .image = "i" });
}
test "root_verify: table JSON round trip, root binding and header policy" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    _ = try table.put(.leaf, @splat(1), testKey(1), "leaf-a");
    _ = try table.put(.fold, @splat(2), testKey(2), "fold-a");
    try std.testing.expect(!try table.put(.leaf, @splat(1), testKey(1), "dup"));
    try std.testing.expectError(error.VkLeafClassMismatch, table.put(.leaf, @splat(1), testKey(3), "clash"));
    const bytes = try table.toJson(a);
    defer a.free(bytes);
    var back = try Table.fromJson(a, bytes);
    defer back.deinit();
    try std.testing.expectEqualDeep(table.root(), back.root());
    try std.testing.expect(std.meta.eql(back.find(.fold, @splat(2)).?.*, testKey(2)));
    try requireHeader(&back, table.header);
    var other = table.header;
    other.receiver_sha256 = "x";
    try std.testing.expectError(error.VkTableNotDerivedByThisReceiver, requireHeader(&back, other));
    other = table.header;
    other.image = "j";
    try std.testing.expectError(error.VkTableImageMismatch, requireHeader(&back, other));
    other = table.header;
    other.native_profile = "m";
    try std.testing.expectError(error.VkTableNativeProfileMismatch, requireHeader(&back, other));
    // Tampering with an entry breaks the recomputed table root.
    const tampered = try a.dupe(u8, bytes);
    defer a.free(tampered);
    const at = std.mem.indexOf(u8, tampered, "\"total_constraints\": 101").?;
    tampered[at + "\"total_constraints\": 10".len] = '9';
    try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, tampered));
    // Every header field is bound: relabelling the deriving receiver (review A1)
    // or the fold version without a reseal breaks the root.
    for ([_][]const u8{ "\"receiver_sha256\": \"r\"", "\"source_commit\": \"c\"" }) |needle| {
        const relabel = try a.dupe(u8, bytes);
        defer a.free(relabel);
        const at_field = std.mem.indexOf(u8, relabel, needle).?;
        relabel[at_field + needle.len - 2] = 'z';
        try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, relabel));
    }
    var plain = try testTable(a);
    defer plain.deinit();
    var relabelled = try testTable(a);
    defer relabelled.deinit();
    relabelled.header.fold_version +%= 1;
    try std.testing.expect(!std.mem.eql(u8, &relabelled.root(), &plain.root()));
    // Operator pin.
    const pin = try hexAlloc(a, &back.root());
    defer a.free(pin);
    try requirePinnedRoot(&back, pin);
    pin[0] = if (pin[0] == '0') '1' else '0';
    try std.testing.expectError(error.VkTableRootPinMismatch, requirePinnedRoot(&back, pin));
    try std.testing.expectError(error.InvalidVkTableRootPin, requirePinnedRoot(&back, "00"));
}
test "root_verify: tree shape, adjacency and missing classes" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const leaf = testKey(7);
    _ = try table.put(.leaf, @splat(7), leaf, "");
    var leaves: [3]LeafInput = undefined;
    for (&leaves, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
    var folds: usize = 0;
    try std.testing.expectError(error.VkTableMissingFoldClass, expectedRoot(&table, &leaves, &folds));
    const fold = testKey(9);
    _ = try table.put(.fold, foldClassKey(&leaf, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &fold), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &leaf), fold, "");
    folds = 0;
    const root = try expectedRoot(&table, &leaves, &folds);
    try std.testing.expectEqual(@as(usize, 2), folds);
    // [0,1) + [1,2) first, then ([0,2) + [2,3)).
    const d01 = try foldDigest(.{ .{ .key = &leaf, .digest = leaves[0].digest }, .{ .key = &leaf, .digest = leaves[1].digest } });
    const d = try foldDigest(.{ .{ .key = &fold, .digest = d01 }, .{ .key = &leaf, .digest = leaves[2].digest } });
    try std.testing.expectEqualDeep(d, root.digest);
    // Permuting two leaves changes the root digest (order is bound).
    std.mem.swap(LeafInput, &leaves[0], &leaves[1]);
    folds = 0;
    try std.testing.expect(!std.mem.eql(u8, &d, &(try expectedRoot(&table, &leaves, &folds)).digest));
    // Unknown leaf class.
    leaves[2].key = @splat(8);
    folds = 0;
    try std.testing.expectError(error.VkTableMissingLeafClass, expectedRoot(&table, &leaves, &folds));
}
test "root_verify: native VK section is root-bound, deduplicated and refused when altered" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const empty_root = table.root();
    try std.testing.expect(try table.putNative(@splat(3), "artifact-three"));
    try std.testing.expect(!try table.putNative(@splat(3), "artifact-three"));
    try std.testing.expectError(error.VkNativeClassMismatch, table.putNative(@splat(3), "artifact-other"));
    try std.testing.expectError(error.InvalidNativeVkArtifact, table.putNative(@splat(4), ""));
    try std.testing.expect(try table.putNative(@splat(1), "artifact-one"));
    try std.testing.expect(!std.mem.eql(u8, &empty_root, &table.root()));
    const bytes = try table.toJson(a);
    defer a.free(bytes);
    var back = try Table.fromJson(a, bytes);
    defer back.deinit();
    try std.testing.expectEqualDeep(table.root(), back.root());
    try std.testing.expectEqualStrings("artifact-three", back.findNative(@splat(3)).?);
    try std.testing.expect(back.findNative(@splat(9)) == null);
    // One flipped artifact byte (hex) breaks the recomputed root.
    const tampered = try a.dupe(u8, bytes);
    defer a.free(tampered);
    const hex_one = "61727469666163742d6f6e65"; // "artifact-one"
    const at = std.mem.indexOf(u8, tampered, hex_one).?;
    tampered[at + 1] = '2';
    try std.testing.expectError(error.VkTableRootMismatch, Table.fromJson(a, tampered));
    // The v0 schema (M5 tables without the native section) is refused.
    const old = try std.mem.replaceOwned(u8, a, bytes, SCHEMA, "rv64-vk-receiver-table/v0");
    defer a.free(old);
    try std.testing.expectError(error.UnknownVkTableSchema, Table.fromJson(a, old));
}
test "root_verify: plan-driven tree equals the binary carry; k-ary keys bind the arity" {
    const a = std.testing.allocator;
    var table = try testTable(a);
    defer table.deinit();
    const leaf = testKey(7);
    const fold = testKey(9);
    _ = try table.put(.leaf, @splat(7), leaf, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&leaf, &fold), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &leaf), fold, "");
    _ = try table.put(.fold, foldClassKey(&fold, &fold), fold, "");
    for ([_]usize{ 1, 2, 3, 5, 7, 11, 17 }) |n| {
        const leaves = try a.alloc(LeafInput, n);
        defer a.free(leaves);
        for (leaves, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
        var f1: usize = 0;
        var f2: usize = 0;
        const carry = try expectedRoot(&table, leaves, &f1);
        const planned = try expectedRootArity(a, &table, leaves, 2, &f2);
        try std.testing.expectEqualDeep(carry.digest, planned.digest);
        try std.testing.expectEqual(f1, f2);
        try std.testing.expectEqual(n - 1, f2);
    }
    // k = 2 keeps the historical class key; k = 3 differs (version word).
    const k2 = try foldClassKeyK(&.{ &leaf, &leaf });
    try std.testing.expectEqualDeep(foldClassKey(&leaf, &leaf), k2);
    const k3 = try foldClassKeyK(&.{ &leaf, &leaf, &leaf });
    try std.testing.expect(!std.mem.eql(u8, &k2, &k3));
    try std.testing.expectError(error.InvalidRecursiveFoldArity, foldClassKeyK(&.{&leaf}));
    // 4-ary: 5 leaves -> one 4-fold + a binary finalisation over the carry.
    _ = try table.put(.fold, try foldClassKeyK(&.{ &leaf, &leaf, &leaf, &leaf }), fold, "");
    var leaves5: [5]LeafInput = undefined;
    for (&leaves5, 0..) |*l, i| l.* = .{ .key = @splat(7), .digest = @splat(@intCast(i)) };
    var f4: usize = 0;
    const r4 = try expectedRootArity(a, &table, &leaves5, 4, &f4);
    try std.testing.expectEqual(@as(usize, 2), f4);
    const d4 = try foldDigestK(&.{ .{ .key = &leaf, .digest = leaves5[0].digest }, .{ .key = &leaf, .digest = leaves5[1].digest }, .{ .key = &leaf, .digest = leaves5[2].digest }, .{ .key = &leaf, .digest = leaves5[3].digest } });
    const d = try foldDigestK(&.{ .{ .key = &fold, .digest = d4 }, .{ .key = &leaf, .digest = leaves5[4].digest } });
    try std.testing.expectEqualDeep(d, r4.digest);
}
