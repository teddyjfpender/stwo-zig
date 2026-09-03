//! Process-local cache for an authenticated immutable preprocessed commitment.
//!
//! A cache entry is published only after the caller has rebuilt the exact
//! preprocessed tree and compared its root. The key closes the circuit,
//! program, profile, PCS policy, padding layout, and preprocessed tree/layout
//! identities. Neither the key nor the cached authority has a codec or grants
//! proof freshness; every proof still runs its own transcript and PCS verifier.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

const KEY_DOMAIN =
    "stwo-zig/process-local-preprocessed-authority-key/v1\x00";
const PREPROCESSED_DOMAIN =
    "stwo-zig/process-local-preprocessed-tree/v1\x00";
const AUTHORITY_DOMAIN =
    "stwo-zig/process-local-preprocessed-authority/v1\x00";

pub const Error = error{InvalidProcessLocalPreprocessedAuthority};

pub const KeyV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_identity_sha256: [32]u8,
    preprocessed_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn init(value: KeyV1) Error!KeyV1 {
        var result = value;
        result.identity_sha256 = keyIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const KeyV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidProcessLocalPreprocessedAuthority;
        }
        inline for (.{
            self.circuit_identity_sha256,
            self.program_identity_sha256,
            self.profile_identity_sha256,
            self.pcs_identity_sha256,
            self.padding_identity_sha256,
            self.preprocessed_identity_sha256,
            self.identity_sha256,
        }) |identity| if (std.mem.allEqual(u8, &identity, 0))
            return error.InvalidProcessLocalPreprocessedAuthority;
        if (!std.mem.eql(u8, &self.identity_sha256, &keyIdentity(self)))
            return error.InvalidProcessLocalPreprocessedAuthority;
    }
};

pub const CounterSnapshotV1 = struct {
    lookups: u64,
    hits: u64,
    misses: u64,
    full_rebuilds: u64,
    rejections: u64,
    evictions: u64,
    lookup_ns: u64,
    hit_validation_ns: u64,
    rebuild_ns: u64,
};

pub fn AuthorityV1(comptime Root: type) type {
    assertRootType(Root);
    return struct {
        key: KeyV1,
        root: Root,
        seal_sha256: [32]u8,

        const Self = @This();

        pub fn init(key: KeyV1, root: Root) Error!Self {
            try key.validate();
            if (rootIsZero(root))
                return error.InvalidProcessLocalPreprocessedAuthority;
            const result = Self{
                .key = key,
                .root = root,
                .seal_sha256 = authorityIdentity(Root, key, root),
            };
            try result.validateAgainst(&key, root);
            return result;
        }

        pub fn validateAgainst(
            self: *const Self,
            key: *const KeyV1,
            root: Root,
        ) Error!void {
            try key.validate();
            try self.key.validate();
            if (!std.meta.eql(self.key, key.*) or
                !std.meta.eql(self.root, root) or
                !std.mem.eql(
                    u8,
                    &self.seal_sha256,
                    &authorityIdentity(Root, self.key, self.root),
                )) return error.InvalidProcessLocalPreprocessedAuthority;
        }
    };
}

/// Single-entry cache per concrete verifier kernel. Holding the mutex through
/// the first rebuild prevents concurrent cold opens from duplicating the very
/// tree construction this cache removes. A failed rebuild never publishes or
/// replaces the prior authenticated entry.
pub fn CacheV1(comptime Root: type) type {
    const Authority = AuthorityV1(Root);
    return struct {
        mutex: std.Thread.Mutex = .{},
        authority: ?Authority = null,
        lookups: u64 = 0,
        hits: u64 = 0,
        misses: u64 = 0,
        full_rebuilds: u64 = 0,
        rejections: u64 = 0,
        evictions: u64 = 0,
        lookup_ns: u64 = 0,
        hit_validation_ns: u64 = 0,
        rebuild_ns: u64 = 0,

        const Self = @This();

        pub fn ensure(
            self: *Self,
            key: KeyV1,
            root: Root,
            context: anytype,
            comptime rebuildAndValidate: anytype,
        ) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            var lookup_timer = std.time.Timer.start() catch null;
            defer self.lookup_ns +%= timerRead(&lookup_timer);
            self.lookups +%= 1;
            key.validate() catch |err| {
                self.rejections +%= 1;
                return err;
            };
            if (self.authority) |*authority| {
                if (std.meta.eql(authority.key, key)) {
                    var hit_timer = std.time.Timer.start() catch null;
                    authority.validateAgainst(&key, root) catch |err| {
                        self.rejections +%= 1;
                        return err;
                    };
                    self.hit_validation_ns +%= timerRead(&hit_timer);
                    self.hits +%= 1;
                    return;
                }
            }
            self.misses +%= 1;
            var rebuild_timer = std.time.Timer.start() catch null;
            rebuildAndValidate(context) catch |err| {
                self.rejections +%= 1;
                return err;
            };
            const admitted = Authority.init(key, root) catch |err| {
                self.rejections +%= 1;
                return err;
            };
            if (self.authority != null) self.evictions +%= 1;
            self.authority = admitted;
            self.full_rebuilds +%= 1;
            self.rebuild_ns +%= timerRead(&rebuild_timer);
        }

        pub fn snapshot(self: *const Self) CounterSnapshotV1 {
            const mutable = @constCast(self);
            mutable.mutex.lock();
            defer mutable.mutex.unlock();
            return .{
                .lookups = mutable.lookups,
                .hits = mutable.hits,
                .misses = mutable.misses,
                .full_rebuilds = mutable.full_rebuilds,
                .rejections = mutable.rejections,
                .evictions = mutable.evictions,
                .lookup_ns = mutable.lookup_ns,
                .hit_validation_ns = mutable.hit_validation_ns,
                .rebuild_ns = mutable.rebuild_ns,
            };
        }
    };
}

fn timerRead(timer: *?std.time.Timer) u64 {
    if (timer.*) |*active| return active.read();
    return 0;
}

pub fn preprocessedIdentity(
    comptime Root: type,
    table_layout_identity_sha256: [32]u8,
    manifest_identity_sha256: [32]u8,
    root: Root,
) Error![32]u8 {
    assertRootType(Root);
    if (std.mem.allEqual(u8, &table_layout_identity_sha256, 0) or
        std.mem.allEqual(u8, &manifest_identity_sha256, 0) or
        rootIsZero(root))
    {
        return error.InvalidProcessLocalPreprocessedAuthority;
    }
    var hash = Sha256.init(.{});
    hash.update(PREPROCESSED_DOMAIN);
    hash.update(&table_layout_identity_sha256);
    hash.update(&manifest_identity_sha256);
    hashRoot(Root, &hash, root);
    return hash.finalResult();
}

fn keyIdentity(value: *const KeyV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(KEY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.circuit_identity_sha256);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.profile_identity_sha256);
    hash.update(&value.pcs_identity_sha256);
    hash.update(&value.padding_identity_sha256);
    hash.update(&value.preprocessed_identity_sha256);
    return hash.finalResult();
}

fn authorityIdentity(
    comptime Root: type,
    key: KeyV1,
    root: Root,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hash.update(&key.identity_sha256);
    hashRoot(Root, &hash, root);
    return hash.finalResult();
}

fn rootIsZero(root: anytype) bool {
    for (root) |word| if (word != 0) return false;
    return true;
}

fn hashRoot(comptime Root: type, hash: *Sha256, root: Root) void {
    assertRootType(Root);
    for (root) |word| hashInt(hash, u32, word);
}

fn assertRootType(comptime Root: type) void {
    switch (@typeInfo(Root)) {
        .array => |array| if (array.child != u32 or array.len == 0)
            @compileError("preprocessed cache root must be a nonempty [N]u32"),
        else => @compileError(
            "preprocessed cache root must be a nonempty [N]u32",
        ),
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    const RepresentativeAuthority = AuthorityV1([8]u32);
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        @hasDecl(KeyV1, "encode") or @hasDecl(KeyV1, "decode") or
        @hasDecl(RepresentativeAuthority, "encode") or
        @hasDecl(RepresentativeAuthority, "decode"))
    {
        @compileError("process-local preprocessed authority contract drifted");
    }
}
