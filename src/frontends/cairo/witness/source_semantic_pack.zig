//! Versioned, proof-independent Cairo source semantic authority.
//!
//! V3 authenticates source emitted by stwo-cairo's witness_genericize tool and
//! admits only proof-plan components present in the configured source catalog.
//! Dependencies are filtered to the plan's active component set. It does not
//! claim to be a full Cairo AIR/PIE program until the catalog covers that plan.

const std = @import("std");
const proof_plan = @import("../proof_plan.zig");

pub const format = "stwo-zig-cairo-source-semantic-pack";
pub const version: u32 = 3;
pub const registry_format = "stwo-zig-cairo-source-component-registry";
pub const registry_version: u32 = 1;
pub const identity_domain = "stwo-zig/cairo/source-semantic-pack/v3\x00";
pub const max_document_bytes: usize = 4 * 1024 * 1024;
pub const max_components: usize = 4096;

pub const AuthenticatedFile = struct {
    path: []const u8,
    sha256: [32]u8,
};

pub const ComponentFile = struct {
    name: []const u8,
    path: []const u8,
};

/// These paths are supplied by trusted process configuration, never by a PIE.
pub const Files = struct {
    manifest: AuthenticatedFile,
    registry: []const u8,
    components: []const ComponentFile,
};

pub const SourceIdentity = struct {
    repository: []const u8,
    revision: []const u8,
    tree: []const u8,
    stwo_binding_kind: []const u8,
    stwo_declared_revision: []const u8,
    stwo_resolved_revision: []const u8,
    stwo_resolved_tree: []const u8,
};

pub const ToolchainIdentity = struct {
    rustc: []const u8,
    cargo: []const u8,
    rustfmt: []const u8,
    source_cargo_lock_sha256: []const u8,
    generator_cargo_lock_sha256: []const u8,
    generator_sha256: []const u8,
};

pub const Manifest = struct {
    format: []const u8,
    version: u32,
    provenance: []const u8,
    source: SourceIdentity,
    toolchain: ToolchainIdentity,
    registry_sha256: []const u8,
    authority_sha256: []const u8,
};

pub const TracePartSpec = struct {
    kind: []const u8,
    index: ?u32 = null,
};

pub const ProducerEdgeSpec = struct {
    producer: []const u8,
    word_base: u32,
    words_per_instance: u32,
    instances: u32,
};

pub const CapacityFeedSpec = struct {
    producer: []const u8,
    instances: u32,
};

pub const OracleGeometry = struct {
    trace_columns: u32,
    lookup_words: u32,
    sub_input_words: u32,
};

pub const Component = struct {
    name: []const u8,
    canonical_ordinal: u32,
    writer: []const u8,
    trace_parts: []const TracePartSpec,
    producer_edges: []const ProducerEdgeSpec,
    capacity_feeds: []const CapacityFeedSpec,
    relation_outputs: []const []const u8,
    artifact_sha256: []const u8,
    oracle: OracleGeometry,
};

pub const Registry = struct {
    format: []const u8,
    version: u32,
    components: []const Component,
};

pub const Measurement = struct {
    sha256: [32]u8,
    stat: std.fs.File.Stat,
};

pub const Loaded = struct {
    allocator: std.mem.Allocator,
    files: Files,
    manifest: std.json.Parsed(Manifest),
    registry: std.json.Parsed(Registry),
    authority_sha256: [32]u8,
    registry_sha256: [32]u8,
    manifest_measurement: Measurement,
    registry_measurement: Measurement,
    component_measurements: []Measurement,

    pub fn deinit(self: *Loaded) void {
        self.allocator.free(self.component_measurements);
        self.registry.deinit();
        self.manifest.deinit();
        deinitFiles(self.allocator, self.files);
        self.* = undefined;
    }

    pub fn assertUnchanged(self: *const Loaded) !void {
        try assertMeasurement(self.files.manifest.path, self.manifest_measurement);
        try assertMeasurement(self.files.registry, self.registry_measurement);
        for (self.files.components, self.component_measurements) |file, expected|
            try assertMeasurement(file.path, expected);
    }

    /// Requires source authority for every active component and its closed
    /// active dependency graph. Row counts remain runtime execution geometry
    /// and are deliberately not selected by this registry.
    pub fn admitProofPlan(self: *const Loaded, plan: *const proof_plan.CairoProofPlan) !void {
        try self.assertUnchanged();
        for (plan.canonical_order, 0..) |component_index, ordinal| {
            const actual = plan.components[component_index];
            const expected = findRegistryComponent(self.registry.value, actual.name) orelse
                return error.ComponentSetMismatch;
            if (actual.canonical_ordinal != ordinal or
                !writerMatches(expected.writer, actual.writer) or
                !tracePartsMatch(expected.trace_parts, actual.trace_parts) or
                !producerEdgesMatch(expected.producer_edges, actual.producer_edges, plan) or
                !capacityFeedsMatch(expected.capacity_feeds, actual.capacity_feeds, plan))
                return error.ComponentAuthorityMismatch;
        }
        try self.assertUnchanged();
    }
};

pub fn load(allocator: std.mem.Allocator, files: Files) !Loaded {
    try validateFiles(files);
    const owned_files = try cloneFiles(allocator, files);
    errdefer deinitFiles(allocator, owned_files);
    const manifest_measurement = try authenticateFile(owned_files.manifest.path, owned_files.manifest.sha256);
    const manifest_bytes = try readSmallFile(allocator, owned_files.manifest.path);
    defer allocator.free(manifest_bytes);
    var manifest = try std.json.parseFromSlice(Manifest, allocator, manifest_bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer manifest.deinit();
    try validateManifest(manifest.value);

    const registry_sha256 = try parseDigest(manifest.value.registry_sha256);
    const registry_measurement = try authenticateFile(owned_files.registry, registry_sha256);
    const registry_bytes = try readSmallFile(allocator, owned_files.registry);
    defer allocator.free(registry_bytes);
    var registry = try std.json.parseFromSlice(Registry, allocator, registry_bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer registry.deinit();
    try validateRegistry(allocator, registry.value, owned_files);

    const component_measurements = try allocator.alloc(Measurement, owned_files.components.len);
    errdefer allocator.free(component_measurements);
    for (registry.value.components, owned_files.components, component_measurements) |component, file, *measurement| {
        measurement.* = try authenticateFile(file.path, try parseDigest(component.artifact_sha256));
    }

    const authority_sha256 = canonicalIdentity(manifest.value, registry_sha256) catch
        return error.InvalidAuthorityIdentity;
    if (!std.mem.eql(u8, &authority_sha256, &(try parseDigest(manifest.value.authority_sha256))))
        return error.AuthorityIdentityMismatch;

    var loaded = Loaded{
        .allocator = allocator,
        .files = owned_files,
        .manifest = manifest,
        .registry = registry,
        .authority_sha256 = authority_sha256,
        .registry_sha256 = registry_sha256,
        .manifest_measurement = manifest_measurement,
        .registry_measurement = registry_measurement,
        .component_measurements = component_measurements,
    };
    try loaded.assertUnchanged();
    return loaded;
}

/// Loads a configured source catalog without requiring callers to duplicate its
/// authenticated component list. Registry bytes select only paths below the
/// supplied absolute directory; `load` re-authenticates the complete closure.
pub fn loadDirectory(
    allocator: std.mem.Allocator,
    manifest_file: AuthenticatedFile,
    directory: []const u8,
) !Loaded {
    if (!std.fs.path.isAbsolute(directory) or
        !std.fs.path.isAbsolute(manifest_file.path))
        return error.ArtifactPathNotAbsolute;
    const expected_manifest = try std.fs.path.join(allocator, &.{ directory, "manifest.json" });
    defer allocator.free(expected_manifest);
    if (!std.mem.eql(u8, expected_manifest, manifest_file.path))
        return error.ArtifactPathOutsideDirectory;

    _ = try authenticateFile(manifest_file.path, manifest_file.sha256);
    const manifest_bytes = try readSmallFile(allocator, manifest_file.path);
    defer allocator.free(manifest_bytes);
    var manifest = try std.json.parseFromSlice(Manifest, allocator, manifest_bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer manifest.deinit();
    try validateManifest(manifest.value);

    const registry_path = try std.fs.path.join(allocator, &.{ directory, "registry.json" });
    defer allocator.free(registry_path);
    _ = try authenticateFile(
        registry_path,
        try parseDigest(manifest.value.registry_sha256),
    );
    const registry_bytes = try readSmallFile(allocator, registry_path);
    defer allocator.free(registry_bytes);
    var registry = try std.json.parseFromSlice(Registry, allocator, registry_bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer registry.deinit();
    if (!std.mem.eql(u8, registry.value.format, registry_format) or
        registry.value.version != registry_version)
        return error.UnsupportedSourceRegistry;
    if (registry.value.components.len == 0 or
        registry.value.components.len > max_components)
        return error.ComponentSetMismatch;

    const component_files = try allocator.alloc(
        ComponentFile,
        registry.value.components.len,
    );
    var initialized: usize = 0;
    defer {
        for (component_files[0..initialized]) |component| allocator.free(component.path);
        allocator.free(component_files);
    }
    while (initialized < component_files.len) : (initialized += 1) {
        const component = registry.value.components[initialized];
        try validateComponentName(component.name);
        const filename = try std.fmt.allocPrint(allocator, "{s}.rs", .{component.name});
        defer allocator.free(filename);
        component_files[initialized] = .{
            .name = component.name,
            .path = try std.fs.path.join(
                allocator,
                &.{ directory, "components", filename },
            ),
        };
    }
    return load(allocator, .{
        .manifest = manifest_file,
        .registry = registry_path,
        .components = component_files,
    });
}

pub fn canonicalIdentity(manifest: Manifest, registry_sha256: [32]u8) ![32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(identity_domain);
    var integer: [8]u8 = undefined;
    std.mem.writeInt(u32, integer[0..4], version, .little);
    hasher.update(integer[0..4]);
    try hashString(&hasher, &integer, manifest.source.repository);
    try hashString(&hasher, &integer, manifest.source.revision);
    try hashString(&hasher, &integer, manifest.source.tree);
    try hashString(&hasher, &integer, manifest.source.stwo_binding_kind);
    try hashString(&hasher, &integer, manifest.source.stwo_declared_revision);
    try hashString(&hasher, &integer, manifest.source.stwo_resolved_revision);
    try hashString(&hasher, &integer, manifest.source.stwo_resolved_tree);
    try hashString(&hasher, &integer, manifest.toolchain.rustc);
    try hashString(&hasher, &integer, manifest.toolchain.cargo);
    try hashString(&hasher, &integer, manifest.toolchain.rustfmt);
    hasher.update(&(try parseDigest(manifest.toolchain.source_cargo_lock_sha256)));
    hasher.update(&(try parseDigest(manifest.toolchain.generator_cargo_lock_sha256)));
    hasher.update(&(try parseDigest(manifest.toolchain.generator_sha256)));
    hasher.update(&registry_sha256);
    return hasher.finalResult();
}

fn validateManifest(manifest: Manifest) !void {
    if (!std.mem.eql(u8, manifest.format, format) or manifest.version != version)
        return error.UnsupportedSourceSemanticPack;
    if (!std.mem.eql(u8, manifest.provenance, "source-derived"))
        return error.ProofDerivedAuthorityRejected;
    if (manifest.source.repository.len == 0 or
        !std.mem.eql(
            u8,
            manifest.source.stwo_binding_kind,
            "clean_local_path_patch",
        ) or manifest.toolchain.rustc.len == 0 or
        manifest.toolchain.cargo.len == 0 or manifest.toolchain.rustfmt.len == 0)
        return error.InvalidSourceIdentity;
    try validateRevision(manifest.source.revision);
    try validateRevision(manifest.source.tree);
    try validateRevision(manifest.source.stwo_declared_revision);
    try validateRevision(manifest.source.stwo_resolved_revision);
    try validateRevision(manifest.source.stwo_resolved_tree);
    _ = try parseDigest(manifest.toolchain.source_cargo_lock_sha256);
    _ = try parseDigest(manifest.toolchain.generator_cargo_lock_sha256);
    _ = try parseDigest(manifest.toolchain.generator_sha256);
    _ = try parseDigest(manifest.registry_sha256);
    _ = try parseDigest(manifest.authority_sha256);
}

fn validateRegistry(allocator: std.mem.Allocator, registry: Registry, files: Files) !void {
    if (!std.mem.eql(u8, registry.format, registry_format) or registry.version != registry_version)
        return error.UnsupportedSourceRegistry;
    if (registry.components.len == 0 or registry.components.len > max_components or
        registry.components.len != files.components.len)
        return error.ComponentSetMismatch;
    for (registry.components, 0..) |component, ordinal| {
        validateComponentName(component.name) catch return error.NonCanonicalRegistry;
        if (component.canonical_ordinal != ordinal or
            !std.mem.eql(u8, component.name, files.components[ordinal].name))
            return error.NonCanonicalRegistry;
        if (component.trace_parts.len == 0 or component.oracle.trace_columns == 0)
            return error.InvalidComponentOracle;
        _ = try parseDigest(component.artifact_sha256);
        for (registry.components[0..ordinal]) |prior|
            if (std.mem.eql(u8, prior.name, component.name)) return error.DuplicateComponent;
        for (component.producer_edges) |edge| {
            if (edge.words_per_instance == 0 or edge.instances == 0 or
                !registryContains(registry, edge.producer))
                return error.DanglingRegistryDependency;
        }
        for (component.capacity_feeds) |feed| {
            if (feed.instances == 0 or !registryContains(registry, feed.producer))
                return error.DanglingRegistryDependency;
        }
        for (component.trace_parts) |part| {
            if (!std.mem.eql(u8, part.kind, "main") and
                !std.mem.eql(u8, part.kind, "memory_small") and
                !std.mem.eql(u8, part.kind, "memory_big"))
                return error.InvalidTracePart;
            if (std.mem.eql(u8, part.kind, "memory_big") != (part.index != null))
                return error.InvalidTracePart;
        }
    }
    try validateRegistryAcyclic(allocator, registry);
}

fn registryContains(registry: Registry, name: []const u8) bool {
    for (registry.components) |component|
        if (std.mem.eql(u8, component.name, name)) return true;
    return false;
}

fn validateRegistryAcyclic(allocator: std.mem.Allocator, registry: Registry) !void {
    const indegrees = try allocator.alloc(usize, registry.components.len);
    defer allocator.free(indegrees);
    @memset(indegrees, 0);
    const removed = try allocator.alloc(bool, registry.components.len);
    defer allocator.free(removed);
    @memset(removed, false);
    for (registry.components, indegrees) |component, *indegree| {
        indegree.* = component.producer_edges.len + component.capacity_feeds.len;
    }

    var removed_count: usize = 0;
    while (removed_count < registry.components.len) {
        const producer_index = for (indegrees, removed, 0..) |indegree, was_removed, index| {
            if (!was_removed and indegree == 0) break index;
        } else return error.CyclicRegistryDependency;
        removed[producer_index] = true;
        removed_count += 1;
        const producer = registry.components[producer_index].name;
        for (registry.components, indegrees, removed) |consumer, *indegree, was_removed| {
            if (was_removed) continue;
            for (consumer.producer_edges) |edge| {
                if (std.mem.eql(u8, edge.producer, producer)) indegree.* -= 1;
            }
            for (consumer.capacity_feeds) |feed| {
                if (std.mem.eql(u8, feed.producer, producer)) indegree.* -= 1;
            }
        }
    }
}

fn writerMatches(expected: []const u8, actual: proof_plan.WriterKind) bool {
    const parsed = std.meta.stringToEnum(proof_plan.WriterKind, expected) orelse return false;
    return parsed == actual;
}

fn tracePartsMatch(expected: []const TracePartSpec, actual: []const proof_plan.TracePart) bool {
    if (expected.len != actual.len) return false;
    for (expected, actual) |left, right| {
        if (std.mem.eql(u8, left.kind, "main")) {
            if (right.id != .main or left.index != null) return false;
        } else if (std.mem.eql(u8, left.kind, "memory_small")) {
            if (right.id != .memory_small or left.index != null) return false;
        } else if (std.mem.eql(u8, left.kind, "memory_big")) {
            if (right.id != .memory_big or right.id.memory_big != left.index.?) return false;
        } else return false;
    }
    return true;
}

fn findRegistryComponent(registry: Registry, name: []const u8) ?Component {
    for (registry.components) |component|
        if (std.mem.eql(u8, component.name, name)) return component;
    return null;
}

fn producerEdgesMatch(
    expected: []const ProducerEdgeSpec,
    actual: []const proof_plan.ProducerEdge,
    plan: *const proof_plan.CairoProofPlan,
) bool {
    var actual_index: usize = 0;
    for (expected) |left| {
        if (plan.find(left.producer) == null) continue;
        if (actual_index == actual.len) return false;
        const right = actual[actual_index];
        if (!std.mem.eql(u8, left.producer, right.producer) or
            left.word_base != right.word_base or
            left.words_per_instance != right.words_per_instance or
            left.instances != right.instances) return false;
        actual_index += 1;
    }
    return actual_index == actual.len;
}

fn capacityFeedsMatch(
    expected: []const CapacityFeedSpec,
    actual: []const proof_plan.CapacityFeed,
    plan: *const proof_plan.CairoProofPlan,
) bool {
    var actual_index: usize = 0;
    for (expected) |left| {
        if (plan.find(left.producer) == null) continue;
        if (actual_index == actual.len) return false;
        const right = actual[actual_index];
        if (!std.mem.eql(u8, left.producer, right.producer) or
            left.instances != right.instances) return false;
        actual_index += 1;
    }
    return actual_index == actual.len;
}

fn validateFiles(files: Files) !void {
    if (!std.fs.path.isAbsolute(files.manifest.path) or !std.fs.path.isAbsolute(files.registry))
        return error.ArtifactPathNotAbsolute;
    for (files.components) |file|
        if (file.name.len == 0 or !std.fs.path.isAbsolute(file.path))
            return error.ArtifactPathNotAbsolute;
}

fn cloneFiles(allocator: std.mem.Allocator, source: Files) !Files {
    const manifest_path = try allocator.dupe(u8, source.manifest.path);
    errdefer allocator.free(manifest_path);
    const registry_path = try allocator.dupe(u8, source.registry);
    errdefer allocator.free(registry_path);
    const components = try allocator.alloc(ComponentFile, source.components.len);
    var initialized: usize = 0;
    errdefer {
        for (components[0..initialized]) |component| {
            allocator.free(component.name);
            allocator.free(component.path);
        }
        allocator.free(components);
    }
    while (initialized < components.len) : (initialized += 1) {
        const name = try allocator.dupe(u8, source.components[initialized].name);
        errdefer allocator.free(name);
        components[initialized] = .{
            .name = name,
            .path = try allocator.dupe(u8, source.components[initialized].path),
        };
    }
    return .{
        .manifest = .{ .path = manifest_path, .sha256 = source.manifest.sha256 },
        .registry = registry_path,
        .components = components,
    };
}

fn deinitFiles(allocator: std.mem.Allocator, files: Files) void {
    allocator.free(files.manifest.path);
    allocator.free(files.registry);
    for (files.components) |component| {
        allocator.free(component.name);
        allocator.free(component.path);
    }
    allocator.free(files.components);
}

fn validateRevision(value: []const u8) !void {
    if (value.len != 40) return error.InvalidSourceIdentity;
    for (value) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidSourceIdentity,
    };
}

fn validateComponentName(value: []const u8) !void {
    if (value.len == 0) return error.InvalidComponentName;
    for (value, 0..) |byte, index| switch (byte) {
        'a'...'z' => {},
        '0'...'9', '_' => if (index == 0) return error.InvalidComponentName,
        else => return error.InvalidComponentName,
    };
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    for (value) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidDigest,
    };
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, value) catch return error.InvalidDigest;
    return digest;
}

fn hashString(hasher: anytype, buffer: *[8]u8, value: []const u8) !void {
    std.mem.writeInt(u64, buffer, std.math.cast(u64, value.len) orelse return error.IdentityOverflow, .little);
    hasher.update(buffer);
    hasher.update(value);
}

fn authenticateFile(path: []const u8, expected: [32]u8) !Measurement {
    const measured = try measureFile(path);
    if (!std.mem.eql(u8, &measured.sha256, &expected)) return error.ArtifactDigestMismatch;
    return measured;
}

fn measureFile(path: []const u8) !Measurement {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0) return error.InvalidArtifactFile;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var count: u64 = 0;
    while (true) {
        const read = try file.read(&buffer);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        count = std.math.add(u64, count, read) catch return error.ArtifactLengthOverflow;
    }
    const after = try file.stat();
    if (!sameFile(before, after) or count != before.size) return error.ArtifactChangedDuringRead;
    return .{ .sha256 = hasher.finalResult(), .stat = after };
}

fn readSmallFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size == 0 or stat.size > max_document_bytes)
        return error.InvalidDocumentFile;
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.TruncatedDocument;
    return bytes;
}

fn assertMeasurement(path: []const u8, expected: Measurement) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    if (!sameFile(expected.stat, try file.stat()))
        return error.ArtifactChangedAfterAuthentication;
}

fn sameFile(left: std.fs.File.Stat, right: std.fs.File.Stat) bool {
    return left.kind == right.kind and left.inode == right.inode and left.size == right.size and
        left.mtime == right.mtime and left.ctime == right.ctime;
}

test "source-derived catalog matches Rust oracle and admits a closed active subset" {
    const allocator = std.testing.allocator;
    const directory = try std.fs.cwd().realpathAlloc(
        allocator,
        "vectors/cairo/source_semantics/v3",
    );
    defer allocator.free(directory);
    const manifest_path = try std.fs.cwd().realpathAlloc(
        allocator,
        "vectors/cairo/source_semantics/v3/manifest.json",
    );
    defer allocator.free(manifest_path);
    var loaded = try loadDirectory(
        allocator,
        .{
            .path = manifest_path,
            .sha256 = try parseDigest("cfbeff3da13461d0d9cf2df2a215d951df713698db18036f4882ddf1f857bd3a"),
        },
        directory,
    );
    defer loaded.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &(try parseDigest("f7ce36fc9540d972b5ad2e1d4572663f3d159aefdf7552c036d1cbbb6e956b61")),
        &loaded.authority_sha256,
    );
    try std.testing.expectEqual(@as(usize, 35), loaded.registry.value.components.len);
    const add_opcode_small = findRegistryComponent(
        loaded.registry.value,
        "add_opcode_small",
    ).?;
    const oracle = add_opcode_small.oracle;
    try std.testing.expectEqual(@as(u32, 39), oracle.trace_columns);
    try std.testing.expectEqual(@as(u32, 117), oracle.lookup_words);
    try std.testing.expectEqual(@as(u32, 13), oracle.sub_input_words);
    const expected_outputs = [_][]const u8{
        "verify_instruction",
        "memory_address_to_id",
        "memory_id_to_big",
    };
    const actual_outputs = add_opcode_small.relation_outputs;
    try std.testing.expectEqual(expected_outputs.len, actual_outputs.len);
    for (expected_outputs, actual_outputs) |expected, actual|
        try std.testing.expectEqualStrings(expected, actual);

    const parts = [_]proof_plan.TracePart{.{
        .id = .main,
        .rows = .{ .real_rows = 16, .padded_rows = 16 },
    }};
    const components = [_]proof_plan.Component{.{
        .name = "add_opcode_small",
        .canonical_ordinal = 0,
        .writer = .recorded_aot,
        .trace_parts = &parts,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    }};
    var plan = try proof_plan.CairoProofPlan.init(allocator, &components);
    defer plan.deinit();
    try loaded.admitProofPlan(&plan);

    const verify_edges = [_]proof_plan.ProducerEdge{.{
        .producer = "add_opcode_small",
        .word_base = 0,
        .words_per_instance = 7,
        .instances = 1,
    }};
    const verify_feeds = [_]proof_plan.CapacityFeed{.{
        .producer = "add_opcode_small",
        .instances = 1,
    }};
    const closed_components = [_]proof_plan.Component{
        components[0],
        .{
            .name = "verify_instruction",
            .canonical_ordinal = 1,
            .writer = .recorded_aot,
            .trace_parts = &parts,
            .producer_edges = &verify_edges,
            .capacity_feeds = &verify_feeds,
        },
    };
    var closed_plan = try proof_plan.CairoProofPlan.init(allocator, &closed_components);
    defer closed_plan.deinit();
    try loaded.admitProofPlan(&closed_plan);

    var missing_edge_components = closed_components;
    missing_edge_components[1].producer_edges = &.{};
    var missing_edge_plan = try proof_plan.CairoProofPlan.init(
        allocator,
        &missing_edge_components,
    );
    defer missing_edge_plan.deinit();
    try std.testing.expectError(
        error.ComponentAuthorityMismatch,
        loaded.admitProofPlan(&missing_edge_plan),
    );

    const wrong_components = [_]proof_plan.Component{.{
        .name = "add_opcode_small",
        .canonical_ordinal = 0,
        .writer = .native_backend,
        .trace_parts = &parts,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    }};
    var wrong_plan = try proof_plan.CairoProofPlan.init(allocator, &wrong_components);
    defer wrong_plan.deinit();
    try std.testing.expectError(
        error.ComponentAuthorityMismatch,
        loaded.admitProofPlan(&wrong_plan),
    );

    const extra_components = [_]proof_plan.Component{
        components[0],
        .{
            .name = "proof_selected_extra",
            .canonical_ordinal = 1,
            .writer = .recorded_aot,
            .trace_parts = &parts,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
    };
    var extra_plan = try proof_plan.CairoProofPlan.init(allocator, &extra_components);
    defer extra_plan.deinit();
    try std.testing.expectError(
        error.ComponentSetMismatch,
        loaded.admitProofPlan(&extra_plan),
    );
}

test "source authority rejects proof-derived provenance and dangling registry closure" {
    const source = SourceIdentity{
        .repository = "https://github.com/teddyjfpender/stwo-cairo.git",
        .revision = "6a9c1c895b821eb5542843e7d9398e02e8f378d0",
        .tree = "17fbbfc61fc51e0697c4e1f3cd39885784a027f2",
        .stwo_binding_kind = "clean_local_path_patch",
        .stwo_declared_revision = "1dad88f1c3a714ac26c8ad57812429ac58541909",
        .stwo_resolved_revision = "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035",
        .stwo_resolved_tree = "55cbec6c408dfc4e81c722deca9f5526d3785536",
    };
    const toolchain = ToolchainIdentity{
        .rustc = "rustc pinned",
        .cargo = "cargo pinned",
        .rustfmt = "rustfmt pinned",
        .source_cargo_lock_sha256 = "f55a45ffc57dfedd0d093567b41af34ad9d2cdad78a17bac91e0d65559b0e8b4",
        .generator_cargo_lock_sha256 = "afc4f3bcf0bafd10c09b5dffc003cfd39d01d08441c3bc8e834d9a3e3f7f6ab3",
        .generator_sha256 = "723ed2ad3764c4206686c874599dec398842a02601f3876cba107944a59c2ebd",
    };
    try std.testing.expectError(error.ProofDerivedAuthorityRejected, validateManifest(.{
        .format = format,
        .version = version,
        .provenance = "proof-derived",
        .source = source,
        .toolchain = toolchain,
        .registry_sha256 = "655a8a923bfa92c9cc73ae5ec69e25cf89d65c654c9af4f64607410105f2bf3e",
        .authority_sha256 = "3f56921f75e4d16387b1a8747a231464b02e057f70cc156878098daf16714ed8",
    }));

    const files = [_]ComponentFile{.{ .name = "consumer", .path = "/not-opened" }};
    const components = [_]Component{.{
        .name = "consumer",
        .canonical_ordinal = 0,
        .writer = "recorded_aot",
        .trace_parts = &.{.{ .kind = "main" }},
        .producer_edges = &.{.{
            .producer = "missing",
            .word_base = 0,
            .words_per_instance = 1,
            .instances = 1,
        }},
        .capacity_feeds = &.{},
        .relation_outputs = &.{},
        .artifact_sha256 = "58c5a7742cbe7dfe72e889de3034fa7adf0a2696376b241eca4d1ea4885024a7",
        .oracle = .{ .trace_columns = 1, .lookup_words = 0, .sub_input_words = 0 },
    }};
    try std.testing.expectError(
        error.DanglingRegistryDependency,
        validateRegistry(std.testing.allocator, .{
            .format = registry_format,
            .version = registry_version,
            .components = &components,
        }, .{
            .manifest = .{ .path = "/not-opened", .sha256 = [_]u8{0} ** 32 },
            .registry = "/not-opened",
            .components = &files,
        }),
    );

    const cyclic_edges = [_]ProducerEdgeSpec{.{
        .producer = "consumer",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 1,
    }};
    var cyclic_components = components;
    cyclic_components[0].producer_edges = &cyclic_edges;
    try std.testing.expectError(
        error.CyclicRegistryDependency,
        validateRegistry(std.testing.allocator, .{
            .format = registry_format,
            .version = registry_version,
            .components = &cyclic_components,
        }, .{
            .manifest = .{ .path = "/not-opened", .sha256 = [_]u8{0} ** 32 },
            .registry = "/not-opened",
            .components = &files,
        }),
    );
}
