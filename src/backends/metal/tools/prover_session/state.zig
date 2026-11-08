//! Persistent prover-session configuration, evidence, caches, and request state.

const std = @import("std");
const stwo = @import("stwo");
const artifact_manifest = stwo.metal_session.artifact_manifest;
const artifact_store = stwo.metal_session.artifact_store;
const artifact_views = stwo.metal_session.artifact_views;
const metal_runtime = stwo.backends.metal.runtime;
const one_shot = @import("one_shot");
const protocol = stwo.metal_session.protocol;
const io = @import("io.zig");
const copyFileExclusive = io.copyFileExclusive;

pub const persistent_report_schema_version: u32 = 3;
pub const in_process_runner_linkage = "in_process";
pub const rust_verifier_adapter_version = "0.1.0";
pub const rust_verifier_envelope_abi = "STWZCVE/1";
pub const rust_verifier_mode = "compact_metal_proof_v1";
pub const rust_verifier_cargo_lock_sha256 = "72ee6a80235ff78a6e2c1724a8c6d1c45798c2a11c1c1539bc675af066b0e31c";
pub const rust_verifier_stwo_cairo_revision = "dcd5834565b7a26a27a614e353c9c60109ebc1d9";
pub const rust_verifier_stwo_revision = "9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2";

pub const PreparedGeometryKey = [32]u8;
pub const CompositionAotAdmissionKey = [32]u8;
pub const composition_aot_admission_capacity = 8;

pub const CompositionAotAdmissionCache = struct {
    entries: [composition_aot_admission_capacity]?CompositionAotAdmissionKey =
        [_]?CompositionAotAdmissionKey{null} ** composition_aot_admission_capacity,
    next_victim: usize = 0,

    pub fn contains(self: *const CompositionAotAdmissionCache, key: CompositionAotAdmissionKey) bool {
        for (self.entries) |entry| {
            const admitted = entry orelse continue;
            if (std.mem.eql(u8, &admitted, &key)) return true;
        }
        return false;
    }

    pub fn put(self: *CompositionAotAdmissionCache, key: CompositionAotAdmissionKey) void {
        if (self.contains(key)) return;
        self.entries[self.next_victim] = key;
        self.next_victim = (self.next_victim + 1) % self.entries.len;
    }
};

pub const RustVerifierConfig = struct {
    allocator: std.mem.Allocator,
    executable_path: []const u8,
    measurement: artifact_manifest.Measurement,
    executable_sha256: [64]u8,
    lockfile_path: []const u8,
    lockfile_measurement: artifact_manifest.Measurement,

    pub fn init(
        allocator: std.mem.Allocator,
        executable_path: []const u8,
        lockfile_path: []const u8,
        store_root: []const u8,
    ) !RustVerifierConfig {
        const source = try std.fs.realpathAlloc(allocator, executable_path);
        defer allocator.free(source);
        const source_measurement = try artifact_manifest.measureFile(allocator, source);
        const source_lockfile = try std.fs.realpathAlloc(allocator, lockfile_path);
        defer allocator.free(source_lockfile);
        const source_lockfile_measurement = try artifact_manifest.measureFile(allocator, source_lockfile);
        const lockfile_sha256 = std.fmt.bytesToHex(source_lockfile_measurement.sha256, .lower);
        if (!std.mem.eql(u8, &lockfile_sha256, rust_verifier_cargo_lock_sha256))
            return error.InvalidRustVerifierLockfile;
        const canonical = try std.fs.path.join(allocator, &.{ store_root, "rust-verifier-adapter" });
        errdefer allocator.free(canonical);
        const measurement = try copyFileExclusive(allocator, source, canonical, 0o500);
        errdefer std.fs.deleteFileAbsolute(canonical) catch {};
        if (measurement.bytes != source_measurement.bytes or
            !std.mem.eql(u8, &measurement.sha256, &source_measurement.sha256))
            return error.RustVerifierCopyMismatch;
        const canonical_lockfile = try std.fs.path.join(
            allocator,
            &.{ store_root, "rust-verifier.Cargo.lock" },
        );
        errdefer allocator.free(canonical_lockfile);
        const lockfile_measurement = try copyFileExclusive(
            allocator,
            source_lockfile,
            canonical_lockfile,
            0o400,
        );
        errdefer std.fs.deleteFileAbsolute(canonical_lockfile) catch {};
        if (lockfile_measurement.bytes != source_lockfile_measurement.bytes or
            !std.mem.eql(u8, &lockfile_measurement.sha256, &source_lockfile_measurement.sha256))
            return error.RustVerifierLockfileCopyMismatch;
        return .{
            .allocator = allocator,
            .executable_path = canonical,
            .measurement = measurement,
            .executable_sha256 = std.fmt.bytesToHex(measurement.sha256, .lower),
            .lockfile_path = canonical_lockfile,
            .lockfile_measurement = lockfile_measurement,
        };
    }

    pub fn deinit(self: *RustVerifierConfig) void {
        self.allocator.free(self.executable_path);
        self.allocator.free(self.lockfile_path);
        self.* = undefined;
    }

    pub fn assertUnchanged(self: RustVerifierConfig) !void {
        const current = try artifact_manifest.measureFile(self.allocator, self.executable_path);
        if (!current.identity.eql(self.measurement.identity) or
            !std.mem.eql(u8, &current.sha256, &self.measurement.sha256))
            return error.RustVerifierIdentityChanged;
        const current_lockfile = try artifact_manifest.measureFile(self.allocator, self.lockfile_path);
        if (!current_lockfile.identity.eql(self.lockfile_measurement.identity) or
            !std.mem.eql(u8, &current_lockfile.sha256, &self.lockfile_measurement.sha256))
            return error.RustVerifierLockfileChanged;
    }
};

pub const RustVerifierEvidence = struct {
    protocol_digest: [64]u8,
    statement_digest: [64]u8,
    proof_digest: [64]u8,
    provenance_digest: [64]u8,
    executable_sha256: [64]u8,
    wall_time_ns: u64,
    service_wall_time_ns: u64,
    result_sha256: [64]u8,

    pub fn jsonStringify(self: RustVerifierEvidence, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("schema_version");
        try writer.write(1);
        try writer.objectField("status");
        try writer.write("passed");
        try writer.objectField("verified");
        try writer.write(true);
        try writer.objectField("envelope_abi");
        try writer.write(rust_verifier_envelope_abi);
        try writer.objectField("adapter_version");
        try writer.write(rust_verifier_adapter_version);
        try writer.objectField("verification_mode");
        try writer.write(rust_verifier_mode);
        try writer.objectField("protocol_digest");
        try writer.write(&self.protocol_digest);
        try writer.objectField("statement_digest");
        try writer.write(&self.statement_digest);
        try writer.objectField("proof_digest");
        try writer.write(&self.proof_digest);
        try writer.objectField("provenance_digest");
        try writer.write(&self.provenance_digest);
        try writer.objectField("executable_sha256");
        try writer.write(&self.executable_sha256);
        try writer.objectField("cargo_lock_sha256");
        try writer.write(rust_verifier_cargo_lock_sha256);
        try writer.objectField("stwo_cairo_revision");
        try writer.write(rust_verifier_stwo_cairo_revision);
        try writer.objectField("stwo_revision");
        try writer.write(rust_verifier_stwo_revision);
        try writer.objectField("wall_time_ns");
        try writer.write(self.wall_time_ns);
        try writer.objectField("service_wall_time_ns");
        try writer.write(self.service_wall_time_ns);
        try writer.objectField("result_sha256");
        try writer.write(&self.result_sha256);
        try writer.endObject();
    }
};

pub const PreparedGeometryPolicy = struct {
    replay_retained_lookups: bool,
};

pub const prepared_host_geometry_capacity = 4;

pub const PreparedHostGeometryEntry = struct {
    key: PreparedGeometryKey,
    geometry: *one_shot.PreparedHostGeometry,
    last_used: u64,
};

pub const PreparedHostGeometryAcquire = struct {
    geometry: *const one_shot.PreparedHostGeometry,
    cache_hit: bool,
};

pub const PreparedHostGeometryTransaction = union(enum) {
    none,
    hit: u8,
    pending: struct {
        key: PreparedGeometryKey,
        geometry: *one_shot.PreparedHostGeometry,
    },
};

pub const PreparedHostGeometryCache = struct {
    allocator: std.mem.Allocator,
    entries: [prepared_host_geometry_capacity]?PreparedHostGeometryEntry =
        [_]?PreparedHostGeometryEntry{null} ** prepared_host_geometry_capacity,
    active: PreparedHostGeometryTransaction = .none,
    clock: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) PreparedHostGeometryCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PreparedHostGeometryCache) void {
        self.poison();
        for (&self.entries) |*entry| {
            if (entry.*) |value| value.geometry.deinit();
            entry.* = null;
        }
        self.* = undefined;
    }

    pub fn begin(
        self: *PreparedHostGeometryCache,
        key: PreparedGeometryKey,
        args: []const []const u8,
    ) !PreparedHostGeometryAcquire {
        if (self.active != .none) return error.PreparedHostGeometryAlreadyBorrowed;
        for (&self.entries, 0..) |*entry, index| {
            const value = if (entry.*) |*candidate| candidate else continue;
            if (!std.mem.eql(u8, &value.key, &key)) continue;
            const slot: u8 = @intCast(index);
            self.active = .{ .hit = slot };
            return .{ .geometry = value.geometry, .cache_hit = true };
        }
        const geometry = try one_shot.PreparedHostGeometry.init(self.allocator, args);
        self.active = .{ .pending = .{ .key = key, .geometry = geometry } };
        return .{ .geometry = geometry, .cache_hit = false };
    }

    pub fn commit(self: *PreparedHostGeometryCache) !void {
        try self.validateCommit();
        self.commitAssumeValid();
    }

    pub fn commitAssumeValid(self: *PreparedHostGeometryCache) void {
        switch (self.active) {
            .none => unreachable,
            .hit => |raw_index| {
                const index: usize = raw_index;
                self.clock = self.clock +| 1;
                self.entries[index].?.last_used = self.clock;
            },
            .pending => |pending| {
                const index = self.chooseVictim();
                if (self.entries[index]) |value| value.geometry.deinit();
                self.clock = self.clock +| 1;
                self.entries[index] = .{
                    .key = pending.key,
                    .geometry = pending.geometry,
                    .last_used = self.clock,
                };
            },
        }
        self.active = .none;
    }

    pub fn validateCommit(self: *const PreparedHostGeometryCache) !void {
        switch (self.active) {
            .none => return error.PreparedHostGeometryNotBorrowed,
            .hit => |raw_index| if (self.entries[raw_index] == null)
                return error.PreparedHostGeometryNotBorrowed,
            .pending => {},
        }
    }

    pub fn poison(self: *PreparedHostGeometryCache) void {
        switch (self.active) {
            .none, .hit => {},
            .pending => |pending| pending.geometry.deinit(),
        }
        self.active = .none;
    }

    pub fn chooseVictim(self: *const PreparedHostGeometryCache) usize {
        for (self.entries, 0..) |entry, index| if (entry == null) return index;
        var victim: usize = 0;
        for (self.entries[1..], 1..) |entry, index| {
            if (entry.?.last_used < self.entries[victim].?.last_used) victim = index;
        }
        return victim;
    }
};

pub extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
pub extern "c" fn unsetenv(name: [*:0]const u8) c_int;

pub const ProofResult = struct {
    adapted_cycles: u64,
    adapted_input_sha256: [64]u8,
    prove_wall_s: f64,
    prove_mhz: f64,
    session_block_wall_s: f64,
    proof_bytes: u64,
    proof_sha256: [64]u8,
    pipeline_cache_delta: metal_runtime.PipelineCacheStats,
    provenance: ProvenanceEvidence,
    executable_identity: ExecutableIdentity,
    artifact_objects: ArtifactObjectsEvidence,
    prepared_state_cache_hit: bool,
    rust_verifier: RustVerifierEvidence,
};

pub const ArtifactObjectEvidence = struct {
    object_id: [32]u8,
    bytes: u64,
    diagnostic_path: []const u8,

    pub fn jsonStringify(self: ArtifactObjectEvidence, writer: anytype) !void {
        const digest_hex = std.fmt.bytesToHex(self.object_id, .lower);
        try writer.beginObject();
        try writer.objectField("object_id");
        try writer.write(&digest_hex);
        try writer.objectField("bytes");
        try writer.write(self.bytes);
        try writer.objectField("diagnostic_path");
        try writer.write(self.diagnostic_path);
        try writer.endObject();
    }
};

pub const ArtifactObjectsEvidence = struct {
    adapted_input: ArtifactObjectEvidence,
    schedule: ArtifactObjectEvidence,
    witness_programs: ArtifactObjectEvidence,
    multiplicity_feeds: ArtifactObjectEvidence,
    relation_templates: ArtifactObjectEvidence,
    fixed_tables: ArtifactObjectEvidence,
    composition: ArtifactObjectEvidence,
    composition_program: ArtifactObjectEvidence,
    preprocessed_evaluations: ArtifactObjectEvidence,
    preprocessed_tree0_merkle: ArtifactObjectEvidence,
    preprocessed_coefficients: ArtifactObjectEvidence,
    transcript_reference: ?ArtifactObjectEvidence,
    quotient_reference: ?ArtifactObjectEvidence,

    pub fn jsonStringify(self: ArtifactObjectsEvidence, writer: anytype) !void {
        try writer.beginObject();
        inline for (.{
            "adapted_input",
            "schedule",
            "witness_programs",
            "multiplicity_feeds",
            "relation_templates",
            "fixed_tables",
            "composition",
            "composition_program",
            "preprocessed_evaluations",
            "preprocessed_tree0_merkle",
            "preprocessed_coefficients",
        }) |name| {
            try writer.objectField(name);
            try writer.write(@field(self, name));
        }
        if (self.transcript_reference) |value| {
            try writer.objectField("transcript_reference");
            try writer.write(value);
        }
        if (self.quotient_reference) |value| {
            try writer.objectField("quotient_reference");
            try writer.write(value);
        }
        try writer.endObject();
    }
};

pub const ExecutableIdentity = struct {
    // Content measurement only. Deployment policy must separately decide which
    // executable digest is authorized to serve production requests.
    daemon_executable_sha256: [64]u8,
    runner_executable_sha256: [64]u8,
    measurement: artifact_manifest.Measurement = undefined,
};

pub const ProvenanceEvidence = struct {
    self_contained: bool,
    parity_fixture_used: bool,
    proof_derived_artifact_used: bool,
    statement_self_derived: bool,
    artifact_manifest_digest: ?[64]u8,
    provenance_complete: bool,

    pub fn failClosed() ProvenanceEvidence {
        return .{
            .self_contained = false,
            .parity_fixture_used = true,
            .proof_derived_artifact_used = true,
            .statement_self_derived = false,
            .artifact_manifest_digest = null,
            .provenance_complete = false,
        };
    }
};

pub const EnvironmentValue = struct {
    name: []const u8,
    value: []const u8,
};

pub const VerifierScratch = struct {
    allocator: std.mem.Allocator,
    root: []const u8,
    proof: []const u8,
    statement: []const u8,
    runner_report: []const u8,
    envelope: []const u8,
    result: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        store_root: []const u8,
        sequence: u64,
    ) !VerifierScratch {
        var nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
        const root = try std.fmt.allocPrint(
            allocator,
            "{s}/verify-{}-{s}",
            .{ store_root, sequence, &nonce_hex },
        );
        errdefer allocator.free(root);
        try std.posix.mkdir(root, 0o700);
        errdefer std.fs.deleteTreeAbsolute(root) catch {};
        var directory = try std.fs.openDirAbsolute(root, .{ .no_follow = true });
        defer directory.close();
        try directory.chmod(0o700);

        const proof = try std.fs.path.join(allocator, &.{ root, "proof.bin" });
        errdefer allocator.free(proof);
        const statement = try std.fs.path.join(allocator, &.{ root, "statement.bin" });
        errdefer allocator.free(statement);
        const runner_report = try std.fs.path.join(allocator, &.{ root, "runner-report.json" });
        errdefer allocator.free(runner_report);
        const envelope = try std.fs.path.join(allocator, &.{ root, "proof.stwzcve" });
        errdefer allocator.free(envelope);
        const result = try std.fs.path.join(allocator, &.{ root, "verifier-result.json" });
        errdefer allocator.free(result);
        return .{
            .allocator = allocator,
            .root = root,
            .proof = proof,
            .statement = statement,
            .runner_report = runner_report,
            .envelope = envelope,
            .result = result,
        };
    }

    pub fn deinit(self: *VerifierScratch) void {
        std.fs.deleteTreeAbsolute(self.root) catch {};
        self.allocator.free(self.proof);
        self.allocator.free(self.statement);
        self.allocator.free(self.runner_report);
        self.allocator.free(self.envelope);
        self.allocator.free(self.result);
        self.allocator.free(self.root);
        self.* = undefined;
    }
};

pub const ArtifactSlot = enum {
    adapted_input,
    schedule,
    witness_programs,
    multiplicity_feeds,
    relation_templates,
    fixed_tables,
    composition,
    composition_program,
    preprocessed_evaluations,
    preprocessed_tree0_merkle,
    preprocessed_coefficients,
    transcript_reference,
    quotient_reference,
};

pub const artifact_slot_count = std.meta.fields(ArtifactSlot).len;

pub const PreparedArtifacts = struct {
    snapshots: [artifact_slot_count]?artifact_store.Snapshot = .{null} ** artifact_slot_count,
    view: ?*const artifact_views.View = null,
    entries: [artifact_slot_count + 1]artifact_manifest.Entry = undefined,
    entry_count: usize = 0,
    tree0_root_hex: [64]u8 = undefined,

    pub fn deinit(self: *PreparedArtifacts, allocator: std.mem.Allocator) void {
        for (&self.snapshots) |*optional_snapshot|
            if (optional_snapshot.*) |*stored| stored.deinit(allocator);
        self.* = undefined;
    }

    pub fn snapshot(self: *const PreparedArtifacts, slot: ArtifactSlot) *const artifact_store.Snapshot {
        return &self.snapshots[@intFromEnum(slot)].?;
    }

    pub fn addSnapshot(
        self: *PreparedArtifacts,
        store: *artifact_store.Store,
        slot: ArtifactSlot,
        role: artifact_manifest.Role,
        reference: protocol.ArtifactRef,
        provenance: artifact_manifest.Provenance,
        policy: artifact_store.IngestPolicy,
    ) !void {
        const index = @intFromEnum(slot);
        if (self.snapshots[index] != null) return error.DuplicateArtifactSlot;
        self.snapshots[index] = switch (reference) {
            .path => |path| try store.ingestPathWithPolicy(path, policy),
            .object => |object| try store.resolveRef(.{
                .object_id = try parseObjectId(object.object_id),
                .bytes = object.bytes,
            }),
        };
        const snapshot_value = self.snapshots[index].?;
        self.entries[self.entry_count] = .{
            .role = role,
            .format_version = 1,
            .provenance = provenance,
            .measurement = snapshot_value.measurement,
            .source_chain_complete = false,
        };
        self.entry_count += 1;
    }

    pub fn runnerArtifacts(self: *const PreparedArtifacts) RunnerArtifacts {
        return .{
            .adapted_input = self.snapshot(.adapted_input).path,
            .schedule = self.snapshot(.schedule).path,
            .witness_programs = self.snapshot(.witness_programs).path,
            .multiplicity_feeds = self.snapshot(.multiplicity_feeds).path,
            .relation_templates = self.snapshot(.relation_templates).path,
            .fixed_tables = self.snapshot(.fixed_tables).path,
            .composition = self.view.?.composition,
            .composition_program = self.view.?.composition_program,
            .preprocessed_evaluations = self.view.?.preprocessed_evaluations,
            .preprocessed_tree0_merkle = self.view.?.preprocessed_tree0_merkle,
            .preprocessed_coefficients = self.snapshot(.preprocessed_coefficients).path,
            .transcript_reference = if (self.snapshots[@intFromEnum(ArtifactSlot.transcript_reference)]) |snapshot_value|
                snapshot_value.path
            else
                null,
            .quotient_reference = if (self.snapshots[@intFromEnum(ArtifactSlot.quotient_reference)]) |snapshot_value|
                snapshot_value.path
            else
                null,
        };
    }

    pub fn objectEvidence(
        self: *const PreparedArtifacts,
        slot: ArtifactSlot,
        reference: protocol.ArtifactRef,
    ) ArtifactObjectEvidence {
        const stored = self.snapshot(slot);
        return .{
            .object_id = stored.object_id,
            .bytes = stored.measurement.bytes,
            .diagnostic_path = reference.diagnosticPath(),
        };
    }

    pub fn objectEvidenceOptional(
        self: *const PreparedArtifacts,
        slot: ArtifactSlot,
        reference: ?protocol.ArtifactRef,
    ) ?ArtifactObjectEvidence {
        return if (reference) |value| self.objectEvidence(slot, value) else null;
    }

    pub fn artifactObjects(
        self: *const PreparedArtifacts,
        artifacts: protocol.Artifacts,
    ) ArtifactObjectsEvidence {
        return .{
            .adapted_input = self.objectEvidence(.adapted_input, artifacts.adapted_input),
            .schedule = self.objectEvidence(.schedule, artifacts.schedule),
            .witness_programs = self.objectEvidence(.witness_programs, artifacts.witness_programs),
            .multiplicity_feeds = self.objectEvidence(.multiplicity_feeds, artifacts.multiplicity_feeds),
            .relation_templates = self.objectEvidence(.relation_templates, artifacts.relation_templates),
            .fixed_tables = self.objectEvidence(.fixed_tables, artifacts.fixed_tables),
            .composition = self.objectEvidence(.composition, artifacts.composition),
            .composition_program = self.objectEvidence(.composition_program, artifacts.composition_program),
            .preprocessed_evaluations = self.objectEvidence(.preprocessed_evaluations, artifacts.preprocessed_evaluations),
            .preprocessed_tree0_merkle = self.objectEvidence(.preprocessed_tree0_merkle, artifacts.preprocessed_tree0_merkle),
            .preprocessed_coefficients = self.objectEvidence(.preprocessed_coefficients, artifacts.preprocessed_coefficients),
            .transcript_reference = self.objectEvidenceOptional(.transcript_reference, artifacts.transcript_reference),
            .quotient_reference = self.objectEvidenceOptional(.quotient_reference, artifacts.quotient_reference),
        };
    }
};

pub const RunnerArtifacts = struct {
    adapted_input: []const u8,
    schedule: []const u8,
    witness_programs: []const u8,
    multiplicity_feeds: []const u8,
    relation_templates: []const u8,
    fixed_tables: []const u8,
    composition: []const u8,
    composition_program: []const u8,
    preprocessed_evaluations: []const u8,
    preprocessed_tree0_merkle: []const u8,
    preprocessed_coefficients: []const u8,
    transcript_reference: ?[]const u8,
    quotient_reference: ?[]const u8,
};

pub const RunnerRequest = struct {
    sequence: u64,
    request_id: []const u8,
    artifacts: RunnerArtifacts,
    proof_output: []const u8,
    report_output: []const u8,
    budget_gib: []const u8,
    tree0_root_hex: []const u8,
};

pub const ViewKey = struct {
    preprocessed_evaluations: [32]u8,
    preprocessed_tree0_merkle: [32]u8,
    composition: [32]u8,
    composition_program: [32]u8,
    composition_program_kind: u8,
};

pub const ViewCache = struct {
    allocator: std.mem.Allocator,
    views: std.AutoHashMap(ViewKey, artifact_views.View),

    pub fn init(allocator: std.mem.Allocator) ViewCache {
        return .{
            .allocator = allocator,
            .views = std.AutoHashMap(ViewKey, artifact_views.View).init(allocator),
        };
    }

    pub fn deinit(self: *ViewCache) void {
        var iterator = self.views.valueIterator();
        while (iterator.next()) |view| view.deinit(self.allocator);
        self.views.deinit();
        self.* = undefined;
    }

    pub fn getOrCreate(
        self: *ViewCache,
        parent_directory: []const u8,
        request_name: []const u8,
        inputs: artifact_views.Inputs,
    ) !*const artifact_views.View {
        const program_object = switch (inputs.composition_program) {
            .metal => |object| object,
            .metallib => |object| object,
        };
        const program_kind: u8 = switch (inputs.composition_program) {
            .metal => 0,
            .metallib => 1,
        };
        const key = ViewKey{
            .preprocessed_evaluations = inputs.preprocessed_evaluations.object_id,
            .preprocessed_tree0_merkle = inputs.preprocessed_tree0_merkle.object_id,
            .composition = inputs.composition.object_id,
            .composition_program = program_object.object_id,
            .composition_program_kind = program_kind,
        };
        if (self.views.getPtr(key)) |view| {
            if (inputs.expected_tree0_root) |expected|
                if (!std.mem.eql(u8, &view.tree0_root, &expected)) return error.Tree0RootMismatch;
            return view;
        }
        var view = try artifact_views.create(
            self.allocator,
            parent_directory,
            request_name,
            inputs,
            true,
        );
        errdefer view.deinit(self.allocator);
        try self.views.putNoClobber(key, view);
        return self.views.getPtr(key).?;
    }
};

pub fn parseObjectId(encoded: []const u8) ![32]u8 {
    var object_id: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&object_id, encoded) catch return error.InvalidObjectId;
    return object_id;
}
