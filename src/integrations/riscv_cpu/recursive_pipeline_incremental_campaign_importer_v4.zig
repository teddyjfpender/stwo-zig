//! Zig-owned importer for one sealed incremental V4 publication.
//!
//! The filesystem root is only an input custody boundary.  Every object is
//! cold-opened through its typed V4 codec, copied into the immutable Zig CAS,
//! and named by a `BlobRefV1`.  The final operation publishes a path-free
//! campaign table containing the exact seven Stage-101 refs per leaf.  No
//! digest, recipe, or admission capability is supplied by Python.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const boundary_artifact = @import("ethereum_incremental_boundary_artifact_v4.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const guest_profile = @import("ethereum_guest_pc_profile.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const recovery_manifest =
    @import("ethereum_incremental_capture_raw_recovery_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const recipe_mod = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const table_mod = @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const minimal = frontend.runner.minimal_trace;
const source_wire = support.source_wire;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PRODUCTION_ACTIVE = false;
pub const PYTHON_MINTS_RECIPES = false;
pub const PYTHON_HASHES_CAPTURE_BYTES = false;
pub const TABLE_SEALED_LAST = true;

pub const profile_receipt_basename = "execution-profile-receipt.json";
pub const compact_manifest_basename = "compact-capture-manifest.json";
pub const CAPTURE_REFERENCE_CAS_SCHEMA_VERSION: u16 = 4;
pub const PUBLIC_WIRE_CAS_SCHEMA_VERSION =
    wire_publication.CAS_WIRE_SCHEMA_VERSION;

const max_program_bytes: u64 = 64 * 1024 * 1024;
const max_input_bytes: u64 = 64 * 1024 * 1024;
const max_output_bytes: u64 = 16 * 1024 * 1024;
const max_journal_bytes: u64 = 64 * 1024 * 1024;
const max_journal_record_bytes: usize = 1024 * 1024;

pub const Error = error{
    IncrementalCampaignImportBindingMismatchV4,
    IncrementalCampaignImportCodecMismatchV4,
    IncrementalCampaignImportCountMismatchV4,
    IncrementalCampaignImportJournalMismatchV4,
    IncrementalCampaignImportManifestMismatchV4,
    IncrementalCampaignImportOrderMismatchV4,
    IncrementalCampaignImportPathMismatchV4,
    IncrementalCampaignImportStoreMismatchV4,
};

pub const OwnedImportResultV4 = struct {
    allocator: std.mem.Allocator,
    segment_count: u32,
    topology: table_mod.TopologyV4,
    table_bytes: []u8,
    table_ref: artifact_store.BlobRefV1,

    pub fn deinit(self: *OwnedImportResultV4) void {
        self.allocator.free(self.table_bytes);
        self.* = undefined;
    }
};

/// Count authority shared by STWESG31/materialization and the two sealed
/// campaign manifests.  This function applies only protocol bounds; a block
/// profile may impose a narrower count in a separate admission wrapper.
pub fn authenticatedRetainedSegmentCount(
    retained: *const retained_mod.RetainedAuthorityV4,
) !u32 {
    retained.materialization.value.validate() catch
        return error.IncrementalCampaignImportCountMismatchV4;
    const count = retained.materialization.value.segment_count;
    _ = table_mod.TopologyV4.derive(count) catch
        return error.IncrementalCampaignImportCountMismatchV4;
    if (!lengthMatches(retained.sources.len, count) or
        !lengthMatches(retained.journal_records.len, count))
    {
        return error.IncrementalCampaignImportCountMismatchV4;
    }
    const execution = retained.executionAuthority() catch
        return error.IncrementalCampaignImportCountMismatchV4;
    if (execution.segment_count != count)
        return error.IncrementalCampaignImportCountMismatchV4;
    for (retained.sources, 0..) |source, ordinal| {
        const segment_index = std.math.cast(u32, ordinal) orelse
            return error.IncrementalCampaignImportCountMismatchV4;
        source.value.validate() catch
            return error.IncrementalCampaignImportCountMismatchV4;
        if (source.value.metadata.segment_count != count or
            source.value.metadata.segment_index != segment_index)
        {
            return error.IncrementalCampaignImportCountMismatchV4;
        }
    }
    return count;
}

/// Convenience entry for a controller holding only the two filesystem roots.
/// The store persists; only its in-process index is released on return.
pub fn importSealedCampaignAlloc(
    allocator: std.mem.Allocator,
    publication_root: []const u8,
    cas_root: []const u8,
    retained: *const retained_mod.RetainedAuthorityV4,
) !OwnedImportResultV4 {
    _ = try authenticatedRetainedSegmentCount(retained);
    const resolved_publication = try artifact_io.resolveAbsolute(
        allocator,
        publication_root,
    );
    defer allocator.free(resolved_publication);
    const resolved_cas = try artifact_io.resolveAbsolute(allocator, cas_root);
    defer allocator.free(resolved_cas);
    try validateDisjointRoots(resolved_publication, resolved_cas);
    var store = try artifact_store.Store.openOrCreate(
        allocator,
        resolved_cas,
        false,
    );
    defer store.deinit();
    return importIntoStoreAlloc(
        allocator,
        &store,
        resolved_publication,
        retained,
    );
}

/// Imports into an already-open shared store.  CAS writes may leave harmless
/// unreachable immutable objects after an error, but the table itself is put
/// only after every row has passed a second CAS-only cold validation.
pub fn importIntoStoreAlloc(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    publication_root: []const u8,
    retained: *const retained_mod.RetainedAuthorityV4,
) !OwnedImportResultV4 {
    const segment_count = try authenticatedRetainedSegmentCount(retained);
    const root = try artifact_io.resolveAbsolute(allocator, publication_root);
    defer allocator.free(root);
    const store_root = try artifact_io.resolveAbsolute(allocator, store.root_path);
    defer allocator.free(store_root);
    try validateDisjointRoots(root, store_root);
    var sealed = try OwnedSealedCampaignV4.open(allocator, root, retained);
    defer sealed.deinit();
    if (sealed.capture.value.segment_count != segment_count or
        sealed.public.value.segment_count != segment_count)
    {
        return error.IncrementalCampaignImportCountMismatchV4;
    }

    var journal_payloads = try extractJournalPayloadsAlloc(
        allocator,
        retained.journal_bytes,
        retained.journal_records,
    );
    defer journal_payloads.deinit();

    const globals = try ingestGlobals(store, retained, &sealed);
    const records = try allocator.alloc(
        table_mod.LeafRecordV4,
        @intCast(segment_count),
    );
    var initialized: usize = 0;
    errdefer allocator.free(records);
    while (initialized < records.len) : (initialized += 1) {
        records[initialized] = try importLeaf(
            allocator,
            store,
            root,
            retained,
            &sealed,
            globals,
            @intCast(initialized),
            journal_payloads.values[initialized],
        );
    }

    const table = try table_mod.CampaignTableV4.seal(.{
        .segment_count = segment_count,
        .globals = globals,
        .records = records,
        .content_sha256 = undefined,
    });
    const table_bytes = try table_mod.encodeAlloc(allocator, &table);
    errdefer allocator.free(table_bytes);
    try coldValidateCampaignTable(allocator, store, table_bytes);
    const table_ref = try store.putBytes(
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        table_bytes,
    );
    const topology = try table.topology();
    allocator.free(records);
    return .{
        .allocator = allocator,
        .segment_count = segment_count,
        .topology = topology,
        .table_bytes = table_bytes,
        .table_ref = table_ref,
    };
}

/// Complete CAS-only custody replay.  It opens every recipe and all seven
/// direct refs, then follows both nested reference identities (STWIMR04 and
/// STWIPW04) and replays their typed codecs against the two sealed manifests.
pub fn coldValidateCampaignTable(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    table_bytes: []const u8,
) !void {
    const header = try table_mod.decodeHeader(table_bytes);
    var capture_blob = try openBlob(
        store,
        header.globals.capture_manifest,
        publication.manifest_max_byte_count,
    );
    defer capture_blob.deinit(store.allocator);
    var capture = try publication.decodeManifestAlloc(
        allocator,
        capture_blob.bytes,
    );
    defer capture.deinit();
    var public_blob = try openBlob(
        store,
        header.globals.public_wire_manifest,
        wire_publication.manifest_max_byte_count,
    );
    defer public_blob.deinit(store.allocator);
    var public = try wire_publication.decodeManifestAlloc(
        allocator,
        public_blob.bytes,
    );
    defer public.deinit();
    try public.value.validateAgainst(
        capture.value.execution,
        capture.value.final_bindings,
        capture.file,
    );
    if (!identityMatchesRef(capture.file, header.globals.capture_manifest) or
        !identityMatchesRef(public.file, header.globals.public_wire_manifest) or
        capture.value.segment_count != header.segment_count or
        public.value.segment_count != header.segment_count)
    {
        return error.IncrementalCampaignImportManifestMismatchV4;
    }
    var owned = try table_mod.decodeAllocAgainstAuthenticatedCount(
        allocator,
        table_bytes,
        capture.value.segment_count,
    );
    defer owned.deinit();
    const table = &owned.value;
    try table_mod.coldValidateRecipeBindings(store, table);
    try validateGlobalManifestRefs(
        store,
        table.globals,
        &capture.value,
        &public.value,
    );
    for (table.records, 0..) |record, ordinal| try coldValidateLeaf(
        allocator,
        store,
        table.globals,
        capture.value.segments[ordinal],
        public.value.segments[ordinal],
        record,
    );
}

pub const OwnedJournalPayloadsV4 = struct {
    allocator: std.mem.Allocator,
    values: [][]const u8,

    pub fn deinit(self: *OwnedJournalPayloadsV4) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

/// Extracts the exact canonical JSON payload bytes already authenticated by
/// `ethereum_block_leaf_journal.validate`.  The envelope digest is checked
/// both textually and over the borrowed payload bytes before CAS ingestion.
pub fn extractJournalPayloadsAlloc(
    allocator: std.mem.Allocator,
    journal_bytes: []const u8,
    expected_digests: []const [32]u8,
) !OwnedJournalPayloadsV4 {
    if (expected_digests.len < 2 or journal_bytes.len == 0 or
        journal_bytes[journal_bytes.len - 1] != '\n')
    {
        return error.IncrementalCampaignImportJournalMismatchV4;
    }
    var lines = std.mem.splitScalar(u8, journal_bytes, '\n');
    const header = lines.next() orelse
        return error.IncrementalCampaignImportJournalMismatchV4;
    if (header.len == 0)
        return error.IncrementalCampaignImportJournalMismatchV4;
    const values = try allocator.alloc([]const u8, expected_digests.len);
    errdefer allocator.free(values);
    for (values, expected_digests) |*destination, expected| {
        const line = lines.next() orelse
            return error.IncrementalCampaignImportJournalMismatchV4;
        destination.* = try extractJournalPayload(line, expected);
    }
    const summary = lines.next() orelse
        return error.IncrementalCampaignImportJournalMismatchV4;
    const terminator = lines.next() orelse
        return error.IncrementalCampaignImportJournalMismatchV4;
    if (summary.len == 0 or terminator.len != 0 or lines.next() != null)
        return error.IncrementalCampaignImportJournalMismatchV4;
    return .{ .allocator = allocator, .values = values };
}

pub const AuxiliaryManifestKindV4 = enum {
    legacy_compact,
    raw_recovery,

    pub fn casSchema(self: AuxiliaryManifestKindV4) u16 {
        return switch (self) {
            .legacy_compact => table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
            .raw_recovery => table_mod.RECOVERY_MANIFEST_CAS_SCHEMA_VERSION,
        };
    }
};

const OwnedSelectedAuxiliaryV4 = struct {
    allocator: std.mem.Allocator,
    kind: AuxiliaryManifestKindV4,
    bytes: []u8,

    fn deinit(self: *OwnedSelectedAuxiliaryV4) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn selectAuxiliaryManifestAlloc(
    allocator: std.mem.Allocator,
    root: []const u8,
    expected: publication.ArtifactIdentityV4,
) !OwnedSelectedAuxiliaryV4 {
    try expected.validate(false);
    var selected: ?OwnedSelectedAuxiliaryV4 = null;
    errdefer if (selected) |*owned| owned.deinit();

    if (try readRootChildOptional(
        allocator,
        root,
        compact_manifest_basename,
        compact_manifest.max_manifest_bytes,
    )) |bytes| {
        if (std.meta.eql(
            publication.ArtifactIdentityV4.fromBytes(bytes),
            expected,
        )) {
            selected = .{
                .allocator = allocator,
                .kind = .legacy_compact,
                .bytes = bytes,
            };
        } else {
            allocator.free(bytes);
        }
    }
    if (try readRootChildOptional(
        allocator,
        root,
        recovery_manifest.manifest_basename,
        recovery_manifest.manifest_max_byte_count,
    )) |bytes| {
        if (std.meta.eql(
            publication.ArtifactIdentityV4.fromBytes(bytes),
            expected,
        )) {
            if (selected != null) {
                allocator.free(bytes);
                return error.IncrementalCampaignImportManifestMismatchV4;
            }
            selected = .{
                .allocator = allocator,
                .kind = .raw_recovery,
                .bytes = bytes,
            };
        } else {
            allocator.free(bytes);
        }
    }
    const result = selected orelse
        return error.IncrementalCampaignImportManifestMismatchV4;
    selected = null;
    return result;
}

const OwnedSealedCampaignV4 = struct {
    allocator: std.mem.Allocator,
    profile_bytes: []u8,
    auxiliary: OwnedSelectedAuxiliaryV4,
    capture_bytes: []u8,
    public_bytes: []u8,
    capture: publication.OwnedManifestV4,
    public: wire_publication.OwnedManifestV4,

    fn open(
        allocator: std.mem.Allocator,
        root: []const u8,
        retained: *const retained_mod.RetainedAuthorityV4,
    ) !OwnedSealedCampaignV4 {
        const profile_bytes = try readRootChild(
            allocator,
            root,
            profile_receipt_basename,
            guest_profile.max_receipt_bytes,
        );
        errdefer allocator.free(profile_bytes);
        var profile = try guest_profile.parseReceipt(allocator, profile_bytes);
        defer profile.deinit();

        const capture_path = try publication.manifestPathAlloc(allocator, root);
        defer allocator.free(capture_path);
        const capture_bytes = try artifact_io.readFileBounded(
            allocator,
            capture_path,
            publication.manifest_max_byte_count,
        );
        errdefer allocator.free(capture_bytes);
        var capture = try publication.decodeManifestAlloc(
            allocator,
            capture_bytes,
        );
        errdefer capture.deinit();
        const execution = try retained.executionAuthority();
        const segment_count = try authenticatedRetainedSegmentCount(retained);
        try capture.value.validateAgainst(execution, capture.value.final_bindings);
        try validateRetainedBindings(retained, capture.value.final_bindings);
        if (!std.meta.eql(
            capture.value.final_bindings.execution_profile_receipt,
            publication.ArtifactIdentityV4.fromBytes(profile_bytes),
        ) or capture.value.segment_count != segment_count or
            !lengthMatches(capture.value.segments.len, segment_count))
        {
            return error.IncrementalCampaignImportManifestMismatchV4;
        }
        var auxiliary = try selectAuxiliaryManifestAlloc(
            allocator,
            root,
            capture.value.final_bindings.compact_manifest,
        );
        errdefer auxiliary.deinit();

        const public_path = try wire_publication.manifestPathAlloc(
            allocator,
            root,
        );
        defer allocator.free(public_path);
        const public_bytes = try artifact_io.readFileBounded(
            allocator,
            public_path,
            wire_publication.manifest_max_byte_count,
        );
        errdefer allocator.free(public_bytes);
        var public = try wire_publication.decodeManifestAlloc(
            allocator,
            public_bytes,
        );
        errdefer public.deinit();
        try public.value.validateAgainst(
            execution,
            capture.value.final_bindings,
            capture.file,
        );
        if (public.value.segment_count != segment_count or
            !lengthMatches(public.value.segments.len, segment_count))
        {
            return error.IncrementalCampaignImportCountMismatchV4;
        }
        try validateSelectedAuxiliary(
            allocator,
            root,
            retained,
            profile.value,
            publication.ArtifactIdentityV4.fromBytes(profile_bytes),
            auxiliary.kind,
            auxiliary.bytes,
            &capture.value,
            &public.value,
        );
        return .{
            .allocator = allocator,
            .profile_bytes = profile_bytes,
            .auxiliary = auxiliary,
            .capture_bytes = capture_bytes,
            .public_bytes = public_bytes,
            .capture = capture,
            .public = public,
        };
    }

    fn deinit(self: *OwnedSealedCampaignV4) void {
        self.public.deinit();
        self.capture.deinit();
        self.allocator.free(self.public_bytes);
        self.allocator.free(self.capture_bytes);
        self.auxiliary.deinit();
        self.allocator.free(self.profile_bytes);
        self.* = undefined;
    }
};

fn ingestGlobals(
    store: *artifact_store.Store,
    retained: *const retained_mod.RetainedAuthorityV4,
    sealed: *const OwnedSealedCampaignV4,
) !table_mod.GlobalRefsV4 {
    return .{
        .capture_manifest = try putExpected(
            store,
            .capture_transport,
            4,
            sealed.capture_bytes,
            sealed.capture.file,
        ),
        .public_wire_manifest = try putExpected(
            store,
            .capture_transport,
            wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
            sealed.public_bytes,
            sealed.public.file,
        ),
        .compact_manifest = try putExpected(
            store,
            .capture_transport,
            sealed.auxiliary.kind.casSchema(),
            sealed.auxiliary.bytes,
            sealed.capture.value.final_bindings.compact_manifest,
        ),
        .execution_profile_receipt = try putExpected(
            store,
            .profile_receipt,
            1,
            sealed.profile_bytes,
            sealed.capture.value.final_bindings.execution_profile_receipt,
        ),
        .materialization_result = try putExpected(
            store,
            .source,
            table_mod.MATERIALIZATION_CAS_SCHEMA_VERSION,
            retained.materialization_bytes,
            retained.materialization_identity,
        ),
        .source_request = try putExpected(
            store,
            .source,
            1,
            retained.source_request_bytes,
            retained.source_request_identity,
        ),
        .execution_journal = try putExpected(
            store,
            .journal,
            table_mod.FULL_JOURNAL_CAS_SCHEMA_VERSION,
            retained.journal_bytes,
            retained.journal_identity,
        ),
        .program = try putExpected(
            store,
            .program,
            1,
            retained.elf_bytes,
            retained.elf_identity,
        ),
        .raw_input = try putExpected(
            store,
            .raw,
            1,
            retained.input_bytes,
            retained.input_identity,
        ),
        .expected_output = try putExpected(
            store,
            .raw,
            1,
            retained.output_bytes,
            retained.output_identity,
        ),
    };
}

fn importLeaf(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    root: []const u8,
    retained: *const retained_mod.RetainedAuthorityV4,
    sealed: *const OwnedSealedCampaignV4,
    globals: table_mod.GlobalRefsV4,
    segment_index: u32,
    journal_payload: []const u8,
) !table_mod.LeafRecordV4 {
    const ordinal: usize = @intCast(segment_index);
    const expected_capture = sealed.capture.value.segments[ordinal];
    const expected_public = sealed.public.value.segments[ordinal];
    var capture = try publication.coldOpenSegment(
        allocator,
        root,
        segment_index,
        false,
    );
    defer capture.deinit();
    if (!std.meta.eql(capture.reference, expected_capture))
        return error.IncrementalCampaignImportOrderMismatchV4;
    var public = try openPublicSegmentReusingRetained(
        allocator,
        root,
        segment_index,
        expected_capture,
        &retained.sources[ordinal].value,
    );
    defer public.deinit();
    if (!std.meta.eql(public.reference, expected_public))
        return error.IncrementalCampaignImportOrderMismatchV4;

    const capture_ref_bytes = try readCaptureReference(
        allocator,
        root,
        segment_index,
        expected_capture,
    );
    defer allocator.free(capture_ref_bytes);
    _ = try putExpected(
        store,
        .capture_transport,
        CAPTURE_REFERENCE_CAS_SCHEMA_VERSION,
        capture_ref_bytes,
        expected_capture.reference,
    );
    const statement = try putExpected(
        store,
        .statement,
        1,
        retained.sources[ordinal].bytes,
        expected_capture.segment.source,
    );
    const compact = try putExpected(
        store,
        .capture_transport,
        1,
        capture.compact_bytes,
        expected_capture.segment.compact_tape,
    );
    const boundary = try putExpected(
        store,
        .capture_transport,
        4,
        capture.artifact_bytes,
        expected_capture.segment.artifact,
    );
    _ = try putExpected(
        store,
        .capture_transport,
        PUBLIC_WIRE_CAS_SCHEMA_VERSION,
        public.wire_bytes,
        expected_public.segment.wire_artifact,
    );
    const public_reference = try putExpected(
        store,
        .capture_transport,
        wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
        public.reference_bytes,
        expected_public.reference,
    );
    if (journal_payload.len == 0 or
        journal_payload.len > max_journal_record_bytes)
    {
        return error.IncrementalCampaignImportJournalMismatchV4;
    }
    const journal = try store.putBytes(.journal, 1, journal_payload);
    if (!std.mem.eql(
        u8,
        &journal.sha256,
        &expected_capture.segment.journal_record_sha256,
    )) return error.IncrementalCampaignImportJournalMismatchV4;

    const recipe = try recipe_mod.RecipeV4.seal(.{
        .segment_index = segment_index,
        .segment_count = sealed.capture.value.segment_count,
        .statement = statement,
        .program = globals.program,
        .compact_witness = compact,
        .boundary_v4 = boundary,
        .public_wire_reference_v4 = public_reference,
        .journal_record = journal,
        .raw_input = globals.raw_input,
        .expected_output = globals.expected_output,
        .boundary_manifest_v4 = globals.capture_manifest,
        .public_wire_manifest_v4 = globals.public_wire_manifest,
        .content_sha256 = undefined,
    });
    const recipe_bytes = try recipe_mod.encode(&recipe);
    const recipe_ref = try store.putBytes(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        &recipe_bytes,
    );
    const inputs = [table_mod.STAGE_INPUT_COUNT]artifact_store.InputRefV1{
        input(.statement, 0, statement),
        input(.program, 0, globals.program),
        input(.profile, 0, recipe_ref),
        input(.witness, 0, compact),
        input(.capture, 0, boundary),
        input(.capture, 1, public_reference),
        input(.journal, 0, journal),
    };
    try recipe.validateStageInputs(&inputs, recipe_ref);
    const result = table_mod.LeafRecordV4{
        .segment_index = segment_index,
        .recipe = recipe_ref,
        .stage_inputs = inputs,
    };
    try result.validate(@intCast(segment_index), globals);
    return result;
}

const OwnedPublicSegmentV4 = struct {
    allocator: std.mem.Allocator,
    wire_bytes: []u8,
    wire: wire_publication.OwnedWireV4,
    reference_bytes: []u8,
    reference: wire_publication.CommittedSegmentV4,

    fn deinit(self: *OwnedPublicSegmentV4) void {
        self.allocator.free(self.reference_bytes);
        self.wire.deinit();
        self.allocator.free(self.wire_bytes);
        self.* = undefined;
    }
};

fn openPublicSegmentReusingRetained(
    allocator: std.mem.Allocator,
    root: []const u8,
    segment_index: u32,
    expected_capture: publication.CommittedSegmentV4,
    retained_source: *const source_wire.Source,
) !OwnedPublicSegmentV4 {
    try expected_capture.validate();
    try retained_source.validate();
    // The exact source-file identity is checked by `putExpected` in the
    // caller.  This retained decoded value supplies only its authenticated
    // coordinate and precomputed roots to the root-reusing wire decoder.
    if (expected_capture.segment.segment_index != segment_index or
        retained_source.metadata.segment_index != segment_index)
    {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
    const wire_path = try wire_publication.wirePathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(wire_path);
    const wire_bytes = try artifact_io.readFileBounded(
        allocator,
        wire_path,
        wire_publication.max_wire_bytes,
    );
    errdefer allocator.free(wire_bytes);
    var wire = try wire_publication.decodeWireAllocAgainstRetainedMetadata(
        allocator,
        wire_bytes,
        &retained_source.metadata,
    );
    errdefer wire.deinit();
    const reference_path = try wire_publication.referencePathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(reference_path);
    const reference_bytes = try artifact_io.readFileBounded(
        allocator,
        reference_path,
        wire_publication.reference_byte_count,
    );
    errdefer allocator.free(reference_bytes);
    const reference = wire_publication.CommittedSegmentV4{
        .segment = try wire_publication.decodeSegmentRef(reference_bytes),
        .reference = publication.ArtifactIdentityV4.fromBytes(reference_bytes),
    };
    try reference.validate();
    if (!std.meta.eql(reference.segment.coordinate, wire.coordinate) or
        !std.meta.eql(reference.segment.wire_id, wire.data.wireId()) or
        !std.meta.eql(
            reference.segment.wire_artifact,
            publication.ArtifactIdentityV4.fromBytes(wire_bytes),
        ) or !std.meta.eql(
        reference.segment.v4_segment_reference,
        expected_capture.reference,
    ) or !std.meta.eql(
        reference.segment.source,
        expected_capture.segment.source,
    ) or !std.mem.eql(
        u8,
        &reference.segment.journal_record_sha256,
        &expected_capture.segment.journal_record_sha256,
    ) or !std.meta.eql(
        reference.segment.wire_id,
        expected_capture.segment.segment_public_wire_id,
    )) return error.IncrementalCampaignImportBindingMismatchV4;
    return .{
        .allocator = allocator,
        .wire_bytes = wire_bytes,
        .wire = wire,
        .reference_bytes = reference_bytes,
        .reference = reference,
    };
}

fn coldValidateLeaf(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    globals: table_mod.GlobalRefsV4,
    capture: publication.CommittedSegmentV4,
    public: wire_publication.CommittedSegmentV4,
    record: table_mod.LeafRecordV4,
) !void {
    try capture.validate();
    try public.validate();
    const inputs = record.stage_inputs;
    var source_blob = try openBlob(store, inputs[0].blob, source_wire.encoded_size);
    defer source_blob.deinit(store.allocator);
    const source = try source_wire.decode(source_blob.bytes);
    try source.validate();
    var program_blob = try openBlob(store, inputs[1].blob, max_program_bytes);
    defer program_blob.deinit(store.allocator);
    var recipe_blob = try openBlob(
        store,
        inputs[2].blob,
        recipe_mod.ENCODED_BYTE_COUNT,
    );
    defer recipe_blob.deinit(store.allocator);
    const recipe = try recipe_mod.decode(recipe_blob.bytes);
    try recipe.validateStageInputs(&inputs, record.recipe);
    var compact_blob = try openBlob(
        store,
        inputs[3].blob,
        minimal.ethereum_wire.MAX_ENCODED_BYTES,
    );
    defer compact_blob.deinit(store.allocator);
    var compact = try minimal.decodeEthereumMinimalArtifactAlloc(
        allocator,
        compact_blob.bytes,
    );
    defer compact.deinit();
    var boundary_blob = try openBlob(
        store,
        inputs[4].blob,
        boundary_artifact.default_limits.max_bytes,
    );
    defer boundary_blob.deinit(store.allocator);
    var boundary = try boundary_artifact.decodeAlloc(
        allocator,
        boundary_blob.bytes,
        boundary_artifact.default_limits,
    );
    defer boundary.deinit();
    try boundary.validateCanonical(boundary_artifact.default_limits);
    var public_ref_blob = try openBlob(
        store,
        inputs[5].blob,
        wire_publication.reference_byte_count,
    );
    defer public_ref_blob.deinit(store.allocator);
    const public_ref = try wire_publication.decodeSegmentRef(
        public_ref_blob.bytes,
    );
    var journal_blob = try openBlob(
        store,
        inputs[6].blob,
        max_journal_record_bytes,
    );
    defer journal_blob.deinit(store.allocator);

    const wire_ref = try blobRefFromIdentity(
        .capture_transport,
        wire_publication.CAS_WIRE_SCHEMA_VERSION,
        public_ref.wire_artifact,
    );
    var wire_blob = try openBlob(store, wire_ref, wire_publication.max_wire_bytes);
    defer wire_blob.deinit(store.allocator);
    var wire = try wire_publication.decodeWireAllocAgainstRetainedMetadata(
        allocator,
        wire_blob.bytes,
        &source.metadata,
    );
    defer wire.deinit();
    const capture_ref = try blobRefFromIdentity(
        .capture_transport,
        CAPTURE_REFERENCE_CAS_SCHEMA_VERSION,
        capture.reference,
    );
    var capture_ref_blob = try openBlob(
        store,
        capture_ref,
        publication.segment_ref_byte_count,
    );
    defer capture_ref_blob.deinit(store.allocator);
    const decoded_capture_ref = try publication.decodeSegmentRef(
        capture_ref_blob.bytes,
    );

    if (record.segment_index != capture.segment.segment_index or
        record.segment_index != public.segment.coordinate.segment_index or
        recipe.segment_count != capture.segment.segment_count or
        recipe.segment_count != public.segment.coordinate.segment_count or
        recipe.segment_count != source.metadata.segment_count or
        source.metadata.segment_index != record.segment_index or
        !std.meta.eql(decoded_capture_ref, capture.segment) or
        !identityMatchesRef(capture.segment.source, inputs[0].blob) or
        !identityMatchesRef(capture.segment.compact_tape, inputs[3].blob) or
        !identityMatchesRef(capture.segment.artifact, inputs[4].blob) or
        !identityMatchesRef(public.reference, inputs[5].blob) or
        !std.meta.eql(public.segment, public_ref) or
        !std.meta.eql(public_ref.v4_segment_reference, capture.reference) or
        !std.meta.eql(public_ref.wire_id, wire.data.wireId()) or
        !std.mem.eql(
            u8,
            &inputs[6].blob.sha256,
            &capture.segment.journal_record_sha256,
        ) or !artifact_store.BlobRefV1.eql(recipe.program, globals.program) or
        !std.mem.eql(
            u8,
            &capture.segment.artifact_content_sha256,
            &boundary.content_sha256,
        )) return error.IncrementalCampaignImportBindingMismatchV4;
}

fn validateGlobalManifestRefs(
    store: *artifact_store.Store,
    globals: table_mod.GlobalRefsV4,
    capture: *const publication.ManifestV4,
    public: *const wire_publication.ManifestV4,
) !void {
    try globals.validate();
    if (!identityMatchesRef(capture.execution.elf, globals.program) or
        !identityMatchesRef(capture.execution.input, globals.raw_input) or
        !identityMatchesRef(
            capture.execution.expected_output,
            globals.expected_output,
        ) or !identityMatchesRef(
        capture.final_bindings.compact_manifest,
        globals.compact_manifest,
    ) or !identityMatchesRef(
        capture.final_bindings.materialization_result,
        globals.materialization_result,
    ) or !identityMatchesRef(
        capture.final_bindings.source_request,
        globals.source_request,
    ) or !identityMatchesRef(
        capture.final_bindings.journal,
        globals.execution_journal,
    ) or !identityMatchesRef(
        capture.final_bindings.execution_profile_receipt,
        globals.execution_profile_receipt,
    )) return error.IncrementalCampaignImportManifestMismatchV4;

    var compact_blob = try openBlob(
        store,
        globals.compact_manifest,
        @max(
            compact_manifest.max_manifest_bytes,
            recovery_manifest.manifest_max_byte_count,
        ),
    );
    defer compact_blob.deinit(store.allocator);
    var profile_blob = try openBlob(
        store,
        globals.execution_profile_receipt,
        guest_profile.max_receipt_bytes,
    );
    defer profile_blob.deinit(store.allocator);
    var profile = try guest_profile.parseReceipt(store.allocator, profile_blob.bytes);
    defer profile.deinit();
    const auxiliary_kind: AuxiliaryManifestKindV4 =
        if (globals.compact_manifest.schema_version ==
        table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION)
            .legacy_compact
        else if (globals.compact_manifest.schema_version ==
        table_mod.RECOVERY_MANIFEST_CAS_SCHEMA_VERSION)
            .raw_recovery
        else
            return error.IncrementalCampaignImportCodecMismatchV4;
    try validateSelectedAuxiliary(
        store.allocator,
        null,
        null,
        profile.value,
        publication.ArtifactIdentityV4.fromBytes(profile_blob.bytes),
        auxiliary_kind,
        compact_blob.bytes,
        capture,
        public,
    );
    var materialization = try openBlob(
        store,
        globals.materialization_result,
        max_journal_bytes,
    );
    defer materialization.deinit(store.allocator);
    var source_request = try openBlob(
        store,
        globals.source_request,
        max_journal_bytes,
    );
    defer source_request.deinit(store.allocator);
    var journal = try openBlob(
        store,
        globals.execution_journal,
        max_journal_bytes,
    );
    defer journal.deinit(store.allocator);
    var program = try openBlob(store, globals.program, max_program_bytes);
    defer program.deinit(store.allocator);
    var input_blob = try openBlob(store, globals.raw_input, max_input_bytes);
    defer input_blob.deinit(store.allocator);
    var output = try openBlob(store, globals.expected_output, max_output_bytes);
    defer output.deinit(store.allocator);
}

fn validateRetainedBindings(
    retained: *const retained_mod.RetainedAuthorityV4,
    bindings: publication.FinalBindingsV4,
) !void {
    try bindings.validate();
    if (!std.meta.eql(bindings.materialization_result, retained.materialization_identity) or
        !std.meta.eql(bindings.source_request, retained.source_request_identity) or
        !std.meta.eql(bindings.journal, retained.journal_identity))
    {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
}

fn validateSelectedAuxiliary(
    allocator: std.mem.Allocator,
    root: ?[]const u8,
    retained: ?*const retained_mod.RetainedAuthorityV4,
    profile: guest_profile.Receipt,
    profile_identity: publication.ArtifactIdentityV4,
    kind: AuxiliaryManifestKindV4,
    bytes: []const u8,
    capture: *const publication.ManifestV4,
    public: *const wire_publication.ManifestV4,
) !void {
    const retained_elf_path = if (retained) |value|
        value.elfEvidence().path
    else
        null;
    const retained_journal_path = if (retained) |value|
        value.journalEvidence().path
    else
        null;
    const retained_source_path = if (retained) |value|
        value.sourceRequestEvidence().path
    else
        null;
    try requireJsonIdentity(
        profile.elf,
        capture.execution.elf,
        retained_elf_path,
    );
    try requireJsonIdentity(
        profile.execution_journal,
        capture.final_bindings.journal,
        retained_journal_path,
    );
    try requireJsonIdentity(
        profile.materialization_result,
        capture.final_bindings.materialization_result,
        null,
    );
    try requireJsonIdentity(
        profile.source_request,
        capture.final_bindings.source_request,
        retained_source_path,
    );
    switch (kind) {
        .legacy_compact => {
            var compact = try compact_manifest.parse(allocator, bytes);
            defer compact.deinit();
            try validateLegacyCompact(
                allocator,
                root,
                retained,
                compact.value,
                profile_identity,
                capture,
            );
        },
        .raw_recovery => {
            var recovery = try recovery_manifest.decodeManifestAlloc(
                allocator,
                bytes,
            );
            defer recovery.deinit();
            try validateRecoveryManifest(
                &recovery.value,
                profile_identity,
                capture,
                public,
            );
        },
    }
}

fn validateLegacyCompact(
    allocator: std.mem.Allocator,
    root: ?[]const u8,
    retained: ?*const retained_mod.RetainedAuthorityV4,
    compact: compact_manifest.Receipt,
    profile_identity: publication.ArtifactIdentityV4,
    capture: *const publication.ManifestV4,
) !void {
    if (compact.segment_count != capture.segment_count or
        !lengthMatches(compact.artifacts.len, capture.segment_count) or
        compact.segment_step_budget != capture.execution.segment_step_budget)
    {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
    var profile_path: ?[]u8 = null;
    defer if (profile_path) |path| allocator.free(path);
    if (root) |value| profile_path = try std.fs.path.join(
        allocator,
        &.{ value, profile_receipt_basename },
    );
    try requireJsonIdentity(
        compact.elf,
        capture.execution.elf,
        if (retained) |value| value.elfEvidence().path else null,
    );
    try requireJsonIdentity(
        compact.execution_journal,
        capture.final_bindings.journal,
        if (retained) |value| value.journalEvidence().path else null,
    );
    try requireJsonIdentity(
        compact.execution_profile_receipt,
        profile_identity,
        profile_path,
    );
    try requireJsonIdentity(
        compact.expected_output,
        capture.execution.expected_output,
        if (retained) |value| value.outputEvidence().path else null,
    );
    try requireJsonIdentity(
        compact.input,
        capture.execution.input,
        if (retained) |value| value.inputEvidence().path else null,
    );
    try requireJsonIdentity(
        compact.materialization_result,
        capture.final_bindings.materialization_result,
        null,
    );
    try requireJsonIdentity(
        compact.source_request,
        capture.final_bindings.source_request,
        if (retained) |value| value.sourceRequestEvidence().path else null,
    );
    const semantic = try contract.parseSha256(
        compact.execution_profile_semantic_sha256,
    );
    const session = try contract.parseSha256(compact.session_sha256);
    const expected_session = try capture.execution.sessionIdentity();
    if (!std.mem.eql(
        u8,
        &semantic,
        &capture.execution.execution_profile_semantic_sha256,
    ) or !std.mem.eql(u8, &session, &expected_session)) {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
    for (compact.artifacts, capture.segments, 0..) |
        artifact,
        committed,
        ordinal,
    | {
        var expected_path: ?[]u8 = null;
        defer if (expected_path) |path| allocator.free(path);
        if (root) |value| expected_path = try publication.compactTapePathAlloc(
            allocator,
            value,
            @intCast(ordinal),
        );
        requireJsonIdentity(
            artifact.artifact,
            committed.segment.compact_tape,
            expected_path,
        ) catch return error.IncrementalCampaignImportPathMismatchV4;
    }
}

fn validateRecoveryManifest(
    recovery: *const recovery_manifest.ManifestV4,
    profile_identity: publication.ArtifactIdentityV4,
    capture: *const publication.ManifestV4,
    public: *const wire_publication.ManifestV4,
) !void {
    try recovery.validate();
    const session = try capture.execution.sessionIdentity();
    if (!std.meta.eql(recovery.execution, capture.execution) or
        !std.meta.eql(
            recovery.materialization_result,
            capture.final_bindings.materialization_result,
        ) or !std.meta.eql(
        recovery.source_request,
        capture.final_bindings.source_request,
    ) or !std.meta.eql(recovery.journal, capture.final_bindings.journal) or
        !std.meta.eql(recovery.execution_profile_receipt, profile_identity) or
        recovery.segment_count != capture.segment_count or
        recovery.segment_count != public.segment_count or
        !lengthMatches(recovery.records.len, capture.segment_count) or
        !std.mem.eql(u8, &recovery.session_identity_sha256, &session))
    {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
    for (recovery.records, capture.segments, public.segments, 0..) |
        record,
        capture_segment,
        public_segment,
        ordinal,
    | {
        const segment_index = std.math.cast(u32, ordinal) orelse
            return error.IncrementalCampaignImportBindingMismatchV4;
        if (record.segment_index != segment_index or
            !std.meta.eql(
                record.compact_tape,
                capture_segment.segment.compact_tape,
            ) or !std.meta.eql(record.source, capture_segment.segment.source) or
            !std.meta.eql(
                record.public_wire,
                public_segment.segment.wire_artifact,
            ) or !std.mem.eql(
            u8,
            &record.journal_record_sha256,
            &capture_segment.segment.journal_record_sha256,
        )) return error.IncrementalCampaignImportBindingMismatchV4;
    }
}

fn requireJsonIdentity(
    value: contract.Identity,
    expected: publication.ArtifactIdentityV4,
    expected_path: ?[]const u8,
) !void {
    const digest = try contract.parseSha256(value.sha256);
    if (value.bytes != expected.byte_count or
        !std.mem.eql(u8, &digest, &expected.sha256) or
        (expected_path != null and
            !std.mem.eql(u8, value.path, expected_path.?)))
    {
        return error.IncrementalCampaignImportBindingMismatchV4;
    }
}

fn extractJournalPayload(
    line: []const u8,
    expected: [32]u8,
) ![]const u8 {
    const prefix = "{\"payload\":";
    const marker = ",\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, line, prefix) or
        line.len > max_journal_record_bytes)
    {
        return error.IncrementalCampaignImportJournalMismatchV4;
    }
    const marker_at = std.mem.lastIndexOf(u8, line, marker) orelse
        return error.IncrementalCampaignImportJournalMismatchV4;
    const digest_at = marker_at + marker.len;
    if (marker_at <= prefix.len or digest_at + 64 + 2 != line.len or
        !std.mem.eql(u8, line[line.len - 2 ..], "\"}"))
    {
        return error.IncrementalCampaignImportJournalMismatchV4;
    }
    const expected_hex = std.fmt.bytesToHex(expected, .lower);
    if (!std.mem.eql(u8, line[digest_at .. digest_at + 64], &expected_hex))
        return error.IncrementalCampaignImportJournalMismatchV4;
    const payload = line[prefix.len..marker_at];
    var observed: [32]u8 = undefined;
    Sha256.hash(payload, &observed, .{});
    if (!std.mem.eql(u8, &observed, &expected))
        return error.IncrementalCampaignImportJournalMismatchV4;
    return payload;
}

fn readCaptureReference(
    allocator: std.mem.Allocator,
    root: []const u8,
    segment_index: u32,
    expected: publication.CommittedSegmentV4,
) ![]u8 {
    const path = try publication.segmentReferencePathAlloc(
        allocator,
        root,
        segment_index,
    );
    defer allocator.free(path);
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        publication.segment_ref_byte_count,
    );
    errdefer allocator.free(bytes);
    const decoded = try publication.decodeSegmentRef(bytes);
    if (!std.meta.eql(decoded, expected.segment) or
        !std.meta.eql(
            publication.ArtifactIdentityV4.fromBytes(bytes),
            expected.reference,
        )) return error.IncrementalCampaignImportPathMismatchV4;
    return bytes;
}

fn readRootChild(
    allocator: std.mem.Allocator,
    root: []const u8,
    basename: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, basename });
    defer allocator.free(path);
    return artifact_io.readFileBounded(allocator, path, maximum_bytes);
}

fn readRootChildOptional(
    allocator: std.mem.Allocator,
    root: []const u8,
    basename: []const u8,
    maximum_bytes: usize,
) !?[]u8 {
    return readRootChild(
        allocator,
        root,
        basename,
        maximum_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// The immutable publication and mutable CAS must be separate directory
/// trees.  This is checked before `Store.openOrCreate` in the path-based entry
/// and repeated against `Store.root_path` in the already-open entry.
pub fn validateDisjointRoots(
    publication_root: []const u8,
    cas_root: []const u8,
) !void {
    if (!std.fs.path.isAbsolute(publication_root) or
        !std.fs.path.isAbsolute(cas_root) or
        pathContains(publication_root, cas_root) or
        pathContains(cas_root, publication_root))
    {
        return error.IncrementalCampaignImportPathMismatchV4;
    }
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, child)) return true;
    if (parent.len == 1 and parent[0] == std.fs.path.sep) return true;
    return child.len > parent.len and
        std.mem.startsWith(u8, child, parent) and
        child[parent.len] == std.fs.path.sep;
}

fn putExpected(
    store: *artifact_store.Store,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    bytes: []const u8,
    expected: publication.ArtifactIdentityV4,
) !artifact_store.BlobRefV1 {
    const reference = try store.putBytes(kind, schema_version, bytes);
    if (!identityMatchesRef(expected, reference))
        return error.IncrementalCampaignImportStoreMismatchV4;
    return reference;
}

fn openBlob(
    store: *artifact_store.Store,
    reference: artifact_store.BlobRefV1,
    maximum_bytes: u64,
) !artifact_store.OwnedBlobV1 {
    return store.openBlob(
        reference,
        reference.kind,
        reference.schema_version,
        maximum_bytes,
    );
}

fn blobRefFromIdentity(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    identity: publication.ArtifactIdentityV4,
) !artifact_store.BlobRefV1 {
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        identity.byte_count,
        identity.sha256,
    );
}

fn identityMatchesRef(
    identity: publication.ArtifactIdentityV4,
    reference: artifact_store.BlobRefV1,
) bool {
    return identity.byte_count == reference.byte_count and
        std.mem.eql(u8, &identity.sha256, &reference.sha256);
}

fn lengthMatches(length: usize, count: u32) bool {
    const actual = std.math.cast(u32, length) orelse return false;
    return actual == count;
}

fn input(
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) artifact_store.InputRefV1 {
    return .{ .role = role, .ordinal = ordinal, .blob = blob };
}
