//! Fast retained-authority replay observer for raw V4 capture only.
//!
//! This observer performs one deterministic VM replay and publishes exactly
//! STWEMT01 followed by STWIPW04 for each segment. It deliberately owns no
//! incremental transition tree. Retained STWESG31 roots authenticate the
//! global-to-local statement projection without rebuilding sparse Poseidon
//! roots; the separate postprocessor advances the authority chain later.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const pc_profile = @import("ethereum_guest_pc_profile.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const raw_transport =
    @import("ethereum_incremental_capture_raw_transport_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const execution_profile = frontend.isa.execution_profile;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const minimal = frontend.runner.minimal_trace;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const span = frontend.recursion.span_statement;

pub const PRODUCTION_ACTIVE = false;
pub const TRANSITION_WORK_PERFORMED = false;
pub const RETAINED_ROOT_REUSE_REQUIRED = true;

pub const RawObserverV4 = struct {
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    root: []const u8,
    raw_owner: raw_transport.EarlyRawOwnerV4,
    semantic: minimal.EthereumSemanticSegmentObservationV1,
    profiler: pc_profile.Profiler,
    program_words: []minimal.ProgramWord = &.{},
    program: ?minimal.SliceProgram = null,
    compact_artifacts: std.ArrayList(compact_manifest.ArtifactInput) = .empty,
    observed_count: u32 = 0,
    terminal_output_validated: bool = false,
    capture_wall_ns: u64 = 0,
    encode_wall_ns: u64 = 0,
    publish_wall_ns: u64 = 0,
    observer_wall_ns: u64 = 0,
    pc_attribution_wall_ns: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        retained: *const retained_mod.RetainedAuthorityV4,
        root: []const u8,
    ) !RawObserverV4 {
        var owner = try raw_transport.EarlyRawOwnerV4.initExisting(
            allocator,
            root,
            try retained.executionAuthority(),
        );
        errdefer owner.deinit();
        var semantic = minimal.EthereumSemanticSegmentObservationV1.init(
            allocator,
        );
        errdefer semantic.deinit();
        var profiler = try pc_profile.Profiler.init(allocator, retained.elf_bytes);
        errdefer profiler.deinit();
        return .{
            .allocator = allocator,
            .retained = retained,
            .root = root,
            .raw_owner = owner,
            .semantic = semantic,
            .profiler = profiler,
        };
    }

    pub fn deinit(self: *RawObserverV4) void {
        self.compact_artifacts.deinit(self.allocator);
        if (self.program_words.len != 0)
            self.allocator.free(self.program_words);
        self.profiler.deinit();
        self.semantic.deinit();
        self.raw_owner.deinit();
        self.* = undefined;
    }

    pub fn retirementObserver(
        self: *RawObserverV4,
    ) ?frontend.runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginRetirementSegment,
            .core_row_fn = observeRetiredCoreRow,
        };
    }

    fn beginRetirementSegment(context: *anyopaque, segment_index: u32) !void {
        const self: *RawObserverV4 = @ptrCast(@alignCast(context));
        return self.semantic.begin(segment_index);
    }

    fn observeRetiredCoreRow(
        context: *anyopaque,
        row: frontend.runner.trace.TraceRow,
    ) !void {
        const self: *RawObserverV4 = @ptrCast(@alignCast(context));
        return self.semantic.observeCoreRow(row);
    }

    pub fn observe(
        self: *RawObserverV4,
        comptime profile: execution_profile.ExecutionProfile,
        configured: anytype,
        journal_record_sha256: [32]u8,
    ) !void {
        if (comptime profile != .rv32im_zkvm_ethereum_v1) {
            return error.ExecutionProfileMismatch;
        } else {
            var observer_timer = try std.time.Timer.start();
            const segment = &configured.base;
            const index = segment.segment_index;
            if (index != self.observed_count or
                index >= self.retained.sources.len)
            {
                return error.ExecutionSegmentOrderMismatch;
            }
            const retained_source = &self.retained.sources[index];
            if (!std.mem.eql(
                u8,
                &retained_source.value.journal_record_sha256,
                &journal_record_sha256,
            )) return error.JournalRecordMismatch;

            const is_final = index + 1 == self.retained.sources.len;
            if (segment.isComplete() != is_final)
                return error.InvalidTerminalSegment;
            if (is_final) {
                const output = segment.output orelse return error.MissingOutput;
                if (!std.mem.eql(u8, output, self.retained.output_bytes))
                    return error.PublicOutputMismatch;
                self.terminal_output_validated = true;
            }

            const global_statement = span.SpanStatement.fromCanonicalWords(
                &retained_source.value.metadata.base_statement_words,
            ) catch return error.BaseStatementMismatch;
            const global_source = try global_v3.SourceV3
                .fromSegmentResultAgainstMetadata(
                global_statement,
                segment,
                &retained_source.value.metadata,
            );
            const projection = try projection_v3.ProjectionV3
                .initAgainstRetainedMetadata(
                &global_source,
                &retained_source.value.metadata,
            );
            const execution = try self.retained.executionAuthority();
            const session_identity = try execution.sessionIdentity();
            const local_source = try projection.sourceV2AgainstRetainedMetadata(
                &global_source,
                &retained_source.value.metadata,
                support.sessionDigest(session_identity),
            );
            const local_wire = try support.encodeLocalPublicDataReusingRoots(
                self.allocator,
                &local_source,
                &retained_source.value.metadata,
            );
            defer self.allocator.free(local_wire.words);

            try self.ensureProgram(segment);
            var capture_timer = try std.time.Timer.start();
            var captured = try self.semantic.capture(self.allocator, .{
                .segment = configured,
                .program = self.program.?.source(),
                .input_identity = self.retained.input_identity.sha256,
                .session_identity = session_identity,
            });
            defer captured.deinit();
            const capture_wall_ns = capture_timer.read();
            self.capture_wall_ns = try add(
                self.capture_wall_ns,
                capture_wall_ns,
            );

            var encode_timer = try std.time.Timer.start();
            const compact_bytes = try minimal.encodeEthereumMinimalArtifactAlloc(
                self.allocator,
                &.{
                    .leaf = captured.leaf,
                    .boundary_words = captured.boundary_words,
                    .allocator = self.allocator,
                },
            );
            defer self.allocator.free(compact_bytes);
            const encode_wall_ns = encode_timer.read();
            self.encode_wall_ns = try add(self.encode_wall_ns, encode_wall_ns);

            const compact_path = try publication.compactTapePathAlloc(
                self.allocator,
                self.root,
                index,
            );
            defer self.allocator.free(compact_path);
            const wire_path = try wire_publication.wirePathAlloc(
                self.allocator,
                self.root,
                index,
            );
            defer self.allocator.free(wire_path);
            const pair_existed = try publication.pathExists(compact_path) and
                try publication.pathExists(wire_path);
            var publish_timer = try std.time.Timer.start();
            _ = try self.raw_owner.publishOrCompareLive(
                index,
                compact_bytes,
                &local_wire.value,
                &retained_source.value.metadata,
            );
            const publish_wall_ns = if (pair_existed) 0 else publish_timer.read();
            self.publish_wall_ns = try add(
                self.publish_wall_ns,
                publish_wall_ns,
            );

            try self.compact_artifacts.append(self.allocator, .{
                .artifact = evidence.identity(compact_path, compact_bytes),
                .capture_wall_ns = capture_wall_ns,
                .completion = captured.leaf.completion,
                .core_cycle_count = captured.leaf.core_cycle_count,
                .cycle_count = captured.leaf.cycle_count,
                .encode_wall_ns = encode_wall_ns,
                .entry_boundary = captured.leaf.entry_boundary,
                .entry_cpu = compact_manifest.cpuIdentity(segment.entry_cpu),
                .entry_memory = captured.leaf.source.entry_memory,
                .exit_boundary = captured.leaf.exit_boundary,
                .exit_cpu = compact_manifest.cpuIdentity(segment.exit_cpu),
                .exit_memory = captured.leaf.source.exit_memory,
                .global_first_cycle = captured.leaf.global_first_cycle,
                .keccak_calls = @intCast(captured.leaf.keccak_records.len),
                .leaf_seal = captured.leaf.seal,
                .publish_wall_ns = publish_wall_ns,
                .recovery_calls = @intCast(captured.leaf.recovery_records.len),
                .segment_index = index,
            });

            var profile_timer = try std.time.Timer.start();
            try self.profiler.observeCoreRows(segment.execution_trace.rows.items);
            try self.profiler.observeExternalRecords(
                .keccakf,
                configured.keccakf_calls.records(),
                configured.keccakf_execution_rows.rows().len,
            );
            try self.profiler.observeExternalRecords(
                .secp256k1_recover,
                configured.signer_recovery_calls.records(),
                configured.signer_recovery_execution_rows.rows().len,
            );
            self.pc_attribution_wall_ns = try add(
                self.pc_attribution_wall_ns,
                profile_timer.read(),
            );
            self.observed_count += 1;
            self.observer_wall_ns = try add(
                self.observer_wall_ns,
                observer_timer.read(),
            );
        }
    }

    pub fn validateComplete(self: *const RawObserverV4) !void {
        try self.raw_owner.requireComplete();
        if (self.observed_count != publication.CANONICAL_SEGMENT_COUNT or
            self.compact_artifacts.items.len !=
                publication.CANONICAL_SEGMENT_COUNT or
            !self.terminal_output_validated)
        {
            return error.IncompleteIncrementalRawPublicationV4;
        }
    }

    pub fn programIdentity(self: *const RawObserverV4) ![32]u8 {
        return (self.program orelse return error.MissingProgramAuthority).identity;
    }

    fn ensureProgram(
        self: *RawObserverV4,
        segment: *const frontend.runner.SegmentResult,
    ) !void {
        if (self.program != null) return;
        const words = try self.allocator.alloc(
            minimal.ProgramWord,
            segment.rw_memory.program_words.len,
        );
        errdefer self.allocator.free(words);
        for (words, segment.rw_memory.program_words) |*destination, source|
            destination.* = .{
                .address = source.addr,
                .word = source.initial_word,
            };
        self.program_words = words;
        self.program = try minimal.SliceProgram.init(words);
    }
};

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch error.ProfileTimingOverflow;
}
