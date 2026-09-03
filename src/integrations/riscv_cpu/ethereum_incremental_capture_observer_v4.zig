//! Fresh one-pass observer for retained 210-leaf source authority.
//!
//! One execution simultaneously mints STWEMT01 and STWIMT04.  Retained
//! STWESG31 supplies the already-sealed global statement for each callback;
//! the local V2 public wire is nevertheless derived from the exact live
//! `SegmentResult`.  A durable prefix is byte-compared and cold-reconstructed,
//! but the VM is always replayed from segment zero.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const publication_owner =
    @import("ethereum_incremental_capture_publication_owner_v4.zig");
const public_wire_owner_mod =
    @import("ethereum_incremental_public_wire_publication_owner_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const capture_mod = @import("ethereum_incremental_boundary_capture_v2.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");

const execution_profile = frontend.isa.execution_profile;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const minimal_trace = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;
const span = frontend.recursion.span_statement;

pub const ObserverV4 = struct {
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    root: []const u8,
    semantic: minimal_trace.EthereumSemanticSegmentObservationV1,
    profiler: @import("ethereum_guest_pc_profile.zig").Profiler,
    program_words: []minimal_trace.ProgramWord = &.{},
    program: ?minimal_trace.SliceProgram = null,
    capture: ?capture_mod.SessionCaptureV2 = null,
    owner: ?publication_owner.PublicationOwnerV4 = null,
    public_wire_owner: ?public_wire_owner_mod.PublicationOwnerV4 = null,
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
    ) !ObserverV4 {
        return .{
            .allocator = allocator,
            .retained = retained,
            .root = root,
            .semantic = minimal_trace.EthereumSemanticSegmentObservationV1
                .init(allocator),
            .profiler = try @import("ethereum_guest_pc_profile.zig")
                .Profiler.init(allocator, retained.elf_bytes),
        };
    }

    pub fn deinit(self: *ObserverV4) void {
        self.compact_artifacts.deinit(self.allocator);
        if (self.public_wire_owner) |*owner| owner.deinit();
        if (self.owner) |*owner| owner.deinit();
        if (self.capture) |*capture| capture.deinit();
        if (self.program_words.len != 0)
            self.allocator.free(self.program_words);
        self.profiler.deinit();
        self.semantic.deinit();
        self.* = undefined;
    }

    pub fn retirementObserver(
        self: *ObserverV4,
    ) ?frontend.runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginRetirementSegment,
            .core_row_fn = observeRetiredCoreRow,
        };
    }

    fn beginRetirementSegment(context: *anyopaque, segment_index: u32) !void {
        const self: *ObserverV4 = @ptrCast(@alignCast(context));
        return self.semantic.begin(segment_index);
    }

    fn observeRetiredCoreRow(
        context: *anyopaque,
        row: frontend.runner.trace.TraceRow,
    ) !void {
        const self: *ObserverV4 = @ptrCast(@alignCast(context));
        return self.semantic.observeCoreRow(row);
    }

    pub fn observe(
        self: *ObserverV4,
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
            if (index != self.observed_count or index >= self.retained.sources.len)
                return error.ExecutionSegmentOrderMismatch;
            const retained_source = &self.retained.sources[index];
            if (!std.mem.eql(
                u8,
                &retained_source.value.journal_record_sha256,
                &journal_record_sha256,
            )) return error.JournalRecordMismatch;

            const is_final = index + 1 == self.retained.sources.len;
            if (segment.isComplete() != is_final)
                return error.InvalidTerminalSegment;
            // Terminal output is admitted before either fresh transport is
            // published. A failed output comparison leaves no final artifact.
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
            const live_metadata = retained_source.value.metadata;
            const projection = try projection_v3.ProjectionV3
                .initAgainstRetainedMetadata(
                &global_source,
                &retained_source.value.metadata,
            );
            const session_identity = try (try self.retained.executionAuthority())
                .sessionIdentity();
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
            self.capture_wall_ns = try add(self.capture_wall_ns, capture_wall_ns);

            var encode_timer = try std.time.Timer.start();
            const compact_value = minimal_trace.EthereumMinimalArtifactV1{
                .leaf = captured.leaf,
                .boundary_words = captured.boundary_words,
                .allocator = self.allocator,
            };
            const compact_bytes = try minimal_trace
                .encodeEthereumMinimalArtifactAlloc(
                self.allocator,
                &compact_value,
            );
            defer self.allocator.free(compact_bytes);
            const encode_wall_ns = encode_timer.read();
            self.encode_wall_ns = try add(self.encode_wall_ns, encode_wall_ns);

            if (self.capture == null) {
                self.capture = try capture_mod.SessionCaptureV2.init(
                    self.allocator,
                    session_identity,
                    0,
                    &segment.rw_memory,
                    live_metadata.entry.continuation_root,
                );
                self.owner = try publication_owner.PublicationOwnerV4
                    .initExisting(
                    self.allocator,
                    self.root,
                    &self.capture.?,
                    try self.retained.executionAuthority(),
                );
                self.public_wire_owner = try public_wire_owner_mod
                    .PublicationOwnerV4.initExisting(
                    self.allocator,
                    self.root,
                    try self.retained.executionAuthority(),
                );
            }

            const touched = try self.allocator.alloc(
                u32,
                captured.boundary_words.len,
            );
            defer self.allocator.free(touched);
            for (touched, captured.boundary_words) |*destination, word|
                destination.* = word.address;

            const input_words = if (segment.segment_role.is_first)
                try public_data.packInputWords(
                    self.allocator,
                    self.retained.input_bytes,
                )
            else
                try self.allocator.alloc(u32, 0);
            defer self.allocator.free(input_words);
            const output_words = try self.allocator.alloc(
                public_data.OutputWord,
                if (segment.segment_role.is_last) segment.output_words.len else 0,
            );
            defer self.allocator.free(output_words);
            for (output_words, segment.output_words) |*destination, word|
                destination.* = .{
                    .addr = word.addr,
                    .value = word.value,
                    .clock = word.clock,
                };
            var public_value = try frontend.air.statement_v2
                .canonicalCorePublicData(&local_wire.value);
            if (public_value.completion == null) {
                public_value.completion = public_data.Completion.canonicalSelfLoop(
                    public_value.final_pc,
                );
            }
            public_value.io_entries = .{
                .input_start = segment.input_start,
                .input_len = if (segment.segment_role.is_first)
                    @intCast(self.retained.input_bytes.len)
                else
                    0,
                .input_words = input_words,
                .output_len = if (segment.segment_role.is_last)
                    segment.output_len
                else
                    0,
                .output_len_addr = segment.output_len_addr,
                .output_data_addr = segment.output_data_addr,
                .output_words = output_words,
            };
            const public_authority = boundary_v4.SegmentPublicAuthorityV4{
                .coordinate = .{
                    .segment_index = index,
                    .segment_count = @intCast(self.retained.sources.len),
                },
                .segment_role = segment.segment_role,
                .layout = segment.rw_memory.layout,
                .public_data = &public_value,
                .continuation_roots = .{
                    .entry = live_metadata.entry.continuation_root,
                    .exit = live_metadata.exit.continuation_root,
                },
            };

            const compact_path = try publication.compactTapePathAlloc(
                self.allocator,
                self.root,
                index,
            );
            defer self.allocator.free(compact_path);
            const existed = try publication.pathExists(compact_path);
            var publish_timer = try std.time.Timer.start();
            const committed = try self.owner.?.captureAndPublish(
                index,
                &segment.rw_memory,
                touched,
                live_metadata.entry.continuation_root,
                live_metadata.exit.continuation_root,
                compact_bytes,
                retained_source.identity,
                journal_record_sha256,
                &local_wire.value,
                public_authority,
            );
            _ = try self.public_wire_owner.?.captureAndPublish(
                &local_wire.value,
                committed,
            );
            const publish_wall_ns = if (existed) 0 else publish_timer.read();
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

            var pc_timer = try std.time.Timer.start();
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
                pc_timer.read(),
            );
            self.observed_count += 1;
            self.observer_wall_ns = try add(
                self.observer_wall_ns,
                observer_timer.read(),
            );
        }
    }

    pub fn validateComplete(self: *const ObserverV4) !void {
        if (self.observed_count != publication.CANONICAL_SEGMENT_COUNT or
            self.compact_artifacts.items.len != publication.CANONICAL_SEGMENT_COUNT or
            !self.terminal_output_validated or self.owner == null or
            self.capture == null or self.public_wire_owner == null or
            self.public_wire_owner.?.publishedCount() !=
                publication.CANONICAL_SEGMENT_COUNT)
        {
            return error.IncompleteIncrementalCapturePublicationV4;
        }
    }

    pub fn programIdentity(self: *const ObserverV4) ![32]u8 {
        return (self.program orelse return error.MissingProgramAuthority).identity;
    }

    fn ensureProgram(
        self: *ObserverV4,
        segment: *const frontend.runner.SegmentResult,
    ) !void {
        if (self.program != null) return;
        const words = try self.allocator.alloc(
            minimal_trace.ProgramWord,
            segment.rw_memory.program_words.len,
        );
        errdefer self.allocator.free(words);
        for (words, segment.rw_memory.program_words) |*destination, source|
            destination.* = .{
                .address = source.addr,
                .word = source.initial_word,
            };
        self.program_words = words;
        self.program = try minimal_trace.SliceProgram.init(words);
    }
};

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch error.ProfileTimingOverflow;
}
