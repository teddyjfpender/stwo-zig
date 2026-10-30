//! Finite-family complete source census, including every committed cell.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return struct {
        const is_local = family == .local_open;
        // Complete independently reconstructed source geometry for endpoint root
        // benchmarks. Cell counts are physical (include padding and every fixed/key
        // column); no endpoint/native/provider tree is omitted from the census.
        const std = @import("std");
        const core = @import("stwo_core");
        const Profile = @import("block_v8_endpoint_recursive_profile_v1.zig").For(family);
        pub const Cells = struct {
            columns: usize = 0,
            cells: u64 = 0,
            bytes: u64 = 0,
            pub fn from(logs: []const u32) !Cells {
                var out = Cells{ .columns = logs.len };
                for (logs) |log| {
                    if (log >= 63) return error.EndpointReportGeometryOverflow;
                    out.cells = try std.math.add(u64, out.cells, @as(u64, 1) << @intCast(log));
                }
                out.bytes = try std.math.mul(u64, out.cells, @sizeOf(core.fields.m31.M31));
                return out;
            }
        };
        pub const Part = struct { fixed: Cells, main: Cells, interaction: Cells };
        pub const Tree = struct {
            index: usize,
            columns: usize,
            raw_cells: u64,
            extended_cells: u64,
            samples: usize,
            minimum_raw_log: u32,
            maximum_raw_log: u32,
        };
        pub const Report = struct {
            schema: []const u8 = "stwo-b8-endpoint-root-source-full-cells-v1",
            family: []const u8 = @tagName(family),
            trace_trees: usize = Profile.TRACE_TREES,
            composition_trees: usize = 1,
            first_roots: usize = Profile.FIRST_ROOTS,
            relation_pairs: usize = Profile.RELATION_PAIRS,
            queries: usize,
            pow_bits: u32,
            native: Part,
            endpoints: Part,
            endpoint_range16: Part,
            program: Part,
            lookup: Part,
            global_memory: ?Part,
            trees: [Profile.TRACE_TREES + 1]Tree,
            total_raw_cells: u64,
            total_extended_cells: u64,
            total_raw_bytes: u64,
            total_extended_bytes: u64,
            native_guard_components: usize,
            native_guard_main_cells: u64,
            native_projection_claims: usize,
            endpoint_count: u32,
            logical_ram_accesses: u64,
            global_ram_components: usize,
            snapshot_changes: usize,
            physical_public_operands: usize,
            snapshot_delta_public_byte_ports: usize,
            cpu_boundary_public_byte_ports: usize = 104 * 4,
            total_public_operands: usize,
            total_oods_samples: usize,
            original_constraints: usize,
            composition_log: u32,
            composition_split: u32,
            mask_log: u32,
            lifting_log: u32,
            source_profile_id: [64]u8,
            source_epoch: [64]u8,
            native_identity: [64]u8,
            native_layout: [64]u8,
            fixed_root: [64]u8,
            deep_profile: [64]u8,
            fri_profile: [64]u8,
        };
        pub fn derive(p: *const Profile.Owned) !Report {
            try p.validate();
            const local = p.context.local.?;
            const bits = p.shape.config.fri_config.log_blowup_factor;
            var trees: [Profile.TRACE_TREES + 1]Tree = undefined;
            var total_raw: u64 = 0;
            var total_extended: u64 = 0;
            var total_samples: usize = 0;
            var column: usize = 0;
            for (&trees, p.shape.columns, 0..) |*tree, logs, index| {
                var raw: u64 = 0;
                var extended: u64 = 0;
                var samples: usize = 0;
                var minimum: u32 = 0;
                var maximum: u32 = 0;
                for (logs, 0..) |log, ordinal| {
                    if (log < bits or log >= 63) return error.EndpointReportGeometryOverflow;
                    const raw_log = log - bits;
                    raw = try std.math.add(u64, raw, @as(u64, 1) << @intCast(raw_log));
                    extended = try std.math.add(u64, extended, @as(u64, 1) << @intCast(log));
                    samples = try std.math.add(usize, samples, p.shape.layouts[column].sampleCount());
                    minimum = if (ordinal == 0) raw_log else @min(minimum, raw_log);
                    maximum = @max(maximum, raw_log);
                    column += 1;
                }
                tree.* = .{ .index = index, .columns = logs.len, .raw_cells = raw, .extended_cells = extended, .samples = samples, .minimum_raw_log = minimum, .maximum_raw_log = maximum };
                total_raw = try std.math.add(u64, total_raw, raw);
                total_extended = try std.math.add(u64, total_extended, extended);
                total_samples = try std.math.add(usize, total_samples, samples);
            }
            if (column != p.shape.layouts.len) return error.InvalidEndpointReportSampleInventory;
            const native_fixed = try Cells.from(local.native.fixed);
            const endpoint_log = local.endpoint_log;
            const endpoint_rows = @as(u64, 1) << @intCast(endpoint_log);
            var guard_cells: u64 = 0;
            for (local.native.guards) |guard| guard_cells = try std.math.add(u64, guard_cells, @as(u64, 2) << @intCast(guard.log_size));
            var logical_accesses: u64 = 0;
            for (p.statement.input.shape.component_descs[0..p.statement.input.shape.n_components]) |desc| {
                if (desc.family == .load_store) logical_accesses = try std.math.add(u64, logical_accesses, desc.n_rows);
            }
            const changes = if (is_local) 0 else p.statement.trusted.window.?.changes.len;
            const physical = if (is_local) 8 + p.claims.native.len + 11 + 2 + 1 + 6 else try std.math.add(usize, 8 + p.claims.native.len + 11 + 2 + 1 + 6 + 4, try std.math.mul(usize, 86, p.claims.memory.ram.len));
            const delta_ports = try std.math.mul(usize, 12, changes);
            const public = try std.math.add(usize, physical + 104 * 4, delta_ports);
            const out = Report{
                .queries = p.shape.config.fri_config.n_queries,
                .pow_bits = p.shape.config.pow_bits,
                .native = .{ .fixed = native_fixed, .main = try Cells.from(local.native.main), .interaction = try Cells.from(local.native.interactions) },
                .endpoints = .{ .fixed = .{ .columns = 2, .cells = 2 * endpoint_rows, .bytes = 8 * endpoint_rows }, .main = try Cells.from(&local.endpoint_main_logs), .interaction = try Cells.from(&local.endpoint_interaction_logs) },
                .endpoint_range16 = .{ .fixed = .{ .columns = 2, .cells = 2 * 65536, .bytes = 8 * 65536 }, .main = try Cells.from(&local.range_main_logs), .interaction = try Cells.from(&local.range_interaction_logs) },
                .program = try part(p.context.program.?.logs),
                .lookup = try part(p.context.lookup.?.logs),
                .global_memory = if (is_local) null else try part(p.context.memory.?.logs),
                .trees = trees,
                .total_raw_cells = total_raw,
                .total_extended_cells = total_extended,
                .total_raw_bytes = try std.math.mul(u64, total_raw, 4),
                .total_extended_bytes = try std.math.mul(u64, total_extended, 4),
                .native_guard_components = local.native.guards.len,
                .native_guard_main_cells = guard_cells,
                .native_projection_claims = p.claims.native.len,
                .endpoint_count = p.statement.input.endpoint_count,
                .logical_ram_accesses = logical_accesses,
                .global_ram_components = if (is_local) 0 else p.claims.memory.ram.len,
                .snapshot_changes = changes,
                .physical_public_operands = physical,
                .snapshot_delta_public_byte_ports = delta_ports,
                .total_public_operands = public,
                .total_oods_samples = total_samples,
                .original_constraints = p.constraint_count,
                .composition_log = p.shape.composition_log,
                .composition_split = p.shape.split,
                .mask_log = p.shape.mask_log,
                .lifting_log = p.shape.lifting_log,
                .source_profile_id = std.fmt.bytesToHex(p.seal, .lower),
                .source_epoch = std.fmt.bytesToHex(p.scope.epoch.digest, .lower),
                .native_identity = std.fmt.bytesToHex(p.scope.descriptor.scope.native_identity, .lower),
                .native_layout = std.fmt.bytesToHex(local.native.layout.digest, .lower),
                .fixed_root = std.fmt.bytesToHex(p.fixed_root, .lower),
                .deep_profile = std.fmt.bytesToHex(p.shape.deepProfile().identityDigest(), .lower),
                .fri_profile = std.fmt.bytesToHex(p.shape.friProfile().identityDigest(), .lower),
            };
            var part_cells: u64 = 0;
            for ([_]Part{ out.native, out.endpoints, out.endpoint_range16, out.program, out.lookup }) |item| {
                part_cells = try std.math.add(u64, part_cells, item.fixed.cells);
                part_cells = try std.math.add(u64, part_cells, item.main.cells);
                part_cells = try std.math.add(u64, part_cells, item.interaction.cells);
            }
            if (out.global_memory) |memory| {
                for ([_]Cells{ memory.fixed, memory.main, memory.interaction }) |cells| part_cells = try std.math.add(u64, part_cells, cells.cells);
            }
            if (part_cells != out.total_raw_cells - out.trees[Profile.TRACE_TREES].raw_cells) return error.IncompleteEndpointReportCellInventory;
            return out;
        }
        fn part(logs: [3][]u32) !Part {
            return .{ .fixed = try Cells.from(logs[0]), .main = try Cells.from(logs[1]), .interaction = try Cells.from(logs[2]) };
        }

        // This frontend manifest is embedded at compilation, so later workspace edits
        // cannot relabel a benchmark binary. The complete engine/backend manifest is
        // archived by the enclosing campaign independently.
        const source_files = .{
            .{ "block_v8_endpoint_local_recursive_v1.zig", @embedFile("block_v8_endpoint_local_recursive_v1.zig") },
            .{ "tests/block_v8_endpoint_local_recursion_test.zig", @embedFile("tests/block_v8_endpoint_local_recursion_test.zig") },
            .{ "block_v8_endpoint_recursive_fixed_roster_v1.zig", @embedFile("block_v8_endpoint_recursive_fixed_roster_v1.zig") },
            .{ "block_v8_endpoint_recursive_pcs_preparation_v1.zig", @embedFile("block_v8_endpoint_recursive_pcs_preparation_v1.zig") },
            .{ "block_v8_endpoint_recursive_pcs_profile_v1.zig", @embedFile("block_v8_endpoint_recursive_pcs_profile_v1.zig") },
            .{ "block_v8_endpoint_recursive_pipeline_v1.zig", @embedFile("block_v8_endpoint_recursive_pipeline_v1.zig") },
            .{ "block_v8_endpoint_recursive_preparation_v1.zig", @embedFile("block_v8_endpoint_recursive_preparation_v1.zig") },
            .{ "block_v8_endpoint_recursive_profile_v1.zig", @embedFile("block_v8_endpoint_recursive_profile_v1.zig") },
            .{ "block_v8_endpoint_recursive_protocol_v1.zig", @embedFile("block_v8_endpoint_recursive_protocol_v1.zig") },
            .{ "block_v8_endpoint_recursive_public_v1.zig", @embedFile("block_v8_endpoint_recursive_public_v1.zig") },
            .{ "block_v8_endpoint_recursive_receiver_v1.zig", @embedFile("block_v8_endpoint_recursive_receiver_v1.zig") },
            .{ "block_v8_endpoint_recursive_source_v1.zig", @embedFile("block_v8_endpoint_recursive_source_v1.zig") },
            .{ "air/block_v8_endpoint_recursive_closure_v1.zig", @embedFile("air/block_v8_endpoint_recursive_closure_v1.zig") },
            .{ "air/block_v8_endpoint_recursive_composition_v1.zig", @embedFile("air/block_v8_endpoint_recursive_composition_v1.zig") },
            .{ "air/block_v8_endpoint_recursive_transcript_v1.zig", @embedFile("air/block_v8_endpoint_recursive_transcript_v1.zig") },
            .{ "block_v8_endpoint_recursive_report_v1.zig", @embedFile("block_v8_endpoint_recursive_report_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_bundle_v1.zig", @embedFile("../prover/block_v8_endpoint_local_bundle_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_codec_v1.zig", @embedFile("../prover/block_v8_endpoint_local_codec_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_context_v1.zig", @embedFile("../prover/block_v8_endpoint_local_context_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_execution_v1.zig", @embedFile("../prover/block_v8_endpoint_local_execution_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_ledger_v1.zig", @embedFile("../prover/block_v8_endpoint_local_ledger_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_placement_v1.zig", @embedFile("../prover/block_v8_endpoint_local_placement_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_program_v1.zig", @embedFile("../prover/block_v8_endpoint_local_program_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_proof_v1.zig", @embedFile("../prover/block_v8_endpoint_local_proof_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_retained_v1.zig", @embedFile("../prover/block_v8_endpoint_local_retained_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_scope_v1.zig", @embedFile("../prover/block_v8_endpoint_local_scope_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_shape_v1.zig", @embedFile("../prover/block_v8_endpoint_local_shape_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_statement_v1.zig", @embedFile("../prover/block_v8_endpoint_local_statement_v1.zig") },
            .{ "../prover/block_v8_endpoint_local_statement_wire_v1.zig", @embedFile("../prover/block_v8_endpoint_local_statement_wire_v1.zig") },

            .{ "air/blake3_parent_input_inventory.zig", @embedFile("air/blake3_parent_input_inventory.zig") },
            .{ "block_v5_recursive_fused_public_bus_v1.zig", @embedFile("block_v5_recursive_fused_public_bus_v1.zig") },
            .{ "block_v8_endpoint_root_source_report_v1.zig", @embedFile("block_v8_endpoint_root_source_report_v1.zig") },
            .{ "tests/block_v8_endpoint_saved_root_benchmark.zig", @embedFile("tests/block_v8_endpoint_saved_root_benchmark.zig") },
            .{ "block_v8_endpoint_original_profile_v1.zig", @embedFile("block_v8_endpoint_original_profile_v1.zig") },
            .{ "air/block_v8_endpoint_composition_v1.zig", @embedFile("air/block_v8_endpoint_composition_v1.zig") },
            .{ "air/block_v8_endpoint_closure_v1.zig", @embedFile("air/block_v8_endpoint_closure_v1.zig") },
            .{ "air/block_v8_endpoint_transcript_v1.zig", @embedFile("air/block_v8_endpoint_transcript_v1.zig") },
            .{ "air/block_v6_partitioned_composition_v1.zig", @embedFile("air/block_v6_partitioned_composition_v1.zig") },
            .{ "block_v8_endpoint_fixed_roster_v1.zig", @embedFile("block_v8_endpoint_fixed_roster_v1.zig") },
            .{ "block_v8_endpoint_pipeline_v1.zig", @embedFile("block_v8_endpoint_pipeline_v1.zig") },
            .{ "block_v8_endpoint_preparation_v1.zig", @embedFile("block_v8_endpoint_preparation_v1.zig") },
            .{ "block_v8_endpoint_public_v1.zig", @embedFile("block_v8_endpoint_public_v1.zig") },
            .{ "block_v8_endpoint_receiver_v1.zig", @embedFile("block_v8_endpoint_receiver_v1.zig") },
            .{ "block_v8_endpoint_pcs_preparation_v1.zig", @embedFile("block_v8_endpoint_pcs_preparation_v1.zig") },
            .{ "block_v8_endpoint_pcs_profile_v1.zig", @embedFile("block_v8_endpoint_pcs_profile_v1.zig") },
            .{ "block_v8_endpoint_parent_protocol_v1.zig", @embedFile("block_v8_endpoint_parent_protocol_v1.zig") },
            .{ "block_v6_original_fixed_shape_v1.zig", @embedFile("block_v6_original_fixed_shape_v1.zig") },
            .{ "component_sample_layout_v1.zig", @embedFile("component_sample_layout_v1.zig") },
            .{ "../prover/block_v8_native_endpoint_layout_v1.zig", @embedFile("../prover/block_v8_native_endpoint_layout_v1.zig") },
            .{ "../air/statement.zig", @embedFile("../air/statement.zig") },
            .{ "../prover/guest_precompile/proof_artifact_wire.zig", @embedFile("../prover/guest_precompile/proof_artifact_wire.zig") },
            .{ "../prover/block_v8_native_endpoint_layout_v3.zig", @embedFile("../prover/block_v8_native_endpoint_layout_v3.zig") },
            .{ "../prover/block_v8_native_endpoint_profile_v1.zig", @embedFile("../prover/block_v8_native_endpoint_profile_v1.zig") },
            .{ "../prover/block_v8_native_endpoint_interactions_v3.zig", @embedFile("../prover/block_v8_native_endpoint_interactions_v3.zig") },
            .{ "../prover/block_v8_ram_clock_v3_kernel.zig", @embedFile("../prover/block_v8_ram_clock_v3_kernel.zig") },
            .{ "../prover/block_v8_ram_clock_v3_component.zig", @embedFile("../prover/block_v8_ram_clock_v3_component.zig") },
            .{ "../prover/block_v8_ram_clock_v3_infrastructure.zig", @embedFile("../prover/block_v8_ram_clock_v3_infrastructure.zig") },
            .{ "../prover/block_v8_ram_clock_v3_lookup.zig", @embedFile("../prover/block_v8_ram_clock_v3_lookup.zig") },
            .{ "../prover/block_v8_ram_clock_v3_stage.zig", @embedFile("../prover/block_v8_ram_clock_v3_stage.zig") },
            .{ "../prover/block_v8_ram_clock_v3_range.zig", @embedFile("../prover/block_v8_ram_clock_v3_range.zig") },
            .{ "../prover/block_v8_native_endpoint_components_v1.zig", @embedFile("../prover/block_v8_native_endpoint_components_v1.zig") },
            .{ "../prover/block_v8_native_halt_policy_v1.zig", @embedFile("../prover/block_v8_native_halt_policy_v1.zig") },
            .{ "../prover/block_v8_native_halt_component_v1.zig", @embedFile("../prover/block_v8_native_halt_component_v1.zig") },
            .{ "../prover/block_v8_native_endpoint_local_source_v1.zig", @embedFile("../prover/block_v8_native_endpoint_local_source_v1.zig") },
            .{ "../prover/block_v8_native_endpoint_closure_v1.zig", @embedFile("../prover/block_v8_native_endpoint_closure_v1.zig") },
            .{ "../prover/block_v8_ram_endpoint_component_v1.zig", @embedFile("../prover/block_v8_ram_endpoint_component_v1.zig") },
            .{ "../prover/block_v8_ram_endpoint_kernel_v1.zig", @embedFile("../prover/block_v8_ram_endpoint_kernel_v1.zig") },
            .{ "../prover/block_v8_endpoint_range_provider_v1.zig", @embedFile("../prover/block_v8_endpoint_range_provider_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_proof_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_proof_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_context_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_context_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_scope_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_scope_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_ledger_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_ledger_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_placement_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_placement_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_codec_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_codec_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_loader_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_loader_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_statement_wire_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_statement_wire_v1.zig") },
            .{ "../prover/block_v8_endpoint_whole_shape_v1.zig", @embedFile("../prover/block_v8_endpoint_whole_shape_v1.zig") },
        };
        pub const SourcePin = struct { path: []const u8, sha256: [64]u8 };
        pub const Manifest = struct {
            schema: []const u8 = "stwo-b8-endpoint-embedded-frontend-source-v2",
            family: []const u8 = @tagName(family),
            base_directory: []const u8 = "src/frontends/riscv/recursion",
            digest: [64]u8,
            files: [source_files.len]SourcePin,
        };
        pub fn manifest() Manifest {
            var out: Manifest = undefined;
            out.schema = "stwo-b8-endpoint-embedded-frontend-source-v2";
            out.family = @tagName(family);
            out.base_directory = "src/frontends/riscv/recursion";
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(out.schema);
            h.update(out.family);
            inline for (source_files, 0..) |source, index| {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(source[1], &digest, .{});
                h.update(source[0]);
                h.update(&.{0});
                h.update(&digest);
                out.files[index] = .{ .path = source[0], .sha256 = std.fmt.bytesToHex(digest, .lower) };
            }
            var digest: [32]u8 = undefined;
            h.final(&digest);
            out.digest = std.fmt.bytesToHex(digest, .lower);
            return out;
        }
    };
}
