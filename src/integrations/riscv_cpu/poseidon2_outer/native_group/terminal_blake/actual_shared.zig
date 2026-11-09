//! Concrete qualification harness shared by explicit six/eight-role tests.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Format = @import("../keys.zig").Format;
pub fn ForArithmetic(comptime format: Format) type {
    return struct {
        const C = @import("../../../rv64_recursion/om31_poseidon/common.zig");
        const Runtime = @import("../../sponge_cpu/runtime.zig");
        const Receiver = @import("../../sponge_cpu/receiver.zig");
        const Capture = @import("../../sponge_cpu/captured_source.zig");
        const Adapter = @import("../native_adapter.zig");
        const Walk = @import("../source_walk.zig");
        const BaseStream = @import("../source.zig").Stream;
        const Stream = if (format == .r6) BaseStream else @import("../../native_dot/group_source.zig").Stream;
        const Admission = @import("../../sponge_cpu/root_admission.zig");
        const Templates = @import("../../pure_p2_gkr_templates_wire.zig");
        const Cost = if (format == .r6) @import("../cost.zig").Model else @import("../../native_dot/group_source.zig").Cost;
        const Suite = @import("profile.zig");
        const Key = if (format == .r6) @import("authority.zig").Key else @import("authority.zig").R7.Key;
        const Proof = if (format == .r6) @import("proof.zig") else @import("proof.zig").R7;
        const P2 = if (format == .r6) @import("../../native_omul/proof.zig") else @import("../../native_dot/outer_proof.zig");
        const Write = @import("../../../rv64_ethereum_batch_receipt.zig").writeExclusive;
        const native_profile = @import("../../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
        const metadata_format = if (format == .r6) "op-terminal-blake-R6-selected/v1" else "op-terminal-blake-R7-selected/v1";
        const env_prefix = if (format == .r6) "STWO_OP_TERMINAL_BLAKE_" else "STWO_OP_TERMINAL_BLAKE_R7_";
        const Metadata = struct {
            schema: u32 = 1,
            format: []const u8 = metadata_format,
            native_profile: @import("../../op_profile.zig").Profile = native_profile,
            statement: Admission.Metadata,
        };
        fn authority(source: Runtime.SourceDirectory) Admission.Authority {
            return .{ .inventory = source.inventory, .cpus = source.authority.cpu, .detached = source.authority.detached, .catalog = source.authority.catalogs, .towers = source.authority.catalog.miller, .image = source.image };
        }
        fn requireBindings(selected: *const Stream, source: Runtime.SourceDirectory) !void {
            const stream = if (format == .r6) selected else &selected.inner;
            if (source.inventory.workers.len != 4 or stream.appended != 4) return error.TerminalBlakeSelectedCoverage;
            for (stream.bindings, source.inventory.workers, 0..) |binding, worker, i| {
                if (binding.ordinal != i or worker.authority.ordinal != i or worker.authority.profile != native_profile or !std.mem.eql(u8, &binding.fixed_identity, &worker.authority.fixed_identity)) return error.TerminalBlakeSelectedSource;
            }
        }
        const Producer = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            physical: bool,
            source: ?Stream = null,
            numeric: ?Stream = null,
            leaves: std.ArrayList(Adapter.Leaf) = .empty,
            shapes: std.ArrayList([]const u8) = .empty,
            manifest: ?[36]u8 = null,
            completed: bool = false,
            fn deinit(self: *Producer) void {
                if (self.source) |*s| s.deinit();
                if (self.numeric) |*s| s.deinit();
                for (self.leaves.items) |leaf| self.a.free(leaf.claims);
                self.leaves.deinit(self.a);
                for (self.shapes.items) |shape| self.a.free(shape);
                self.shapes.deinit(self.a);
                self.dir.close();
            }
            fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, verified: Receiver.Verified) !void {
                const self: *Producer = @ptrCast(@alignCast(raw.?));
                if (verified.ordinal != self.leaves.items.len or verified.manifest.entries.len != 4) return error.TerminalBlakeSelectedCoverage;
                try Adapter.visit(a, verified, .{ .context = self, .visit = append });
            }
            fn append(raw: *anyopaque, _: std.mem.Allocator, member: Capture.View) !void {
                const self: *Producer = @ptrCast(@alignCast(raw));
                if (self.source == null) {
                    self.manifest = member.manifest();
                    self.source = try Stream.init(self.a, true, 0, 4, native_profile, self.manifest.?);
                    if (self.physical) self.numeric = try Stream.init(self.a, false, 0, 4, native_profile, self.manifest.?);
                }
                try self.leaves.ensureUnusedCapacity(self.a, 1);
                self.leaves.appendAssumeCapacity(try Adapter.metadata(self.a, member));
                if (try Adapter.template(self.a, member)) |shape| {
                    errdefer self.a.free(shape);
                    try self.shapes.append(self.a, shape);
                }
                try self.source.?.append(member);
                if (self.numeric) |*s| try s.append(member);
            }
            fn complete(raw: ?*anyopaque, _: std.mem.Allocator, source: Runtime.SourceDirectory, closed: *const Receiver.Closed) !void {
                const self: *Producer = @ptrCast(@alignCast(raw.?));
                if (self.completed or self.source == null or self.manifest == null or !std.mem.eql(u8, &closed.pending.digest, &self.manifest.?)) return error.TerminalBlakeSelectedCoverage;
                try requireBindings(&self.source.?, source);
                const metadata = Metadata{ .statement = .{ .execution = source.inventory.execution, .manifest = self.manifest.?, .leaves = self.leaves.items } };
                var prepared = try Admission.prepare(self.a, authority(source), metadata.statement);
                defer prepared.deinit();
                const output = try prepared.expectedRoot();
                try std.testing.expectEqualDeep(output, try self.source.?.expectedOutput());
                var trace = try self.source.?.finish();
                defer trace.deinit();
                const model = try Cost.derive(&trace);
                var key = try Key.init(self.a, &trace);
                defer key.deinit();
                const info = try std.json.Stringify.valueAlloc(self.a, .{ .schema = if (format == .r6) "terminal-blake-actual-source-v1" else "terminal-blake-r7-actual-source-v1", .model = model, .p2_source_identity = std.fmt.bytesToHex((if (format == .r6) key.inner.base.identity else key.inner.core.base.identity), .lower), .terminal_identity = std.fmt.bytesToHex(key.identity, .lower), .cold_p2_source_and_FIXED_ns = key.p2_source_setup_ns, .additional_blake_FIXED_ns = key.blake_fixed_setup_ns, .both_cold_costs_counted = true, .production_admission = false }, .{ .whitespace = .indent_2 });
                defer self.a.free(info);
                try Write(self.dir, "source.json", info);
                const json = try std.json.Stringify.valueAlloc(self.a, metadata, .{ .whitespace = .indent_2 });
                defer self.a.free(json);
                try Write(self.dir, "root.json", json);
                const templates = try Templates.encode(self.a, self.shapes.items);
                defer self.a.free(templates);
                try Write(self.dir, "templates.bin", templates);
                if (self.physical) {
                    var numeric = try self.numeric.?.finish();
                    defer numeric.deinit();
                    try std.testing.expectEqualDeep(model, try Cost.derive(&numeric));
                    try std.testing.expectEqualDeep(trace.base.circuit, numeric.base.circuit);
                    try std.testing.expectEqualDeep(trace.calls.items, numeric.calls.items);
                    try std.testing.expectEqualDeep(trace.native_mul_calls.items, numeric.native_mul_calls.items);
                    if (format == .r7) {
                        try std.testing.expectEqualDeep(trace.native_dot_calls.items, numeric.native_dot_calls.items);
                        try std.testing.expectEqualDeep(trace.native_input_ids.items, numeric.native_input_ids.items);
                    }
                    var recorder = E.stage_profile.Recorder.initWithOptions(self.a, "cpu", "op_terminal_blake_actual", .{ .capture_tasks = false, .capture_process_usage = true });
                    defer recorder.deinit();
                    var timer = try std.time.Timer.start();
                    const proof = try Proof.proveProfiled(self.a, &numeric, &key, &output, &recorder);
                    defer self.a.free(proof);
                    const prove_ns = timer.lap();
                    try Proof.verify(self.a, &key, &output, proof);
                    const verify_ns = timer.lap();
                    var stages = try recorder.snapshot(self.a);
                    defer stages.deinit(self.a);
                    const stage_json = try std.json.Stringify.valueAlloc(self.a, stages, .{});
                    defer self.a.free(stage_json);
                    try Write(self.dir, "stages.json", stage_json);
                    // Publication follows complete native/manifest/global/terminal
                    // admission, source binding, and the physical final proof check.
                    try Write(self.dir, "root.bin", proof);
                    try std.posix.fsync(self.dir.fd);
                    std.debug.print("OP_TERMINAL_BLAKE_ACTUAL bytes={} prove_ns={} self_verify_ns={} p2_source_and_FIXED_ns={} additional_blake_FIXED_ns={} native_reproof=false production_admission=false\n", .{ proof.len, prove_ns, verify_ns, key.p2_source_setup_ns, key.blake_fixed_setup_ns });
                }
                self.completed = true;
            }
        };
        const SourceReceiver = struct {
            a: std.mem.Allocator,
            stream: Stream,
            fn append(raw: *anyopaque, _: std.mem.Allocator, member: Capture.View) !void {
                const self: *SourceReceiver = @ptrCast(@alignCast(raw));
                try self.stream.append(member);
            }
        };
        const Reception = struct {
            path: []const u8,
            p2_path: []const u8,
            passed: bool = false,
            fn run(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
                const self: *Reception = @ptrCast(@alignCast(raw.?));
                var dir = try std.fs.cwd().openDir(self.path, .{});
                defer dir.close();
                const json = try dir.readFileAlloc(a, "root.json", 4 << 20);
                defer a.free(json);
                const parsed = try std.json.parseFromSlice(Metadata, a, json, .{});
                defer parsed.deinit();
                const metadata = parsed.value;
                if (metadata.schema != 1 or metadata.native_profile != native_profile or !std.mem.eql(u8, metadata.format, metadata_format)) return error.TerminalBlakeMetadata;
                var prepared = try Admission.prepare(a, authority(source), metadata.statement);
                defer prepared.deinit();
                const shape_bytes = try dir.readFileAlloc(a, "templates.bin", Templates.MAX_BYTES);
                defer a.free(shape_bytes);
                var shapes = try Walk.decodeTemplates(a, authority(source), shape_bytes);
                defer shapes.deinit(a);
                var receiver = SourceReceiver{ .a = a, .stream = try Stream.init(a, true, 0, 4, native_profile, prepared.manifest) };
                defer receiver.stream.deinit();
                var timer = try std.time.Timer.start();
                try Walk.visit(a, authority(source), &prepared, metadata.statement, &shapes, .{ .context = &receiver, .visit = SourceReceiver.append });
                try requireBindings(&receiver.stream, source);
                try std.testing.expectEqualDeep(try prepared.expectedRoot(), try receiver.stream.expectedOutput());
                var trace = try receiver.stream.finish();
                defer trace.deinit();
                var key = try Key.init(a, &trace);
                defer key.deinit();
                key.retireProverData();
                const setup_ns = timer.lap();
                const proof = try dir.readFileAlloc(a, "root.bin", Proof.MAX_PROOF_BYTES);
                defer a.free(proof);
                const output = try prepared.expectedRoot();
                try Proof.verify(a, &key, &output, proof);
                const verify_ns = timer.lap();
                const controls = try attacks(a, authority(source), &key, &prepared, metadata.statement, proof, self.p2_path);
                self.passed = true;
                std.debug.print("OP_TERMINAL_BLAKE_FRESH bytes={} source_setup_ns={} root_read_verify_ns={} p2_source_and_FIXED_ns={} additional_blake_FIXED_ns={} controls={} native_proof_bytes_read=0 production_admission=false\n", .{ proof.len, setup_ns, verify_ns, key.p2_source_setup_ns, key.blake_fixed_setup_ns, controls });
            }
        };
        fn refuse(a: std.mem.Allocator, key: *const Key, output: *const [9]C.Q, proof: []const u8) !void {
            if (Proof.verify(a, key, output, proof)) |_| return error.TerminalBlakeAcceptedForgery else |_| {}
        }
        fn metadataRefused(a: std.mem.Allocator, source: Admission.Authority, metadata: Admission.Metadata) !void {
            if (Admission.prepare(a, source, metadata)) |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.TerminalBlakeMetadataAccepted;
            } else |_| {}
        }
        fn attacks(a: std.mem.Allocator, source: Admission.Authority, key: *const Key, prepared: *const Admission.Prepared, metadata: Admission.Metadata, proof: []const u8, p2_path: []const u8) !u32 {
            const output = try prepared.expectedRoot();
            try Proof.verify(a, key, &output, proof);
            var controls: u32 = 0;
            var wrong = output;
            wrong[8] = wrong[8].add(C.Q.one());
            try refuse(a, key, &wrong, proof);
            controls += 1;
            const corrupt = try a.dupe(u8, proof);
            defer a.free(corrupt);
            corrupt[corrupt.len / 2] ^= 1;
            try refuse(a, key, &output, corrupt);
            controls += 1;
            var other = key.*;
            other.identity[0] ^= 1;
            try refuse(a, &other, &output, proof);
            controls += 1;
            const leaves = try a.dupe(Adapter.Leaf, metadata.leaves);
            defer a.free(leaves);
            var proposal = metadata;
            proposal.leaves = leaves[0 .. leaves.len - 1];
            try metadataRefused(a, source, proposal);
            controls += 1;
            proposal.leaves = leaves;
            std.mem.swap(Adapter.Leaf, &leaves[0], &leaves[1]);
            try metadataRefused(a, source, proposal);
            std.mem.swap(Adapter.Leaf, &leaves[0], &leaves[1]);
            controls += 1;
            leaves[0].receipt = null;
            try metadataRefused(a, source, proposal);
            leaves[0] = metadata.leaves[0];
            controls += 1;
            const cpu = try a.dupe(C.O, leaves[0].claims);
            defer a.free(cpu);
            const di = source.cpus.len;
            const detached = try a.dupe(C.O, leaves[di].claims);
            defer a.free(detached);
            cpu[cpu.len - 1] = cpu[cpu.len - 1].add(C.O.one());
            detached[2] = detached[2].sub(C.O.one());
            leaves[0].claims = cpu;
            leaves[di].claims = detached;
            var balanced = try Admission.prepare(a, source, proposal);
            defer balanced.deinit();
            try refuse(a, key, &try balanced.expectedRoot(), proof);
            controls += 1;
            // This independently built inner key is the genuine original P2 source
            // authority. Use its VALID retained proof as the cross-suite control.
            var p2_dir = try std.fs.cwd().openDir(p2_path, .{});
            defer p2_dir.close();
            const p2 = try p2_dir.readFileAlloc(a, "root.bin", 2 << 20);
            defer a.free(p2);
            try P2.verify(a, &key.inner, &output, p2);
            try std.testing.expectError(error.TerminalBlakeWire, Proof.verify(a, key, &output, p2));
            try std.testing.expectError(if (format == .r6) error.InvalidNativeOmulWire else error.InvalidNativeDotR7Wire, P2.verify(a, &key.inner, &output, proof));
            controls += 2;
            try Proof.verify(a, key, &output, proof);
            return controls;
        }
        pub fn run() !void {
            const config_path = std.posix.getenv(env_prefix ++ "CONFIG") orelse return error.SkipZigTest;
            const input = std.posix.getenv(env_prefix ++ "NATIVE") orelse return error.MissingTerminalBlakeInput;
            const out = std.posix.getenv(env_prefix ++ "OUT") orelse return error.MissingTerminalBlakeOutput;
            const mode = std.posix.getenv(env_prefix ++ "MODE") orelse "source";
            const physical = std.mem.eql(u8, mode, "prove");
            const verify = std.mem.eql(u8, mode, "verify");
            if (!physical and !verify and !std.mem.eql(u8, mode, "source")) return error.TerminalBlakeMode;
            const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
            defer std.testing.allocator.free(raw);
            const parsed = try std.json.parseFromSlice(@import("../../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
            defer parsed.deinit();
            if (parsed.value.max_steps > 10_000_000) return error.TerminalBlakeSmallOnly;
            const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
            defer budget.destroy();
            var pool: E.work_pool.WorkPool = .{};
            try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
            defer pool.deinit();
            var bind = try E.work_pool.ScopedPoolBinding.init(&pool);
            defer bind.deinit();
            var timer = try std.time.Timer.start();
            if (!verify) {
                try std.fs.cwd().makeDir(out);
                var producer = Producer{ .a = budget.allocator(), .dir = try std.fs.cwd().openDir(out, .{}), .physical = physical };
                defer producer.deinit();
                try Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, input, native_profile, .{}, .{ .context = &producer, .complete = Producer.complete, .fragments = .{ .context = &producer, .fragment = Producer.fragment } });
                if (!producer.completed) return error.TerminalBlakeSelectedCoverage;
            } else {
                const p2_path = std.posix.getenv(env_prefix ++ "P2_CONTROL") orelse return error.MissingTerminalBlakeP2Control;
                var receiver = Reception{ .path = out, .p2_path = p2_path };
                try Runtime.withSourceDirectory(budget.allocator(), parsed.value, input, native_profile, .{}, &receiver, Reception.run);
                if (!receiver.passed) return error.TerminalBlakeSelectedCoverage;
            }
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
            std.debug.print("OP_TERMINAL_BLAKE_COMPLETE mode={s} total_ns={} peak_requested={} cap={} final_live=0 security_qualified=false production_admission=false\n", .{ mode, timer.read(), budget.snapshot().peak_live_bytes, @as(usize, 32) << 30 });
        }
    };
}
