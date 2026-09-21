//! Focused product commands for the complete typed CSP ECDSA guest proof.
const std = @import("std");

pub fn App(comptime Deps: type) type {
    return struct {
        const stwo = Deps.stwo;
        const frontend = stwo.frontends.riscv;
        const csp = frontend.prover_mod.guest_precompile.ecdsa_csp;
        const Engine = Deps.Engine;
        const stage_profile = stwo.prover.stage_profile;
        const resources = stwo.prover.measurement.resource_report;
        const config = frontend.prover_mod.SECURE_PCS_CONFIG;
        const identity = Deps.csp_identity;
        const atomic = stwo.interop.atomic_file;
        const Runtime = if (Deps.backend == .metal) Deps.CspRuntime else NoRuntime;
        const Sample = struct {
            execution_ns: u64,
            witness_and_proving_ns: u64,
            verification_ns: u64,
            metal_dispatches: u64,
            cpu_fallbacks: u64,
        };
        const Options = struct {
            input: ?[]const u8 = null,
            elf: ?[]const u8 = null,
            artifact: ?[]const u8 = null,
            proof_out: ?[]const u8 = null,
            report_out: ?[]const u8 = null,
            profile_out: ?[]const u8 = null,
            warmups: usize = 1,
            samples: usize = 10,
            workers: usize = 16,
        };

        pub fn tryRun(allocator: std.mem.Allocator, args: []const []const u8) !bool {
            if (args.len == 0 or !std.mem.startsWith(u8, args[0], "ecdsa-csp-")) return false;
            const select = std.mem.eql(u8, args[0], "ecdsa-csp-select");
            const verify = std.mem.eql(u8, args[0], "ecdsa-csp-verify");
            if (!select and !verify and !std.mem.eql(u8, args[0], "ecdsa-csp-bench"))
                return error.UnknownCommand;
            if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
                try Deps.cli.writeUsage(std.fs.File.stdout().deprecatedWriter(), null);
                return true;
            }
            var options = Options{};
            var seen = std.StringHashMap(void).init(allocator);
            defer seen.deinit();
            var index: usize = 1;
            while (index < args.len) : (index += 2) {
                if (index + 1 >= args.len) return error.MissingArgumentValue;
                const flag = args[index];
                const entry = try seen.getOrPut(flag);
                if (entry.found_existing) return error.DuplicateArgument;
                const value = args[index + 1];
                if (std.mem.eql(u8, flag, "--input")) options.input = value else if (std.mem.eql(u8, flag, "--elf")) options.elf = value else if (std.mem.eql(u8, flag, "--artifact")) options.artifact = value else if (std.mem.eql(u8, flag, "--proof-out")) options.proof_out = value else if (std.mem.eql(u8, flag, "--report-out")) options.report_out = value else if (std.mem.eql(u8, flag, "--profile-out")) options.profile_out = value else if (std.mem.eql(u8, flag, "--warmups")) options.warmups = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, flag, "--samples")) options.samples = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, flag, "--workers")) options.workers = try std.fmt.parseInt(usize, value, 10) else return error.UnknownArgument;
            }
            const input = try read(allocator, options.input orelse return error.MissingInput, 161);
            defer allocator.free(input);
            if (input.len != 161) return error.InvalidCspInputLength;
            if (select) {
                if (seen.count() != 1) return error.IrrelevantArgument;
                try writeJson(allocator, .{ .schema = "stwo.csp.ecdsa-route.v1", .recovery_id = csp.recoveryId(input), .input_sha256 = &hex(input) });
                return true;
            }
            const elf = try read(allocator, options.elf orelse return error.MissingElf, 16 * 1024 * 1024);
            defer allocator.free(elf);
            if (verify) {
                if (seen.count() != 3) return error.IrrelevantArgument;
                const encoded = try read(allocator, options.artifact orelse return error.MissingArtifact, 256 * 1024 * 1024);
                defer allocator.free(encoded);
                const digest = try csp.verify(Engine, allocator, elf, input, config, encoded);
                try writeJson(allocator, .{
                    .schema = "stwo.csp.ecdsa-verify.v1",
                    .status = "verified",
                    .artifact_sha256 = &hex(encoded),
                    .statement_sha256 = &std.fmt.bytesToHex(digest, .lower),
                    .elf_sha256 = &hex(elf),
                    .input_sha256 = &hex(input),
                    .pcs_config = config,
                });
                return true;
            }
            if (options.artifact != null or options.samples == 0 or options.samples > 21 or
                options.warmups > 10 or options.workers < 1 or options.workers > 32)
                return error.InvalidBenchmarkOptions;
            const proof_out = options.proof_out orelse return error.MissingOutput;
            const report_out = options.report_out orelse return error.MissingReport;
            try Deps.output_transaction.prepare(proof_out, report_out);
            var runtime = try Runtime.init(allocator);
            defer runtime.deinit();
            const samples = try allocator.alloc(Sample, options.samples);
            defer allocator.free(samples);
            var retained: ?csp.Result = null;
            defer if (retained) |result| allocator.free(result.encoded);
            var recorder = stage_profile.Recorder.initWithOptions(allocator, @tagName(Deps.backend), "csp_ecdsa_guest", .{ .capture_tasks = false });
            defer recorder.deinit();
            const resources_before = resources.capture();
            for (0..options.warmups + options.samples) |iteration| {
                const before = if (Deps.backend == .metal) try Engine.telemetrySnapshot() else {};
                const result = try csp.proveWithRecorder(Engine, allocator, elf, input, config, options.workers, if (options.profile_out != null) &recorder else null);
                errdefer allocator.free(result.encoded);
                var dispatches: u64 = 0;
                var fallbacks: u64 = 0;
                if (Deps.backend == .metal) {
                    const delta = (try Engine.telemetrySnapshot()).delta(before);
                    try delta.requireMetalDispatch();
                    dispatches = delta.counters.metalDispatchTotal();
                    fallbacks = delta.counters.cpuFallbackTotal();
                }
                if (iteration >= options.warmups) samples[iteration - options.warmups] = .{
                    .execution_ns = result.execution_ns,
                    .witness_and_proving_ns = result.proving_ns,
                    .verification_ns = result.verification_ns,
                    .metal_dispatches = dispatches,
                    .cpu_fallbacks = fallbacks,
                };
                if (retained) |previous| allocator.free(previous.encoded);
                retained = result;
            }
            if (options.profile_out) |path| {
                var profile = try recorder.snapshot(allocator);
                defer profile.deinit(allocator);
                const profile_json = try std.json.Stringify.valueAlloc(allocator, profile, .{});
                defer allocator.free(profile_json);
                try atomic.writeExclusive(allocator, path, profile_json);
            }
            try runtime.finish();
            const result = retained.?;
            const report = try std.json.Stringify.valueAlloc(allocator, .{
                .schema = "stwo.csp.ecdsa-guest-benchmark.v1",
                .backend = @tagName(Deps.backend),
                .proof_scope = "riscv_guest",
                .uses_precompile = true,
                .recursion_enabled = false,
                .implementation_commit = identity.implementation_commit,
                .implementation_dirty = identity.implementation_dirty,
                .pcs_config = config,
                .warmups = options.warmups,
                .samples = options.samples,
                .verified_samples = options.samples,
                .workers = options.workers,
                .cycles = result.cycles,
                .proof_bytes = result.proof_bytes,
                .artifact_bytes = result.encoded.len,
                .recovery_id = result.recovery_id,
                .input_sha256 = &hex(input),
                .elf_sha256 = &hex(elf),
                .artifact_sha256 = &hex(result.encoded),
                .statement_sha256 = &std.fmt.bytesToHex(result.statement_sha256, .lower),
                .output_digest = &std.fmt.bytesToHex(input[0..32].*, .lower),
                .measurements = samples,
                .resources = resources.report(resources_before, resources.capture()),
            }, .{});
            defer allocator.free(report);
            const temporary = try atomic.temporaryPathAlloc(allocator, proof_out, "csp-ecdsa");
            defer allocator.free(temporary);
            defer std.fs.cwd().deleteFile(temporary) catch {};
            try atomic.writeExclusive(allocator, temporary, result.encoded);
            try Deps.output_transaction.publishResult(atomic, allocator, temporary, proof_out, report, report_out, std.fs.File.stdout().deprecatedWriter());
            return true;
        }

        fn read(allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
            return std.fs.cwd().readFileAlloc(allocator, path, limit);
        }
        fn hex(bytes: []const u8) [64]u8 {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            return std.fmt.bytesToHex(digest, .lower);
        }
        fn writeJson(allocator: std.mem.Allocator, value: anytype) !void {
            const encoded = try std.json.Stringify.valueAlloc(allocator, value, .{});
            defer allocator.free(encoded);
            try std.fs.File.stdout().deprecatedWriter().print("{s}\n", .{encoded});
        }
    };
}

const NoRuntime = struct {
    fn init(_: std.mem.Allocator) !NoRuntime {
        return .{};
    }
    fn finish(_: *NoRuntime) !void {}
    fn deinit(_: *NoRuntime) void {}
};
