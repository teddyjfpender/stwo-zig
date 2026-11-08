//! Focused product commands for the complete typed CSP ECDSA guest proof.
const std = @import("std");

pub fn App(comptime Deps: type) type {
    return struct {
        const stwo = Deps.stwo;
        const frontend = stwo.frontends.riscv;
        const csp = frontend.prover_mod.guest_precompile.ecdsa_csp;
        const Engine = Deps.Engine;
        const config = frontend.prover_mod.SECURE_PCS_CONFIG;
        const atomic = stwo.interop.atomic_file;
        const Options = struct {
            input: ?[]const u8 = null,
            elf: ?[]const u8 = null,
            artifact: ?[]const u8 = null,
            expected_statement: ?[]const u8 = null,
            proof_out: ?[]const u8 = null,
            report_out: ?[]const u8 = null,
            profile_out: ?[]const u8 = null,
            warmups: usize = 1,
            samples: usize = 10,
            workers: usize = 16,
            host_byte_budget: ?usize = null,
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
                if (std.mem.eql(u8, flag, "--host-byte-budget")) options.host_byte_budget = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, flag, "--expect-statement-digest")) options.expected_statement = value else if (std.mem.eql(u8, flag, "--input")) options.input = value else if (std.mem.eql(u8, flag, "--elf")) options.elf = value else if (std.mem.eql(u8, flag, "--artifact")) options.artifact = value else if (std.mem.eql(u8, flag, "--proof-out")) options.proof_out = value else if (std.mem.eql(u8, flag, "--report-out")) options.report_out = value else if (std.mem.eql(u8, flag, "--profile-out")) options.profile_out = value else if (std.mem.eql(u8, flag, "--warmups")) options.warmups = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, flag, "--samples")) options.samples = try std.fmt.parseInt(usize, value, 10) else if (std.mem.eql(u8, flag, "--workers")) options.workers = try std.fmt.parseInt(usize, value, 10) else return error.UnknownArgument;
            }
            if (!select and !verify and comptime Engine.Hasher != stwo.core.proof_suites.Blake3.Hasher)
                return error.LegacyProofGenerationRemoved;
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
            if (verify and Engine.Hasher == stwo.core.proof_suites.Blake3.Hasher) {
                if (seen.count() != 4) return error.IrrelevantArgument;
                const expected_hex = options.expected_statement orelse return error.MissingStatementDigest;
                if (expected_hex.len != 64) return error.InvalidStatementDigest;
                var expected: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(&expected, expected_hex);
                try Deps.adapter.verifyCspPath(Engine, allocator, options.artifact orelse return error.MissingArtifact, expected, options.elf.?, options.input.?);
                return true;
            }
            if (verify) {
                if (seen.count() != 3) return error.IrrelevantArgument;
                const encoded = try read(allocator, options.artifact orelse return error.MissingArtifact, 256 * 1024 * 1024);
                defer allocator.free(encoded);
                const verified = try csp.verifyWithReceipt(Engine, allocator, elf, input, config, encoded);
                try writeJson(allocator, .{
                    .schema = "stwo.csp.ecdsa-verify.v2",
                    .status = "verified",
                    .transcript_receipt = receiptJson(verified.transcript_receipt),
                    .artifact_sha256 = &hex(encoded),
                    .statement_sha256 = &std.fmt.bytesToHex(verified.statement_sha256, .lower),
                    .elf_sha256 = &hex(elf),
                    .input_sha256 = &hex(input),
                    .pcs_config = config,
                });
                return true;
            }
            if (options.expected_statement != null or options.artifact != null or options.samples == 0 or options.samples > 21 or
                options.warmups > 10 or options.workers < 1 or options.workers > 32)
                return error.InvalidBenchmarkOptions;
            const proof_out = options.proof_out orelse return error.MissingOutput;
            const report_out = options.report_out orelse return error.MissingReport;
            try Deps.output_transaction.prepare(proof_out, report_out);
            if (Engine.Hasher == stwo.core.proof_suites.Blake3.Hasher) {
                try frontend.runner.elf_loader.validateReleaseAbiForProfile(elf, .rv32im_zkvm_ethereum_v1);
                if (csp.recoveryId(input) == null) return error.SoftwareFallbackRequired;
                if (options.profile_out) |path| {
                    if (std.mem.eql(u8, path, proof_out) or std.mem.eql(u8, path, report_out)) return error.OutputPathCollision;
                    try Deps.output_transaction.prepare(null, path);
                }
                const temporary = try atomic.temporaryPathAlloc(allocator, proof_out, "proof");
                defer allocator.free(temporary);
                defer std.fs.cwd().deleteFile(temporary) catch {};
                const report = try Deps.adapter.run(Engine, Deps.backend, allocator, options.elf.?, options.input, .{
                    .backend = Deps.backend,
                    .protocol = .secure,
                    .mode = .{ .bench = .{ .warmups = options.warmups, .samples = options.samples, .profiled = options.profile_out != null } },
                    .experimental = false,
                    .proof_temporary = temporary,
                    .proof_report_path = proof_out,
                    .workers = options.workers,
                    .csp_ecdsa = true,
                    .host_byte_budget = options.host_byte_budget,
                });
                defer allocator.free(report);
                // Full-width profiling uses the report's disjoint phase timings.
                if (options.profile_out) |path| try atomic.writeExclusive(allocator, path, report);
                errdefer if (options.profile_out) |path| std.fs.cwd().deleteFile(path) catch {};
                try Deps.output_transaction.publishResult(atomic, allocator, temporary, proof_out, report, report_out, std.fs.File.stdout().deprecatedWriter());
                return true;
            }
            return error.LegacyProofGenerationRemoved;
        }

        const ReceiptJson = struct {
            version: u16,
            suite: []const u8,
            digest: [64]u8,
            pub fn jsonStringify(self: @This(), writer: anytype) !void {
                try writer.write(.{ .version = self.version, .suite = self.suite, .digest = &self.digest });
            }
        };
        fn receiptJson(receipt: stwo.core.channel.transcript_receipt.Receipt) ReceiptJson {
            return .{ .version = receipt.version, .suite = @tagName(receipt.suite), .digest = std.fmt.bytesToHex(receipt.digest, .lower) };
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
