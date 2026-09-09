//! Create-only checker for one externally digest-bound Ethereum+SWAP ELF.

const std = @import("std");

const authority_mod = @import("isa/ethereum_stack_swap_candidate_v1.zig");
const combined_decode =
    @import("prover/guest_precompile/ethereum_stack_swap_candidate_decode_v1.zig");
const receipt_mod =
    @import("runner/guest_precompile/ethereum_stack_swap_candidate_elf_receipt_v1.zig");

const maximum_elf_bytes: usize = 64 << 20;
const maximum_checker_bytes: usize = 256 << 20;
const maximum_receipt_bytes: usize = 4 << 20;

pub fn main() void {
    run() catch |err| {
        std.debug.print("Ethereum+SWAP candidate ELF check failed: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 5 or
        !std.fs.path.isAbsolute(args[1]) or
        !std.fs.path.isAbsolute(args[3]) or
        !std.fs.path.isAbsolute(args[4]))
    {
        std.debug.print(
            "usage: check-stack-swap-candidate-elf-v1 " ++
                "<absolute-candidate.elf> <expected-lowercase-sha256> " ++
                "<absolute-guest-source-root> <absolute-create-only-receipt.json>\n",
            .{},
        );
        return error.InvalidArguments;
    }

    const elf_path = args[1];
    const externally_expected_elf_sha256 = try receipt_mod.parseDigest(args[2]);
    const source_root = args[3];
    const receipt_path = args[4];
    const elf_bytes = try readAbsoluteAlloc(allocator, elf_path, maximum_elf_bytes);
    defer allocator.free(elf_bytes);
    if (elf_bytes.len != receipt_mod.expected_elf_bytes)
        return error.InvalidStackSwapElf;
    const actual_elf_sha256 = receipt_mod.hashBytes(elf_bytes);
    if (!std.mem.eql(u8, &actual_elf_sha256, &externally_expected_elf_sha256))
        return error.EthereumStackSwapGuestIdentityMismatch;

    // The candidate capability is minted only after the caller's external
    // digest has matched the bytes reopened above.
    const authority = try authority_mod.Authority.create(
        externally_expected_elf_sha256,
    );
    try authority.validateElf(elf_bytes);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    var owned_inventory = try receipt_mod.inspectElf(allocator, elf_bytes, decoder);
    defer owned_inventory.deinit(allocator);
    const program = try receipt_mod.buildProgramCommitment(
        allocator,
        decoder,
        &owned_inventory,
        authority,
    );
    try receipt_mod.constructAndDeinitSession(allocator, elf_bytes, authority);
    const source_files = try receipt_mod.collectSourceFiles(source_root);
    const checker = try checkerIdentity(allocator);

    var receipt = receipt_mod.Receipt{
        .elf_path = elf_path,
        .source_root = source_root,
        .elf_bytes = @intCast(elf_bytes.len),
        .elf_sha256 = actual_elf_sha256,
        .externally_expected_elf_sha256 = externally_expected_elf_sha256,
        .checker_executable_bytes = checker.bytes,
        .checker_executable_sha256 = checker.sha256,
        .authority_identity = authority.identity,
        .registry_identity = authority.stack_swap.allocation.registry_identity,
        .stack_swap_semantic_identity = authority.stack_swap.semantic_identity,
        .inventory = owned_inventory.inventory,
        .program_row_count = program.row_count,
        .program_root = program.root,
        .program_commitment_identity = program.identity,
        .source_files = source_files,
        .guest_source_identity = undefined,
        .cargo_build_identity = undefined,
        .source_closure_identity = undefined,
        .session_constructed_and_deinitialized = true,
        .receipt_identity = undefined,
    };
    try receipt_mod.bindReceiptIdentity(&receipt);
    const encoded = try receipt_mod.encodeAlloc(allocator, receipt);
    defer allocator.free(encoded);
    {
        var output = try std.fs.createFileAbsolute(receipt_path, .{
            .exclusive = true,
            .mode = 0o600,
        });
        defer output.close();
        try output.writeAll(encoded);
        try output.writeAll("\n");
        try output.sync();
    }

    try coldReopen(
        allocator,
        receipt_path,
        elf_path,
        externally_expected_elf_sha256,
        source_root,
    );
}

fn coldReopen(
    allocator: std.mem.Allocator,
    receipt_path: []const u8,
    elf_path: []const u8,
    externally_expected_elf_sha256: receipt_mod.Digest,
    source_root: []const u8,
) !void {
    const receipt_bytes = try readAbsoluteAlloc(
        allocator,
        receipt_path,
        maximum_receipt_bytes,
    );
    defer allocator.free(receipt_bytes);
    if (receipt_bytes.len < 2 or receipt_bytes[receipt_bytes.len - 1] != '\n')
        return error.InvalidStackSwapElfReceipt;
    const body = receipt_bytes[0 .. receipt_bytes.len - 1];
    var parsed = try receipt_mod.decodeAlloc(allocator, body);
    defer parsed.deinit();
    const receipt = try receipt_mod.fromWire(parsed.value);
    if (!std.mem.eql(u8, receipt.elf_path, elf_path) or
        !std.mem.eql(u8, receipt.source_root, source_root) or
        !std.mem.eql(
            u8,
            &receipt.externally_expected_elf_sha256,
            &externally_expected_elf_sha256,
        ))
    {
        return error.InvalidStackSwapElfReceipt;
    }
    const canonical = try receipt_mod.encodeAlloc(allocator, receipt);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, body))
        return error.NonCanonicalStackSwapElfReceipt;

    const reopened_elf = try readAbsoluteAlloc(allocator, elf_path, maximum_elf_bytes);
    defer allocator.free(reopened_elf);
    const reopened_elf_sha256 = receipt_mod.hashBytes(reopened_elf);
    if (reopened_elf.len != receipt.elf_bytes or
        !std.mem.eql(
            u8,
            &reopened_elf_sha256,
            &externally_expected_elf_sha256,
        ))
    {
        return error.EthereumStackSwapGuestIdentityMismatch;
    }
    const authority = try authority_mod.Authority.create(
        externally_expected_elf_sha256,
    );
    try authority.validateElf(reopened_elf);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    var inventory = try receipt_mod.inspectElf(allocator, reopened_elf, decoder);
    defer inventory.deinit(allocator);
    if (!receipt_mod.sameInventory(inventory.inventory, receipt.inventory))
        return error.InvalidStackSwapElfInventory;
    const source_files = try receipt_mod.collectSourceFiles(source_root);
    if (!receipt_mod.sameFiles(source_files, receipt.source_files))
        return error.InvalidStackSwapSourceIdentity;
    const checker = try checkerIdentity(allocator);
    if (checker.bytes != receipt.checker_executable_bytes or
        !std.mem.eql(u8, &checker.sha256, &receipt.checker_executable_sha256))
    {
        return error.StackSwapCheckerIdentityMismatch;
    }
    try receipt_mod.constructAndDeinitSession(allocator, reopened_elf, authority);
}

const CheckerIdentity = struct {
    bytes: u64,
    sha256: receipt_mod.Digest,
};

fn checkerIdentity(allocator: std.mem.Allocator) !CheckerIdentity {
    const path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(path);
    const bytes = try readAbsoluteAlloc(allocator, path, maximum_checker_bytes);
    defer allocator.free(bytes);
    if (bytes.len == 0) return error.StackSwapCheckerIdentityMismatch;
    return .{
        .bytes = @intCast(bytes.len),
        .sha256 = receipt_mod.hashBytes(bytes),
    };
}

fn readAbsoluteAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, maximum_bytes);
}

comptime {
    if (receipt_mod.production_active or receipt_mod.proof_or_fresh_verification or
        authority_mod.production_active)
    {
        @compileError("candidate ELF checker cannot activate production");
    }
}
