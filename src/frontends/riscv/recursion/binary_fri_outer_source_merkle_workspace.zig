//! Retained MerkleWorkspace authority storage for the binary FRI source.

pub fn Type(comptime Context: type, comptime Workspace: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Context.PreparedAuthorityType;
    const std = Context.std;
    const M31 = Context.M31;
    const air_digest = Context.air_digest;
    const merkle_path_witness = Context.merkle_path_witness;
    const merkle_path_poseidon = Context.merkle_path_poseidon;
    const MERKLE_PATH_MAIN_COLUMN_COUNT = Context.MERKLE_PATH_MAIN_COLUMN_COUNT;
    const merkleLeafCount = Context.merkleLeafCount;
    const merkleInvocationCount = Context.merkleInvocationCount;
    const sharedPoseidonCallCount = Context.sharedPoseidonCallCount;
    const merkleWorkspaceDigest = Context.merkleWorkspaceDigest;
    const validateMerkleWorkspaceAliases = Context.validateMerkleWorkspaceAliases;
    const traceLogSize = Context.traceLogSize;

    return struct {
        const MerkleWorkspace = @This();
        allocator: std.mem.Allocator,
        leaf_digests: [][merkle_path_witness.DIGEST_WORD_COUNT]u32,
        invocations: []merkle_path_witness.Invocation,
        logical_rows: [][MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        poseidon_calls: []merkle_path_poseidon.Call,
        poseidon_outputs: [][merkle_path_poseidon.WIDTH]u32,
        source_authority_digest: air_digest.Digest,
        fri_path_leaf_digest: air_digest.Digest,
        authority_digest: air_digest.Digest,
        /// Row 33's path geometry.
        log_size: u32,
        /// Row 34's unified rows 1/23/25/26/33 provider geometry.
        provider_log_size: u32,
        ready: bool,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !MerkleWorkspace {
            try source.validate();
            return initAssumeAuthority(allocator, source);
        }

        pub fn initPrepared(
            allocator: std.mem.Allocator,
            source: *const Self,
            authority: *const PreparedAuthority,
        ) !MerkleWorkspace {
            try authority.validateFor(source);
            return initAssumeAuthority(allocator, source);
        }

        fn initAssumeAuthority(
            allocator: std.mem.Allocator,
            source: *const Self,
        ) !MerkleWorkspace {
            const leaf_count = try merkleLeafCount(source);
            const invocation_count = try merkleInvocationCount(source);
            const provider_call_count = try sharedPoseidonCallCount(source);
            const leaf_digests = try allocator.alloc(
                [merkle_path_witness.DIGEST_WORD_COUNT]u32,
                leaf_count,
            );
            errdefer allocator.free(leaf_digests);
            const invocations = try allocator.alloc(
                merkle_path_witness.Invocation,
                invocation_count,
            );
            errdefer allocator.free(invocations);
            const logical_rows = try allocator.alloc(
                [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
                invocation_count,
            );
            errdefer allocator.free(logical_rows);
            const poseidon_calls = try allocator.alloc(
                merkle_path_poseidon.Call,
                provider_call_count,
            );
            errdefer allocator.free(poseidon_calls);
            const poseidon_outputs = try allocator.alloc(
                [merkle_path_poseidon.WIDTH]u32,
                provider_call_count,
            );
            errdefer allocator.free(poseidon_outputs);
            var result = MerkleWorkspace{
                .allocator = allocator,
                .leaf_digests = leaf_digests,
                .invocations = invocations,
                .logical_rows = logical_rows,
                .poseidon_calls = poseidon_calls,
                .poseidon_outputs = poseidon_outputs,
                .source_authority_digest = source.source_authority_digest,
                .fri_path_leaf_digest = [_]u8{0} ** @sizeOf(air_digest.Digest),
                .authority_digest = [_]u8{0} ** @sizeOf(air_digest.Digest),
                .log_size = try traceLogSize(invocation_count),
                .provider_log_size = try traceLogSize(provider_call_count),
                .ready = false,
            };
            try result.validateGeometryFor(source);
            return result;
        }

        pub fn deinit(self: *MerkleWorkspace) void {
            self.allocator.free(self.poseidon_outputs);
            self.allocator.free(self.poseidon_calls);
            self.allocator.free(self.logical_rows);
            self.allocator.free(self.invocations);
            self.allocator.free(self.leaf_digests);
            self.* = undefined;
        }

        pub fn validateGeometryFor(
            self: *const MerkleWorkspace,
            source: *const Self,
        ) !void {
            const invocation_count = try merkleInvocationCount(source);
            const provider_call_count = try sharedPoseidonCallCount(source);
            if (!std.mem.eql(
                u8,
                &self.source_authority_digest,
                &source.source_authority_digest,
            ) or self.leaf_digests.len != try merkleLeafCount(source) or
                self.invocations.len != invocation_count or
                self.logical_rows.len != invocation_count or
                self.poseidon_calls.len != provider_call_count or
                self.poseidon_outputs.len != provider_call_count or
                self.log_size != try traceLogSize(invocation_count) or
                self.provider_log_size != try traceLogSize(provider_call_count))
            {
                return error.WorkspaceAuthorityMismatch;
            }
            try validateMerkleWorkspaceAliases(self);
        }

        pub fn validateReadyFor(
            self: *const MerkleWorkspace,
            source: *const Self,
            fri_workspace: *const Workspace,
        ) !void {
            try self.validateGeometryFor(source);
            if (!self.ready or !fri_workspace.main_ready or
                !std.mem.eql(
                    u8,
                    &self.fri_path_leaf_digest,
                    &fri_workspace.path_leaf_digest,
                ) or !std.mem.eql(
                u8,
                &self.authority_digest,
                &merkleWorkspaceDigest(self),
            )) {
                return error.WorkspaceAuthorityMismatch;
            }
        }
    };
}
