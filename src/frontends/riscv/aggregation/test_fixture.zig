//! Deterministic fixtures shared by the isolated reference tests.

const hash = @import("hash.zig");
const manifest = @import("manifest.zig");
const types = @import("types.zig");

pub const FourLeafFixture = struct {
    accepted: types.AcceptedProtocolV1,
    header: types.ManifestHeaderV1,
    descriptors: [4]types.LeafDescriptorV1,

    pub fn view(self: *const FourLeafFixture) types.ManifestViewV1 {
        return .{ .header = self.header, .descriptors = &self.descriptors };
    }
};

pub const TwoLeafFixture = struct {
    accepted: types.AcceptedProtocolV1,
    header: types.ManifestHeaderV1,
    descriptors: [2]types.LeafDescriptorV1,

    pub fn view(self: *const TwoLeafFixture) types.ManifestViewV1 {
        return .{ .header = self.header, .descriptors = &self.descriptors };
    }
};

pub fn fourLeaves() FourLeafFixture {
    const accepted = acceptedProtocol();
    const job0 = digest(0x10);
    const job1 = digest(0x20);
    const empty = hash.emptyCallCommitment();
    const one_call = digest(0x31);
    const descriptors = [4]types.LeafDescriptorV1{
        descriptor(0, 0, .core_request, job0, empty, 0, accepted),
        descriptor(1, 0, .poseidon2_provider, job0, empty, 0, accepted),
        descriptor(2, 1, .core_request, job1, one_call, 1, accepted),
        descriptor(3, 1, .poseidon2_provider, job1, one_call, 1, accepted),
    };
    const request_root = hash.hashPair(
        hash.REQUEST_NODE_DOMAIN,
        manifest.requestLeafDigest(job0),
        manifest.requestLeafDigest(job1),
    );
    return .{
        .accepted = accepted,
        .header = header(4, request_root, accepted),
        .descriptors = descriptors,
    };
}

pub fn twoLeaves(call_count: u64) TwoLeafFixture {
    const accepted = acceptedProtocol();
    const job = digest(0x18);
    const commitment = if (call_count == 0)
        hash.emptyCallCommitment()
    else
        digest(0x38);
    return .{
        .accepted = accepted,
        .header = header(
            2,
            manifest.requestLeafDigest(job),
            accepted,
        ),
        .descriptors = .{
            descriptor(
                0,
                0,
                .core_request,
                job,
                commitment,
                call_count,
                accepted,
            ),
            descriptor(
                1,
                0,
                .poseidon2_provider,
                job,
                commitment,
                call_count,
                accepted,
            ),
        },
    };
}

pub fn digest(byte: u8) hash.Digest {
    return .{byte} ** 32;
}

pub fn nonzeroSum() types.SecureFelt {
    return .{ .limbs = .{ 1, 2, 3, 4 } };
}

fn acceptedProtocol() types.AcceptedProtocolV1 {
    return .{
        .proof_protocol_digest = digest(0xa1),
        .relation_registry_digest = digest(0xa2),
    };
}

fn header(
    leaf_count: u32,
    request_root: hash.Digest,
    accepted: types.AcceptedProtocolV1,
) types.ManifestHeaderV1 {
    return .{
        .proof_protocol_digest = accepted.proof_protocol_digest,
        .relation_registry_digest = accepted.relation_registry_digest,
        .leaf_count = leaf_count,
        .request_set_digest = request_root,
    };
}

fn descriptor(
    leaf_index: u32,
    pair_index: u32,
    role: types.LeafRole,
    job_digest: hash.Digest,
    call_commitment: hash.Digest,
    call_count: u64,
    accepted: types.AcceptedProtocolV1,
) types.LeafDescriptorV1 {
    const offset: u8 = @intCast(leaf_index);
    return .{
        .leaf_index = leaf_index,
        .pair_index = pair_index,
        .role = role,
        .job_digest = job_digest,
        .leaf_statement_digest = digest(0x40 + offset),
        .leaf_air_artifact_digest = digest(0x50 + offset),
        .preprocessed_root = digest(0x60 + offset),
        .main_root = digest(0x70 + offset),
        .guest_call_commitment = call_commitment,
        .guest_call_count = call_count,
        .proof_protocol_digest = accepted.proof_protocol_digest,
        .relation_registry_digest = accepted.relation_registry_digest,
    };
}
