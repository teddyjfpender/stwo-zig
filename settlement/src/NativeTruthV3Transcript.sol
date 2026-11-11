// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";
import {NativeOods} from "./NativeOods.sol";
import {NativePcsTranscript} from "./NativePcsTranscript.sol";

/// @notice Receiver framing for a fixed-authority V3 classic truth worker.
/// @dev The parent verifier must derive the worker statement and fixed key,
///      authenticate the manifest and its MAIN root, and enforce global closure.
///      This library is for the exact b2/q108/p20/fold4 candidate only.
library NativeTruthV3Transcript {
    error WorkerRootMismatch();

    // OM31 raw-mod channel initialization followed by PcsConfig.mixInto.
    bytes32 private constant INITIAL = 0xcb2602a668aeaeedc3f74093c531872895593ceaa4984640e37266b92aab50bd;
    // BLAKE2s of the native Manifest.PROFILE and FixedAuthority.PROFILE.
    bytes32 private constant WORKER_PROFILE = 0x163be0c550304467f21c31fff84632cfe136a75bd9607720a689862b906734ef;
    bytes32 private constant FIXED_PROFILE = 0xf6b301ea5228561feea994daf5c6912ffa4385060f14eea270abaeef8d15ba86;
    // Candidate.profileIdentity(conjectured128_b2_q108_p20_fold4).
    bytes32 private constant CANDIDATE = 0x55c37941b9b243ba910eb2044b6be3a27e4cd5e89df39ebf42e3a8d209a640b2;

    struct Authority {
        uint32 ordinal;
        bytes32 statement;
        bytes32 fixedIdentity;
        bytes32 fixedRoot;
        bytes32 mainRoot;
        bytes32 manifest;
    }

    function derive(Authority memory authority, bytes32[3] calldata roots, bytes32 wireClaim)
        internal pure returns (bytes32 preComposition, uint32[8] memory byteChallenge)
    {
        if (roots[0] != authority.fixedRoot || roots[1] != authority.mainRoot) revert WorkerRootMismatch();
        NativeOods.readField(wireClaim); // The physical claim has exactly one canonical OM31 element.
        bytes32 header = bytes32(0x4f4b475701000000080000000400000000000000000000000000000000000000)
            | (bytes32(bytes4(NativePcsTranscript.reverse32(authority.ordinal))) >> 128);
        bytes32 digest = Blake2sLifted.shortDigest(INITIAL, header, 52);
        digest = mix(digest, WORKER_PROFILE);
        digest = mix(digest, authority.statement);
        digest = mix(digest, FIXED_PROFILE);
        digest = mix(digest, authority.fixedIdentity);
        digest = mix(digest, authority.fixedRoot);
        digest = mix(digest, CANDIDATE);
        digest = mix(digest, roots[0]);
        digest = mix(digest, roots[1]);
        digest = Blake2sLifted.shortDigest(digest, bytes32(hex"594233560100000008000000"), 44);
        byteChallenge = NativePcsTranscript.secureDraw(digest);
        digest = Blake2sLifted.shortDigest(digest, bytes32(hex"324b47570100000001000000"), 44);
        digest = mix(digest, authority.manifest);
        digest = mix(digest, wireClaim);
        preComposition = mix(digest, roots[2]);
    }

    function mix(bytes32 digest, bytes32 word) private pure returns (bytes32) {
        return Blake2sLifted.shortDigest(digest, word, 64);
    }
}
