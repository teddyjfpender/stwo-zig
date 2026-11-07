// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";

/// @notice The commitment phase of native OM31 DEEP/FRI, up to proof of work.
/// @dev The caller must reconstruct the prefix and own the sample shape and domain.
///      This phase derives challenges. Fold, OODS and AIR checks are separate.
library NativePcsTranscript {
    error InvalidPcsShape();
    error NonCanonicalField();

    uint32 private constant M31 = 0x7fffffff;
    uint256 private constant FOLD_STEP = 4;
    uint256 private constant BLOWUP_LOG = 2;

    struct Challenges {
        uint32[8] deep;
        uint32[8][] folding;
        bytes32 prePowDigest;
    }

    function derive(
        bytes32 prefix,
        uint8 domainLog,
        uint256 sampleCount,
        bytes calldata samples,
        bytes32[] calldata friRoots,
        bytes calldata lastCoefficient
    ) internal pure returns (Challenges memory result) {
        if (domainLog < BLOWUP_LOG + FOLD_STEP || domainLog > 30 || samples.length % 32 != 0
            || samples.length / 32 != sampleCount || lastCoefficient.length > 32
            || lastCoefficient.length % 32 != 0) revert InvalidPcsShape();
        uint256 degreeLog = domainLog - BLOWUP_LOG;
        uint256 layerCount = (degreeLog + FOLD_STEP - 1) / FOLD_STEP;
        if (friRoots.length != layerCount) revert InvalidPcsShape();
        requireCanonical(samples);
        requireCanonical(lastCoefficient);

        bytes32 digest = Blake2sLifted.absorb(prefix, samples);
        result.deep = secureDraw(digest);
        result.folding = new uint32[8][](layerCount);
        for (uint256 i; i < layerCount; ++i) {
            digest = Blake2sLifted.shortDigest(digest, friRoots[i], 64);
            result.folding[i] = secureDraw(digest);
        }
        result.prePowDigest = Blake2sLifted.absorb(digest, lastCoefficient);
    }

    function drawBlock(bytes32 digest, uint32 counter) internal pure returns (bytes32) {
        return Blake2sLifted.shortDigest(digest, bytes32(bytes4(reverse32(counter))), 37);
    }

    function secureDraw(bytes32 digest) private pure returns (uint32[8] memory words) {
        bytes32 blockHash = drawBlock(digest, 0);
        for (uint256 i; i < 8; ++i) words[i] = wordLE(blockHash, i) % M31;
    }

    function requireCanonical(bytes calldata fields) private pure {
        for (uint256 i; i < fields.length; i += 4) {
            uint32 word;
            assembly ("memory-safe") { word := shr(224, calldataload(add(fields.offset, i))) }
            if (reverse32(word) >= M31) revert NonCanonicalField();
        }
    }

    function wordLE(bytes32 value, uint256 lane) internal pure returns (uint32) {
        return reverse32(uint32(uint256(value) >> (224 - 32 * lane)));
    }

    function reverse32(uint32 value) internal pure returns (uint32) {
        uint32 pairs = ((value & 0x00ff00ff) << 8) | ((value >> 8) & 0x00ff00ff);
        return (pairs << 16) | (pairs >> 16);
    }
}
