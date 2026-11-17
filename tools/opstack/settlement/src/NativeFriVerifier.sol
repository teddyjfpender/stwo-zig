// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";
import {LiftedOpeningVerifier} from "./LiftedOpeningVerifier.sol";
import {NativeFriFold} from "./NativeFriFold.sol";
import {NativePcsTranscript} from "./NativePcsTranscript.sol";

/// @notice Internal native OM31 FRI verification for b2/q108/p20/fold4.
/// @dev The caller owns the OODS prefix and sample shape, and must compute
///      first-layer DEEP values from authenticated trace rows and OODS claims.
///      This component has no external entry point accepting those values.
abstract contract NativeFriVerifier is LiftedOpeningVerifier {
    error InvalidFriShape();

    uint8 private constant FOLD_STEP = 4;
    uint8 private constant LAST_DOMAIN_LOG = 1;
    uint256 private constant QUERY_COUNT = 108;
    uint32 private constant POW_MASK = (1 << 20) - 1;

    struct LayerOpening {
        bytes rows;
        bytes32[] siblings;
        uint32[] inverses;
    }

    struct FriState {
        uint8 domainLog;
        uint32[8] deepChallenge;
        uint32[8][] foldingChallenges;
        uint32[] queries;
        bytes32[] roots;
        bytes32 lastCoefficient;
    }

    /// @notice Reconstructs the transcript and derives its sorted unique queries.
    /// @dev On invalid PoW the returned state is unusable (its queries are empty).
    function beginFri(
        bytes32 prefix,
        uint8 domainLog,
        uint256 sampleCount,
        bytes calldata samples,
        bytes32[] calldata roots,
        bytes calldata lastCoefficient,
        uint64 nonce
    ) internal pure returns (bool, FriState memory state) {
        NativePcsTranscript.Challenges memory challenges =
            NativePcsTranscript.derive(prefix, domainLog, sampleCount, samples, roots, lastCoefficient);
        uint32[] memory positions = drawQueries(challenges.prePowDigest, nonce, domainLog);
        if (positions.length == 0) return (false, state);
        state = FriState(
            domainLog, challenges.deep, challenges.folding, positions, roots, bytes32(lastCoefficient)
        );
        return (true, state);
    }

    /// @param state The state returned by beginFri for this proof.
    /// @param deepValues One packed OM31 value per state.queries entry, in
    ///        position order. Each word is eight little-endian M31 limbs.
    function verifyFriLayers(
        FriState memory state,
        bytes32[] memory deepValues,
        LayerOpening[] calldata layers
    ) internal pure returns (bool) {
        uint32[] memory queries = state.queries;
        if (queries.length == 0 || queries.length != deepValues.length || layers.length != state.roots.length) {
            revert InvalidFriShape();
        }
        uint8 domainLog = state.domainLog;
        for (uint256 i; i < layers.length; ++i) {
            uint8 remaining = domainLog - LAST_DOMAIN_LOG;
            uint8 step = remaining > FOLD_STEP ? FOLD_STEP : remaining;
            uint32[] memory groups = foldedPositions(queries, step);
            if (!verifyLayerOpening(state.roots[i], domainLog, step, groups, layers[i])) return false;
            if (!matchesQueries(queries, deepValues, step, groups, layers[i].rows)) return false;
            deepValues = foldLayer(groups, layers[i], state.foldingChallenges[i], domainLog, step, i == 0);
            queries = groups;
            domainLog -= step;
        }
        // The native last polynomial has degree zero in this profile.
        if (domainLog != LAST_DOMAIN_LOG) revert InvalidFriShape();
        for (uint256 i; i < deepValues.length; ++i) {
            if (deepValues[i] != state.lastCoefficient) return false;
        }
        return true;
    }

    function verifyLayerOpening(
        bytes32 root,
        uint8 domainLog,
        uint8 step,
        uint32[] memory groups,
        LayerOpening calldata layer
    ) private pure returns (bool) {
        // Native FRI leaves hold four consecutive OM31 values when folding
        // two or more levels, and one value for a single-level fold.
        uint8 leafLog = domainLog >= 2 && step > 1 ? 2 : 0;
        uint8 groupLeafLog = step - leafLog;
        uint256 groupLeaves = uint256(1) << groupLeafLog;
        uint32[] memory leaves = new uint32[](groups.length * groupLeaves);
        for (uint256 i; i < groups.length; ++i) {
            uint32 base = groups[i] << groupLeafLog;
            for (uint32 j; j < groupLeaves; ++j) leaves[i * groupLeaves + j] = base + j;
        }
        return verifyOpeningInPlace(root, domainLog - leafLog, leaves, layer.rows, uint32(32) << leafLog, layer.siblings);
    }

    function matchesQueries(
        uint32[] memory queries,
        bytes32[] memory expected,
        uint8 step,
        uint32[] memory groups,
        bytes calldata rows
    ) private pure returns (bool) {
        uint256 width = uint256(1) << step;
        uint256 group;
        for (uint256 i; i < queries.length; ++i) {
            uint32 query = queries[i];
            if ((query >> step) != groups[group]) ++group;
            if (readValue(rows, group * width + (query & (width - 1))) != expected[i]) return false;
        }
        return true;
    }

    function foldLayer(
        uint32[] memory groups,
        LayerOpening calldata layer,
        uint32[8] memory alpha,
        uint8 domainLog,
        uint8 step,
        bool circleLayer
    ) private pure returns (bytes32[] memory folded) {
        uint256 width = uint256(1) << step;
        uint256 inverseCount = width - 1;
        if (layer.inverses.length != groups.length * inverseCount) revert InvalidFriShape();
        folded = new bytes32[](groups.length);
        uint32[8][] memory subgroup = new uint32[8][](width);
        for (uint256 i; i < groups.length; ++i) {
            for (uint256 j; j < width; ++j) {
                bytes32 value = readValue(layer.rows, i * width + j);
                uint32[8] memory decoded;
                for (uint256 k; k < 8; ++k) decoded[k] = NativePcsTranscript.wordLE(value, k);
                subgroup[j] = decoded;
            }
            uint256 at = i * inverseCount;
            folded[i] = packFriValue(NativeFriFold.foldCanonical(
                subgroup, alpha, layer.inverses[at:at + inverseCount], domainLog, groups[i] << step, circleLayer
            ));
        }
    }

    function readValue(bytes calldata rows, uint256 i) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := calldataload(add(rows.offset, shl(5, i)))
        }
    }

    function packFriValue(uint32[8] memory value) internal pure returns (bytes32 encoded) {
        for (uint256 i; i < 8; ++i) {
            encoded |= bytes32(uint256(NativePcsTranscript.reverse32(value[i])) << (224 - 32 * i));
        }
    }

    function foldedPositions(uint32[] memory queries, uint8 step) private pure returns (uint32[] memory groups) {
        groups = new uint32[](queries.length);
        uint256 count;
        for (uint256 i; i < queries.length; ++i) {
            uint32 group = queries[i] >> step;
            if (count == 0 || groups[count - 1] != group) groups[count++] = group;
        }
        assembly ("memory-safe") { mstore(groups, count) }
    }

    function drawQueries(bytes32 prePowDigest, uint64 nonce, uint8 domainLog)
        private pure returns (uint32[] memory positions)
    {
        bytes32 nonceWord = bytes32(
            (uint256(NativePcsTranscript.reverse32(uint32(nonce))) << 224)
                | (uint256(NativePcsTranscript.reverse32(uint32(nonce >> 32))) << 192)
        );
        bytes32 powPrefix = Blake2sLifted.shortDigest(
            bytes32(bytes4(0x78563412)) | (prePowDigest >> 128),
            (prePowDigest << 128) | bytes32(uint256(0x14000000) << 96),
            52
        );
        if ((NativePcsTranscript.wordLE(Blake2sLifted.shortDigest(powPrefix, nonceWord, 40), 0) & POW_MASK) != 0) {
            return new uint32[](0);
        }
        bytes32 mixed = Blake2sLifted.shortDigest(prePowDigest, nonceWord, 40);
        uint32 mask = (uint32(1) << domainLog) - 1;
        positions = new uint32[](QUERY_COUNT);
        uint256 count;
        for (uint32 counter; counter * 8 < QUERY_COUNT; ++counter) {
            bytes32 blockHash = NativePcsTranscript.drawBlock(mixed, counter);
            for (uint256 lane; lane < 8 && counter * 8 + lane < QUERY_COUNT; ++lane) {
                uint32 query = NativePcsTranscript.wordLE(blockHash, lane) & mask;
                uint256 at;
                while (at < count && positions[at] < query) ++at;
                if (at < count && positions[at] == query) continue;
                for (uint256 j = count; j > at; --j) positions[j] = positions[j - 1];
                positions[at] = query;
                ++count;
            }
        }
        assembly ("memory-safe") { mstore(positions, count) }
    }
}
