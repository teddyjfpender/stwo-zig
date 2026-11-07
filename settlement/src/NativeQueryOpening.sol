// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";
import {LiftedOpeningVerifier} from "./LiftedOpeningVerifier.sol";

/// @notice Verifies the native 20-bit PoW, derives all 108 queries and checks
///         a lifted tree opening at their exact projected positions.
/// @dev The root, pre-PoW digest and domain sizes are verifier-owned inputs.
///      This component does not establish their relationship to a statement.
contract NativeQueryOpening is LiftedOpeningVerifier {
    error InvalidQueryContext();

    uint256 private constant QUERY_COUNT = 108;
    uint256 private constant POW_MASK = (1 << 20) - 1;

    struct QueryContext {
        bytes32 prePowDigest;
        uint64 nonce;
        uint8 domainLog;
    }

    /// @notice Checks one opening for the exact union of queries from workers
    ///         that share a commitment and tree geometry.
    function verifyQueriedOpening(
        bytes32 root,
        uint8 treeLog,
        QueryContext[] calldata contexts,
        uint32[] calldata positions,
        bytes calldata rows,
        uint32 rowBytes,
        bytes32[] calldata witness
    ) external pure returns (bool) {
        if (
            treeLog > 30 || contexts.length == 0 || contexts.length > 8
                || positions.length == 0 || positions.length > 256
        ) revert InvalidQueryContext();

        // Binary search and the exact-set check require a canonical order.
        for (uint256 i = 1; i < positions.length; ++i) {
            if (positions[i] <= positions[i - 1]) revert InvalidQueryContext();
        }

        uint256 seen;
        for (uint256 i; i < contexts.length; ++i) {
            uint256 workerSeen = verifyQueries(contexts[i], treeLog, positions);
            if (workerSeen == 0) return false;
            seen |= workerSeen;
        }
        uint256 expected = type(uint256).max >> (256 - positions.length);
        if (seen != expected) return false;

        return verifyOpening(root, treeLog, positions, rows, rowBytes, witness);
    }

    function verifyQueries(QueryContext calldata context, uint8 treeLog, uint32[] calldata positions)
        private
        pure
        returns (uint256 seen)
    {
        if (context.domainLog == 0 || context.domainLog > 30) revert InvalidQueryContext();
        bytes32 nonceWord = bytes32(
            (uint256(reverse32(uint32(context.nonce))) << 224)
                | (uint256(reverse32(uint32(context.nonce >> 32))) << 192)
        );

        // LE32(0x12345678) || zero[12] || digest || LE32(20).
        bytes32 prefix = Blake2sLifted.shortDigest(
            bytes32(bytes4(0x78563412)) | (context.prePowDigest >> 128),
            (context.prePowDigest << 128) | bytes32(uint256(0x14000000) << 96),
            52
        );
        if (wordLE(Blake2sLifted.shortDigest(prefix, nonceWord, 40), 0) & POW_MASK != 0) return 0;

        // Mixing the nonce resets the draw counter. Each draw supplies eight
        // raw little-endian u32s. Masking precedes projection and deduplication.
        bytes32 mixed = Blake2sLifted.shortDigest(context.prePowDigest, nonceWord, 40);
        uint32 mask = (uint32(1) << context.domainLog) - 1;
        for (uint32 counter; counter * 8 < QUERY_COUNT; ++counter) {
            bytes32 blockHash =
                Blake2sLifted.shortDigest(mixed, bytes32(bytes4(reverse32(counter))), 37);
            for (uint256 lane; lane < 8 && counter * 8 + lane < QUERY_COUNT; ++lane) {
                uint32 query = project(wordLE(blockHash, lane) & mask, context.domainLog, treeLog);
                uint256 index = find(positions, query);
                if (index == positions.length) return 0;
                seen |= uint256(1) << index;
            }
        }
    }

    // Same odd/even coset preservation as prepareTreeQueryPositions in Zig.
    function project(uint32 position, uint8 domainLog, uint8 treeLog) private pure returns (uint32) {
        if (treeLog == 0) return 0;
        uint32 pair = position >> 1;
        if (treeLog > domainLog) pair <<= treeLog - domainLog;
        else pair >>= domainLog - treeLog;
        return (pair << 1) | (position & 1);
    }

    function find(uint32[] calldata positions, uint32 query) private pure returns (uint256) {
        uint256 lo;
        uint256 hi = positions.length;
        while (lo < hi) {
            uint256 middle = (lo + hi) >> 1;
            uint32 value = positions[middle];
            if (value == query) return middle;
            if (value < query) lo = middle + 1;
            else hi = middle;
        }
        return positions.length;
    }

    function wordLE(bytes32 value, uint256 lane) private pure returns (uint32) {
        return reverse32(uint32(uint256(value) >> (224 - 32 * lane)));
    }

    function reverse32(uint32 value) private pure returns (uint32) {
        uint32 pairs = ((value & 0x00ff00ff) << 8) | ((value >> 8) & 0x00ff00ff);
        return (pairs << 16) | (pairs >> 16);
    }
}
