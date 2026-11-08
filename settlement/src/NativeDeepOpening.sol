// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {LiftedOpeningVerifier} from "./LiftedOpeningVerifier.sol";
import {NativeDeep} from "./NativeDeep.sol";

/// @notice Joins authenticated native trace rows to the DEEP quotient.
/// @dev Roots, geometry, query positions and DEEP plan must come from the
/// surrounding verifier. Returned answers feed the first FRI layer.
abstract contract NativeDeepOpening is LiftedOpeningVerifier {
    error InvalidDeepOpening();

    struct TraceTree {
        bytes32 root;
        uint8 logSize;
        uint16 columnCount;
    }

    struct TraceOpening {
        uint32[] positions;
        bytes rows;
        bytes32[] witness;
    }

    function openedDeepAnswers(
        NativeDeep.Plan memory plan,
        TraceTree[] memory trees,
        TraceOpening[] calldata openings,
        uint32[] memory queries
    ) internal pure returns (uint32[8][] memory answers) {
        if (trees.length == 0 || trees.length != openings.length || queries.length == 0 || queries.length > 256) {
            revert InvalidDeepOpening();
        }
        for (uint256 i; i < queries.length; ++i) {
            if (queries[i] >= (uint256(1) << plan.domainLog) || (i != 0 && queries[i] <= queries[i - 1])) {
                revert InvalidDeepOpening();
            }
        }

        uint32[] memory rowOffsets = new uint32[](queries.length * trees.length);
        uint256 totalColumns;
        for (uint256 i; i < trees.length; ++i) {
            TraceTree memory tree = trees[i];
            TraceOpening calldata opening = openings[i];
            if (tree.logSize > 30) revert InvalidDeepOpening();
            if (tree.columnCount == 0) {
                if (tree.logSize != 0 || opening.positions.length != 0 || opening.rows.length != 0
                    || opening.witness.length != 0) revert InvalidDeepOpening();
                continue;
            }
            totalColumns += tree.columnCount;
            if (totalColumns > plan.columnCount) revert InvalidDeepOpening();
            uint32 rowBytes = uint32(tree.columnCount) * 4;
            if (!verifyOpening(tree.root, tree.logSize, opening.positions, opening.rows, rowBytes, opening.witness)) {
                revert InvalidDeepOpening();
            }

            uint256 seen;
            for (uint256 j; j < queries.length; ++j) {
                uint32 position = project(queries[j], plan.domainLog, tree.logSize);
                uint256 index = find(opening.positions, position);
                if (index == opening.positions.length) revert InvalidDeepOpening();
                seen |= uint256(1) << index;
                rowOffsets[j * trees.length + i] = uint32(index * rowBytes);
            }
            if (seen != type(uint256).max >> (256 - opening.positions.length)) revert InvalidDeepOpening();
        }

        if (totalColumns != plan.columnCount) revert InvalidDeepOpening();
        answers = new uint32[8][](queries.length);
        NativeDeep.RowWorkspace memory workspace = NativeDeep.rowWorkspace(plan);
        bytes memory row = new bytes(totalColumns * 4);
        for (uint256 i; i < queries.length; ++i) {
            uint256 at;
            for (uint256 j; j < trees.length; ++j) {
                uint256 rowBytes = uint256(trees[j].columnCount) * 4;
                if (rowBytes == 0) continue;
                bytes calldata source = openings[j].rows;
                uint256 offset = rowOffsets[i * trees.length + j];
                // The opening check bounds each source slice, and row is
                // exactly the sum of the checked tree widths.
                assembly ("memory-safe") {
                    calldatacopy(add(add(row, 32), at), add(source.offset, offset), rowBytes)
                }
                at += rowBytes;
            }
            answers[i] = NativeDeep.evaluate(plan, queries[i], row, workspace);
        }
    }

    // Mirrors Zig prepareTreeQueryPositions and preserves the conjugate bit.
    function project(uint32 query, uint8 domainLog, uint8 treeLog) private pure returns (uint32) {
        if (treeLog == 0) return 0;
        uint32 pair = query >> 1;
        if (treeLog > domainLog) pair <<= treeLog - domainLog;
        else pair >>= domainLog - treeLog;
        return (pair << 1) | (query & 1);
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
}
