// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "../src/Blake2sLifted.sol";
import {IKonaTransitionVerifier} from "../src/KonaCheckpoint.sol";
import {LiftedOpeningVerifier} from "../src/LiftedOpeningVerifier.sol";

contract Harness {
    function leaf(bytes calldata row) external pure returns (bytes32) {
        require(row.length != 0);
        return Blake2sLifted.leaf(row);
    }

    function node(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return Blake2sLifted.node(left, right);
    }

    function checkSeparately(
        LiftedOpeningVerifier verifier,
        bytes32 root,
        uint8 depth,
        uint32[] calldata positions,
        bytes calldata rows,
        uint32 rowBytes,
        bytes32[][] calldata paths
    ) external view returns (bool) {
        uint32[] memory position = new uint32[](1);
        for (uint256 i; i < positions.length; ++i) {
            position[0] = positions[i];
            uint256 start = i * rowBytes;
            if (!verifier.verifyOpening(root, depth, position, rows[start:start + rowBytes], rowBytes, paths[i])) {
                return false;
            }
        }
        return true;
    }
}

/// Test double for exercising the checkpoint interface only.
contract MockTransitionVerifier is IKonaTransitionVerifier {
    function verifyTransition(bytes32 statement, bytes calldata proof) external pure returns (bool) {
        return proof.length == 32 && bytes32(proof) == statement;
    }
}
