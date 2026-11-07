// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";

/// @notice Authenticates a compressed opening in a Stwo BLAKE2s lifted tree.
/// @dev A root and tree geometry must come from a full verifier to carry
///      proof authority. This contract only checks the commitment opening.
contract LiftedOpeningVerifier {
    error InvalidOpening();

    function verifyOpening(
        bytes32 root,
        uint8 depth,
        uint32[] calldata positions,
        bytes calldata rows,
        uint32 rowBytes,
        bytes32[] calldata witness
    ) external pure returns (bool) {
        uint256 count = positions.length;
        if (
            depth > 30 || count == 0 || count > 256 || rowBytes == 0 || rowBytes > 65_536
                || rowBytes % 4 != 0 || rows.length != count * rowBytes
                || witness.length > count * depth
        ) revert InvalidOpening();

        uint32[] memory indices = new uint32[](count);
        bytes32[] memory hashes = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            uint32 index = positions[i];
            if (index >= (uint256(1) << depth) || (i != 0 && index <= indices[i - 1])) {
                revert InvalidOpening();
            }
            indices[i] = index;
            uint256 start = i * rowBytes;
            hashes[i] = Blake2sLifted.leaf(rows[start:start + rowBytes]);
        }

        uint256 nextWitness;
        for (uint256 level; level < depth; ++level) {
            uint256 write;
            uint256 read;
            while (read < count) {
                uint32 index = indices[read];
                bytes32 hash = hashes[read++];
                if ((index & 1) == 0 && read < count && indices[read] == index + 1) {
                    hash = Blake2sLifted.node(hash, hashes[read++]);
                } else {
                    if (nextWitness == witness.length) revert InvalidOpening();
                    bytes32 sibling = witness[nextWitness++];
                    hash = (index & 1) == 0 ? Blake2sLifted.node(hash, sibling) : Blake2sLifted.node(sibling, hash);
                }
                // Every output replaces an already consumed input.
                indices[write] = index >> 1;
                hashes[write++] = hash;
            }
            count = write;
        }
        if (nextWitness != witness.length || count != 1) revert InvalidOpening();
        return hashes[0] == root;
    }
}
