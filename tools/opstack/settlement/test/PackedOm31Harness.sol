// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {NativeOm31Packed as P} from "../src/NativeOm31Packed.sol";
import {NativeFriFold} from "../src/NativeFriFold.sol";

contract PackedOm31Harness {
    function vectors(uint32[8][] calldata a, uint32[8][] calldata b) external pure returns (bytes32[] memory results) {
        require(a.length == b.length);
        results = new bytes32[](a.length * 4);
        for (uint256 i; i < a.length; ++i) {
            bytes32 x = P.fromLimbs(a[i]);
            bytes32 y = P.fromLimbs(b[i]);
            results[4 * i] = x;
            results[4 * i + 1] = P.add(x, y);
            results[4 * i + 2] = P.sub(x, y);
            results[4 * i + 3] = P.mul(x, y);
        }
    }

    function referenceProducts(uint32[8][] calldata a, uint32[8][] calldata b) external pure returns (bytes32[] memory results) {
        require(a.length == b.length);
        results = new bytes32[](a.length);
        for (uint256 i; i < a.length; ++i) results[i] = P.fromLimbs(NativeFriFold.multiply(a[i], b[i]));
    }

    function wire(bytes32 value) external pure returns (uint32[8] memory) {
        return P.toLimbs(P.fromCanonicalWire(value));
    }

    function repeated(uint32[8] calldata a, uint32[8] calldata b, uint256 count)
        external
        pure
        returns (uint256 growth, uint32[8] memory result)
    {
        require(count <= 1024);
        bytes32 x = P.fromLimbs(a);
        bytes32 y = P.fromLimbs(b);
        bytes memory guard = new bytes(96);
        for (uint256 i; i < guard.length; ++i) {
            guard[i] = bytes1(uint8(i));
        }
        bytes32 identity = keccak256(guard);
        uint256 before;
        assembly ("memory-safe") { before := mload(0x40) }
        for (uint256 i; i < count; ++i) {
            x = P.mul(x, y);
        }
        assembly ("memory-safe") { growth := sub(mload(0x40), before) }
        require(keccak256(guard) == identity, "scratch clobbered live memory");
        result = P.toLimbs(x);
    }
}
