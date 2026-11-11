// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeFriVerifier} from "../src/NativeFriVerifier.sol";

/// @dev Tests only: production callers compute the DEEP values internally.
contract NativeFriHarness is NativeFriVerifier {
    struct Fixture {
        bytes32 prefix;
        uint8 domainLog;
        uint256 sampleCount;
        bytes samples;
        bytes32[] roots;
        bytes lastCoefficient;
        uint64 nonce;
    }

    function check(Fixture calldata fixture, bytes32[] calldata deepValues, LayerOpening[] calldata layers)
        external pure returns (bool)
    {
        (bool valid, FriState memory state) = open(fixture);
        return valid && verifyFriLayers(state, deepValues, layers);
    }

    function positions(Fixture calldata fixture) external pure returns (uint32[] memory) {
        (bool valid, FriState memory state) = open(fixture);
        require(valid);
        return state.queries;
    }

    function open(Fixture calldata fixture) private pure returns (bool, FriState memory) {
        return beginFri(
            fixture.prefix, fixture.domainLog, fixture.sampleCount, fixture.samples,
            fixture.roots, fixture.lastCoefficient, fixture.nonce
        );
    }
}
