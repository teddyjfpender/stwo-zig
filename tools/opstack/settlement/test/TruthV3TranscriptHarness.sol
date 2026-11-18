// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeTruthV3Transcript} from "../src/NativeTruthV3Transcript.sol";

contract TruthV3TranscriptHarness {
    function derive(NativeTruthV3Transcript.Authority calldata authority, bytes32[3] calldata roots, bytes32 claim)
        external pure returns (bytes32, uint32[8] memory)
    {
        return NativeTruthV3Transcript.derive(authority, roots, claim);
    }
}
