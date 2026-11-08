// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativePcsVerifier} from "../src/NativePcsVerifier.sol";

contract DeepFriHarness is NativePcsVerifier {
    function check(
        bytes32 prefix, bytes calldata samples, DeepLayout calldata layout, PcsOpening calldata proof
    ) external view returns (bool) {
        return verifyPcs(prefix, samples, layout, proof);
    }
}
