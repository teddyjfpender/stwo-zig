// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeFriFold} from "../src/NativeFriFold.sol";
import {NativeOods} from "../src/NativeOods.sol";

contract OodsHarness {
    function check(bytes32 preComposition, bytes32 compositionRoot, bytes calldata samples, bytes32 inverse)
        external pure returns (bytes32)
    {
        return NativeOods.check(preComposition, compositionRoot, NativeOods.Shape(33, 9, 2), samples, inverse, evaluate);
    }

    function point(bytes32 prefix, bytes32 inverse) external pure returns (NativeOods.Point memory) {
        return NativeOods.derivePoint(prefix, inverse);
    }

    // Fixed test evaluator that consumes the non-composition sample and both
    // transcript challenges. This fixture has no RV64 AIR authority.
    function evaluate(NativeOods.Point memory at, uint32[8] memory alpha, bytes calldata traceSamples)
        private pure returns (uint32[8] memory)
    {
        return NativeOods.add(
            NativeFriFold.multiply(alpha, NativeOods.readField(bytes32(traceSamples))),
            NativeFriFold.multiply(at.x, at.y)
        );
    }
}
