// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "../src/Blake2sLifted.sol";
import {NativeDeep} from "../src/NativeDeep.sol";
import {NativeDeepOpening} from "../src/NativeDeepOpening.sol";
import {NativePcsTranscript} from "../src/NativePcsTranscript.sol";

contract DeepHarness is NativeDeepOpening {
    function deep(
        uint8 domainLog,
        NativeDeep.Column[] calldata columns,
        NativeDeep.Point[] calldata points,
        bytes32 prefix,
        bytes calldata samples,
        TraceTree[] calldata trees,
        TraceOpening[] calldata openings,
        uint32[] calldata queries
    ) external pure returns (uint32[8][] memory) {
        bytes32 random = NativePcsTranscript.drawBlock(Blake2sLifted.absorb(prefix, samples), 0);
        uint32[8] memory alpha;
        for (uint256 i; i < 8; ++i) alpha[i] = NativePcsTranscript.wordLE(random, i) % 0x7fffffff;
        NativeDeep.Plan memory plan = NativeDeep.prepare(domainLog, columns, points, alpha, samples);
        return openedDeepAnswers(plan, trees, openings, queries);
    }
}
