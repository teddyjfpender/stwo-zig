// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {KonaTransitionStatement} from "./KonaTransitionStatement.sol";

/// @notice A verifier for the complete Kona transition relation. Implementations
/// must authenticate the L1 origin and derivation data from the canonical L1
/// anchor, and bind every field of the statement digest
/// to the proven derivation and execution. An opening checker cannot implement it.
interface IKonaTransitionVerifier {
    function verifyTransition(bytes32 statement, bytes calldata proof) external view returns (bool);
}

/// @notice Sequential OP Stack checkpoints gated by a dedicated verifier.
/// @dev The verifier and genesis are deployment trust parameters. Use a
/// standalone verifier with a fixed relation and verification key.
contract KonaCheckpoint {
    error InvalidConfiguration();
    error InvalidTransition();
    error InvalidProof();
    error InvalidL1Anchor();

    struct L1Anchor {
        uint64 number;
        bytes32 hash;
    }

    bytes32 public constant STATEMENT_TYPEHASH = KonaTransitionStatement.TYPEHASH;

    uint256 public immutable rollupChainId;
    bytes32 public immutable rollupConfig;
    IKonaTransitionVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;

    uint64 public blockNumber;
    bytes32 public outputRoot;

    event CheckpointAdvanced(uint64 indexed number, bytes32 indexed root, bytes32 indexed l1Origin);

    constructor(
        uint256 rollupChainId_,
        bytes32 rollupConfig_,
        uint64 initialNumber,
        bytes32 initialRoot,
        IKonaTransitionVerifier verifier_,
        bytes32 expectedVerifierCodeHash
    ) {
        address target = address(verifier_);
        if (
            rollupChainId_ == 0 || rollupConfig_ == 0 || initialRoot == 0 || target.code.length == 0
                || target.codehash != expectedVerifierCodeHash
        ) revert InvalidConfiguration();
        rollupChainId = rollupChainId_;
        rollupConfig = rollupConfig_;
        verifier = verifier_;
        verifierCodeHash = expectedVerifierCodeHash;
        blockNumber = initialNumber;
        outputRoot = initialRoot;
    }

    function transitionDigest(uint64 nextNumber, bytes32 nextRoot, bytes32 l1Origin, L1Anchor calldata anchor)
        public
        view
        returns (bytes32)
    {
        return KonaTransitionStatement.digest(
            KonaTransitionStatement.Scope(block.chainid, address(this), rollupChainId, rollupConfig),
            KonaTransitionStatement.Checkpoint(
                blockNumber, outputRoot, nextNumber, nextRoot, l1Origin, anchor.number, anchor.hash
            )
        );
    }

    function advance(
        uint64 nextNumber,
        bytes32 nextRoot,
        bytes32 l1Origin,
        L1Anchor calldata anchor,
        bytes calldata proof
    ) external {
        if (uint256(nextNumber) != uint256(blockNumber) + 1 || nextRoot == 0 || l1Origin == 0) {
            revert InvalidTransition();
        }
        // BLOCKHASH returns zero for the current block, future blocks and
        // blocks outside its history window. Reject an unavailable anchor.
        if (anchor.hash == 0 || blockhash(anchor.number) != anchor.hash) revert InvalidL1Anchor();
        if (
            address(verifier).codehash != verifierCodeHash
                || !verifier.verifyTransition(transitionDigest(nextNumber, nextRoot, l1Origin, anchor), proof)
        ) revert InvalidProof();
        blockNumber = nextNumber;
        outputRoot = nextRoot;
        emit CheckpointAdvanced(nextNumber, nextRoot, l1Origin);
    }
}
