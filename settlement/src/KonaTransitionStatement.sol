// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Opens the checkpoint digest into the exact public outputs of the Kona guests.
/// @dev The caller owns the deployment scope and checks both outputs in the
///      recursively verified proof. Opening the statement alone is no proof.
library KonaTransitionStatement {
    error InvalidStatement();

    bytes32 internal constant TYPEHASH = keccak256(
        "KonaTransition(uint256 settlementChainId,address checkpoint,uint256 rollupChainId,bytes32 rollupConfig,uint64 previousNumber,bytes32 previousRoot,uint64 nextNumber,bytes32 nextRoot,bytes32 l1Origin,uint64 l1AnchorNumber,bytes32 l1AnchorHash)"
    );

    struct Scope {
        uint256 settlementChainId;
        address checkpoint;
        uint256 rollupChainId;
        bytes32 rollupConfig;
    }

    struct Checkpoint {
        uint64 previousNumber;
        bytes32 previousRoot;
        uint64 nextNumber;
        bytes32 nextRoot;
        bytes32 originHash;
        uint64 anchorNumber;
        bytes32 anchorHash;
    }

    struct Witness {
        Checkpoint checkpoint;
        uint64 originNumber;
        bytes32 payloadCommitment;
        bytes32 blockHash;
    }

    function digest(Scope memory scope, Checkpoint memory checkpoint) internal pure returns (bytes32) {
        return keccak256(abi.encode(TYPEHASH, scope, checkpoint));
    }

    function outputs(bytes32 expectedDigest, Scope memory scope, Witness memory witness)
        internal pure returns (bytes memory derivation, bytes memory execution)
    {
        Checkpoint memory checkpoint = witness.checkpoint;
        if (digest(scope, checkpoint) != expectedDigest
            || scope.settlementChainId == 0 || scope.settlementChainId > type(uint64).max
            || scope.rollupChainId == 0 || scope.rollupChainId > type(uint64).max
            || uint256(checkpoint.previousNumber) + 1 != checkpoint.nextNumber
            || witness.originNumber > checkpoint.anchorNumber) revert InvalidStatement();

        bytes8 chain = littleEndian(uint64(scope.rollupChainId));
        bytes32 derivationDigest = sha256(abi.encodePacked(
            "stwo/opstack/anchored-transition/v1\x00", chain, littleEndian(uint64(scope.settlementChainId)),
            littleEndian(checkpoint.anchorNumber), checkpoint.anchorHash,
            littleEndian(checkpoint.previousNumber), checkpoint.previousRoot,
            littleEndian(checkpoint.nextNumber), checkpoint.nextRoot,
            littleEndian(witness.originNumber), checkpoint.originHash,
            witness.payloadCommitment, witness.blockHash
        ));
        bytes32 executionDigest = sha256(abi.encodePacked(
            "stwo/opstack/execution-range/v1\x00", witness.payloadCommitment, witness.blockHash
        ));
        derivation = abi.encodePacked(derivationDigest, hex"01", chain, "OD");
        execution = abi.encodePacked(executionDigest, hex"01", chain, "OP");
    }

    function littleEndian(uint64 value) private pure returns (bytes8) {
        uint64 reversed;
        for (uint256 i; i < 8; ++i) {
            reversed = (reversed << 8) | uint8(value);
            value >>= 8;
        }
        return bytes8(reversed);
    }
}
