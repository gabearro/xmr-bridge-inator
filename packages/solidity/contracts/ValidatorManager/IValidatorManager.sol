// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

interface IValidatorManager {
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event ValidatorQuorumSet(uint8 quorum);
    event ValidatorNonceInvalidated(address indexed validator, bytes32 nonce);

    error InvalidValidatorAddress(address validator);
    error ValidatorAlreadyAdded(address validator);
    error ValidatorNotAdded(address validator);
    error InvalidValidatorSignatureCount(uint256 count, uint256 min, uint256 max);
    error InvalidSignatureOrdering();
    error InvalidSignatureLength();
    error AddressNotValidator(address signer);
    error InvalidValidatorCount();
    error InvalidValidatorQuorum();
    error RequestExpired(uint256 expiry, uint256 current);
    error InvalidSubjectSignature();
    error SignatureInvalidated(address signer, bytes32 nonce);
    error NonceAlreadyInvalidated(bytes32 nonce);

    struct ChangeValidatorRequest {
        address validator;
        bool isValidator;
        uint256 expiry;
        bytes32 nonce;
    }

    struct ChangeValidatorQuorumRequest {
        uint8 quorum;
        uint256 expiry;
        bytes32 nonce;
    }

    function isValidator(address validator) external view returns (bool);
    function assertValidatorSignatures(
        bytes32 _messageHash,
        bytes calldata _signatures,
        uint256 expiry,
        bytes32 requestNonce
    ) external view;
    function getValidatorQuorum() external view returns (uint8);
    function getValidatorCount() external view returns (uint8);
    function usedNonces(address signer, bytes32 nonce) external view returns (bool);
    function invalidateNonce(bytes32 nonce) external;
    function changeValidator(
        ChangeValidatorRequest calldata request,
        bytes calldata signatures,
        bytes calldata subjectSignature
    ) external;
    function changeValidatorQuorum(
        ChangeValidatorQuorumRequest calldata request,
        bytes calldata signatures
    ) external;
}
