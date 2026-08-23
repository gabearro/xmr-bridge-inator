// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { IValidatorManager } from "./IValidatorManager.sol";

contract ValidatorManager is IValidatorManager, EIP712 {
    uint8 public constant MAX_VALIDATORS = 255;
    uint8 public constant MIN_VALIDATORS = 2;
    uint8 public constant MIN_QUORUM = 1;

    bytes32 public constant CHANGE_VALIDATOR_TYPEHASH = keccak256(
        "ChangeValidatorRequest(address validator,bool isValidator,uint256 expiry,bytes32 nonce)"
    );
    bytes32 public constant CHANGE_VALIDATOR_QUORUM_TYPEHASH = keccak256(
        "ChangeValidatorQuorumRequest(uint8 quorum,uint256 expiry,bytes32 nonce)"
    );

    mapping(address => bool) private validators;
    mapping(address => mapping(bytes32 => bool)) public usedNonces;
    uint8 private validatorQuorum;
    uint8 private validatorCount;

    constructor(address[] memory _initialValidators, uint8 _initialQuorum) EIP712("ValidatorManager", "1") {
        uint256 initialCount = _initialValidators.length;
        if (initialCount < MIN_VALIDATORS || initialCount > MAX_VALIDATORS) {
            revert InvalidValidatorCount();
        }

        for (uint256 i = 0; i < initialCount; i++) {
            _addValidator(_initialValidators[i]);
        }

        _setValidatorQuorum(_initialQuorum);
    }

    function isValidator(address _validator) public view returns (bool) {
        return validators[_validator];
    }

    function getValidatorQuorum() external view returns (uint8) {
        return validatorQuorum;
    }

    function getValidatorCount() external view returns (uint8) {
        return validatorCount;
    }

    function invalidateNonce(bytes32 _nonce) external {
        if (!isValidator(msg.sender)) revert AddressNotValidator(msg.sender);
        if (usedNonces[msg.sender][_nonce]) revert NonceAlreadyInvalidated(_nonce);
        usedNonces[msg.sender][_nonce] = true;
        emit ValidatorNonceInvalidated(msg.sender, _nonce);
    }

    function _hashRequest(bytes32 structHash) internal view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    function changeValidator(
        ChangeValidatorRequest calldata request,
        bytes calldata signatures,
        bytes calldata subjectSignature
    ) external {
        bytes32 digest = _hashRequest(
            keccak256(
                abi.encode(
                    CHANGE_VALIDATOR_TYPEHASH,
                    request.validator,
                    request.isValidator,
                    request.expiry,
                    request.nonce
                )
            )
        );
        assertValidatorSignatures(digest, signatures, request.expiry, request.nonce);

        if (request.isValidator) {
            if (subjectSignature.length != 65) revert InvalidSignatureLength();
            address signer = ECDSA.recover(digest, subjectSignature);
            if (signer != request.validator) revert InvalidSubjectSignature();
            _addValidator(request.validator);
        } else {
            if (subjectSignature.length != 0) revert InvalidSubjectSignature();
            _removeValidator(request.validator);
        }

        _consumeValidatorSignatures(digest, signatures, request.nonce);
    }

    function changeValidatorQuorum(
        ChangeValidatorQuorumRequest calldata request,
        bytes calldata signatures
    ) external {
        bytes32 digest = _hashRequest(
            keccak256(
                abi.encode(
                    CHANGE_VALIDATOR_QUORUM_TYPEHASH,
                    request.quorum,
                    request.expiry,
                    request.nonce
                )
            )
        );
        assertValidatorSignatures(digest, signatures, request.expiry, request.nonce);
        _setValidatorQuorum(request.quorum);
        _consumeValidatorSignatures(digest, signatures, request.nonce);
    }

    function assertValidatorSignatures(
        bytes32 _messageHash,
        bytes calldata _signatures,
        uint256 expiry,
        bytes32 requestNonce
    ) public view {
        if (block.timestamp > expiry) revert RequestExpired(expiry, block.timestamp);
        if (_signatures.length % 65 != 0) revert InvalidSignatureLength();

        uint256 signatureCount = _signatures.length / 65;

        if (signatureCount < validatorQuorum || signatureCount > validatorCount) {
            revert InvalidValidatorSignatureCount(signatureCount, validatorQuorum, validatorCount);
        }

        address lastSigner = address(0);
        for (uint8 i = 0; i < signatureCount; i++) {
            address signer = ECDSA.recover(_messageHash, _signatures[(i * 65):((i + 1) * 65)]);
            if (!isValidator(signer)) revert AddressNotValidator(signer);
            if (signer <= lastSigner) revert InvalidSignatureOrdering();
            if (usedNonces[signer][requestNonce]) revert SignatureInvalidated(signer, requestNonce);
            lastSigner = signer;
        }
    }

    function _consumeValidatorSignatures(bytes32 _messageHash, bytes calldata _signatures, bytes32 requestNonce) internal {
        uint256 signatureCount = _signatures.length / 65;
        for (uint8 i = 0; i < signatureCount; i++) {
            address signer = ECDSA.recover(_messageHash, _signatures[(i * 65):((i + 1) * 65)]);
            usedNonces[signer][requestNonce] = true;
        }
    }

    function _addValidator(address _validator) internal {
        if (_validator == address(0)) revert InvalidValidatorAddress(_validator);
        if (isValidator(_validator)) revert ValidatorAlreadyAdded(_validator);
        if (validatorCount >= MAX_VALIDATORS) revert InvalidValidatorCount();
        ++validatorCount;
        validators[_validator] = true;
        emit ValidatorAdded(_validator);
    }

    function _removeValidator(address _validator) internal {
        if (!isValidator(_validator)) revert ValidatorNotAdded(_validator);
        if (validatorCount <= MIN_VALIDATORS || validatorQuorum >= validatorCount - 1) {
            revert InvalidValidatorCount();
        }

        --validatorCount;
        delete validators[_validator];

        emit ValidatorRemoved(_validator);
    }

    function _setValidatorQuorum(uint8 _quorum) internal {
        if (_quorum < MIN_QUORUM || _quorum >= validatorCount || validatorQuorum == _quorum) {
            revert InvalidValidatorQuorum();
        }
        validatorQuorum = _quorum;
        emit ValidatorQuorumSet(_quorum);
    }
}
