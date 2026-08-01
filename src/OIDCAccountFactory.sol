// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCAccount } from "./OIDCAccount.sol";
import { OIDCRecoveryController } from "./OIDCRecoveryController.sol";

/// @notice Deterministically creates an account from an exact, action-bound OIDC claim.
contract OIDCAccountFactory is EIP712, ReentrancyGuard {
    using SignatureChecker for bytes;

    struct CreateRequest {
        address account;
        bytes32 salt;
        bytes32 providerPolicyId;
        bytes32 identityCommitment;
        bytes32 initialSignerHash;
        uint64 validAfter;
        uint64 validUntil;
    }

    bytes32 public constant CREATE_TYPEHASH = keccak256(
        "CreateAccount(address account,bytes32 salt,bytes32 providerPolicyId,bytes32 identityCommitment,bytes32 initialSignerHash,uint64 validAfter,uint64 validUntil)"
    );

    OIDCRecoveryController public immutable identityController;
    IOIDCClaimVerifier public immutable claimVerifier;
    uint64 public immutable maxClaimAge;

    event AccountCreated(
        address indexed account,
        bytes32 indexed providerPolicyId,
        bytes32 indexed identityCommitment,
        bytes32 initialSignerHash,
        bytes32 createDigest
    );

    error InvalidConfiguration();
    error InvalidCreateRequest();
    error InvalidClaim();
    error InvalidProofOfPossession();
    error AccountAlreadyDeployed(address account);

    constructor(OIDCRecoveryController identityController_) EIP712("OIDC Account Factory", "1") {
        if (address(identityController_) == address(0)) revert InvalidConfiguration();
        identityController = identityController_;
        claimVerifier = identityController_.claimVerifier();
        maxClaimAge = identityController_.maxClaimAge();
    }

    function predictAccount(
        bytes32 salt,
        bytes32 providerPolicyId,
        bytes32 identityCommitment,
        bytes calldata initialSigner
    ) public view returns (address) {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(OIDCAccount).creationCode,
                abi.encode(
                    address(identityController), providerPolicyId, identityCommitment, initialSigner
                )
            )
        );
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash))
                )
            )
        );
    }

    function hashCreate(CreateRequest memory request) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CREATE_TYPEHASH,
                    request.account,
                    request.salt,
                    request.providerPolicyId,
                    request.identityCommitment,
                    request.initialSignerHash,
                    request.validAfter,
                    request.validUntil
                )
            )
        );
    }

    function createAccount(
        CreateRequest calldata request,
        bytes calldata initialSigner,
        bytes calldata proofOfPossession,
        bytes calldata oidcProof
    ) external nonReentrant returns (OIDCAccount account) {
        address predicted = predictAccount(
            request.salt, request.providerPolicyId, request.identityCommitment, initialSigner
        );
        if (
            request.account != predicted || request.providerPolicyId == bytes32(0)
                || request.identityCommitment == bytes32(0)
                || request.initialSignerHash != keccak256(initialSigner)
                || block.timestamp < request.validAfter || block.timestamp >= request.validUntil
                || request.validUntil <= request.validAfter
        ) revert InvalidCreateRequest();
        if (predicted.code.length != 0) revert AccountAlreadyDeployed(predicted);

        bytes32 digest = hashCreate(request);
        if (!initialSigner.isValidSignatureNow(digest, proofOfPossession)) {
            revert InvalidProofOfPossession();
        }

        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = claimVerifier.verifyClaim(oidcProof);
        if (!_matchesClaim(request, claim, digest)) revert InvalidClaim();

        account = new OIDCAccount{ salt: request.salt }(
            address(identityController),
            request.providerPolicyId,
            request.identityCommitment,
            initialSigner
        );
        if (address(account) != predicted) revert InvalidCreateRequest();
        emit AccountCreated(
            address(account),
            request.providerPolicyId,
            request.identityCommitment,
            request.initialSignerHash,
            digest
        );
    }

    function _matchesClaim(
        CreateRequest calldata request,
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim,
        bytes32 expectedNonce
    ) private view returns (bool) {
        return claim.providerPolicyId == request.providerPolicyId
            && claim.identityCommitment == request.identityCommitment
            && claim.nonce == expectedNonce && claim.issuedAt <= block.timestamp
            && claim.expiresAt > block.timestamp && claim.expiresAt > claim.issuedAt
            && block.timestamp - claim.issuedAt <= maxClaimAge;
    }
}
