// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCAccount } from "./OIDCAccount.sol";
import { OIDCRecoveryController } from "./OIDCRecoveryController.sol";

/// @title OIDC Account Factory
/// @notice Deterministically deploys an account authorized by an OIDC claim and its initial signer.
/// @dev The OIDC claim nonce must equal the EIP-712 create digest. The initial signer separately proves
/// possession of the same digest before the account is deployed with CREATE2.
contract OIDCAccountFactory is EIP712, ReentrancyGuard {
    using SignatureChecker for bytes;

    /// @notice Immutable values authorized for one account deployment.
    /// @param account Predicted CREATE2 account address.
    /// @param salt Public CREATE2 deployment salt.
    /// @param providerPolicyId OIDC provider and client policy assigned to the account.
    /// @param identityCommitment Commitment to the stable provider subject and identity salt.
    /// @param initialSignerHash Keccak-256 hash of the complete initial signer encoding.
    /// @param validAfter First timestamp at which creation is valid.
    /// @param validUntil First timestamp at which creation is no longer valid.
    struct CreateRequest {
        address account;
        bytes32 salt;
        bytes32 providerPolicyId;
        bytes32 identityCommitment;
        bytes32 initialSignerHash;
        uint64 validAfter;
        uint64 validUntil;
    }

    /// @dev EIP-712 type hash used to construct the create digest. The digest is the provider nonce and
    /// initial-signer signature message.
    bytes32 public constant CREATE_TYPEHASH = keccak256(
        "CreateAccount(address account,bytes32 salt,bytes32 providerPolicyId,bytes32 identityCommitment,bytes32 initialSignerHash,uint64 validAfter,uint64 validUntil)"
    );

    /// @notice Recovery controller assigned to every account created by this factory.
    OIDCRecoveryController public immutable identityController;
    /// @notice Claim verifier inherited from the recovery controller.
    IOIDCClaimVerifier public immutable claimVerifier;
    /// @notice Maximum accepted age of a verified claim in seconds.
    uint64 public immutable maxClaimAge;

    /// @dev Emitted after a deterministic account deployment succeeds.
    /// @param account Deployed account address.
    /// @param providerPolicyId Provider policy stored by the account.
    /// @param identityCommitment Identity commitment stored by the account.
    /// @param initialSignerHash Hash of the installed signer encoding.
    /// @param createDigest EIP-712 digest authorized by OIDC and the initial signer.
    event AccountCreated(
        address indexed account,
        bytes32 indexed providerPolicyId,
        bytes32 indexed identityCommitment,
        bytes32 initialSignerHash,
        bytes32 createDigest
    );

    /// @dev Thrown when the factory is constructed with an invalid controller.
    error InvalidConfiguration();
    /// @dev Thrown when request fields, address prediction, or validity bounds do not match.
    error InvalidCreateRequest();
    /// @dev Thrown when the verified OIDC claim does not authorize this exact request.
    error InvalidClaim();
    /// @dev Thrown when the initial signer does not prove control of the create digest.
    error InvalidProofOfPossession();
    /// @dev Thrown when code already exists at the predicted account address.
    /// @param account Occupied predicted account address.
    error AccountAlreadyDeployed(address account);

    /// @param identityController_ Recovery controller and claim-policy source for created accounts.
    constructor(OIDCRecoveryController identityController_) EIP712("OIDC Account Factory", "1") {
        if (address(identityController_) == address(0)) revert InvalidConfiguration();
        identityController = identityController_;
        claimVerifier = identityController_.claimVerifier();
        maxClaimAge = identityController_.maxClaimAge();
    }

    /// @notice Computes the CREATE2 address for an account configuration and initial signer.
    /// @dev The deployment address commits to the controller, policy, identity, signer bytes, and salt.
    /// @param salt Public CREATE2 deployment salt.
    /// @param providerPolicyId Provider policy stored by the account.
    /// @param identityCommitment Identity commitment stored by the account.
    /// @param initialSigner Initial 20-byte address signer or ERC-7913 verifier-and-key encoding.
    /// @return Predicted account address.
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
        return Create2.computeAddress(salt, initCodeHash);
    }

    /// @notice Computes the EIP-712 digest that OIDC and the initial signer must authorize.
    /// @param request Exact account creation request.
    /// @return Chain- and factory-bound create digest.
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

    /// @notice Verifies both authorizations and deploys the requested account with CREATE2.
    /// @dev The claim must match the policy, identity commitment, digest, and freshness requirements.
    /// Exact replay is prevented by CREATE2 address occupancy.
    /// @param request Exact account address, identity, signer hash, salt, and validity interval.
    /// @param initialSigner Complete 20-byte address signer or ERC-7913 verifier-and-key encoding.
    /// @param proofOfPossession Initial signer signature over `hashCreate(request)`.
    /// @param oidcProof Evidence accepted by `claimVerifier` with the same digest as its nonce.
    /// @return account Newly deployed account.
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

    /// @dev Checks that an authenticated claim authorizes this request and is currently fresh.
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
