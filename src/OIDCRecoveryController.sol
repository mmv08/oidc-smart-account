// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCAccount } from "./OIDCAccount.sol";

/// @notice Delayed signer recovery driven by a normalized, action-bound OIDC claim.
/// @dev The proof verifier is deliberately abstract. This contract never parses JWTs or trusts oracle-specific data.
contract OIDCRecoveryController is EIP712, ReentrancyGuard {
    using SignatureChecker for bytes;

    struct RecoveryRequest {
        address account;
        bytes32 expectedSignerHash;
        uint256 expectedSignerEpoch;
        bytes32 newSignerHash;
        uint256 nonce;
        uint64 validAfter;
        uint64 validUntil;
    }

    struct PendingRecovery {
        bytes32 expectedSignerHash;
        uint256 expectedSignerEpoch;
        bytes newSigner;
        bytes32 digest;
        uint64 executeAfter;
    }

    bytes32 public constant RECOVERY_TYPEHASH = keccak256(
        "Recovery(address account,bytes32 expectedSignerHash,uint256 expectedSignerEpoch,bytes32 newSignerHash,uint256 nonce,uint64 validAfter,uint64 validUntil)"
    );

    IOIDCClaimVerifier public immutable claimVerifier;
    uint64 public immutable recoveryDelay;
    uint64 public immutable recoveryWindow;
    uint64 public immutable maxClaimAge;

    mapping(address account => uint256 nonce) public recoveryNonces;
    mapping(address account => PendingRecovery) private _pending;

    event RecoveryScheduled(
        address indexed account,
        bytes32 indexed digest,
        bytes32 indexed expectedSignerHash,
        uint256 expectedSignerEpoch,
        bytes newSigner,
        uint64 executeAfter
    );
    event RecoveryCancelled(address indexed account, bytes32 indexed digest);
    event ExpiredRecoveryCleared(address indexed account, bytes32 indexed digest);
    event RecoveryFinalized(address indexed account, bytes32 indexed digest);

    error InvalidConfiguration();
    error InvalidRecoveryRequest();
    error InvalidClaim();
    error InvalidProofOfPossession();
    error RecoveryAlreadyPending();
    error NoPendingRecovery();
    error RecoveryNotReady();
    error RecoveryExpired();
    error OnlyAccountCanCancel();

    constructor(
        IOIDCClaimVerifier claimVerifier_,
        uint64 recoveryDelay_,
        uint64 recoveryWindow_,
        uint64 maxClaimAge_
    ) EIP712("OIDC Identity Recovery", "1") {
        if (
            address(claimVerifier_) == address(0) || address(claimVerifier_).code.length == 0
                || recoveryDelay_ == 0 || recoveryWindow_ == 0 || maxClaimAge_ == 0
        ) revert InvalidConfiguration();
        claimVerifier = claimVerifier_;
        recoveryDelay = recoveryDelay_;
        recoveryWindow = recoveryWindow_;
        maxClaimAge = maxClaimAge_;
    }

    function getPending(address account) external view returns (PendingRecovery memory) {
        return _pending[account];
    }

    function hashRecovery(RecoveryRequest memory request) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVERY_TYPEHASH,
                    request.account,
                    request.expectedSignerHash,
                    request.expectedSignerEpoch,
                    request.newSignerHash,
                    request.nonce,
                    request.validAfter,
                    request.validUntil
                )
            )
        );
    }

    function schedule(
        RecoveryRequest calldata request,
        bytes calldata newSigner,
        bytes calldata proofOfPossession,
        bytes calldata oidcProof
    ) external nonReentrant {
        PendingRecovery storage existing = _pending[request.account];
        if (existing.executeAfter != 0) {
            if (block.timestamp <= uint256(existing.executeAfter) + recoveryWindow) {
                revert RecoveryAlreadyPending();
            }
            bytes32 expiredDigest = existing.digest;
            delete _pending[request.account];
            emit ExpiredRecoveryCleared(request.account, expiredDigest);
        }

        if (
            request.account == address(0) || request.newSignerHash != keccak256(newSigner)
                || request.newSignerHash == request.expectedSignerHash
                || request.nonce != recoveryNonces[request.account]
                || block.timestamp < request.validAfter || block.timestamp >= request.validUntil
                || request.validUntil <= request.validAfter
        ) revert InvalidRecoveryRequest();

        OIDCAccount account = OIDCAccount(payable(request.account));
        if (
            account.identityController() != address(this) || !account.identityRecoveryEnabled()
                || account.signerHash() != request.expectedSignerHash
                || account.signerEpoch() != request.expectedSignerEpoch
        ) revert InvalidRecoveryRequest();

        bytes32 digest = hashRecovery(request);
        if (!newSigner.isValidSignatureNow(digest, proofOfPossession)) {
            revert InvalidProofOfPossession();
        }

        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim = claimVerifier.verifyClaim(oidcProof);
        if (!_matchesClaim(account, claim, digest)) revert InvalidClaim();

        recoveryNonces[request.account] = request.nonce + 1;
        uint64 executeAfter = uint64(block.timestamp) + recoveryDelay;
        _pending[request.account] =
            PendingRecovery(
                request.expectedSignerHash,
                request.expectedSignerEpoch,
                newSigner,
                digest,
                executeAfter
            );
        emit RecoveryScheduled(
            request.account,
            digest,
            request.expectedSignerHash,
            request.expectedSignerEpoch,
            newSigner,
            executeAfter
        );
    }

    function cancel(address account) external {
        if (msg.sender != account) revert OnlyAccountCanCancel();
        PendingRecovery storage pending = _pending[account];
        if (pending.executeAfter == 0) revert NoPendingRecovery();
        bytes32 digest = pending.digest;
        delete _pending[account];
        emit RecoveryCancelled(account, digest);
    }

    function finalize(address accountAddress, bytes calldata proofOfPossession)
        external
        nonReentrant
    {
        PendingRecovery memory pending = _pending[accountAddress];
        if (pending.executeAfter == 0) revert NoPendingRecovery();
        if (block.timestamp < pending.executeAfter) revert RecoveryNotReady();
        if (block.timestamp > uint256(pending.executeAfter) + recoveryWindow) {
            revert RecoveryExpired();
        }
        if (!pending.newSigner.isValidSignatureNow(pending.digest, proofOfPossession)) {
            revert InvalidProofOfPossession();
        }

        delete _pending[accountAddress];
        OIDCAccount(payable(accountAddress))
            .replaceSignerFromIdentity(
                pending.expectedSignerHash, pending.expectedSignerEpoch, pending.newSigner
            );
        emit RecoveryFinalized(accountAddress, pending.digest);
    }

    function _matchesClaim(
        OIDCAccount account,
        IOIDCClaimVerifier.VerifiedOIDCClaim memory claim,
        bytes32 expectedNonce
    ) private view returns (bool) {
        return claim.providerPolicyId == account.providerPolicyId()
            && claim.identityCommitment == account.identityCommitment()
            && claim.nonce == expectedNonce && claim.issuedAt <= block.timestamp
            && claim.expiresAt > block.timestamp && claim.expiresAt > claim.issuedAt
            && block.timestamp - claim.issuedAt <= maxClaimAge;
    }
}
