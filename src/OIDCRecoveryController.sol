// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IOIDCClaimVerifier } from "./IOIDCClaimVerifier.sol";
import { OIDCAccount } from "./OIDCAccount.sol";

/// @title OIDC Recovery Controller
/// @notice Schedules delayed signer replacement authorized by an OIDC claim and the replacement signer.
/// @dev The claim nonce must equal the EIP-712 recovery digest. The controller stores no provider-specific
/// data; it relies on `claimVerifier` and compares the normalized result with immutable account state.
contract OIDCRecoveryController is EIP712, ReentrancyGuard {
    using SignatureChecker for bytes;

    /// @notice Exact recovery action authorized by OIDC and the replacement signer.
    /// @param account Account whose signer will be replaced.
    /// @param expectedSignerHash Hash of the signer that must still control the account.
    /// @param expectedSignerEpoch Signer epoch that must still be current.
    /// @param newSignerHash Hash of the complete replacement signer encoding.
    /// @param nonce Current sequential recovery nonce for the account.
    /// @param validAfter First timestamp at which the request may be scheduled.
    /// @param validUntil First timestamp at which the request may no longer be scheduled.
    struct RecoveryRequest {
        address account;
        bytes32 expectedSignerHash;
        uint256 expectedSignerEpoch;
        bytes32 newSignerHash;
        uint256 nonce;
        uint64 validAfter;
        uint64 validUntil;
    }

    /// @notice Recovery data retained during the delay and finalization window.
    /// @param expectedSignerHash Signer hash captured at scheduling time.
    /// @param expectedSignerEpoch Signer epoch captured at scheduling time.
    /// @param newSigner Complete replacement signer encoding.
    /// @param digest EIP-712 recovery digest authorized by OIDC and the replacement signer.
    /// @param executeAfter Earliest timestamp at which the recovery may be finalized.
    struct PendingRecovery {
        bytes32 expectedSignerHash;
        uint256 expectedSignerEpoch;
        bytes newSigner;
        bytes32 digest;
        uint64 executeAfter;
    }

    /// @dev EIP-712 type hash used to construct the recovery digest. The digest is the provider nonce and
    /// replacement-signer signature message.
    bytes32 public constant RECOVERY_TYPEHASH = keccak256(
        "Recovery(address account,bytes32 expectedSignerHash,uint256 expectedSignerEpoch,bytes32 newSignerHash,uint256 nonce,uint64 validAfter,uint64 validUntil)"
    );

    /// @notice Verifier used to authenticate normalized OIDC claims.
    IOIDCClaimVerifier public immutable claimVerifier;
    /// @notice Required delay between scheduling and finalization, in seconds.
    uint64 public immutable recoveryDelay;
    /// @notice Seconds after `executeAfter` during which finalization remains allowed, including the endpoint.
    uint64 public immutable recoveryWindow;
    /// @notice Maximum accepted age of a claim at scheduling time, in seconds.
    uint64 public immutable maxClaimAge;

    /// @notice Next recovery nonce required for each account.
    mapping(address account => uint256 nonce) public recoveryNonces;
    /// @dev At most one pending recovery is stored per account.
    mapping(address account => PendingRecovery) private _pending;

    /// @dev Emitted when a recovery enters its mandatory delay.
    /// @param account Account to recover.
    /// @param digest Authorized EIP-712 recovery digest.
    /// @param expectedSignerHash Signer hash required at finalization.
    /// @param expectedSignerEpoch Signer epoch required at finalization.
    /// @param newSigner Complete replacement signer encoding.
    /// @param executeAfter Earliest finalization timestamp.
    event RecoveryScheduled(
        address indexed account,
        bytes32 indexed digest,
        bytes32 indexed expectedSignerHash,
        uint256 expectedSignerEpoch,
        bytes newSigner,
        uint64 executeAfter
    );
    /// @dev Emitted when an account cancels its pending recovery.
    /// @param account Account whose recovery was cancelled.
    /// @param digest Cancelled recovery digest.
    event RecoveryCancelled(address indexed account, bytes32 indexed digest);
    /// @dev Emitted when scheduling clears a recovery that passed its finalization window.
    /// @param account Account whose expired recovery was cleared.
    /// @param digest Expired recovery digest.
    event ExpiredRecoveryCleared(address indexed account, bytes32 indexed digest);
    /// @dev Emitted after a pending recovery replaces the account signer.
    /// @param account Recovered account.
    /// @param digest Finalized recovery digest.
    event RecoveryFinalized(address indexed account, bytes32 indexed digest);

    /// @dev Thrown when a constructor dependency or timing parameter is invalid.
    error InvalidConfiguration();
    /// @dev Thrown when request fields, account state, nonce, or validity bounds do not match.
    error InvalidRecoveryRequest();
    /// @dev Thrown when the verified claim does not authorize the exact recovery action.
    error InvalidClaim();
    /// @dev Thrown when the replacement signer does not validate the recovery digest.
    error InvalidProofOfPossession();
    /// @dev Thrown when an unexpired recovery already occupies the account's pending slot.
    error RecoveryAlreadyPending();
    /// @dev Thrown when no recovery is pending for the account.
    error NoPendingRecovery();
    /// @dev Thrown when finalization is attempted before the mandatory delay ends.
    error RecoveryNotReady();
    /// @dev Thrown when finalization is attempted after the recovery window closes.
    error RecoveryExpired();

    /// @param claimVerifier_ Contract that authenticates and normalizes OIDC evidence.
    /// @param recoveryDelay_ Mandatory scheduling delay in seconds.
    /// @param recoveryWindow_ Finalization window after the delay, in seconds.
    /// @param maxClaimAge_ Maximum claim age accepted at scheduling time, in seconds.
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

    /// @notice Returns the pending recovery for an account.
    /// @param account Account to query.
    /// @return Stored recovery, or an all-zero value when none is pending.
    function getPending(address account) external view returns (PendingRecovery memory) {
        return _pending[account];
    }

    /// @notice Computes the EIP-712 digest that OIDC and the replacement signer must authorize.
    /// @param request Exact recovery request.
    /// @return Chain- and controller-bound recovery digest.
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

    /// @notice Verifies a recovery request and places it into the mandatory delay.
    /// @dev Scheduling consumes the account recovery nonce even if the account later cancels. An expired
    /// pending recovery is cleared before a new request is evaluated. The deletion and event are rolled
    /// back if the replacement scheduling transaction later reverts.
    /// @param request Exact account state, replacement signer hash, nonce, and validity interval.
    /// @param newSigner Complete 20-byte address signer or ERC-7913 verifier-and-key encoding.
    /// @param proofOfPossession Replacement signer signature over `hashRecovery(request)`.
    /// @param oidcProof Evidence accepted by `claimVerifier` with the same digest as its nonce.
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
        _pending[request.account] = PendingRecovery(
            request.expectedSignerHash, request.expectedSignerEpoch, newSigner, digest, executeAfter
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

    /// @notice Cancels the calling account's pending recovery.
    /// @dev Cancellation is keyed by `msg.sender`. A signer cancels through `OIDCAccount.execute` or
    /// `executeSigned`. The consumed recovery nonce is not restored.
    function cancel() external {
        address account = msg.sender;
        PendingRecovery storage pending = _pending[account];
        if (pending.executeAfter == 0) revert NoPendingRecovery();
        bytes32 digest = pending.digest;
        delete _pending[account];
        emit RecoveryCancelled(account, digest);
    }

    /// @notice Finalizes a mature recovery and installs the replacement signer.
    /// @dev Any caller may finalize while
    /// `executeAfter <= block.timestamp <= executeAfter + recoveryWindow`. Replacement-key possession
    /// is checked again, and the account revalidates the expected signer hash and epoch.
    /// @param accountAddress Account with a pending recovery.
    /// @param proofOfPossession Replacement-signer signature over the stored digest.
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

    /// @dev Checks that an authenticated claim authorizes this account action and is currently fresh.
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
