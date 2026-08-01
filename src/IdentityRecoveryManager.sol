// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IdentityIntentVerifier } from "./IdentityIntentVerifier.sol";
import { IndependentKeyAccount } from "./IndependentKeyAccount.sol";

/// @notice Timelocked, narrowly-scoped OIDC recovery coordinator.
/// @dev It can only add or replace one exact signer; it has no arbitrary account execution capability.
contract IdentityRecoveryManager is Ownable2Step, ReentrancyGuard {
    using SignatureChecker for bytes;

    struct PendingRecovery {
        IdentityIntentVerifier.Action action;
        bytes currentSigner;
        bytes newSigner;
        bytes32 digest;
        uint64 executeAfter;
    }

    IdentityIntentVerifier public immutable verifier;
    uint64 public immutable recoveryDelay;
    uint64 public immutable recoveryWindow;
    mapping(address account => uint256) public recoveryNonces;
    mapping(address account => PendingRecovery) private _pending;
    mapping(address signerVerifier => bytes32 pinnedCodehash) public verifierCodehash;

    event SignerVerifierPolicySet(address indexed signerVerifier, bytes32 codehash);
    event RecoveryScheduled(
        address indexed account,
        IdentityIntentVerifier.Action indexed action,
        bytes32 indexed digest,
        uint64 executeAfter,
        bytes currentSigner,
        bytes newSigner
    );
    event RecoveryCancelled(address indexed account, bytes32 indexed digest);
    event ExpiredRecoveryCleared(address indexed account, bytes32 indexed digest);
    event RecoveryFinalized(address indexed account, bytes32 indexed digest);

    error InvalidConfiguration();
    error InvalidRecoveryIntent();
    error InvalidSignerPolicy(bytes signer);
    error InvalidProofOfPossession();
    error RecoveryAlreadyPending();
    error NoPendingRecovery();
    error RecoveryNotReady();
    error RecoveryExpired();
    error OnlyAccountCanCancel();

    constructor(
        IdentityIntentVerifier verifier_,
        uint64 delay_,
        uint64 window_,
        address initialOwner
    ) Ownable(initialOwner) {
        if (address(verifier_) == address(0) || delay_ == 0 || window_ == 0) {
            revert InvalidConfiguration();
        }
        verifier = verifier_;
        recoveryDelay = delay_;
        recoveryWindow = window_;
    }

    /// @notice Pins the current runtime code hash of an address-less ERC-7913 verifier.
    function setSignerVerifierPolicy(address signerVerifier, bool allowed) external onlyOwner {
        if (uint160(signerVerifier) <= 0xff) {
            revert InvalidSignerPolicy(abi.encodePacked(signerVerifier));
        }
        bytes32 codehash;
        if (allowed) {
            codehash = signerVerifier.codehash;
            if (signerVerifier.code.length == 0) {
                revert InvalidSignerPolicy(abi.encodePacked(signerVerifier));
            }
        }
        verifierCodehash[signerVerifier] = codehash;
        emit SignerVerifierPolicySet(signerVerifier, codehash);
    }

    function getPending(address account) external view returns (PendingRecovery memory) {
        return _pending[account];
    }

    function schedule(
        address accountAddress,
        bytes calldata currentSigner,
        bytes calldata newSigner,
        bytes calldata proofOfPossession,
        IdentityIntentVerifier.Intent calldata intent,
        bytes[] calldata attestations
    ) external nonReentrant {
        IndependentKeyAccount account = IndependentKeyAccount(payable(accountAddress));
        PendingRecovery storage existing = _pending[accountAddress];
        if (existing.executeAfter != 0) {
            if (block.timestamp <= uint256(existing.executeAfter) + recoveryWindow) {
                revert RecoveryAlreadyPending();
            }
            bytes32 expiredDigest = existing.digest;
            delete _pending[accountAddress];
            emit ExpiredRecoveryCleared(accountAddress, expiredDigest);
        }
        if (!account.recoveryEnabled() || !_isBoundAccount(account)) {
            revert InvalidRecoveryIntent();
        }
        if (
            intent.account != accountAddress || intent.controller != address(this)
                || intent.identityCommitment != account.identityCommitment()
                || intent.recoveryNonce != recoveryNonces[accountAddress]
                || intent.newSignerHash != keccak256(newSigner)
        ) revert InvalidRecoveryIntent();
        if (account.isSigner(newSigner)) revert InvalidRecoveryIntent();

        if (intent.action == IdentityIntentVerifier.Action.ADD) {
            if (currentSigner.length != 0 || intent.currentSignerHash != account.signerSetHash()) {
                revert InvalidRecoveryIntent();
            }
        } else if (intent.action == IdentityIntentVerifier.Action.REPLACE) {
            if (
                !account.isSigner(currentSigner)
                    || intent.currentSignerHash != keccak256(currentSigner)
            ) {
                revert InvalidRecoveryIntent();
            }
        } else {
            revert InvalidRecoveryIntent();
        }

        _validateSignerPolicy(accountAddress, newSigner);
        bytes32 digest = verifier.hashIntent(intent);
        if (!newSigner.isValidSignatureNow(digest, proofOfPossession)) {
            revert InvalidProofOfPossession();
        }
        if (verifier.consume(intent, attestations) != digest) revert InvalidRecoveryIntent();

        recoveryNonces[accountAddress] = intent.recoveryNonce + 1;
        uint64 executeAfter = uint64(block.timestamp) + recoveryDelay;
        _pending[accountAddress] =
            PendingRecovery(intent.action, currentSigner, newSigner, digest, executeAfter);
        emit RecoveryScheduled(
            accountAddress, intent.action, digest, executeAfter, currentSigner, newSigner
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

        // Checks-effects-interactions protects the one-pending invariant against malicious signer/account callbacks.
        delete _pending[accountAddress];
        IndependentKeyAccount account = IndependentKeyAccount(payable(accountAddress));
        if (pending.action == IdentityIntentVerifier.Action.ADD) {
            account.recoveryAddSigner(pending.newSigner);
        } else {
            account.recoveryReplaceSigner(pending.currentSigner, pending.newSigner);
        }
        emit RecoveryFinalized(accountAddress, pending.digest);
    }

    function _validateSignerPolicy(address account, bytes calldata signer) private view {
        if (signer.length < 20) revert InvalidSignerPolicy(signer);
        address signerVerifier = address(bytes20(signer));
        if (uint160(signerVerifier) <= 0xff || signerVerifier == account) {
            revert InvalidSignerPolicy(signer);
        }
        if (signer.length > 20) {
            bytes32 pinned = verifierCodehash[signerVerifier];
            if (pinned == bytes32(0) || signerVerifier.codehash != pinned) {
                revert InvalidSignerPolicy(signer);
            }
        }
    }

    function _isBoundAccount(IndependentKeyAccount account) private view returns (bool) {
        try account.recoveryManager() returns (address configuredManager) {
            return configuredManager == address(this);
        } catch {
            return false;
        }
    }
}
