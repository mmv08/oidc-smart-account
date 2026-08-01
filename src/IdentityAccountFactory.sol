// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IdentityIntentVerifier } from "./IdentityIntentVerifier.sol";
import { IdentityRecoveryManager } from "./IdentityRecoveryManager.sol";
import { IndependentKeyAccount } from "./IndependentKeyAccount.sol";

/// @notice CREATE2 factory for exact OIDC-authorized account bootstrap intents.
/// @dev A relayer/front-runner can only deploy the exact bound account with the exact bound signer.
contract IdentityAccountFactory is ReentrancyGuard {
    using SignatureChecker for bytes;

    address public immutable entryPoint;
    IdentityRecoveryManager public immutable recoveryManager;
    IdentityIntentVerifier public immutable verifier;

    event AccountCreated(
        address indexed account,
        bytes32 indexed identityCommitment,
        bytes32 indexed signerHash,
        bytes32 intentDigest
    );

    error InvalidConfiguration();
    error InvalidCreateIntent();
    error InvalidInitialSigner(bytes signer);
    error InvalidProofOfPossession();

    constructor(
        address entryPoint_,
        IdentityRecoveryManager recoveryManager_,
        IdentityIntentVerifier verifier_
    ) {
        if (
            entryPoint_ == address(0) || address(recoveryManager_) == address(0)
                || address(verifier_) == address(0)
                || address(recoveryManager_.verifier()) != address(verifier_)
        ) {
            revert InvalidConfiguration();
        }
        entryPoint = entryPoint_;
        recoveryManager = recoveryManager_;
        verifier = verifier_;
    }

    function predictAccount(bytes32 salt, bytes32 identityCommitment, bytes calldata initialSigner)
        public
        view
        returns (address)
    {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(IndependentKeyAccount).creationCode,
                abi.encode(entryPoint, address(recoveryManager), identityCommitment, initialSigner)
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

    function createAccount(
        bytes32 salt,
        bytes32 identityCommitment,
        bytes calldata initialSigner,
        bytes calldata proofOfPossession,
        IdentityIntentVerifier.Intent calldata intent,
        bytes[] calldata attestations
    ) external nonReentrant returns (IndependentKeyAccount account) {
        address predicted = predictAccount(salt, identityCommitment, initialSigner);
        if (
            intent.action != IdentityIntentVerifier.Action.CREATE || intent.account != predicted
                || intent.controller != address(this)
                || intent.identityCommitment != identityCommitment
                || intent.currentSignerHash != bytes32(0)
                || intent.newSignerHash != keccak256(initialSigner) || intent.recoveryNonce != 0
        ) revert InvalidCreateIntent();
        _validateInitialSigner(predicted, initialSigner);

        bytes32 digest = verifier.hashIntent(intent);
        if (!initialSigner.isValidSignatureNow(digest, proofOfPossession)) {
            revert InvalidProofOfPossession();
        }
        if (verifier.consume(intent, attestations) != digest) revert InvalidCreateIntent();

        account = new IndependentKeyAccount{ salt: salt }(
            entryPoint, address(recoveryManager), identityCommitment, initialSigner
        );
        if (address(account) != predicted) revert InvalidCreateIntent();
        emit AccountCreated(address(account), identityCommitment, keccak256(initialSigner), digest);
    }

    function _validateInitialSigner(address predicted, bytes calldata signer) private view {
        if (signer.length < 20) revert InvalidInitialSigner(signer);
        address signerVerifier = address(bytes20(signer));
        if (uint160(signerVerifier) <= 0xff || signerVerifier == predicted) {
            revert InvalidInitialSigner(signer);
        }
        if (signer.length > 20) {
            bytes32 pinned = recoveryManager.verifierCodehash(signerVerifier);
            if (pinned == bytes32(0) || signerVerifier.codehash != pinned) {
                revert InvalidInitialSigner(signer);
            }
        }
    }
}
